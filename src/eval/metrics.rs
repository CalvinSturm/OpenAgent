use std::collections::BTreeMap;

use crate::events::{Event, EventKind};
use crate::types::SideEffects;

use super::types::{EvalAggregateMetrics, EvalMetrics, EvalResults, EvalRunRow};

pub fn count_tool_calls_by_side_effects(
    tool_calls: &[crate::types::ToolCall],
) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for key in [
        "filesystem_read",
        "filesystem_write",
        "shell_exec",
        "network",
        "browser",
        "none",
    ] {
        out.insert(key.to_string(), 0u32);
    }
    for tc in tool_calls {
        let key = match crate::tools::tool_side_effects(&tc.name) {
            SideEffects::FilesystemRead => "filesystem_read",
            SideEffects::FilesystemWrite => "filesystem_write",
            SideEffects::ShellExec => "shell_exec",
            SideEffects::Network => "network",
            SideEffects::Browser => "browser",
            SideEffects::None => "none",
        };
        let entry = out.entry(key.to_string()).or_insert(0u32);
        *entry = (*entry).saturating_add(1u32);
    }
    out
}

pub fn derive_tool_retry_metrics(events: &[Event]) -> (u32, BTreeMap<String, u32>) {
    let mut retries = 0u32;
    let mut failures_by_class: BTreeMap<String, u32> = BTreeMap::new();
    for ev in events {
        match ev.kind {
            EventKind::ToolRetry => {
                if ev.data.get("action").and_then(|v| v.as_str()) == Some("retry") {
                    retries = retries.saturating_add(1);
                }
            }
            EventKind::ToolExecEnd => {
                let ok = ev.data.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
                if !ok {
                    let class = ev
                        .data
                        .get("failure_class")
                        .and_then(|v| v.as_str())
                        .unwrap_or("E_OTHER")
                        .to_string();
                    *failures_by_class.entry(class).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }
    (retries, failures_by_class)
}

pub fn derive_step_invariant_violations(events: &[Event]) -> u32 {
    let mut violations = 0u32;
    for ev in events {
        match ev.kind {
            EventKind::StepBlocked | EventKind::StepReplanned => {
                violations = violations.saturating_add(1);
            }
            _ => {}
        }
    }
    violations
}

pub fn derive_io_bytes_from_messages(messages: &[crate::types::Message]) -> (u64, u64) {
    let mut bytes_read = 0u64;
    let mut bytes_written = 0u64;
    for m in messages {
        if !matches!(m.role, crate::types::Role::Tool) {
            continue;
        }
        let Some(content) = &m.content else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
            continue;
        };
        let side = v
            .get("meta")
            .and_then(|m| m.get("side_effects"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let bytes = v
            .get("meta")
            .and_then(|m| m.get("bytes"))
            .and_then(|b| b.as_u64())
            .unwrap_or(0);
        if side == "filesystem_read" {
            bytes_read = bytes_read.saturating_add(bytes);
        } else if side == "filesystem_write" {
            bytes_written = bytes_written.saturating_add(bytes);
        }
    }
    (bytes_read, bytes_written)
}

pub fn compute_eval_metrics(results: &EvalResults) -> EvalMetrics {
    let mut per_model_runs: BTreeMap<String, Vec<&EvalRunRow>> = BTreeMap::new();
    let mut per_task_runs: BTreeMap<String, Vec<&EvalRunRow>> = BTreeMap::new();
    for run in &results.runs {
        per_model_runs
            .entry(run.model.clone())
            .or_default()
            .push(run);
        per_task_runs
            .entry(run.task_id.clone())
            .or_default()
            .push(run);
    }
    let mut out = EvalMetrics {
        summary: aggregate_rows(&results.runs.iter().collect::<Vec<_>>()),
        ..Default::default()
    };
    for (model, rows) in per_model_runs {
        out.per_model.insert(model, aggregate_rows(&rows));
    }
    for (task, rows) in per_task_runs {
        out.per_task.insert(task, aggregate_rows(&rows));
    }
    out
}

pub fn aggregate_rows(rows: &[&EvalRunRow]) -> EvalAggregateMetrics {
    if rows.is_empty() {
        return EvalAggregateMetrics::default();
    }
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;
    let mut steps_sum = 0f64;
    let mut tools_sum = 0f64;
    let mut wall_sum = 0f64;
    let mut retry_sum = 0f64;
    let mut tool_retry_sum = 0f64;
    let mut step_violation_sum = 0f64;
    let mut non_skip = 0usize;
    for r in rows {
        match r.status.as_str() {
            "passed" => pass = pass.saturating_add(1),
            "skipped" => skip = skip.saturating_add(1),
            _ => fail = fail.saturating_add(1),
        }
        if r.status != "skipped" {
            non_skip = non_skip.saturating_add(1);
            if let Some(m) = &r.metrics {
                steps_sum += m.steps as f64;
                tools_sum += m.tool_calls as f64;
                wall_sum += m.wall_time_ms as f64;
                retry_sum += m.provider.http_retries as f64;
                tool_retry_sum += m.tool_retries as f64;
                step_violation_sum += m.step_invariant_violations as f64;
            } else {
                steps_sum += r.stats.steps as f64;
                tools_sum += r.stats.tool_calls as f64;
            }
        }
    }
    let total = rows.len() as f64;
    let denom = if non_skip == 0 { 1.0 } else { non_skip as f64 };
    EvalAggregateMetrics {
        avg_steps: steps_sum / denom,
        avg_tool_calls: tools_sum / denom,
        avg_wall_time_ms: wall_sum / denom,
        pass_rate: pass as f64 / total,
        fail_rate: fail as f64 / total,
        skip_rate: skip as f64 / total,
        avg_provider_retries: retry_sum / denom,
        avg_tool_retries: tool_retry_sum / denom,
        avg_step_invariant_violations: step_violation_sum / denom,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::compute_eval_metrics;
    use crate::eval::types::{
        EvalMetrics, EvalResults, EvalResultsConfig, EvalRunMetrics, EvalRunRow, EvalRunStats,
        EvalSummary, ModelSummary, TaskSummary,
    };

    fn sample_results() -> EvalResults {
        let mut by_model = BTreeMap::new();
        let mut model_summary = ModelSummary::default();
        let mut task_summary = TaskSummary::default();

        let run1 = EvalRunRow {
            model: "m1".to_string(),
            task_id: "task_a".to_string(),
            run_index: 0,
            workdir: None,
            run_id: "r1".to_string(),
            exit_reason: "ok".to_string(),
            status: "passed".to_string(),
            skip_reason: None,
            required_flags: vec![],
            passed: true,
            failures: vec![],
            stats: EvalRunStats {
                steps: 2,
                tool_calls: 1,
            },
            metrics: Some(EvalRunMetrics {
                steps: 2,
                tool_calls: 1,
                wall_time_ms: 100,
                provider: crate::eval::types::EvalProviderMetrics {
                    http_retries: 1,
                    provider_errors: 0,
                },
                tool_retries: 2,
                step_invariant_violations: 1,
                ..Default::default()
            }),
            tokens: None,
            estimated_cost_usd: None,
            verifier: None,
        };
        let run2 = EvalRunRow {
            model: "m1".to_string(),
            task_id: "task_a".to_string(),
            run_index: 1,
            workdir: None,
            run_id: "r2".to_string(),
            exit_reason: "provider_error".to_string(),
            status: "failed".to_string(),
            skip_reason: None,
            required_flags: vec![],
            passed: false,
            failures: vec!["boom".to_string()],
            stats: EvalRunStats {
                steps: 4,
                tool_calls: 3,
            },
            metrics: Some(EvalRunMetrics {
                steps: 4,
                tool_calls: 3,
                wall_time_ms: 300,
                provider: crate::eval::types::EvalProviderMetrics {
                    http_retries: 3,
                    provider_errors: 1,
                },
                tool_retries: 0,
                step_invariant_violations: 0,
                ..Default::default()
            }),
            tokens: None,
            estimated_cost_usd: None,
            verifier: None,
        };
        let run3 = EvalRunRow {
            model: "m2".to_string(),
            task_id: "task_b".to_string(),
            run_index: 0,
            workdir: None,
            run_id: "r3".to_string(),
            exit_reason: "skipped".to_string(),
            status: "skipped".to_string(),
            skip_reason: Some("missing capability".to_string()),
            required_flags: vec![],
            passed: false,
            failures: vec![],
            stats: EvalRunStats {
                steps: 0,
                tool_calls: 0,
            },
            metrics: None,
            tokens: None,
            estimated_cost_usd: None,
            verifier: None,
        };

        model_summary.passed = 1;
        model_summary.failed = 1;
        model_summary.skip_rate = 0.0;
        task_summary.passed = 1;
        task_summary.failed = 1;
        task_summary.runs = vec![run1.clone(), run2.clone()];
        model_summary
            .tasks
            .insert("task_a".to_string(), task_summary);
        by_model.insert("m1".to_string(), model_summary);

        let mut model2_summary = ModelSummary::default();
        model2_summary.skipped = 1;
        let mut task2_summary = TaskSummary::default();
        task2_summary.skipped = 1;
        task2_summary.runs = vec![run3.clone()];
        model2_summary
            .tasks
            .insert("task_b".to_string(), task2_summary);
        by_model.insert("m2".to_string(), model2_summary);

        EvalResults {
            schema_version: "openagent.eval.v1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            config: EvalResultsConfig::minimal_for_tests(),
            summary: EvalSummary::default(),
            by_model,
            runs: vec![run1, run2, run3],
            metrics: None,
            baseline: None,
            regression: None,
        }
    }

    #[test]
    fn compute_eval_metrics_aggregates_summary_model_and_task() {
        let results = sample_results();
        let m: EvalMetrics = compute_eval_metrics(&results);

        // summary rates over 3 runs: 1 pass, 1 fail, 1 skip
        assert!((m.summary.pass_rate - (1.0 / 3.0)).abs() < 1e-9);
        assert!((m.summary.fail_rate - (1.0 / 3.0)).abs() < 1e-9);
        assert!((m.summary.skip_rate - (1.0 / 3.0)).abs() < 1e-9);

        // non-skip denominator is 2 runs: avg steps=(2+4)/2, avg tools=(1+3)/2
        assert_eq!(m.summary.avg_steps, 3.0);
        assert_eq!(m.summary.avg_tool_calls, 2.0);
        assert_eq!(m.summary.avg_wall_time_ms, 200.0);
        assert_eq!(m.summary.avg_provider_retries, 2.0);
        assert_eq!(m.summary.avg_tool_retries, 1.0);
        assert_eq!(m.summary.avg_step_invariant_violations, 0.5);

        // grouping exists and is deterministic by key
        assert!(m.per_model.contains_key("m1"));
        assert!(m.per_model.contains_key("m2"));
        assert!(m.per_task.contains_key("task_a"));
        assert!(m.per_task.contains_key("task_b"));

        // all-skipped task/model yields zero averages due to skip-only denominator handling
        let task_b = m.per_task.get("task_b").expect("task_b metrics");
        assert_eq!(task_b.avg_steps, 0.0);
        assert_eq!(task_b.avg_tool_calls, 0.0);
        assert_eq!(task_b.skip_rate, 1.0);
    }
}
