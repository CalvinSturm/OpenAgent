use std::path::Path;

use crate::eval::types::EvalResults;

pub fn write_results(path: &Path, results: &EvalResults) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(results)?)?;
    Ok(())
}

pub fn write_junit(path: &Path, results: &EvalResults) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n");
    for (model, stats) in &results.by_model {
        let tests = stats.passed + stats.failed + stats.skipped;
        xml.push_str(&format!(
            "<testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" skipped=\"{}\">\n",
            xml_escape(model),
            tests,
            stats.failed,
            stats.skipped
        ));
        for (task_id, task) in &stats.tasks {
            for run in &task.runs {
                xml.push_str(&format!(
                    "<testcase name=\"{}:{}:{}\" time=\"0\">",
                    xml_escape(model),
                    xml_escape(task_id),
                    run.run_index
                ));
                if run.status == "skipped" {
                    xml.push_str(&format!(
                        "<skipped message=\"{}\"/>",
                        xml_escape(run.skip_reason.as_deref().unwrap_or("skipped"))
                    ));
                } else if !run.passed {
                    xml.push_str(&format!(
                        "<failure message=\"{}\">{}</failure>",
                        xml_escape(&run.exit_reason),
                        xml_escape(&run.failures.join("; "))
                    ));
                }
                xml.push_str("</testcase>\n");
            }
        }
        xml.push_str("</testsuite>\n");
    }
    xml.push_str("</testsuites>\n");
    std::fs::write(path, xml)?;
    Ok(())
}

pub fn write_summary_md(path: &Path, results: &EvalResults) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut md = String::new();
    md.push_str("# OpenAgent Eval Summary\n\n");
    md.push_str(&format!(
        "- Total: {}\n- Passed: {}\n- Failed: {}\n- Skipped: {}\n- Pass rate: {:.2}%\n\n",
        results.summary.total_runs,
        results.summary.passed,
        results.summary.failed,
        results.summary.skipped,
        results.summary.pass_rate * 100.0
    ));
    md.push_str("## Per model\n\n");
    for (model, stats) in &results.by_model {
        let metrics = results
            .metrics
            .as_ref()
            .and_then(|m| m.per_model.get(model))
            .cloned()
            .unwrap_or_default();
        md.push_str(&format!(
            "- {}: passed {}, failed {}, skipped {}, pass {:.2}%, avg_steps {:.2}, avg_tool_calls {:.2}, avg_provider_retries {:.2}, avg_tool_retries {:.2}\n",
            model,
            stats.passed,
            stats.failed,
            stats.skipped,
            stats.pass_rate * 100.0,
            metrics.avg_steps,
            metrics.avg_tool_calls,
            metrics.avg_provider_retries,
            metrics.avg_tool_retries
        ));
    }
    let total_cost = results
        .runs
        .iter()
        .filter_map(|r| r.estimated_cost_usd)
        .sum::<f64>();
    if total_cost > 0.0 {
        md.push_str(&format!("\n- Total estimated cost: ${:.6}\n", total_cost));
    }
    std::fs::write(path, md)?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use super::{write_junit, write_results, write_summary_md};
    use crate::eval::types::{
        EvalAggregateMetrics, EvalMetrics, EvalResults, EvalResultsConfig, EvalRunRow,
        EvalRunStats, EvalSummary, ModelSummary, TaskSummary,
    };

    fn sample_results() -> EvalResults {
        let run = EvalRunRow {
            model: "m<1>&".to_string(),
            task_id: "task_a".to_string(),
            run_index: 0,
            workdir: None,
            run_id: "r1".to_string(),
            exit_reason: "provider_error".to_string(),
            status: "failed".to_string(),
            skip_reason: None,
            required_flags: vec![],
            passed: false,
            failures: vec!["failure <xml> & details".to_string()],
            stats: EvalRunStats {
                steps: 1,
                tool_calls: 2,
            },
            metrics: None,
            tokens: None,
            estimated_cost_usd: Some(0.125),
            verifier: None,
        };

        let mut task_summary = TaskSummary::default();
        task_summary.failed = 1;
        task_summary.runs = vec![run.clone()];
        let mut model_summary = ModelSummary::default();
        model_summary.failed = 1;
        model_summary
            .tasks
            .insert("task_a".to_string(), task_summary);

        let mut by_model = BTreeMap::new();
        by_model.insert("m<1>&".to_string(), model_summary);

        let mut per_model = BTreeMap::new();
        per_model.insert(
            "m<1>&".to_string(),
            EvalAggregateMetrics {
                avg_steps: 1.0,
                avg_tool_calls: 2.0,
                avg_provider_retries: 0.0,
                avg_tool_retries: 0.0,
                ..Default::default()
            },
        );

        EvalResults {
            schema_version: "openagent.eval.v1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            config: EvalResultsConfig::minimal_for_tests(),
            summary: EvalSummary {
                total_runs: 1,
                passed: 0,
                failed: 1,
                skipped: 0,
                pass_rate: 0.0,
            },
            by_model,
            runs: vec![run],
            metrics: Some(EvalMetrics {
                summary: EvalAggregateMetrics::default(),
                per_model,
                per_task: BTreeMap::new(),
            }),
            baseline: None,
            regression: None,
        }
    }

    #[test]
    fn report_writers_emit_expected_structures() {
        let tmp = tempdir().expect("tmp");
        let json_path = tmp.path().join("out").join("results.json");
        let junit_path = tmp.path().join("out").join("results.junit.xml");
        let md_path = tmp.path().join("out").join("SUMMARY.md");
        let results = sample_results();

        write_results(&json_path, &results).expect("json write");
        write_junit(&junit_path, &results).expect("junit write");
        write_summary_md(&md_path, &results).expect("md write");

        let json = std::fs::read_to_string(&json_path).expect("json read");
        let junit = std::fs::read_to_string(&junit_path).expect("junit read");
        let md = std::fs::read_to_string(&md_path).expect("md read");

        assert!(json.contains("\"schema_version\": \"openagent.eval.v1\""));
        assert!(json.contains("\"runs\""));

        assert!(junit.contains("<testsuites>"));
        assert!(junit.contains("<testsuite name=\"m&lt;1&gt;&amp;\""));
        assert!(junit.contains("<failure message=\"provider_error\">"));
        assert!(junit.contains("failure &lt;xml&gt; &amp; details"));

        assert!(md.contains("# OpenAgent Eval Summary"));
        assert!(md.contains("## Per model"));
        assert!(md.contains("m<1>&: passed 0, failed 1"));
        assert!(md.contains("Total estimated cost: $0.125000"));
    }
}
