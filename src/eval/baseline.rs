use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

use crate::eval::runner::EvalResults;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalBaseline {
    pub schema_version: String,
    pub created_at: String,
    pub profile_hash_hex: Option<String>,
    pub models: Vec<String>,
    pub pack: String,
    #[serde(default)]
    pub task_expectations: BTreeMap<String, TaskExpectation>,
    pub summary_expectations: SummaryExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskExpectation {
    #[serde(default)]
    pub min_pass_rate: Option<f64>,
    #[serde(default)]
    pub max_fail_rate: Option<f64>,
    #[serde(default)]
    pub dominant_tool_sequence: Vec<String>,
    #[serde(default)]
    pub max_avg_tool_sequence_distance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SummaryExpectation {
    #[serde(default)]
    pub min_pass_rate: Option<f64>,
    #[serde(default)]
    pub max_avg_steps: Option<f64>,
    #[serde(default)]
    pub max_avg_tool_retries: Option<f64>,
    #[serde(default)]
    pub max_avg_tool_failures_by_class: BTreeMap<String, f64>,
    #[serde(default)]
    pub max_avg_step_invariant_violations: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionResult {
    pub checked: bool,
    pub passed: bool,
    #[serde(default)]
    pub failures: Vec<RegressionFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionFailure {
    pub scope: String,
    pub key: String,
    pub expected: String,
    pub actual: String,
}

pub fn baseline_path(state_dir: &Path, name: &str) -> PathBuf {
    state_dir
        .join("eval")
        .join("baselines")
        .join(format!("{name}.json"))
}

pub fn load_baseline(state_dir: &Path, name: &str) -> anyhow::Result<EvalBaseline> {
    let path = baseline_path(state_dir, name);
    let bytes =
        fs::read(&path).with_context(|| format!("failed reading baseline {}", path.display()))?;
    let baseline: EvalBaseline = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed parsing baseline {}", path.display()))?;
    if baseline.schema_version != "openagent.eval_baseline.v1" {
        return Err(anyhow!(
            "unsupported baseline schema {}",
            baseline.schema_version
        ));
    }
    Ok(baseline)
}

pub fn list_baselines(state_dir: &Path) -> anyhow::Result<Vec<String>> {
    let dir = state_dir.join("eval").join("baselines");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

pub fn delete_baseline(state_dir: &Path, name: &str) -> anyhow::Result<()> {
    let path = baseline_path(state_dir, name);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed deleting {}", path.display()))?;
    }
    Ok(())
}

pub fn create_baseline_from_results(
    state_dir: &Path,
    name: &str,
    results_path: &Path,
) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(results_path)
        .with_context(|| format!("failed reading results {}", results_path.display()))?;
    let results: EvalResults = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed parsing results {}", results_path.display()))?;

    let mut task_expectations = BTreeMap::new();
    for (task_id, stats) in aggregate_task_rates(&results) {
        let dominant = dominant_tool_sequence_for_task(&results, &task_id);
        let avg_dist = avg_tool_sequence_distance_for_task(&results, &task_id, &dominant);
        task_expectations.insert(
            task_id,
            TaskExpectation {
                min_pass_rate: Some(stats.0),
                max_fail_rate: Some(stats.1),
                dominant_tool_sequence: dominant,
                max_avg_tool_sequence_distance: Some(avg_dist),
            },
        );
    }

    let baseline = EvalBaseline {
        schema_version: "openagent.eval_baseline.v1".to_string(),
        created_at: crate::trust::now_rfc3339(),
        profile_hash_hex: results.config.resolved_profile_hash_hex.clone(),
        models: results.config.models.clone(),
        pack: results.config.pack.clone(),
        summary_expectations: SummaryExpectation {
            min_pass_rate: Some(results.summary.pass_rate),
            max_avg_steps: Some(avg_steps(&results)),
            max_avg_tool_retries: Some(avg_tool_retries(&results)),
            max_avg_tool_failures_by_class: avg_tool_failures_by_class(&results),
            max_avg_step_invariant_violations: Some(avg_step_invariant_violations(&results)),
        },
        task_expectations,
    };
    let path = baseline_path(state_dir, name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(&baseline)?)?;
    Ok(path)
}

pub fn compare_results(baseline: &EvalBaseline, results: &EvalResults) -> RegressionResult {
    let mut failures = Vec::new();
    if let Some(min) = baseline.summary_expectations.min_pass_rate {
        if results.summary.pass_rate < min {
            failures.push(RegressionFailure {
                scope: "summary".to_string(),
                key: "pass_rate".to_string(),
                expected: format!(">= {min:.4}"),
                actual: format!("{:.4}", results.summary.pass_rate),
            });
        }
    }
    if let Some(max_avg) = baseline.summary_expectations.max_avg_steps {
        let avg = avg_steps(results);
        if avg > max_avg {
            failures.push(RegressionFailure {
                scope: "summary".to_string(),
                key: "avg_steps".to_string(),
                expected: format!("<= {max_avg:.4}"),
                actual: format!("{avg:.4}"),
            });
        }
    }
    if let Some(max_avg) = baseline.summary_expectations.max_avg_tool_retries {
        let avg = avg_tool_retries(results);
        if avg > max_avg {
            failures.push(RegressionFailure {
                scope: "summary".to_string(),
                key: "avg_tool_retries".to_string(),
                expected: format!("<= {max_avg:.4}"),
                actual: format!("{avg:.4}"),
            });
        }
    }
    for (class, max_avg) in &baseline.summary_expectations.max_avg_tool_failures_by_class {
        let avg = avg_tool_failures_by_class(results)
            .get(class)
            .copied()
            .unwrap_or(0.0);
        if avg > *max_avg {
            failures.push(RegressionFailure {
                scope: "summary".to_string(),
                key: format!("avg_tool_failures_by_class.{class}"),
                expected: format!("<= {max_avg:.4}"),
                actual: format!("{avg:.4}"),
            });
        }
    }
    if let Some(max_avg) = baseline
        .summary_expectations
        .max_avg_step_invariant_violations
    {
        let avg = avg_step_invariant_violations(results);
        if avg > max_avg {
            failures.push(RegressionFailure {
                scope: "summary".to_string(),
                key: "avg_step_invariant_violations".to_string(),
                expected: format!("<= {max_avg:.4}"),
                actual: format!("{avg:.4}"),
            });
        }
    }

    let task_rates = aggregate_task_rates(results);
    for (task, exp) in &baseline.task_expectations {
        let (pass_rate, fail_rate) = task_rates.get(task).copied().unwrap_or((0.0, 1.0));
        if let Some(min) = exp.min_pass_rate {
            if pass_rate < min {
                failures.push(RegressionFailure {
                    scope: "task".to_string(),
                    key: task.clone(),
                    expected: format!("pass_rate >= {min:.4}"),
                    actual: format!("{pass_rate:.4}"),
                });
            }
        }
        if let Some(max) = exp.max_fail_rate {
            if fail_rate > max {
                failures.push(RegressionFailure {
                    scope: "task".to_string(),
                    key: task.clone(),
                    expected: format!("fail_rate <= {max:.4}"),
                    actual: format!("{fail_rate:.4}"),
                });
            }
        }
        if !exp.dominant_tool_sequence.is_empty() {
            let avg_dist =
                avg_tool_sequence_distance_for_task(results, task, &exp.dominant_tool_sequence);
            if let Some(max_dist) = exp.max_avg_tool_sequence_distance {
                if avg_dist > max_dist {
                    failures.push(RegressionFailure {
                        scope: "task".to_string(),
                        key: format!("{task}.avg_tool_sequence_distance"),
                        expected: format!("<= {max_dist:.4}"),
                        actual: format!("{avg_dist:.4}"),
                    });
                }
            }
        }
    }

    RegressionResult {
        checked: true,
        passed: failures.is_empty(),
        failures,
    }
}

pub fn avg_steps(results: &EvalResults) -> f64 {
    let mut total_steps = 0usize;
    let mut count = 0usize;
    for run in &results.runs {
        if run.status != "skipped" {
            total_steps = total_steps.saturating_add(run.stats.steps);
            count = count.saturating_add(1);
        }
    }
    if count == 0 {
        0.0
    } else {
        total_steps as f64 / count as f64
    }
}

pub fn avg_tool_retries(results: &EvalResults) -> f64 {
    let mut total = 0u64;
    let mut count = 0u64;
    for run in &results.runs {
        if run.status == "skipped" {
            continue;
        }
        count = count.saturating_add(1);
        if let Some(metrics) = &run.metrics {
            total = total.saturating_add(metrics.tool_retries as u64);
        }
    }
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

pub fn avg_tool_failures_by_class(results: &EvalResults) -> BTreeMap<String, f64> {
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    let mut count = 0u64;
    for run in &results.runs {
        if run.status == "skipped" {
            continue;
        }
        count = count.saturating_add(1);
        if let Some(metrics) = &run.metrics {
            for (class, value) in &metrics.tool_failures_by_class {
                let entry = totals.entry(class.clone()).or_insert(0);
                *entry = (*entry).saturating_add(*value as u64);
            }
        }
    }
    if count == 0 {
        return BTreeMap::new();
    }
    totals
        .into_iter()
        .map(|(class, total)| (class, total as f64 / count as f64))
        .collect()
}

pub fn avg_step_invariant_violations(results: &EvalResults) -> f64 {
    let mut total = 0u64;
    let mut count = 0u64;
    for run in &results.runs {
        if run.status == "skipped" {
            continue;
        }
        count = count.saturating_add(1);
        if let Some(metrics) = &run.metrics {
            total = total.saturating_add(metrics.step_invariant_violations as u64);
        }
    }
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

fn dominant_tool_sequence_for_task(results: &EvalResults, task: &str) -> Vec<String> {
    let mut counts: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    for run in &results.runs {
        if run.status == "skipped" || run.task_id != task {
            continue;
        }
        let seq = run
            .metrics
            .as_ref()
            .map(|m| m.tool_sequence.clone())
            .unwrap_or_default();
        let key = seq.join("|");
        let entry = counts.entry(key).or_insert((0, seq));
        entry.0 = entry.0.saturating_add(1);
    }
    counts
        .into_iter()
        .max_by_key(|(_, (count, _))| *count)
        .map(|(_, (_, seq))| seq)
        .unwrap_or_default()
}

fn avg_tool_sequence_distance_for_task(
    results: &EvalResults,
    task: &str,
    dominant: &[String],
) -> f64 {
    let mut total = 0f64;
    let mut count = 0u64;
    for run in &results.runs {
        if run.status == "skipped" || run.task_id != task {
            continue;
        }
        let seq = run
            .metrics
            .as_ref()
            .map(|m| m.tool_sequence.clone())
            .unwrap_or_default();
        total += normalized_sequence_distance(&seq, dominant);
        count = count.saturating_add(1);
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

fn normalized_sequence_distance(a: &[String], b: &[String]) -> f64 {
    let n = a.len();
    let m = b.len();
    if n == 0 && m == 0 {
        return 0.0;
    }
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in dp.iter_mut().enumerate().take(n + 1) {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate().take(m + 1) {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[n][m] as f64 / n.max(m) as f64
}

fn aggregate_task_rates(results: &EvalResults) -> BTreeMap<String, (f64, f64)> {
    let mut counts: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new(); // pass, fail, total_non_skip
    for run in &results.runs {
        if run.status == "skipped" {
            continue;
        }
        let entry = counts.entry(run.task_id.clone()).or_insert((0, 0, 0));
        if run.passed {
            entry.0 = entry.0.saturating_add(1);
        } else {
            entry.1 = entry.1.saturating_add(1);
        }
        entry.2 = entry.2.saturating_add(1);
    }
    counts
        .into_iter()
        .map(|(task, (p, f, n))| {
            if n == 0 {
                (task, (0.0, 0.0))
            } else {
                (task, (p as f64 / n as f64, f as f64 / n as f64))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use crate::eval::runner::{
        EvalResults, EvalResultsConfig, EvalRunMetrics, EvalRunRow, EvalRunStats, EvalSummary,
    };

    use super::{compare_results, create_baseline_from_results, load_baseline, RegressionResult};

    fn sample_results() -> EvalResults {
        EvalResults {
            schema_version: "openagent.eval.v1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            config: EvalResultsConfig::minimal_for_tests(),
            summary: EvalSummary {
                total_runs: 2,
                passed: 1,
                failed: 1,
                skipped: 0,
                pass_rate: 0.5,
            },
            by_model: BTreeMap::new(),
            runs: vec![
                EvalRunRow {
                    model: "m".to_string(),
                    task_id: "C1".to_string(),
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
                        steps: 10,
                        tool_calls: 1,
                    },
                    metrics: None,
                    tokens: None,
                    estimated_cost_usd: None,
                    verifier: None,
                },
                EvalRunRow {
                    model: "m".to_string(),
                    task_id: "C1".to_string(),
                    run_index: 1,
                    workdir: None,
                    run_id: "r2".to_string(),
                    exit_reason: "ok".to_string(),
                    status: "failed".to_string(),
                    skip_reason: None,
                    required_flags: vec![],
                    passed: false,
                    failures: vec!["x".to_string()],
                    stats: EvalRunStats {
                        steps: 20,
                        tool_calls: 1,
                    },
                    metrics: None,
                    tokens: None,
                    estimated_cost_usd: None,
                    verifier: None,
                },
            ],
            metrics: None,
            baseline: None,
            regression: None,
        }
    }

    #[test]
    fn baseline_create_and_compare() {
        let td = tempfile::tempdir().expect("tempdir");
        let rp = td.path().join("results.json");
        fs::write(
            &rp,
            serde_json::to_vec_pretty(&sample_results()).expect("serialize"),
        )
        .expect("write");
        let bp = create_baseline_from_results(td.path(), "b1", &rp).expect("create");
        let bl = load_baseline(td.path(), "b1").expect("load");
        assert_eq!(bp.file_name().and_then(|s| s.to_str()), Some("b1.json"));
        assert_eq!(bl.schema_version, "openagent.eval_baseline.v1");
        let reg: RegressionResult = compare_results(&bl, &sample_results());
        assert!(reg.passed);
    }

    #[test]
    fn compare_results_flags_failure_class_regression() {
        let mut baseline_results = sample_results();
        baseline_results.runs[0].metrics = Some(EvalRunMetrics {
            tool_failures_by_class: BTreeMap::from([(String::from("E_TIMEOUT_TRANSIENT"), 1)]),
            ..Default::default()
        });
        baseline_results.runs[1].metrics = Some(EvalRunMetrics {
            tool_failures_by_class: BTreeMap::new(),
            ..Default::default()
        });

        let td = tempfile::tempdir().expect("tempdir");
        let rp = td.path().join("results.json");
        fs::write(
            &rp,
            serde_json::to_vec_pretty(&baseline_results).expect("serialize"),
        )
        .expect("write");
        let _ = create_baseline_from_results(td.path(), "b1", &rp).expect("create");
        let mut bl = load_baseline(td.path(), "b1").expect("load");
        bl.summary_expectations
            .max_avg_tool_failures_by_class
            .insert("E_TIMEOUT_TRANSIENT".to_string(), 0.1);

        let mut current = baseline_results.clone();
        current.runs[0].metrics = Some(EvalRunMetrics {
            tool_failures_by_class: BTreeMap::from([(String::from("E_TIMEOUT_TRANSIENT"), 2)]),
            ..Default::default()
        });
        current.runs[1].metrics = Some(EvalRunMetrics {
            tool_failures_by_class: BTreeMap::from([(String::from("E_TIMEOUT_TRANSIENT"), 2)]),
            ..Default::default()
        });
        let reg = compare_results(&bl, &current);
        assert!(!reg.passed);
        assert!(reg
            .failures
            .iter()
            .any(|f| f.key == "avg_tool_failures_by_class.E_TIMEOUT_TRANSIENT"));
    }

    #[test]
    fn compare_results_flags_step_invariant_regression() {
        let mut baseline_results = sample_results();
        baseline_results.runs[0].metrics = Some(EvalRunMetrics {
            step_invariant_violations: 0,
            ..Default::default()
        });
        baseline_results.runs[1].metrics = Some(EvalRunMetrics {
            step_invariant_violations: 0,
            ..Default::default()
        });

        let td = tempfile::tempdir().expect("tempdir");
        let rp = td.path().join("results.json");
        fs::write(
            &rp,
            serde_json::to_vec_pretty(&baseline_results).expect("serialize"),
        )
        .expect("write");
        let _ = create_baseline_from_results(td.path(), "b1", &rp).expect("create");
        let mut bl = load_baseline(td.path(), "b1").expect("load");
        bl.summary_expectations.max_avg_step_invariant_violations = Some(0.0);

        let mut current = baseline_results;
        current.runs[0].metrics = Some(EvalRunMetrics {
            step_invariant_violations: 1,
            ..Default::default()
        });
        current.runs[1].metrics = Some(EvalRunMetrics {
            step_invariant_violations: 2,
            ..Default::default()
        });
        let reg = compare_results(&bl, &current);
        assert!(!reg.passed);
        assert!(
            reg.failures
                .iter()
                .any(|f| f.key == "avg_step_invariant_violations")
        );
    }

    #[test]
    fn compare_results_flags_tool_sequence_distance_regression() {
        let mut baseline_results = sample_results();
        baseline_results.runs[0].metrics = Some(EvalRunMetrics {
            tool_sequence: vec!["read_file".to_string(), "write_file".to_string()],
            ..Default::default()
        });
        baseline_results.runs[1].metrics = Some(EvalRunMetrics {
            tool_sequence: vec!["read_file".to_string(), "write_file".to_string()],
            ..Default::default()
        });

        let td = tempfile::tempdir().expect("tempdir");
        let rp = td.path().join("results.json");
        fs::write(
            &rp,
            serde_json::to_vec_pretty(&baseline_results).expect("serialize"),
        )
        .expect("write");
        let _ = create_baseline_from_results(td.path(), "b1", &rp).expect("create");
        let mut bl = load_baseline(td.path(), "b1").expect("load");
        if let Some(exp) = bl.task_expectations.get_mut("C1") {
            exp.max_avg_tool_sequence_distance = Some(0.0);
        }

        let mut current = baseline_results;
        current.runs[0].metrics = Some(EvalRunMetrics {
            tool_sequence: vec!["read_file".to_string(), "shell".to_string()],
            ..Default::default()
        });
        current.runs[1].metrics = Some(EvalRunMetrics {
            tool_sequence: vec!["read_file".to_string(), "shell".to_string()],
            ..Default::default()
        });
        let reg = compare_results(&bl, &current);
        assert!(!reg.passed);
        assert!(
            reg.failures
                .iter()
                .any(|f| f.key == "C1.avg_tool_sequence_distance")
        );
    }
}
