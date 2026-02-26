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
