use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

use crate::eval::runner::EvalResults;
use crate::store::load_run_record;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub created_at: String,
    pub profile_name: Option<String>,
    pub profile_hash_hex: Option<String>,
    pub baseline_name: Option<String>,
    pub runs: Vec<BundleRunEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRunEntry {
    pub run_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct BundleSpec {
    pub bundle_path: PathBuf,
    pub state_dir: PathBuf,
    pub results_path: PathBuf,
    pub junit_path: Option<PathBuf>,
    pub summary_md_path: Option<PathBuf>,
    pub baseline_name: Option<String>,
    pub profile_name: Option<String>,
    pub profile_hash_hex: Option<String>,
}

pub fn create_bundle(spec: &BundleSpec) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(&spec.results_path)
        .with_context(|| format!("failed to read {}", spec.results_path.display()))?;
    let results: EvalResults = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", spec.results_path.display()))?;

    let staging = std::env::temp_dir().join(format!("openagent_bundle_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&staging).context("failed creating bundle staging dir")?;
    copy_to_staging(&staging, Path::new("results.json"), &spec.results_path)?;
    if let Some(p) = &spec.junit_path {
        if p.exists() {
            copy_to_staging(&staging, Path::new("junit.xml"), p)?;
        }
    }
    if let Some(p) = &spec.summary_md_path {
        if p.exists() {
            copy_to_staging(&staging, Path::new("summary.md"), p)?;
        }
    }

    let mut manifest_runs = Vec::new();
    let mut seen = BTreeSet::new();
    for run in &results.runs {
        if run.passed || run.status == "skipped" || !seen.insert(run.run_id.clone()) {
            continue;
        }
        manifest_runs.push(BundleRunEntry {
            run_id: run.run_id.clone(),
            reason: run.exit_reason.clone(),
        });
        let run_path = spec
            .state_dir
            .join("runs")
            .join(format!("{}.json", run.run_id));
        if run_path.exists() {
            copy_to_staging(
                &staging,
                &PathBuf::from("runs").join(format!("{}.json", run.run_id)),
                &run_path,
            )?;
            if let Ok(record) = load_run_record(&spec.state_dir, &run.run_id) {
                copy_snapshot_if_exists(
                    &staging,
                    &run.run_id,
                    "policy.yaml",
                    &PathBuf::from(&record.resolved_paths.policy_path),
                )?;
                copy_snapshot_if_exists(
                    &staging,
                    &run.run_id,
                    "approvals.json",
                    &PathBuf::from(&record.resolved_paths.approvals_path),
                )?;
                copy_snapshot_if_exists(
                    &staging,
                    &run.run_id,
                    "audit.jsonl",
                    &PathBuf::from(&record.resolved_paths.audit_path),
                )?;
            }
        }
    }

    let manifest = BundleManifest {
        created_at: crate::trust::now_rfc3339(),
        profile_name: spec.profile_name.clone(),
        profile_hash_hex: spec.profile_hash_hex.clone(),
        baseline_name: spec.baseline_name.clone(),
        runs: manifest_runs,
    };
    fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    if let Some(parent) = spec.bundle_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if spec.bundle_path.exists() {
        fs::remove_file(&spec.bundle_path)?;
    }
    let res = compress_staging_dir(&staging, &spec.bundle_path);
    let _ = fs::remove_dir_all(&staging);
    res?;
    Ok(spec.bundle_path.clone())
}

fn copy_snapshot_if_exists(
    root: &Path,
    run_id: &str,
    target_name: &str,
    source: &Path,
) -> anyhow::Result<()> {
    if source.exists() {
        copy_to_staging(
            root,
            &PathBuf::from("snapshots").join(run_id).join(target_name),
            source,
        )?;
    }
    Ok(())
}

fn copy_to_staging(root: &Path, relative: &Path, source: &Path) -> anyhow::Result<()> {
    let target = root.join(relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, &target).with_context(|| {
        format!(
            "failed copying {} -> {}",
            source.display(),
            target.display()
        )
    })?;
    Ok(())
}

fn compress_staging_dir(staging: &Path, output_zip: &Path) -> anyhow::Result<()> {
    if cfg!(windows) {
        compress_with_powershell(staging, output_zip)
            .or_else(|_| compress_with_python(staging, output_zip))
    } else {
        compress_with_python(staging, output_zip)
            .or_else(|_| compress_with_powershell(staging, output_zip))
    }
}

fn compress_with_powershell(staging: &Path, output_zip: &Path) -> anyhow::Result<()> {
    let script = format!(
        "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; if (Test-Path '{}') {{ Remove-Item '{}' -Force }}; [System.IO.Compression.ZipFile]::CreateFromDirectory('{}','{}')",
        output_zip.display(),
        output_zip.display(),
        staging.display(),
        output_zip.display()
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .context("failed to run PowerShell zip")?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("PowerShell zip failed with status {status}"))
    }
}

fn compress_with_python(staging: &Path, output_zip: &Path) -> anyhow::Result<()> {
    let script = r#"
import os, sys, zipfile
staging = sys.argv[1]
out = sys.argv[2]
if os.path.exists(out):
    os.remove(out)
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(staging):
        files.sort()
        for f in files:
            p = os.path.join(root, f)
            rel = os.path.relpath(p, staging).replace("\\", "/")
            z.write(p, rel)
"#;
    let mut last_err: Option<anyhow::Error> = None;
    for py in ["python3", "python"] {
        match std::process::Command::new(py)
            .args([
                "-c",
                script,
                &staging.to_string_lossy(),
                &output_zip.to_string_lossy(),
            ])
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                last_err = Some(anyhow!("{py} zip failed with status {status}"));
            }
            Err(err) => {
                last_err = Some(anyhow!("{py} not available: {err}"));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("python zip unavailable")))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::eval::runner::{
        EvalResults, EvalResultsConfig, EvalRunRow, EvalRunStats, EvalSummary,
    };

    use super::{create_bundle, BundleSpec};

    fn list_zip_entries(zip_path: &Path) -> anyhow::Result<Vec<String>> {
        let script = r#"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "r") as z:
    names = sorted(n.replace("\\", "/") for n in z.namelist() if not n.endswith("/"))
    for n in names:
        print(n)
"#;
        let mut last_err: Option<anyhow::Error> = None;
        for py in ["python3", "python"] {
            match std::process::Command::new(py)
                .args(["-c", script, &zip_path.to_string_lossy()])
                .output()
            {
                Ok(out) if out.status.success() => {
                    let lines = String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();
                    return Ok(lines);
                }
                Ok(out) => {
                    last_err = Some(anyhow::anyhow!(
                        "{py} zip listing failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
                Err(err) => {
                    last_err = Some(anyhow::anyhow!("{py} not available: {err}"));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no python available for zip listing")))
    }

    #[test]
    fn bundle_contains_expected_entries() {
        let td = tempfile::tempdir().expect("tempdir");
        let state_dir = td.path().join(".localagent");
        fs::create_dir_all(state_dir.join("runs")).expect("mkdir");
        fs::write(
            state_dir.join("runs").join("r1.json"),
            "{\"metadata\":{\"run_id\":\"r1\",\"started_at\":\"x\",\"finished_at\":\"x\",\"exit_reason\":\"provider_error\"},\"cli\":{\"provider\":\"ollama\",\"base_url\":\"x\",\"model\":\"m\",\"trust_mode\":\"off\",\"allow_shell\":false,\"allow_write\":false,\"enable_write_tools\":false,\"max_tool_output_bytes\":0,\"max_read_bytes\":0,\"approval_mode\":\"interrupt\",\"auto_approve_scope\":\"run\",\"unsafe_mode\":false,\"no_limits\":false,\"unsafe_bypass_allow_flags\":false,\"stream\":false,\"max_context_chars\":0,\"compaction_mode\":\"off\",\"compaction_keep_last\":0,\"tool_result_persist\":\"digest\",\"hooks_mode\":\"off\",\"caps_mode\":\"off\",\"hooks_config_path\":\"\",\"hooks_strict\":false,\"hooks_timeout_ms\":0,\"hooks_max_stdout_bytes\":0,\"tool_args_strict\":\"on\",\"use_session_settings\":false,\"resolved_settings_source\":{},\"tui_enabled\":false,\"tui_refresh_ms\":0,\"tui_max_log_lines\":0,\"http_max_retries\":0,\"http_timeout_ms\":0,\"http_connect_timeout_ms\":0,\"http_stream_idle_timeout_ms\":0,\"http_max_response_bytes\":0,\"http_max_line_bytes\":0,\"tool_catalog\":[],\"policy_version\":null,\"includes_resolved\":[]},\"resolved_paths\":{\"state_dir\":\"x\",\"policy_path\":\"x\",\"approvals_path\":\"x\",\"audit_path\":\"x\"},\"policy_source\":\"none\",\"policy_hash_hex\":null,\"policy_version\":null,\"includes_resolved\":[],\"config_hash_hex\":\"x\",\"transcript\":[],\"tool_calls\":[],\"tool_decisions\":[],\"hook_report\":[],\"tool_catalog\":[],\"final_output\":\"\",\"error\":null}",
        )
        .expect("run write");
        let results = EvalResults {
            schema_version: "openagent.eval.v1".to_string(),
            created_at: "x".to_string(),
            config: EvalResultsConfig::minimal_for_tests(),
            summary: EvalSummary {
                total_runs: 1,
                passed: 0,
                failed: 1,
                skipped: 0,
                pass_rate: 0.0,
            },
            by_model: Default::default(),
            runs: vec![EvalRunRow {
                model: "m".to_string(),
                task_id: "C1".to_string(),
                run_index: 0,
                workdir: None,
                run_id: "r1".to_string(),
                exit_reason: "provider_error".to_string(),
                status: "failed".to_string(),
                skip_reason: None,
                required_flags: vec![],
                passed: false,
                failures: vec!["x".to_string()],
                stats: EvalRunStats {
                    steps: 0,
                    tool_calls: 0,
                },
                metrics: None,
                tokens: None,
                estimated_cost_usd: None,
                verifier: None,
            }],
            metrics: None,
            baseline: None,
            regression: None,
        };
        let results_path = td.path().join("results.json");
        fs::write(
            &results_path,
            serde_json::to_vec_pretty(&results).expect("serialize"),
        )
        .expect("write results");
        let bundle_path = td.path().join("bundle.zip");
        create_bundle(&BundleSpec {
            bundle_path: bundle_path.clone(),
            state_dir,
            results_path,
            junit_path: None,
            summary_md_path: None,
            baseline_name: None,
            profile_name: None,
            profile_hash_hex: None,
        })
        .expect("bundle");
        let names = list_zip_entries(&bundle_path).expect("entries");
        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"results.json".to_string()));
        assert!(names.iter().any(|n| n.ends_with("runs/r1.json")));
    }
}
