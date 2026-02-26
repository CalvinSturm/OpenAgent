use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use uuid::Uuid;

use crate::agent::AgentOutcome;
use crate::planner::RunMode;

use super::{
    ConfigFingerprintV1, McpPinSnapshotRecord, PlannerRunRecord, PolicyRecordInfo, RunCliConfig,
    RunCompactionRecord, RunMetadata, RunRecord, RunResolvedPaths, StatePaths, WorkerRunRecord,
};

pub fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_run_record(
    paths: &StatePaths,
    cli: RunCliConfig,
    policy: PolicyRecordInfo,
    config_hash_hex: String,
    outcome: &AgentOutcome,
    mode: RunMode,
    planner: Option<PlannerRunRecord>,
    worker: Option<WorkerRunRecord>,
    tool_schema_hash_hex_map: BTreeMap<String, String>,
    hooks_config_hash_hex: Option<String>,
    config_fingerprint: Option<ConfigFingerprintV1>,
    repro: Option<crate::repro::RunReproRecord>,
    mcp_runtime_trace: Vec<crate::agent::McpRuntimeTraceEntry>,
    mcp_pin_snapshot: Option<McpPinSnapshotRecord>,
) -> anyhow::Result<PathBuf> {
    ensure_dir(&paths.runs_dir)?;
    let run_path = paths.runs_dir.join(format!("{}.json", outcome.run_id));
    let tool_catalog = cli.tool_catalog.clone();
    let record = RunRecord {
        metadata: RunMetadata {
            run_id: outcome.run_id.clone(),
            started_at: outcome.started_at.clone(),
            finished_at: outcome.finished_at.clone(),
            exit_reason: outcome.exit_reason.as_str().to_string(),
        },
        mode: format!("{:?}", mode).to_lowercase(),
        planner,
        worker,
        cli,
        resolved_paths: RunResolvedPaths {
            state_dir: paths.state_dir.display().to_string(),
            policy_path: paths.policy_path.display().to_string(),
            approvals_path: paths.approvals_path.display().to_string(),
            audit_path: paths.audit_path.display().to_string(),
        },
        policy_source: policy.source,
        policy_hash_hex: policy.hash_hex,
        policy_version: policy.version,
        includes_resolved: policy.includes_resolved,
        mcp_allowlist: policy.mcp_allowlist,
        config_hash_hex,
        config_fingerprint,
        tool_schema_hash_hex_map,
        hooks_config_hash_hex,
        transcript: outcome.messages.clone(),
        tool_calls: outcome.tool_calls.clone(),
        tool_decisions: outcome.tool_decisions.clone(),
        compaction: Some(RunCompactionRecord {
            settings: outcome.compaction_settings.clone(),
            final_prompt_size_chars: outcome.final_prompt_size_chars,
            report: outcome.compaction_report.clone(),
        }),
        hook_report: outcome.hook_invocations.clone(),
        tool_catalog,
        mcp_runtime_trace,
        mcp_pin_snapshot,
        taint: outcome.taint.clone(),
        repro,
        final_output: outcome.final_output.clone(),
        error: outcome.error.clone(),
    };
    write_json_atomic(&run_path, &record)?;
    Ok(run_path)
}

pub fn load_run_record(state_dir: &Path, run_id: &str) -> anyhow::Result<RunRecord> {
    let path = state_dir.join("runs").join(format!("{}.json", run_id));
    let content = std::fs::read_to_string(path)?;
    let record: RunRecord = serde_json::from_str(&content)?;
    Ok(record)
}

pub(crate) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    let content = serde_json::to_string_pretty(value)?;
    std::fs::write(&tmp_path, content)?;
    if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
        #[cfg(windows)]
        {
            if path.exists() {
                let _ = std::fs::remove_file(path);
                std::fs::rename(&tmp_path, path)?;
                return Ok(());
            }
        }
        return Err(rename_err.into());
    }
    Ok(())
}
