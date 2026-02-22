use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::agent::AgentOutcome;
use crate::compaction::{CompactionReport, CompactionSettings};
use crate::gate::TrustMode;
use crate::planner::RunMode;
use crate::trust::policy::McpAllowSummary;
use crate::types::{Message, SideEffects, ToolCall};

#[derive(Debug, Clone)]
pub struct StatePaths {
    pub state_dir: PathBuf,
    pub policy_path: PathBuf,
    pub approvals_path: PathBuf,
    pub audit_path: PathBuf,
    pub runs_dir: PathBuf,
    pub sessions_dir: PathBuf,
    pub using_legacy_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub metadata: RunMetadata,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner: Option<PlannerRunRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker: Option<WorkerRunRecord>,
    pub cli: RunCliConfig,
    pub resolved_paths: RunResolvedPaths,
    pub policy_source: String,
    pub policy_hash_hex: Option<String>,
    pub policy_version: Option<u32>,
    #[serde(default)]
    pub includes_resolved: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_allowlist: Option<McpAllowSummary>,
    pub config_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_fingerprint: Option<ConfigFingerprintV1>,
    #[serde(default)]
    pub tool_schema_hash_hex_map: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks_config_hash_hex: Option<String>,
    pub transcript: Vec<Message>,
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub tool_decisions: Vec<crate::agent::ToolDecisionRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction: Option<RunCompactionRecord>,
    #[serde(default)]
    pub hook_report: Vec<crate::hooks::protocol::HookInvocationReport>,
    #[serde(default)]
    pub tool_catalog: Vec<ToolCatalogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<crate::agent::AgentTaintRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro: Option<crate::repro::RunReproRecord>,
    pub final_output: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerRunRecord {
    pub model: String,
    pub max_steps: u32,
    pub strict: bool,
    pub output_format: String,
    pub plan_json: Value,
    pub plan_hash_hex: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRunRecord {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected_planner_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_result_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_result_json: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_result_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCatalogEntry {
    pub name: String,
    pub side_effects: SideEffects,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub exit_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunCliConfig {
    pub mode: String,
    pub provider: String,
    pub base_url: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner_max_steps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner_output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner_strict: Option<bool>,
    pub enforce_plan_tools: String,
    pub trust_mode: String,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub enable_write_tools: bool,
    pub exec_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_workdir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_user: Option<String>,
    pub max_tool_output_bytes: usize,
    pub max_read_bytes: usize,
    pub approval_mode: String,
    pub auto_approve_scope: String,
    pub approval_key: String,
    pub unsafe_mode: bool,
    pub no_limits: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_path: Option<String>,
    pub max_context_chars: usize,
    pub compaction_mode: String,
    pub compaction_keep_last: usize,
    pub tool_result_persist: String,
    pub hooks_mode: String,
    pub caps_mode: String,
    pub hooks_config_path: String,
    pub hooks_strict: bool,
    pub hooks_timeout_ms: u64,
    pub hooks_max_stdout_bytes: usize,
    pub tool_args_strict: String,
    pub taint: String,
    pub taint_mode: String,
    pub taint_digest_bytes: usize,
    pub repro: String,
    pub repro_env: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro_out: Option<String>,
    pub use_session_settings: bool,
    #[serde(default)]
    pub resolved_settings_source: BTreeMap<String, String>,
    pub tui_enabled: bool,
    pub tui_refresh_ms: u64,
    pub tui_max_log_lines: usize,
    pub http_max_retries: u32,
    pub http_timeout_ms: u64,
    pub http_connect_timeout_ms: u64,
    pub http_stream_idle_timeout_ms: u64,
    pub http_max_response_bytes: usize,
    pub http_max_line_bytes: usize,
    #[serde(default)]
    pub tool_catalog: Vec<ToolCatalogEntry>,
    pub policy_version: Option<u32>,
    #[serde(default)]
    pub includes_resolved: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_allowlist: Option<McpAllowSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions_config_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions_config_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_model_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_task_profile: Option<String>,
    #[serde(default)]
    pub instruction_message_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResolvedPaths {
    pub state_dir: String,
    pub policy_path: String,
    pub approvals_path: String,
    pub audit_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFingerprintV1 {
    pub schema_version: String,
    pub mode: String,
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub planner_model: String,
    pub worker_model: String,
    pub planner_max_steps: u32,
    pub planner_output: String,
    pub planner_strict: bool,
    pub enforce_plan_tools: String,
    pub trust_mode: String,
    pub state_dir: String,
    pub policy_path: String,
    pub approvals_path: String,
    pub audit_path: String,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub enable_write_tools: bool,
    pub exec_target: String,
    pub docker_image: String,
    pub docker_workdir: String,
    pub docker_network: String,
    pub docker_user: String,
    pub max_steps: usize,
    pub max_tool_output_bytes: usize,
    pub max_read_bytes: usize,
    pub session_name: String,
    pub no_session: bool,
    pub max_session_messages: usize,
    pub approval_mode: String,
    pub auto_approve_scope: String,
    pub approval_key: String,
    pub unsafe_mode: bool,
    pub no_limits: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub stream: bool,
    pub events_path: String,
    pub max_context_chars: usize,
    pub compaction_mode: String,
    pub compaction_keep_last: usize,
    pub tool_result_persist: String,
    pub hooks_mode: String,
    pub caps_mode: String,
    pub hooks_config_path: String,
    pub hooks_strict: bool,
    pub hooks_timeout_ms: u64,
    pub hooks_max_stdout_bytes: usize,
    pub tool_args_strict: String,
    pub taint: String,
    pub taint_mode: String,
    pub taint_digest_bytes: usize,
    pub repro: String,
    pub repro_env: String,
    pub repro_out: String,
    pub use_session_settings: bool,
    pub resolved_settings_source: BTreeMap<String, String>,
    pub tui_enabled: bool,
    pub tui_refresh_ms: u64,
    pub tui_max_log_lines: usize,
    pub http_max_retries: u32,
    pub http_timeout_ms: u64,
    pub http_connect_timeout_ms: u64,
    pub http_stream_idle_timeout_ms: u64,
    pub http_max_response_bytes: usize,
    pub http_max_line_bytes: usize,
    pub tool_catalog_names: Vec<String>,
    pub policy_version: Option<u32>,
    pub includes_resolved: Vec<String>,
    pub mcp_allowlist: Option<McpAllowSummary>,
    pub instructions_config_path: String,
    pub instructions_config_hash_hex: String,
    pub instruction_model_profile: String,
    pub instruction_task_profile: String,
    pub instruction_message_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunCompactionRecord {
    pub settings: CompactionSettings,
    pub final_prompt_size_chars: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<CompactionReport>,
}

#[derive(Debug, Clone)]
pub struct PolicyRecordInfo {
    pub source: String,
    pub hash_hex: Option<String>,
    pub version: Option<u32>,
    pub includes_resolved: Vec<String>,
    pub mcp_allowlist: Option<McpAllowSummary>,
}

pub fn resolve_state_paths(
    workdir: &Path,
    state_dir_override: Option<PathBuf>,
    policy_override: Option<PathBuf>,
    approvals_override: Option<PathBuf>,
    audit_override: Option<PathBuf>,
) -> StatePaths {
    let (state_dir, using_legacy_dir) = resolve_state_dir(workdir, state_dir_override);
    let policy_path = policy_override.unwrap_or_else(|| state_dir.join("policy.yaml"));
    let approvals_path = approvals_override.unwrap_or_else(|| state_dir.join("approvals.json"));
    let audit_path = audit_override.unwrap_or_else(|| state_dir.join("audit.jsonl"));
    StatePaths {
        runs_dir: state_dir.join("runs"),
        sessions_dir: state_dir.join("sessions"),
        state_dir,
        policy_path,
        approvals_path,
        audit_path,
        using_legacy_dir,
    }
}

pub fn resolve_state_dir(workdir: &Path, state_dir_override: Option<PathBuf>) -> (PathBuf, bool) {
    if let Some(path) = state_dir_override {
        return (path, false);
    }

    let new_dir = workdir.join(".localagent");
    (new_dir, false)
}

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

pub fn render_replay(record: &RunRecord) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "run_id: {}\nmode: {}\nprovider: {}\nmodel: {}\nexit_reason: {}\nPolicy hash: {}\nConfig hash: {}\napproval_mode: {}\nauto_approve_scope: {}\nunsafe: {}\nno_limits: {}\nunsafe_bypass_allow_flags: {}\n",
        record.metadata.run_id,
        record.mode,
        record.cli.provider,
        record.cli.model,
        record.metadata.exit_reason,
        record.policy_hash_hex.as_deref().unwrap_or("-"),
        record.config_hash_hex,
        record.cli.approval_mode,
        record.cli.auto_approve_scope,
        record.cli.unsafe_mode,
        record.cli.no_limits,
        record.cli.unsafe_bypass_allow_flags
    ));
    out.push_str(&format!("exec_target: {}\n", record.cli.exec_target));
    out.push_str(&format!("tui_enabled: {}\n", record.cli.tui_enabled));
    out.push_str(&format!(
        "taint: {} mode={} digest_bytes={}\n",
        record.cli.taint, record.cli.taint_mode, record.cli.taint_digest_bytes
    ));
    if let Some(planner) = &record.planner {
        let steps_count = planner
            .plan_json
            .get("steps")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let goal = planner
            .plan_json
            .get("goal")
            .and_then(Value::as_str)
            .unwrap_or_default();
        out.push_str(&format!(
            "planner: model={} ok={} steps={} hash={}\nplanner_goal: {}\n",
            planner.model, planner.ok, steps_count, planner.plan_hash_hex, goal
        ));
    }
    for m in &record.transcript {
        let content = m.content.clone().unwrap_or_default();
        match m.role {
            crate::types::Role::User => out.push_str(&format!("USER: {}\n", content)),
            crate::types::Role::Assistant => out.push_str(&format!("ASSISTANT: {}\n", content)),
            crate::types::Role::Tool => {
                let name = m.tool_name.clone().unwrap_or_else(|| "unknown".to_string());
                out.push_str(&format!("TOOL({}): {}\n", name, content));
            }
            crate::types::Role::System => out.push_str(&format!("SYSTEM: {}\n", content)),
            crate::types::Role::Developer => out.push_str(&format!("DEVELOPER: {}\n", content)),
        }
    }
    out
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
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

pub fn cli_trust_mode(mode: TrustMode) -> String {
    match mode {
        TrustMode::Auto => "auto".to_string(),
        TrustMode::On => "on".to_string(),
        TrustMode::Off => "off".to_string(),
    }
}

pub fn extract_session_messages(messages: &[Message]) -> Vec<Message> {
    messages
        .iter()
        .enumerate()
        .filter_map(|(idx, m)| {
            if idx == 0
                && matches!(m.role, crate::types::Role::System)
                && m.content
                    .as_deref()
                    .unwrap_or_default()
                    .contains("You are an agent that may call tools")
            {
                return None;
            }
            if matches!(m.role, crate::types::Role::Developer)
                && m.content
                    .as_deref()
                    .unwrap_or_default()
                    .starts_with(crate::session::TASK_MEMORY_HEADER)
            {
                return None;
            }
            if matches!(m.role, crate::types::Role::Developer)
                && m.content
                    .as_deref()
                    .unwrap_or_default()
                    .starts_with(crate::planner::PLANNER_HANDOFF_HEADER)
            {
                return None;
            }
            Some(m.clone())
        })
        .collect()
}

pub fn provider_to_string(provider: crate::gate::ProviderKind) -> String {
    match provider {
        crate::gate::ProviderKind::Lmstudio => "lmstudio".to_string(),
        crate::gate::ProviderKind::Llamacpp => "llamacpp".to_string(),
        crate::gate::ProviderKind::Ollama => "ollama".to_string(),
        crate::gate::ProviderKind::Mock => "mock".to_string(),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize())
}

pub fn stable_path_string(path: &Path) -> String {
    match std::fs::canonicalize(path) {
        Ok(p) => p.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

pub fn config_hash_hex(fingerprint: &ConfigFingerprintV1) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(fingerprint)?;
    Ok(sha256_hex(&bytes))
}

pub fn tool_schema_hash_hex_map(tools: &[crate::types::ToolDef]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for tool in tools {
        out.insert(tool.name.clone(), hash_tool_schema(&tool.parameters));
    }
    out
}

pub fn hash_tool_schema(schema: &Value) -> String {
    let canonical = crate::trust::approvals::canonical_json(schema)
        .unwrap_or_else(|_| serde_json::to_string(schema).unwrap_or_else(|_| "null".to_string()));
    sha256_hex(canonical.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use crate::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};

    use super::{
        config_hash_hex, load_run_record, render_replay, resolve_state_dir, sha256_hex,
        write_run_record, ConfigFingerprintV1, PlannerRunRecord, PolicyRecordInfo, RunCliConfig,
        RunMetadata, RunRecord, RunResolvedPaths, WorkerRunRecord,
    };
    use crate::agent::{AgentExitReason, AgentOutcome};
    use crate::planner::RunMode;
    use crate::session::SessionStore;
    use crate::types::{Message, Role};

    #[test]
    fn resolve_state_dir_prefers_legacy_when_new_missing() {
        let tmp = tempdir().expect("tempdir");
        let legacy = tmp.path().join(".localagent");
        std::fs::create_dir_all(&legacy).expect("create localagent");
        let (resolved, legacy_used) = resolve_state_dir(tmp.path(), None);
        assert_eq!(resolved, legacy);
        assert!(!legacy_used);
    }

    #[test]
    fn resolve_state_dir_ignores_openagent_legacy_dir() {
        let tmp = tempdir().expect("tempdir");
        let legacy = tmp.path().join(".openagent");
        std::fs::create_dir_all(&legacy).expect("create legacy");
        let (resolved, legacy_used) = resolve_state_dir(tmp.path(), None);
        assert_eq!(resolved, tmp.path().join(".localagent"));
        assert!(!legacy_used);
    }

    #[test]
    fn resolve_state_dir_ignores_agentloop_legacy_dir() {
        let tmp = tempdir().expect("tempdir");
        let legacy = tmp.path().join(".agentloop");
        std::fs::create_dir_all(&legacy).expect("create legacy");
        let (resolved, legacy_used) = resolve_state_dir(tmp.path(), None);
        assert_eq!(resolved, tmp.path().join(".localagent"));
        assert!(!legacy_used);
    }

    #[test]
    fn resolve_state_dir_prefers_new_when_both_exist() {
        let tmp = tempdir().expect("tempdir");
        let legacy = tmp.path().join(".agentloop");
        let new_dir = tmp.path().join(".localagent");
        std::fs::create_dir_all(&legacy).expect("create legacy");
        std::fs::create_dir_all(&new_dir).expect("create new");
        let (resolved, legacy_used) = resolve_state_dir(tmp.path(), None);
        assert_eq!(resolved, new_dir);
        assert!(!legacy_used);
    }

    #[test]
    fn resolve_state_dir_uses_override() {
        let tmp = tempdir().expect("tempdir");
        let override_dir = tmp.path().join("custom_state");
        let (resolved, legacy_used) = resolve_state_dir(tmp.path(), Some(override_dir.clone()));
        assert_eq!(resolved, override_dir);
        assert!(!legacy_used);
    }

    #[test]
    fn session_roundtrip_and_reset() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("session.json");
        let store = SessionStore::new(path.clone(), "session".to_string());
        let msgs = vec![Message {
            role: Role::User,
            content: Some("hello".to_string()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }];
        let mut data = store.load().expect("load");
        data.messages = msgs;
        store.save(&data, 40).expect("save session");
        let loaded = store.load().expect("load session");
        assert_eq!(loaded.messages.len(), 1);
        store.reset().expect("reset");
        let loaded = store.load().expect("load after reset");
        assert!(loaded.messages.is_empty());
    }

    #[test]
    fn extract_session_messages_skips_task_memory_block() {
        let msgs = vec![
            Message {
                role: Role::System,
                content: Some(
                    "You are an agent that may call tools to gather information.".to_string(),
                ),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            Message {
                role: Role::Developer,
                content: Some(
                    "TASK MEMORY (user-authored, authoritative)\n- [1] foo: bar".to_string(),
                ),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            Message {
                role: Role::User,
                content: Some("hi".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
        ];
        let out = super::extract_session_messages(&msgs);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].role, Role::User));
    }

    #[test]
    fn extract_session_messages_skips_planner_handoff_block() {
        let msgs = vec![
            Message {
                role: Role::Developer,
                content: Some(
                    "PLANNER HANDOFF (openagent.plan.v1)\n{\"schema_version\":\"openagent.plan.v1\"}"
                        .to_string(),
                ),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            Message {
                role: Role::User,
                content: Some("hi".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
        ];
        let out = super::extract_session_messages(&msgs);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].role, Role::User));
    }

    #[test]
    fn run_artifact_write_and_read() {
        let tmp = tempdir().expect("tempdir");
        let paths = super::resolve_state_paths(tmp.path(), None, None, None, None);
        let outcome = AgentOutcome {
            run_id: "run_1".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:01Z".to_string(),
            exit_reason: AgentExitReason::Ok,
            final_output: "done".to_string(),
            error: None,
            messages: Vec::new(),
            tool_calls: Vec::new(),
            tool_decisions: Vec::new(),
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            final_prompt_size_chars: 321,
            compaction_report: Some(crate::compaction::CompactionReport {
                before_chars: 1000,
                after_chars: 321,
                before_messages: 10,
                after_messages: 4,
                compacted_messages: 6,
                summary_digest_sha256: "abc".to_string(),
                summary_text: "COMPACTED SUMMARY (v1)".to_string(),
            }),
            hook_invocations: Vec::new(),
            provider_retry_count: 0,
            provider_error_count: 0,
            token_usage: None,
            taint: Some(crate::agent::AgentTaintRecord {
                enabled: true,
                mode: "propagate".to_string(),
                digest_bytes: 4096,
                overall: "tainted".to_string(),
                spans_by_tool_call_id: BTreeMap::new(),
            }),
        };
        write_run_record(
            &paths,
            RunCliConfig {
                mode: "single".to_string(),
                provider: "ollama".to_string(),
                base_url: "http://localhost:11434".to_string(),
                model: "m".to_string(),
                planner_model: None,
                worker_model: None,
                planner_max_steps: None,
                planner_output: None,
                planner_strict: None,
                enforce_plan_tools: "off".to_string(),
                trust_mode: "off".to_string(),
                allow_shell: false,
                allow_write: false,
                enable_write_tools: false,
                exec_target: "host".to_string(),
                docker_image: None,
                docker_workdir: None,
                docker_network: None,
                docker_user: None,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                approval_mode: "interrupt".to_string(),
                auto_approve_scope: "run".to_string(),
                approval_key: "v1".to_string(),
                unsafe_mode: false,
                no_limits: false,
                unsafe_bypass_allow_flags: false,
                stream: false,
                events_path: None,
                max_context_chars: 0,
                compaction_mode: "off".to_string(),
                compaction_keep_last: 20,
                tool_result_persist: "digest".to_string(),
                hooks_mode: "off".to_string(),
                caps_mode: "off".to_string(),
                hooks_config_path: String::new(),
                hooks_strict: false,
                hooks_timeout_ms: 2000,
                hooks_max_stdout_bytes: 200_000,
                tool_args_strict: "on".to_string(),
                taint: "off".to_string(),
                taint_mode: "propagate".to_string(),
                taint_digest_bytes: 4096,
                repro: "off".to_string(),
                repro_env: "safe".to_string(),
                repro_out: None,
                use_session_settings: false,
                resolved_settings_source: BTreeMap::new(),
                tui_enabled: false,
                tui_refresh_ms: 50,
                tui_max_log_lines: 200,
                http_max_retries: 2,
                http_timeout_ms: 60_000,
                http_connect_timeout_ms: 2_000,
                http_stream_idle_timeout_ms: 15_000,
                http_max_response_bytes: 10_000_000,
                http_max_line_bytes: 200_000,
                tool_catalog: Vec::new(),
                policy_version: None,
                includes_resolved: Vec::new(),
                mcp_allowlist: None,
                instructions_config_path: None,
                instructions_config_hash_hex: None,
                instruction_model_profile: None,
                instruction_task_profile: None,
                instruction_message_count: 0,
            },
            PolicyRecordInfo {
                source: "none".to_string(),
                hash_hex: None,
                version: None,
                includes_resolved: Vec::new(),
                mcp_allowlist: None,
            },
            "cfg_hash".to_string(),
            &outcome,
            RunMode::Single,
            None,
            Some(super::WorkerRunRecord {
                model: "m".to_string(),
                injected_planner_hash_hex: None,
                step_result_valid: None,
                step_result_json: None,
                step_result_error: None,
            }),
            BTreeMap::new(),
            None,
            None,
            None,
        )
        .expect("write run");
        let loaded = load_run_record(&paths.state_dir, "run_1").expect("load run");
        assert_eq!(loaded.metadata.run_id, "run_1");
        assert_eq!(loaded.metadata.exit_reason, "ok");
        assert_eq!(loaded.mode, "single");
        assert_eq!(loaded.config_hash_hex, "cfg_hash");
        assert_eq!(loaded.cli.exec_target, "host");
        assert_eq!(
            loaded
                .taint
                .as_ref()
                .map(|t| t.overall.as_str())
                .unwrap_or(""),
            "tainted"
        );
        let compaction = loaded.compaction.expect("compaction");
        assert_eq!(compaction.final_prompt_size_chars, 321);
        assert_eq!(
            compaction
                .report
                .as_ref()
                .expect("report")
                .summary_digest_sha256,
            "abc"
        );
    }

    #[test]
    fn replay_renders_planner_summary_when_present() {
        let record = RunRecord {
            metadata: RunMetadata {
                run_id: "r".to_string(),
                started_at: "2026-01-01T00:00:00Z".to_string(),
                finished_at: "2026-01-01T00:00:01Z".to_string(),
                exit_reason: "ok".to_string(),
            },
            mode: "planner_worker".to_string(),
            planner: Some(PlannerRunRecord {
                model: "p".to_string(),
                max_steps: 2,
                strict: true,
                output_format: "json".to_string(),
                plan_json: serde_json::json!({
                    "schema_version":"openagent.plan.v1",
                    "goal":"g",
                    "assumptions":[],
                    "steps":[{"id":"S1","summary":"s","intended_tools":[]}],
                    "risks":[],
                    "success_criteria":[]
                }),
                plan_hash_hex: "abc".to_string(),
                ok: true,
                raw_output: None,
                error: None,
            }),
            worker: Some(WorkerRunRecord {
                model: "w".to_string(),
                injected_planner_hash_hex: Some("abc".to_string()),
                step_result_valid: None,
                step_result_json: None,
                step_result_error: None,
            }),
            cli: RunCliConfig {
                mode: "planner_worker".to_string(),
                provider: "ollama".to_string(),
                base_url: "http://localhost:11434".to_string(),
                model: "w".to_string(),
                planner_model: Some("p".to_string()),
                worker_model: Some("w".to_string()),
                planner_max_steps: Some(2),
                planner_output: Some("json".to_string()),
                planner_strict: Some(true),
                enforce_plan_tools: "off".to_string(),
                trust_mode: "off".to_string(),
                allow_shell: false,
                allow_write: false,
                enable_write_tools: false,
                exec_target: "host".to_string(),
                docker_image: None,
                docker_workdir: None,
                docker_network: None,
                docker_user: None,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                approval_mode: "interrupt".to_string(),
                auto_approve_scope: "run".to_string(),
                approval_key: "v1".to_string(),
                unsafe_mode: false,
                no_limits: false,
                unsafe_bypass_allow_flags: false,
                stream: false,
                events_path: None,
                max_context_chars: 0,
                compaction_mode: "off".to_string(),
                compaction_keep_last: 20,
                tool_result_persist: "digest".to_string(),
                hooks_mode: "off".to_string(),
                caps_mode: "off".to_string(),
                hooks_config_path: String::new(),
                hooks_strict: false,
                hooks_timeout_ms: 2000,
                hooks_max_stdout_bytes: 200_000,
                tool_args_strict: "on".to_string(),
                taint: "off".to_string(),
                taint_mode: "propagate".to_string(),
                taint_digest_bytes: 4096,
                repro: "off".to_string(),
                repro_env: "safe".to_string(),
                repro_out: None,
                use_session_settings: false,
                resolved_settings_source: BTreeMap::new(),
                tui_enabled: false,
                tui_refresh_ms: 50,
                tui_max_log_lines: 200,
                http_max_retries: 2,
                http_timeout_ms: 60_000,
                http_connect_timeout_ms: 2_000,
                http_stream_idle_timeout_ms: 15_000,
                http_max_response_bytes: 10_000_000,
                http_max_line_bytes: 200_000,
                tool_catalog: Vec::new(),
                policy_version: None,
                includes_resolved: Vec::new(),
                mcp_allowlist: None,
                instructions_config_path: None,
                instructions_config_hash_hex: None,
                instruction_model_profile: None,
                instruction_task_profile: None,
                instruction_message_count: 0,
            },
            resolved_paths: RunResolvedPaths {
                state_dir: ".".to_string(),
                policy_path: "./policy.yaml".to_string(),
                approvals_path: "./approvals.json".to_string(),
                audit_path: "./audit.jsonl".to_string(),
            },
            policy_source: "none".to_string(),
            policy_hash_hex: None,
            policy_version: None,
            includes_resolved: Vec::new(),
            mcp_allowlist: None,
            config_hash_hex: "cfg".to_string(),
            config_fingerprint: None,
            tool_schema_hash_hex_map: BTreeMap::new(),
            hooks_config_hash_hex: None,
            transcript: vec![Message {
                role: Role::Developer,
                content: Some("PLANNER HANDOFF (openagent.plan.v1)\n{}".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            }],
            tool_calls: Vec::new(),
            tool_decisions: Vec::new(),
            compaction: None,
            hook_report: Vec::new(),
            tool_catalog: Vec::new(),
            taint: None,
            repro: None,
            final_output: String::new(),
            error: None,
        };
        let rendered = render_replay(&record);
        assert!(rendered.contains("mode: planner_worker"));
        assert!(rendered.contains("planner: model=p"));
        assert!(rendered.contains("PLANNER HANDOFF"));
    }

    #[test]
    fn sha256_known_bytes() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn config_hash_stable_and_changes() {
        let mut a = ConfigFingerprintV1 {
            schema_version: "openagent.confighash.v1".to_string(),
            mode: "single".to_string(),
            provider: "ollama".to_string(),
            base_url: "http://localhost:11434".to_string(),
            model: "m".to_string(),
            planner_model: String::new(),
            worker_model: String::new(),
            planner_max_steps: 0,
            planner_output: String::new(),
            planner_strict: false,
            enforce_plan_tools: "off".to_string(),
            trust_mode: "off".to_string(),
            state_dir: "/tmp/s".to_string(),
            policy_path: "/tmp/s/policy.yaml".to_string(),
            approvals_path: "/tmp/s/approvals.json".to_string(),
            audit_path: "/tmp/s/audit.jsonl".to_string(),
            allow_shell: false,
            allow_write: false,
            enable_write_tools: false,
            exec_target: "host".to_string(),
            docker_image: String::new(),
            docker_workdir: String::new(),
            docker_network: String::new(),
            docker_user: String::new(),
            max_steps: 20,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            session_name: "default".to_string(),
            no_session: false,
            max_session_messages: 40,
            approval_mode: "interrupt".to_string(),
            auto_approve_scope: "run".to_string(),
            approval_key: "v1".to_string(),
            unsafe_mode: false,
            no_limits: false,
            unsafe_bypass_allow_flags: false,
            stream: false,
            events_path: String::new(),
            max_context_chars: 0,
            compaction_mode: "off".to_string(),
            compaction_keep_last: 20,
            tool_result_persist: "digest".to_string(),
            hooks_mode: "off".to_string(),
            caps_mode: "off".to_string(),
            hooks_config_path: String::new(),
            hooks_strict: false,
            hooks_timeout_ms: 2000,
            hooks_max_stdout_bytes: 200_000,
            tool_args_strict: "on".to_string(),
            taint: "off".to_string(),
            taint_mode: "propagate".to_string(),
            taint_digest_bytes: 4096,
            repro: "off".to_string(),
            repro_env: "safe".to_string(),
            repro_out: String::new(),
            use_session_settings: false,
            resolved_settings_source: BTreeMap::new(),
            tui_enabled: false,
            tui_refresh_ms: 50,
            tui_max_log_lines: 200,
            http_max_retries: 2,
            http_timeout_ms: 60_000,
            http_connect_timeout_ms: 2_000,
            http_stream_idle_timeout_ms: 15_000,
            http_max_response_bytes: 10_000_000,
            http_max_line_bytes: 200_000,
            tool_catalog_names: Vec::new(),
            policy_version: None,
            includes_resolved: Vec::new(),
            mcp_allowlist: None,
            instructions_config_path: String::new(),
            instructions_config_hash_hex: String::new(),
            instruction_model_profile: String::new(),
            instruction_task_profile: String::new(),
            instruction_message_count: 0,
        };
        let b = a.clone();
        let ha = config_hash_hex(&a).expect("hash a");
        let hb = config_hash_hex(&b).expect("hash b");
        assert_eq!(ha, hb);

        a.max_read_bytes = 100;
        let hc = config_hash_hex(&a).expect("hash c");
        assert_ne!(ha, hc);

        let mut d = b.clone();
        d.exec_target = "docker".to_string();
        let hd = config_hash_hex(&d).expect("hash d");
        assert_ne!(hb, hd);
    }

    #[test]
    fn tool_schema_hash_is_deterministic_for_key_order() {
        let a = serde_json::json!({"type":"object","properties":{"b":{"type":"string"},"a":{"type":"number"}}});
        let b = serde_json::json!({"properties":{"a":{"type":"number"},"b":{"type":"string"}},"type":"object"});
        assert_eq!(super::hash_tool_schema(&a), super::hash_tool_schema(&b));
    }
}
