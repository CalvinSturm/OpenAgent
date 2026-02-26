use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::compaction::{CompactionReport, CompactionSettings};
use crate::trust::policy::McpAllowSummary;
use crate::types::{Message, SideEffects, ToolCall};

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
    #[serde(default)]
    pub mcp_runtime_trace: Vec<crate::agent::McpRuntimeTraceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_pin_snapshot: Option<McpPinSnapshotRecord>,
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
pub struct McpToolSnapshotEntry {
    pub name: String,
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivatedPackRecord {
    pub pack_id: String,
    pub pack_hash_hex: String,
    pub bytes_loaded: u64,
    pub bytes_kept: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPinSnapshotRecord {
    pub enforcement: String,
    pub configured_catalog_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_live_catalog_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_docs_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_live_docs_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_config_hash_hex: Option<String>,
    pub pinned: bool,
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
    pub mcp_pin_enforcement: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_config_summary: Option<String>,
    pub max_tool_output_bytes: usize,
    pub max_read_bytes: usize,
    #[serde(default)]
    pub max_wall_time_ms: u64,
    #[serde(default)]
    pub max_total_tool_calls: usize,
    #[serde(default)]
    pub max_mcp_calls: usize,
    #[serde(default)]
    pub max_filesystem_read_calls: usize,
    #[serde(default)]
    pub max_filesystem_write_calls: usize,
    #[serde(default)]
    pub max_shell_calls: usize,
    #[serde(default)]
    pub max_network_calls: usize,
    #[serde(default)]
    pub max_browser_calls: usize,
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
    #[serde(default)]
    pub mcp_tool_snapshot: Vec<McpToolSnapshotEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_tool_catalog_hash_hex: Option<String>,
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_config_path: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_guidance_hash_hex: Option<String>,
    #[serde(default)]
    pub project_guidance_sources: Vec<String>,
    #[serde(default)]
    pub project_guidance_truncated: bool,
    #[serde(default)]
    pub project_guidance_bytes_loaded: u64,
    #[serde(default)]
    pub project_guidance_bytes_kept: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_map_hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_map_format: Option<String>,
    #[serde(default)]
    pub repo_map_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_map_truncated_reason: Option<String>,
    #[serde(default)]
    pub repo_map_bytes_scanned: u64,
    #[serde(default)]
    pub repo_map_bytes_kept: u64,
    #[serde(default)]
    pub repo_map_file_count_included: u64,
    #[serde(default)]
    pub repo_map_injected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_hash_hex: Option<String>,
    #[serde(default)]
    pub activated_packs: Vec<ActivatedPackRecord>,
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
    pub mcp_pin_enforcement: String,
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
    #[serde(default)]
    pub max_wall_time_ms: u64,
    #[serde(default)]
    pub max_total_tool_calls: usize,
    #[serde(default)]
    pub max_mcp_calls: usize,
    #[serde(default)]
    pub max_filesystem_read_calls: usize,
    #[serde(default)]
    pub max_filesystem_write_calls: usize,
    #[serde(default)]
    pub max_shell_calls: usize,
    #[serde(default)]
    pub max_network_calls: usize,
    #[serde(default)]
    pub max_browser_calls: usize,
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
    #[serde(default)]
    pub mcp_tool_catalog_hash_hex: String,
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    #[serde(default)]
    pub mcp_config_path: String,
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
