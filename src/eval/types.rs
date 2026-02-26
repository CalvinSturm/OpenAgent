use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::compaction::{CompactionMode, ToolResultPersist};
use crate::gate::{ApprovalKeyVersion, ApprovalMode, AutoApproveScope, ProviderKind, TrustMode};
use crate::hooks::config::HooksMode;
use crate::planner::RunMode;
use crate::providers::http::HttpConfig;
use crate::tools::ToolArgsStrict;

use super::tasks::EvalPack;

#[derive(Debug, Clone)]
pub struct EvalConfig {
    pub provider: ProviderKind,
    pub base_url: String,
    pub api_key: Option<String>,
    pub models: Vec<String>,
    pub pack: EvalPack,
    pub out: Option<PathBuf>,
    pub runs_per_task: usize,
    pub max_steps: usize,
    pub max_wall_time_ms: u64,
    pub max_mcp_calls: usize,
    pub timeout_seconds: u64,
    pub trust: TrustMode,
    pub approval_mode: ApprovalMode,
    pub auto_approve_scope: AutoApproveScope,
    pub approval_key: ApprovalKeyVersion,
    pub enable_write_tools: bool,
    pub allow_write: bool,
    pub allow_shell: bool,
    pub unsafe_mode: bool,
    pub no_limits: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub mcp: Vec<String>,
    pub mcp_config: Option<PathBuf>,
    pub session: String,
    pub no_session: bool,
    pub max_session_messages: usize,
    pub max_context_chars: usize,
    pub compaction_mode: CompactionMode,
    pub compaction_keep_last: usize,
    pub tool_result_persist: ToolResultPersist,
    pub hooks_mode: HooksMode,
    pub hooks_config: Option<PathBuf>,
    pub hooks_strict: bool,
    pub hooks_timeout_ms: u64,
    pub hooks_max_stdout_bytes: usize,
    pub tool_args_strict: ToolArgsStrict,
    pub tui_enabled: bool,
    pub tui_refresh_ms: u64,
    pub tui_max_log_lines: usize,
    pub state_dir_override: Option<PathBuf>,
    pub policy_override: Option<PathBuf>,
    pub approvals_override: Option<PathBuf>,
    pub audit_override: Option<PathBuf>,
    pub workdir_override: Option<PathBuf>,
    pub keep_workdir: bool,
    pub http: HttpConfig,
    pub mode: RunMode,
    pub planner_model: Option<String>,
    pub worker_model: Option<String>,
    pub min_pass_rate: f64,
    pub fail_on_any: bool,
    pub max_avg_steps: Option<f64>,
    pub resolved_profile_name: Option<String>,
    pub resolved_profile_path: Option<String>,
    pub resolved_profile_hash_hex: Option<String>,
    pub junit: Option<PathBuf>,
    pub summary_md: Option<PathBuf>,
    pub cost_model_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResults {
    pub schema_version: String,
    pub created_at: String,
    pub config: EvalResultsConfig,
    pub summary: EvalSummary,
    pub by_model: BTreeMap<String, ModelSummary>,
    pub runs: Vec<EvalRunRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<EvalMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<EvalBaselineStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regression: Option<crate::eval::baseline::RegressionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResultsConfig {
    pub provider: String,
    pub base_url: String,
    pub models: Vec<String>,
    pub pack: String,
    pub runs_per_task: usize,
    pub max_steps: usize,
    #[serde(default)]
    pub max_wall_time_ms: u64,
    #[serde(default)]
    pub max_mcp_calls: usize,
    pub timeout_seconds: u64,
    pub trust_mode: String,
    pub approval_mode: String,
    pub auto_approve_scope: String,
    pub approval_key: String,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub enable_write_tools: bool,
    pub unsafe_mode: bool,
    pub no_limits: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub mcp: Vec<String>,
    pub no_session: bool,
    pub session: String,
    pub max_context_chars: usize,
    pub compaction_mode: String,
    pub compaction_keep_last: usize,
    pub tool_result_persist: String,
    pub hooks_mode: String,
    pub hooks_config_path: String,
    pub hooks_strict: bool,
    pub hooks_timeout_ms: u64,
    pub hooks_max_stdout_bytes: usize,
    pub tool_args_strict: String,
    pub tui_enabled: bool,
    pub tui_refresh_ms: u64,
    pub tui_max_log_lines: usize,
    pub http_max_retries: u32,
    pub http_timeout_ms: u64,
    pub http_connect_timeout_ms: u64,
    pub http_stream_idle_timeout_ms: u64,
    pub http_max_response_bytes: usize,
    pub http_max_line_bytes: usize,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_profile_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_profile_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_profile_hash_hex: Option<String>,
    pub min_pass_rate: f64,
    pub fail_on_any: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_avg_steps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_model_path: Option<String>,
}

impl EvalResultsConfig {
    #[cfg(test)]
    pub fn minimal_for_tests() -> Self {
        Self {
            provider: "ollama".to_string(),
            base_url: "http://localhost:11434".to_string(),
            models: vec!["m".to_string()],
            pack: "all".to_string(),
            runs_per_task: 1,
            max_steps: 30,
            max_wall_time_ms: 0,
            max_mcp_calls: 0,
            timeout_seconds: 60,
            trust_mode: "on".to_string(),
            approval_mode: "auto".to_string(),
            auto_approve_scope: "run".to_string(),
            approval_key: "v1".to_string(),
            allow_shell: false,
            allow_write: false,
            enable_write_tools: false,
            unsafe_mode: false,
            no_limits: false,
            unsafe_bypass_allow_flags: false,
            mcp: vec![],
            no_session: true,
            session: "default".to_string(),
            max_context_chars: 0,
            compaction_mode: "off".to_string(),
            compaction_keep_last: 20,
            tool_result_persist: "digest".to_string(),
            hooks_mode: "off".to_string(),
            hooks_config_path: String::new(),
            hooks_strict: false,
            hooks_timeout_ms: 2000,
            hooks_max_stdout_bytes: 200_000,
            tool_args_strict: "on".to_string(),
            tui_enabled: false,
            tui_refresh_ms: 50,
            tui_max_log_lines: 200,
            http_max_retries: 2,
            http_timeout_ms: 60_000,
            http_connect_timeout_ms: 2_000,
            http_stream_idle_timeout_ms: 15_000,
            http_max_response_bytes: 10_000_000,
            http_max_line_bytes: 200_000,
            mode: "single".to_string(),
            planner_model: None,
            worker_model: None,
            resolved_profile_name: None,
            resolved_profile_path: None,
            resolved_profile_hash_hex: None,
            min_pass_rate: 0.0,
            fail_on_any: false,
            max_avg_steps: None,
            cost_model_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalBaselineStatus {
    pub name: String,
    pub path: String,
    pub loaded: bool,
    pub profile_hash_mismatch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalSummary {
    pub total_runs: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub pass_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelSummary {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub pass_rate: f64,
    pub fail_rate: f64,
    pub skip_rate: f64,
    pub tasks: BTreeMap<String, TaskSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskSummary {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub runs: Vec<EvalRunRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalVerifierResult {
    pub ran: bool,
    pub ok: bool,
    pub summary: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRunRow {
    pub model: String,
    pub task_id: String,
    pub run_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    pub run_id: String,
    pub exit_reason: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(default)]
    pub required_flags: Vec<String>,
    pub passed: bool,
    pub failures: Vec<String>,
    pub stats: EvalRunStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<EvalRunMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<EvalTokenMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<EvalVerifierResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRunStats {
    pub steps: usize,
    pub tool_calls: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalRunMetrics {
    pub steps: u32,
    pub tool_calls: u32,
    #[serde(default)]
    pub tool_sequence: Vec<String>,
    pub tool_calls_by_side_effects: BTreeMap<String, u32>,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub wall_time_ms: u64,
    pub verifier_time_ms: u64,
    pub provider: EvalProviderMetrics,
    pub tool_retries: u32,
    #[serde(default)]
    pub tool_failures_by_class: BTreeMap<String, u32>,
    #[serde(default)]
    pub step_invariant_violations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalProviderMetrics {
    pub http_retries: u32,
    pub provider_errors: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalTokenMetrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u32>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalMetrics {
    pub summary: EvalAggregateMetrics,
    pub per_model: BTreeMap<String, EvalAggregateMetrics>,
    pub per_task: BTreeMap<String, EvalAggregateMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalAggregateMetrics {
    pub avg_steps: f64,
    pub avg_tool_calls: f64,
    pub avg_wall_time_ms: f64,
    pub pass_rate: f64,
    pub fail_rate: f64,
    pub skip_rate: f64,
    pub avg_provider_retries: f64,
    pub avg_tool_retries: f64,
    pub avg_step_invariant_violations: f64,
}
