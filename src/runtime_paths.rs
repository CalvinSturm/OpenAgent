use std::path::PathBuf;

use crate::gate::ProviderKind;
use crate::instructions::InstructionResolution;
use crate::planner;
use crate::session;
use crate::store::{
    self, provider_to_string, stable_path_string, ConfigFingerprintV1, RunCliConfig,
};
use crate::target::ExecTargetKind;
use crate::trust::policy::McpAllowSummary;
use crate::types::Message;
use crate::RunArgs;

pub(crate) fn merge_injected_messages(
    mut instruction_messages: Vec<Message>,
    task_memory: Option<Message>,
    planner_handoff: Option<Message>,
) -> Vec<Message> {
    if let Some(m) = task_memory {
        instruction_messages.push(m);
    }
    if let Some(m) = planner_handoff {
        instruction_messages.push(m);
    }
    instruction_messages
}

pub(crate) struct RunCliConfigInput<'a> {
    pub provider_kind: ProviderKind,
    pub base_url: &'a str,
    pub model: &'a str,
    pub args: &'a RunArgs,
    pub resolved_settings: &'a session::RunSettingResolution,
    pub hooks_config_path: &'a std::path::Path,
    pub mcp_config_path: &'a std::path::Path,
    pub tool_catalog: Vec<store::ToolCatalogEntry>,
    pub mcp_tool_snapshot: Vec<store::McpToolSnapshotEntry>,
    pub mcp_tool_catalog_hash_hex: Option<String>,
    pub policy_version: Option<u32>,
    pub includes_resolved: Vec<String>,
    pub mcp_allowlist: Option<McpAllowSummary>,
    pub mode: planner::RunMode,
    pub planner_model: Option<String>,
    pub worker_model: Option<String>,
    pub planner_max_steps: Option<u32>,
    pub planner_output: Option<String>,
    pub planner_strict: Option<bool>,
    pub enforce_plan_tools: Option<String>,
    pub instructions: &'a InstructionResolution,
}

pub(crate) fn build_run_cli_config(input: RunCliConfigInput<'_>) -> RunCliConfig {
    let RunCliConfigInput {
        provider_kind,
        base_url,
        model,
        args,
        resolved_settings,
        hooks_config_path,
        mcp_config_path,
        tool_catalog,
        mcp_tool_snapshot,
        mcp_tool_catalog_hash_hex,
        policy_version,
        includes_resolved,
        mcp_allowlist,
        mode,
        planner_model,
        worker_model,
        planner_max_steps,
        planner_output,
        planner_strict,
        enforce_plan_tools,
        instructions,
    } = input;
    RunCliConfig {
        mode: format!("{:?}", mode).to_lowercase(),
        provider: provider_to_string(provider_kind),
        base_url: base_url.to_string(),
        model: model.to_string(),
        planner_model,
        worker_model,
        planner_max_steps,
        planner_output,
        planner_strict,
        enforce_plan_tools: enforce_plan_tools.unwrap_or_else(|| "off".to_string()),
        mcp_pin_enforcement: format!("{:?}", args.mcp_pin_enforcement).to_lowercase(),
        trust_mode: store::cli_trust_mode(args.trust),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        exec_target: format!("{:?}", args.exec_target).to_lowercase(),
        docker_image: if matches!(args.exec_target, ExecTargetKind::Docker) {
            Some(args.docker_image.clone())
        } else {
            None
        },
        docker_workdir: if matches!(args.exec_target, ExecTargetKind::Docker) {
            Some(args.docker_workdir.clone())
        } else {
            None
        },
        docker_network: if matches!(args.exec_target, ExecTargetKind::Docker) {
            Some(format!("{:?}", args.docker_network).to_lowercase())
        } else {
            None
        },
        docker_user: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_user.clone()
        } else {
            None
        },
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
        max_wall_time_ms: if args.no_limits {
            0
        } else {
            args.max_wall_time_ms
        },
        max_total_tool_calls: args.max_total_tool_calls,
        max_mcp_calls: args.max_mcp_calls,
        max_filesystem_read_calls: args.max_filesystem_read_calls,
        max_filesystem_write_calls: args.max_filesystem_write_calls,
        max_shell_calls: args.max_shell_calls,
        max_network_calls: args.max_network_calls,
        max_browser_calls: args.max_browser_calls,
        approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", args.auto_approve_scope).to_lowercase(),
        approval_key: args.approval_key.as_str().to_string(),
        unsafe_mode: args.unsafe_mode,
        no_limits: args.no_limits,
        unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
        stream: args.stream,
        events_path: args.events.as_ref().map(|p| p.display().to_string()),
        max_context_chars: resolved_settings.max_context_chars,
        compaction_mode: format!("{:?}", resolved_settings.compaction_mode).to_lowercase(),
        compaction_keep_last: resolved_settings.compaction_keep_last,
        tool_result_persist: format!("{:?}", resolved_settings.tool_result_persist).to_lowercase(),
        hooks_mode: format!("{:?}", resolved_settings.hooks_mode).to_lowercase(),
        caps_mode: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
        hooks_config_path: stable_path_string(hooks_config_path),
        hooks_strict: args.hooks_strict,
        hooks_timeout_ms: args.hooks_timeout_ms,
        hooks_max_stdout_bytes: args.hooks_max_stdout_bytes,
        tool_args_strict: format!("{:?}", resolved_settings.tool_args_strict).to_lowercase(),
        taint: format!("{:?}", args.taint).to_lowercase(),
        taint_mode: format!("{:?}", args.taint_mode).to_lowercase(),
        taint_digest_bytes: args.taint_digest_bytes,
        repro: format!("{:?}", args.repro).to_lowercase(),
        repro_env: format!("{:?}", args.repro_env).to_lowercase(),
        repro_out: args.repro_out.as_ref().map(|p| stable_path_string(p)),
        use_session_settings: args.use_session_settings,
        resolved_settings_source: resolved_settings.sources.clone(),
        http_max_retries: args.http_max_retries,
        http_timeout_ms: args.http_timeout_ms,
        http_connect_timeout_ms: args.http_connect_timeout_ms,
        http_stream_idle_timeout_ms: args.http_stream_idle_timeout_ms,
        http_max_response_bytes: args.http_max_response_bytes,
        http_max_line_bytes: args.http_max_line_bytes,
        tui_enabled: args.tui,
        tui_refresh_ms: args.tui_refresh_ms,
        tui_max_log_lines: args.tui_max_log_lines,
        tool_catalog,
        mcp_tool_snapshot,
        mcp_tool_catalog_hash_hex,
        mcp_servers: {
            let mut servers = args.mcp.clone();
            servers.sort();
            servers
        },
        mcp_config_path: Some(stable_path_string(mcp_config_path)),
        policy_version,
        includes_resolved,
        mcp_allowlist,
        instructions_config_path: instructions
            .config_path
            .as_ref()
            .map(|p| stable_path_string(p)),
        instructions_config_hash_hex: instructions.config_hash_hex.clone(),
        instruction_model_profile: instructions.selected_model_profile.clone(),
        instruction_task_profile: instructions.selected_task_profile.clone(),
        instruction_message_count: instructions.messages.len(),
    }
}

pub(crate) fn build_config_fingerprint(
    cli_config: &RunCliConfig,
    args: &RunArgs,
    model: &str,
    paths: &store::StatePaths,
) -> ConfigFingerprintV1 {
    ConfigFingerprintV1 {
        schema_version: "openagent.confighash.v1".to_string(),
        mode: cli_config.mode.clone(),
        provider: cli_config.provider.clone(),
        base_url: cli_config.base_url.clone(),
        model: model.to_string(),
        planner_model: cli_config.planner_model.clone().unwrap_or_default(),
        worker_model: cli_config.worker_model.clone().unwrap_or_default(),
        planner_max_steps: cli_config.planner_max_steps.unwrap_or_default(),
        planner_output: cli_config.planner_output.clone().unwrap_or_default(),
        planner_strict: cli_config.planner_strict.unwrap_or(false),
        enforce_plan_tools: cli_config.enforce_plan_tools.clone(),
        mcp_pin_enforcement: cli_config.mcp_pin_enforcement.clone(),
        trust_mode: store::cli_trust_mode(args.trust),
        state_dir: stable_path_string(&paths.state_dir),
        policy_path: stable_path_string(&paths.policy_path),
        approvals_path: stable_path_string(&paths.approvals_path),
        audit_path: stable_path_string(&paths.audit_path),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        exec_target: format!("{:?}", args.exec_target).to_lowercase(),
        docker_image: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_image.clone()
        } else {
            String::new()
        },
        docker_workdir: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_workdir.clone()
        } else {
            String::new()
        },
        docker_network: if matches!(args.exec_target, ExecTargetKind::Docker) {
            format!("{:?}", args.docker_network).to_lowercase()
        } else {
            String::new()
        },
        docker_user: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_user.clone().unwrap_or_default()
        } else {
            String::new()
        },
        max_steps: args.max_steps,
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
        max_wall_time_ms: if args.no_limits {
            0
        } else {
            args.max_wall_time_ms
        },
        max_total_tool_calls: args.max_total_tool_calls,
        max_mcp_calls: args.max_mcp_calls,
        max_filesystem_read_calls: args.max_filesystem_read_calls,
        max_filesystem_write_calls: args.max_filesystem_write_calls,
        max_shell_calls: args.max_shell_calls,
        max_network_calls: args.max_network_calls,
        max_browser_calls: args.max_browser_calls,
        session_name: if args.no_session {
            String::new()
        } else {
            args.session.clone()
        },
        no_session: args.no_session,
        max_session_messages: args.max_session_messages,
        approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", args.auto_approve_scope).to_lowercase(),
        approval_key: args.approval_key.as_str().to_string(),
        unsafe_mode: args.unsafe_mode,
        no_limits: args.no_limits,
        unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
        stream: args.stream,
        events_path: args
            .events
            .as_ref()
            .map(|p| stable_path_string(p))
            .unwrap_or_default(),
        max_context_chars: cli_config.max_context_chars,
        compaction_mode: cli_config.compaction_mode.clone(),
        compaction_keep_last: cli_config.compaction_keep_last,
        tool_result_persist: cli_config.tool_result_persist.clone(),
        hooks_mode: cli_config.hooks_mode.clone(),
        caps_mode: cli_config.caps_mode.clone(),
        hooks_config_path: cli_config.hooks_config_path.clone(),
        hooks_strict: cli_config.hooks_strict,
        hooks_timeout_ms: cli_config.hooks_timeout_ms,
        hooks_max_stdout_bytes: cli_config.hooks_max_stdout_bytes,
        tool_args_strict: cli_config.tool_args_strict.clone(),
        taint: cli_config.taint.clone(),
        taint_mode: cli_config.taint_mode.clone(),
        taint_digest_bytes: cli_config.taint_digest_bytes,
        repro: cli_config.repro.clone(),
        repro_env: cli_config.repro_env.clone(),
        repro_out: cli_config.repro_out.clone().unwrap_or_default(),
        use_session_settings: cli_config.use_session_settings,
        resolved_settings_source: cli_config.resolved_settings_source.clone(),
        tui_enabled: cli_config.tui_enabled,
        tui_refresh_ms: cli_config.tui_refresh_ms,
        tui_max_log_lines: cli_config.tui_max_log_lines,
        http_max_retries: cli_config.http_max_retries,
        http_timeout_ms: cli_config.http_timeout_ms,
        http_connect_timeout_ms: cli_config.http_connect_timeout_ms,
        http_stream_idle_timeout_ms: cli_config.http_stream_idle_timeout_ms,
        http_max_response_bytes: cli_config.http_max_response_bytes,
        http_max_line_bytes: cli_config.http_max_line_bytes,
        tool_catalog_names: cli_config
            .tool_catalog
            .iter()
            .map(|t| t.name.clone())
            .collect(),
        mcp_tool_catalog_hash_hex: cli_config
            .mcp_tool_catalog_hash_hex
            .clone()
            .unwrap_or_default(),
        mcp_servers: cli_config.mcp_servers.clone(),
        mcp_config_path: cli_config.mcp_config_path.clone().unwrap_or_default(),
        policy_version: cli_config.policy_version,
        includes_resolved: cli_config.includes_resolved.clone(),
        mcp_allowlist: cli_config.mcp_allowlist.clone(),
        instructions_config_path: cli_config
            .instructions_config_path
            .clone()
            .unwrap_or_default(),
        instructions_config_hash_hex: cli_config
            .instructions_config_hash_hex
            .clone()
            .unwrap_or_default(),
        instruction_model_profile: cli_config
            .instruction_model_profile
            .clone()
            .unwrap_or_default(),
        instruction_task_profile: cli_config
            .instruction_task_profile
            .clone()
            .unwrap_or_default(),
        instruction_message_count: cli_config.instruction_message_count,
    }
}

pub(crate) fn resolved_mcp_config_path(args: &RunArgs, state_dir: &std::path::Path) -> PathBuf {
    args.mcp_config
        .clone()
        .unwrap_or_else(|| state_dir.join("mcp_servers.json"))
}

pub(crate) fn resolved_hooks_config_path(args: &RunArgs, state_dir: &std::path::Path) -> PathBuf {
    args.hooks_config
        .clone()
        .unwrap_or_else(|| state_dir.join("hooks.yaml"))
}
