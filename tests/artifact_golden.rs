use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use localagent::agent::{AgentExitReason, AgentOutcome, ToolDecisionRecord};
use localagent::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
use localagent::planner::RunMode;
use localagent::store::{
    self, PolicyRecordInfo, RunCliConfig, RunRecord, ToolCatalogEntry, WorkerRunRecord,
};
use localagent::types::SideEffects;
use serde_json::{json, Map, Value};
use tempfile::tempdir;

fn normalize_sep(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn sorted_object_keys(obj: &Map<String, Value>) -> Vec<String> {
    let mut keys = obj.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

fn build_run_cli_config() -> RunCliConfig {
    RunCliConfig {
        mode: "single".to_string(),
        provider: "ollama".to_string(),
        base_url: "http://localhost:11434".to_string(),
        model: "test-model".to_string(),
        planner_model: None,
        worker_model: None,
        planner_max_steps: None,
        planner_output: None,
        planner_strict: None,
        enforce_plan_tools: "off".to_string(),
        mcp_pin_enforcement: "hard".to_string(),
        trust_mode: "on".to_string(),
        allow_shell: true,
        allow_write: false,
        enable_write_tools: false,
        exec_target: "host".to_string(),
        docker_image: None,
        docker_workdir: None,
        docker_network: None,
        docker_user: None,
        max_tool_output_bytes: 200_000,
        max_read_bytes: 200_000,
        max_wall_time_ms: 0,
        max_total_tool_calls: 8,
        max_mcp_calls: 2,
        max_filesystem_read_calls: 4,
        max_filesystem_write_calls: 0,
        max_shell_calls: 2,
        max_network_calls: 0,
        max_browser_calls: 0,
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
        http_max_retries: 2,
        http_timeout_ms: 0,
        http_connect_timeout_ms: 2_000,
        http_stream_idle_timeout_ms: 0,
        http_max_response_bytes: 10_000_000,
        http_max_line_bytes: 200_000,
        tui_enabled: false,
        tui_refresh_ms: 50,
        tui_max_log_lines: 200,
        tool_catalog: vec![
            ToolCatalogEntry {
                name: "read_file".to_string(),
                side_effects: SideEffects::FilesystemRead,
            },
            ToolCatalogEntry {
                name: "shell".to_string(),
                side_effects: SideEffects::ShellExec,
            },
        ],
        mcp_tool_snapshot: Vec::new(),
        mcp_tool_catalog_hash_hex: None,
        mcp_servers: Vec::new(),
        mcp_config_path: None,
        policy_version: Some(2),
        includes_resolved: vec!["./policy.common.yaml".to_string()],
        mcp_allowlist: None,
        instructions_config_path: None,
        instructions_config_hash_hex: None,
        instruction_model_profile: None,
        instruction_task_profile: None,
        instruction_message_count: 0,
    }
}

fn build_outcome() -> AgentOutcome {
    AgentOutcome {
        run_id: "golden_run_1".to_string(),
        started_at: "2026-02-26T12:00:00Z".to_string(),
        finished_at: "2026-02-26T12:00:01Z".to_string(),
        exit_reason: AgentExitReason::Ok,
        final_output: "done".to_string(),
        error: None,
        messages: Vec::new(),
        tool_calls: Vec::new(),
        tool_decisions: vec![
            ToolDecisionRecord {
                step: 1,
                tool_call_id: "tc_allow".to_string(),
                tool: "read_file".to_string(),
                decision: "allow".to_string(),
                reason: None,
                source: Some("policy".to_string()),
                taint_overall: None,
                taint_enforced: false,
                escalated: false,
                escalation_reason: None,
            },
            ToolDecisionRecord {
                step: 2,
                tool_call_id: "tc_deny".to_string(),
                tool: "shell".to_string(),
                decision: "deny".to_string(),
                reason: Some("dangerous command denied".to_string()),
                source: Some("policy".to_string()),
                taint_overall: Some("clean".to_string()),
                taint_enforced: false,
                escalated: false,
                escalation_reason: None,
            },
            ToolDecisionRecord {
                step: 3,
                tool_call_id: "tc_approve".to_string(),
                tool: "shell".to_string(),
                decision: "require_approval".to_string(),
                reason: Some("shell requires approval".to_string()),
                source: Some("policy".to_string()),
                taint_overall: Some("clean".to_string()),
                taint_enforced: false,
                escalated: false,
                escalation_reason: None,
            },
        ],
        compaction_settings: CompactionSettings {
            max_context_chars: 0,
            mode: CompactionMode::Off,
            keep_last: 20,
            tool_result_persist: ToolResultPersist::Digest,
        },
        final_prompt_size_chars: 42,
        compaction_report: None,
        hook_invocations: Vec::new(),
        provider_retry_count: 0,
        provider_error_count: 0,
        token_usage: None,
        taint: None,
    }
}

fn build_projection(root: &Path, paths: &store::StatePaths, run_path: &Path, record: &RunRecord) -> Value {
    let record_json = serde_json::to_value(record).expect("serialize record");
    let obj = record_json.as_object().expect("record object");
    let cli = obj
        .get("cli")
        .and_then(Value::as_object)
        .expect("cli object");
    let resolved_paths = obj
        .get("resolved_paths")
        .and_then(Value::as_object)
        .expect("resolved_paths object");
    let compaction = obj
        .get("compaction")
        .and_then(Value::as_object)
        .expect("compaction object");

    json!({
        "artifact_layout": {
            "relative_run_artifact_path": normalize_sep(run_path.strip_prefix(root).expect("relative run path")),
            "relative_state_dir": normalize_sep(paths.state_dir.strip_prefix(root).expect("relative state dir")),
            "relative_policy_path": normalize_sep(paths.policy_path.strip_prefix(root).expect("relative policy path")),
            "relative_approvals_path": normalize_sep(paths.approvals_path.strip_prefix(root).expect("relative approvals path")),
            "relative_audit_path": normalize_sep(paths.audit_path.strip_prefix(root).expect("relative audit path")),
            "relative_runs_dir": normalize_sep(paths.runs_dir.strip_prefix(root).expect("relative runs dir")),
            "relative_sessions_dir": normalize_sep(paths.sessions_dir.strip_prefix(root).expect("relative sessions dir")),
        },
        "schema_keys": {
            "top_level": sorted_object_keys(obj),
            "cli": sorted_object_keys(cli),
            "resolved_paths": sorted_object_keys(resolved_paths),
            "compaction": sorted_object_keys(compaction),
        },
        "metadata": obj.get("metadata").cloned().expect("metadata"),
        "mode": obj.get("mode").cloned().expect("mode"),
        "policy_source": obj.get("policy_source").cloned().expect("policy_source"),
        "policy_version": obj.get("policy_version").cloned().expect("policy_version"),
        "tool_decisions": obj.get("tool_decisions").cloned().expect("tool_decisions"),
        "tool_catalog": obj.get("tool_catalog").cloned().expect("tool_catalog"),
        "config_fingerprint_present": obj.get("config_fingerprint").map(|v| !v.is_null()).unwrap_or(false),
        "mcp_pin_snapshot_present": obj.get("mcp_pin_snapshot").map(|v| !v.is_null()).unwrap_or(false),
    })
}

#[test]
fn run_artifact_schema_and_layout_golden_is_stable() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    let paths = store::resolve_state_paths(root, None, None, None, None);

    let cli = build_run_cli_config();
    let outcome = build_outcome();
    let run_path = store::write_run_record(
        &paths,
        cli,
        PolicyRecordInfo {
            source: "file".to_string(),
            hash_hex: Some("abc123".to_string()),
            version: Some(2),
            includes_resolved: vec!["./policy.common.yaml".to_string()],
            mcp_allowlist: None,
        },
        "cfg_hash_golden".to_string(),
        &outcome,
        RunMode::Single,
        None,
        Some(WorkerRunRecord {
            model: "test-model".to_string(),
            injected_planner_hash_hex: None,
            step_result_valid: Some(true),
            step_result_json: Some(json!({"ok": true})),
            step_result_error: None,
        }),
        BTreeMap::new(),
        None,
        None,
        None,
        Vec::new(),
        None,
    )
    .expect("write run record");

    let record = store::load_run_record(&paths.state_dir, &outcome.run_id).expect("load record");
    let got = build_projection(root, &paths, &run_path, &record);

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/run_record_schema_golden.json");

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        if let Some(parent) = fixture_path.parent() {
            std::fs::create_dir_all(parent).expect("fixture dir");
        }
        std::fs::write(
            &fixture_path,
            serde_json::to_string_pretty(&got).expect("fixture json"),
        )
        .expect("write fixture");
    }

    let want: Value = serde_json::from_str(
        &std::fs::read_to_string(&fixture_path).expect("read fixture golden"),
    )
    .expect("parse fixture");

    assert_eq!(
        got, want,
        "artifact schema/layout golden drift detected at {}",
        fixture_path.display()
    );
}
