use std::path::{Path, PathBuf};

use crate::trust::policy::McpAllowSummary;

mod hash;
mod io;
mod render;
mod types;
pub use hash::{
    cli_trust_mode, config_hash_hex, hash_tool_schema, mcp_tool_snapshot_hash_hex,
    provider_to_string, sha256_hex, stable_path_string, tool_schema_hash_hex_map,
};
pub(crate) use io::write_json_atomic;
pub use io::{ensure_dir, load_run_record, write_run_record};
pub use render::{extract_session_messages, render_replay};
pub use types::{
    ActivatedPackRecord, ConfigFingerprintV1, McpPinSnapshotRecord, McpToolSnapshotEntry,
    PlannerRunRecord, RunCliConfig, RunCompactionRecord, RunMetadata, RunRecord, RunResolvedPaths,
    ToolCatalogEntry, WorkerRunRecord,
};

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
                mcp_pin_enforcement: "hard".to_string(),
                trust_mode: "off".to_string(),
                allow_shell: false,
                allow_write: false,
                enable_write_tools: false,
                exec_target: "host".to_string(),
                docker_image: None,
                docker_workdir: None,
                docker_network: None,
                docker_user: None,
                docker_config_summary: None,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                max_wall_time_ms: 0,
                max_total_tool_calls: 0,
                max_mcp_calls: 0,
                max_filesystem_read_calls: 0,
                max_filesystem_write_calls: 0,
                max_shell_calls: 0,
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
                mcp_tool_snapshot: Vec::new(),
                mcp_tool_catalog_hash_hex: None,
                mcp_servers: Vec::new(),
                mcp_config_path: None,
                policy_version: None,
                includes_resolved: Vec::new(),
                mcp_allowlist: None,
                instructions_config_path: None,
                instructions_config_hash_hex: None,
                instruction_model_profile: None,
                instruction_task_profile: None,
                instruction_message_count: 0,
                project_guidance_hash_hex: None,
                project_guidance_sources: Vec::new(),
                project_guidance_truncated: false,
                project_guidance_bytes_loaded: 0,
                project_guidance_bytes_kept: 0,
                repo_map_hash_hex: None,
                repo_map_format: None,
                repo_map_truncated: false,
                repo_map_truncated_reason: None,
                repo_map_bytes_scanned: 0,
                repo_map_bytes_kept: 0,
                repo_map_file_count_included: 0,
                repo_map_injected: false,
                active_profile: None,
                profile_source: None,
                profile_hash_hex: None,
                activated_packs: Vec::new(),
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
            Vec::new(),
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
                mcp_pin_enforcement: "hard".to_string(),
                trust_mode: "off".to_string(),
                allow_shell: false,
                allow_write: false,
                enable_write_tools: false,
                exec_target: "host".to_string(),
                docker_image: None,
                docker_workdir: None,
                docker_network: None,
                docker_user: None,
                docker_config_summary: None,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                max_wall_time_ms: 0,
                max_total_tool_calls: 0,
                max_mcp_calls: 0,
                max_filesystem_read_calls: 0,
                max_filesystem_write_calls: 0,
                max_shell_calls: 0,
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
                mcp_tool_snapshot: Vec::new(),
                mcp_tool_catalog_hash_hex: None,
                mcp_servers: Vec::new(),
                mcp_config_path: None,
                policy_version: None,
                includes_resolved: Vec::new(),
                mcp_allowlist: None,
                instructions_config_path: None,
                instructions_config_hash_hex: None,
                instruction_model_profile: None,
                instruction_task_profile: None,
                instruction_message_count: 0,
                project_guidance_hash_hex: None,
                project_guidance_sources: Vec::new(),
                project_guidance_truncated: false,
                project_guidance_bytes_loaded: 0,
                project_guidance_bytes_kept: 0,
                repo_map_hash_hex: None,
                repo_map_format: None,
                repo_map_truncated: false,
                repo_map_truncated_reason: None,
                repo_map_bytes_scanned: 0,
                repo_map_bytes_kept: 0,
                repo_map_file_count_included: 0,
                repo_map_injected: false,
                active_profile: None,
                profile_source: None,
                profile_hash_hex: None,
                activated_packs: Vec::new(),
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
            mcp_runtime_trace: Vec::new(),
            mcp_pin_snapshot: None,
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
            mcp_pin_enforcement: "hard".to_string(),
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
            max_wall_time_ms: 0,
            max_total_tool_calls: 0,
            max_mcp_calls: 0,
            max_filesystem_read_calls: 0,
            max_filesystem_write_calls: 0,
            max_shell_calls: 0,
            max_network_calls: 0,
            max_browser_calls: 0,
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
            mcp_tool_catalog_hash_hex: String::new(),
            mcp_servers: Vec::new(),
            mcp_config_path: String::new(),
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
