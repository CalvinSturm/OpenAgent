use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;

use tempfile::tempdir;

use crate::providers::{ModelProvider, StreamDelta};

use crate::target::ExecTargetKind;

use crate::taskgraph::{TaskCompaction, TaskFlags, TaskLimits};

use crate::types::{GenerateRequest, GenerateResponse, Message, Role};

use super::{DockerNetwork, ProviderKind};

use crate::{ops_helpers, provider_runtime};

struct CaptureSink {
    events: Arc<Mutex<Vec<crate::events::Event>>>,
}

impl crate::events::EventSink for CaptureSink {
    fn emit(&mut self, event: crate::events::Event) -> anyhow::Result<()> {
        self.events.lock().expect("lock").push(event);

        Ok(())
    }
}

struct PlannerTestProvider {
    seen_tools_none: Arc<Mutex<Vec<bool>>>,
}

#[async_trait]

impl ModelProvider for PlannerTestProvider {
    async fn generate(&self, req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
        self.seen_tools_none
            .lock()
            .expect("lock")
            .push(req.tools.is_none());

        Ok(GenerateResponse {
            assistant: Message {
                role: Role::Assistant,

                content: Some("not-json".to_string()),

                tool_call_id: None,

                tool_name: None,

                tool_calls: None,
            },

            tool_calls: Vec::new(),

            usage: None,
        })
    }

    async fn generate_streaming(
        &self,

        req: GenerateRequest,

        _on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    ) -> anyhow::Result<GenerateResponse> {
        self.generate(req).await
    }
}

enum QualificationProbeMode {
    NativePass,

    InlinePass,

    FailNoTool,
}

struct QualificationTestProvider {
    calls: Arc<AtomicUsize>,

    mode: QualificationProbeMode,
}

#[async_trait]

impl ModelProvider for QualificationTestProvider {
    async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);

        let (assistant_content, tool_calls) = match self.mode {
            QualificationProbeMode::NativePass => (
                Some(String::new()),
                vec![crate::types::ToolCall {
                    id: "q1".to_string(),

                    name: "list_dir".to_string(),

                    arguments: serde_json::json!({"path":"."}),
                }],
            ),

            QualificationProbeMode::InlinePass => (
                Some("{\"name\":\"list_dir\",\"arguments\":{\"path\":\".\"}}".to_string()),
                Vec::new(),
            ),

            QualificationProbeMode::FailNoTool => (Some("no tool".to_string()), Vec::new()),
        };

        Ok(GenerateResponse {
            assistant: Message {
                role: Role::Assistant,

                content: assistant_content,

                tool_call_id: None,

                tool_name: None,

                tool_calls: None,
            },

            tool_calls,

            usage: None,
        })
    }

    async fn generate_streaming(
        &self,

        req: GenerateRequest,

        _on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    ) -> anyhow::Result<GenerateResponse> {
        self.generate(req).await
    }
}

#[test]

fn doctor_url_construction_openai_compat() {
    let urls =
        provider_runtime::doctor_probe_urls(ProviderKind::Lmstudio, "http://localhost:1234/v1/");

    assert_eq!(urls[0], "http://localhost:1234/v1/models");

    assert_eq!(urls[1], "http://localhost:1234/v1");
}

#[test]

fn policy_doctor_helper_works() {
    let tmp = tempdir().expect("tmp");

    let p = tmp.path().join("policy.yaml");

    std::fs::write(
        &p,
        r#"



version: 2



default: deny



rules:



  - tool: "read_file"



    decision: allow



"#,
    )
    .expect("write");

    let out = ops_helpers::policy_doctor_output(&p).expect("doctor");

    assert!(out.contains("version=2"));

    assert!(out.contains("rules=1"));
}

#[test]

fn policy_effective_helper_json_contains_rules() {
    let tmp = tempdir().expect("tmp");

    let p = tmp.path().join("policy.yaml");

    std::fs::write(
        &p,
        r#"



version: 2



default: deny



rules:



  - tool: "read_file"



    decision: allow



"#,
    )
    .expect("write");

    let out = ops_helpers::policy_effective_output(&p, true).expect("print");

    assert!(out.contains("\"rules\""));

    assert!(out.contains("read_file"));
}

#[test]

fn probe_parser_accepts_inline_json_tool_call() {
    let resp = GenerateResponse {
        assistant: Message {
            role: Role::Assistant,

            content: Some("{\"name\":\"list_dir\",\"arguments\":{\"path\":\".\"}}".to_string()),

            tool_call_id: None,

            tool_name: None,

            tool_calls: None,
        },

        tool_calls: Vec::new(),

        usage: None,
    };

    let tc = super::qualification::probe_response_to_tool_call(&resp).expect("tool call");

    assert_eq!(tc.name, "list_dir");

    assert_eq!(tc.arguments, serde_json::json!({"path":"."}));
}

#[test]

fn probe_parser_accepts_fenced_json_tool_call() {
    let resp = GenerateResponse {
        assistant: Message {
            role: Role::Assistant,

            content: Some(
                "```json\n{\"name\":\"list_dir\",\"arguments\":{\"path\":\".\"}}\n```".to_string(),
            ),

            tool_call_id: None,

            tool_name: None,

            tool_calls: None,
        },

        tool_calls: Vec::new(),

        usage: None,
    };

    let tc = super::qualification::probe_response_to_tool_call(&resp).expect("tool call");

    assert_eq!(tc.name, "list_dir");

    assert_eq!(tc.arguments, serde_json::json!({"path":"."}));
}

#[tokio::test]

async fn planner_phase_omits_tools_and_emits_tool_count_zero() {
    let seen = Arc::new(Mutex::new(Vec::<bool>::new()));

    let provider = PlannerTestProvider {
        seen_tools_none: seen.clone(),
    };

    let events = Arc::new(Mutex::new(Vec::<crate::events::Event>::new()));

    let mut sink: Option<Box<dyn crate::events::EventSink>> = Some(Box::new(CaptureSink {
        events: events.clone(),
    }));

    let out = super::planner_runtime::run_planner_phase(
        &provider,
        "run_test",
        "m",
        "do thing",
        1,
        crate::planner::PlannerOutput::Json,
        false,
        &mut sink,
    )
    .await
    .expect("planner");

    assert!(out.plan_json.get("schema_version").is_some());

    assert_eq!(seen.lock().expect("lock").as_slice(), &[true]);

    let model_start = events
        .lock()
        .expect("lock")
        .iter()
        .find(|e| matches!(e.kind, crate::events::EventKind::ModelRequestStart))
        .cloned()
        .expect("model request event");

    assert_eq!(
        model_start.data.get("tool_count").and_then(|v| v.as_u64()),
        Some(0)
    );
}

#[test]

fn task_settings_merge_defaults_then_overrides() {
    let mut args = default_run_args();

    let defaults = crate::taskgraph::TaskDefaults {
        mode: Some("planner_worker".to_string()),

        provider: Some("ollama".to_string()),

        base_url: Some("http://localhost:11434".to_string()),

        model: Some("m1".to_string()),

        planner_model: Some("pm".to_string()),

        worker_model: Some("wm".to_string()),

        trust: Some("on".to_string()),

        approval_mode: Some("auto".to_string()),

        auto_approve_scope: Some("run".to_string()),

        caps: Some("strict".to_string()),

        hooks: Some("auto".to_string()),

        compaction: TaskCompaction {
            max_context_chars: Some(111),

            mode: Some("summary".to_string()),

            keep_last: Some(7),

            tool_result_persist: Some("digest".to_string()),
        },

        limits: TaskLimits {
            max_read_bytes: Some(123),

            max_tool_output_bytes: Some(456),
        },

        flags: TaskFlags {
            enable_write_tools: Some(true),

            allow_write: Some(true),

            allow_shell: Some(false),

            stream: Some(false),
        },

        mcp: vec!["playwright".to_string()],
    };

    super::task_apply::apply_task_defaults(&mut args, &defaults).expect("defaults");

    let override_s = crate::taskgraph::TaskNodeSettings {
        model: Some("m2".to_string()),

        flags: TaskFlags {
            allow_shell: Some(true),

            ..TaskFlags::default()
        },

        ..crate::taskgraph::TaskNodeSettings::default()
    };

    super::task_apply::apply_node_overrides(&mut args, &override_s).expect("overrides");

    assert_eq!(args.model.as_deref(), Some("m2"));

    assert!(args.allow_shell);

    assert!(matches!(args.mode, crate::planner::RunMode::PlannerWorker));

    assert_eq!(args.mcp, vec!["playwright".to_string()]);
}

#[test]

fn node_summary_line_is_deterministic() {
    let a = super::runtime_events::node_summary_line("N1", "ok", "hello\nworld");

    let b = super::runtime_events::node_summary_line("N1", "ok", "hello\nworld");

    assert_eq!(a, b);

    assert!(a.contains("output_sha256="));
}

#[test]

fn planner_worker_defaults_plan_enforcement_to_hard_when_not_explicit() {
    let resolved = super::runtime_flags::resolve_plan_tool_enforcement(
        crate::planner::RunMode::PlannerWorker,
        crate::agent::PlanToolEnforcementMode::Off,
        false,
    );

    assert!(matches!(
        resolved,
        crate::agent::PlanToolEnforcementMode::Hard
    ));
}

#[test]

fn planner_worker_respects_explicit_off_override() {
    let resolved = super::runtime_flags::resolve_plan_tool_enforcement(
        crate::planner::RunMode::PlannerWorker,
        crate::agent::PlanToolEnforcementMode::Off,
        true,
    );

    assert!(matches!(
        resolved,
        crate::agent::PlanToolEnforcementMode::Off
    ));
}

#[test]

fn planner_worker_respects_explicit_soft_override() {
    let resolved = super::runtime_flags::resolve_plan_tool_enforcement(
        crate::planner::RunMode::PlannerWorker,
        crate::agent::PlanToolEnforcementMode::Soft,
        true,
    );

    assert!(matches!(
        resolved,
        crate::agent::PlanToolEnforcementMode::Soft
    ));
}

#[test]

fn timeout_command_off_disables_request_and_stream_idle() {
    let mut args = default_run_args();

    let msg = super::runtime_config::apply_timeout_input(&mut args, "off").expect("timeout off");

    assert_eq!(args.http_timeout_ms, 0);

    assert_eq!(args.http_stream_idle_timeout_ms, 0);

    assert!(msg.contains("disabled"));

    assert!(super::runtime_config::timeout_settings_summary(&args).contains("request=off"));

    assert!(super::runtime_config::timeout_settings_summary(&args).contains("stream-idle=off"));
}

#[tokio::test]

async fn qualification_failure_is_cached_and_short_circuits_future_attempts() {
    let tmp = tempdir().expect("tmp");

    let cache = tmp.path().join("qual_cache.json");

    let tools = crate::tools::builtin_tools_enabled(true, false);

    let model = format!(
        "qual_model_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    );

    let first_calls = Arc::new(AtomicUsize::new(0));

    let first = QualificationTestProvider {
        calls: first_calls.clone(),

        mode: QualificationProbeMode::FailNoTool,
    };

    let err = super::qualification::ensure_orchestrator_qualified(
        &first,
        ProviderKind::Lmstudio,
        "http://localhost:1234/v1",
        &model,
        &tools,
        &cache,
    )
    .await
    .expect_err("expected fail");

    assert!(err.to_string().contains("no tool call returned"));

    assert!(first_calls.load(Ordering::SeqCst) >= 1);

    let second_calls = Arc::new(AtomicUsize::new(0));

    let second = QualificationTestProvider {
        calls: second_calls,

        mode: QualificationProbeMode::NativePass,
    };

    let err2 = super::qualification::ensure_orchestrator_qualified(
        &second,
        ProviderKind::Lmstudio,
        "http://localhost:1234/v1",
        &model,
        &tools,
        &cache,
    )
    .await
    .expect_err("cache should fail fast");

    assert!(err2
        .to_string()
        .contains("failed previously for this model/session"));
}

#[tokio::test]

async fn qualification_fallback_disables_write_tools_and_continues() {
    let tmp = tempdir().expect("tmp");

    let cache = tmp.path().join("qual_cache.json");

    let mut tools = crate::tools::builtin_tools_enabled(true, false);

    assert!(tools
        .iter()
        .any(|t| t.side_effects == crate::types::SideEffects::FilesystemWrite));

    let calls = Arc::new(AtomicUsize::new(0));

    let provider = QualificationTestProvider {
        calls,

        mode: QualificationProbeMode::FailNoTool,
    };

    let mut args = default_run_args();

    args.enable_write_tools = true;

    args.allow_write = true;

    let note = super::qualification::qualify_or_enable_readonly_fallback(
        &provider,
        ProviderKind::Lmstudio,
        "http://localhost:1234/v1",
        "fallback-model",
        args.enable_write_tools || args.allow_write,
        &mut tools,
        &cache,
    )
    .await
    .expect("fallback should not error")
    .expect("fallback note");

    assert!(note.contains("read-only fallback"));

    assert!(!tools
        .iter()
        .any(|t| t.side_effects == crate::types::SideEffects::FilesystemWrite));
}

#[tokio::test]

async fn qualification_fallback_keeps_write_tools_when_probe_passes() {
    let tmp = tempdir().expect("tmp");

    let cache = tmp.path().join("qual_cache.json");

    let mut tools = crate::tools::builtin_tools_enabled(true, false);

    let calls = Arc::new(AtomicUsize::new(0));

    let provider = QualificationTestProvider {
        calls,

        mode: QualificationProbeMode::InlinePass,
    };

    let mut args = default_run_args();

    args.enable_write_tools = true;

    args.allow_write = true;

    let note = super::qualification::qualify_or_enable_readonly_fallback(
        &provider,
        ProviderKind::Lmstudio,
        "http://localhost:1234/v1",
        "pass-model",
        args.enable_write_tools || args.allow_write,
        &mut tools,
        &cache,
    )
    .await
    .expect("qualification ok");

    assert!(note.is_none());

    assert!(tools
        .iter()
        .any(|t| t.side_effects == crate::types::SideEffects::FilesystemWrite));
}

#[test]

fn protocol_hint_detects_tool_call_format_issues() {
    let hint = super::runtime_config::protocol_remediation_hint(



            "MODEL_TOOL_PROTOCOL_VIOLATION: repeated malformed tool calls (tool='list_dir', error='...')",



        )



        .expect("hint");

    assert!(hint.contains("native tool call JSON"));
}

#[test]

fn protocol_hint_detects_invalid_patch_format() {
    let hint = super::runtime_config::protocol_remediation_hint(
        "MODEL_TOOL_PROTOCOL_VIOLATION: repeated invalid patch format for apply_patch",
    )
    .expect("hint");

    assert!(hint.contains("valid unified diff"));
}

#[test]

fn protocol_hint_ignores_non_protocol_errors() {
    assert!(super::runtime_config::protocol_remediation_hint("provider timeout").is_none());
}

fn default_run_args() -> super::RunArgs {
    super::RunArgs {
        provider: None,

        model: None,

        base_url: None,

        api_key: None,

        prompt: None,

        max_steps: 20,

        max_wall_time_ms: 0,

        max_total_tool_calls: 0,

        max_mcp_calls: 0,

        max_filesystem_read_calls: 0,

        max_filesystem_write_calls: 0,

        max_shell_calls: 0,

        max_network_calls: 0,

        max_browser_calls: 0,

        workdir: std::path::PathBuf::from("."),

        state_dir: None,

        mcp: Vec::new(),
        packs: Vec::new(),

        mcp_config: None,

        allow_shell: false,

        allow_shell_in_workdir: false,

        allow_write: false,

        enable_write_tools: false,

        exec_target: ExecTargetKind::Host,

        docker_image: "ubuntu:24.04".to_string(),

        docker_workdir: "/work".to_string(),

        docker_network: DockerNetwork::None,

        docker_user: None,

        max_tool_output_bytes: 200_000,

        max_read_bytes: 200_000,

        trust: crate::gate::TrustMode::Off,

        approval_mode: crate::gate::ApprovalMode::Interrupt,

        auto_approve_scope: crate::gate::AutoApproveScope::Run,

        approval_key: crate::gate::ApprovalKeyVersion::V1,

        unsafe_mode: false,

        no_limits: false,

        unsafe_bypass_allow_flags: false,

        policy: None,

        approvals: None,

        audit: None,

        session: "default".to_string(),

        no_session: false,

        reset_session: false,

        max_session_messages: 40,

        use_session_settings: false,

        max_context_chars: 0,

        use_repomap: false,

        repomap_max_bytes: 32 * 1024,
        reliability_profile: None,

        compaction_mode: crate::compaction::CompactionMode::Off,

        compaction_keep_last: 20,

        tool_result_persist: crate::compaction::ToolResultPersist::Digest,

        hooks: crate::hooks::config::HooksMode::Off,

        hooks_config: None,

        hooks_strict: false,

        hooks_timeout_ms: 2000,

        hooks_max_stdout_bytes: 200_000,

        tool_args_strict: crate::tools::ToolArgsStrict::On,

        instructions_config: None,

        instruction_model_profile: None,

        instruction_task_profile: None,

        task_kind: None,

        taint: crate::taint::TaintToggle::Off,

        taint_mode: crate::taint::TaintMode::Propagate,

        taint_digest_bytes: 4096,

        repro: crate::repro::ReproMode::Off,

        repro_out: None,

        repro_env: crate::repro::ReproEnvMode::Safe,

        caps: crate::session::CapsMode::Off,

        stream: false,

        events: None,

        http_max_retries: 2,

        http_timeout_ms: 0,

        http_connect_timeout_ms: 2_000,

        http_stream_idle_timeout_ms: 0,

        http_max_response_bytes: 10_000_000,

        http_max_line_bytes: 200_000,

        tui: false,

        tui_refresh_ms: 50,

        tui_max_log_lines: 200,

        mode: crate::planner::RunMode::Single,

        planner_model: None,

        worker_model: None,

        planner_max_steps: 2,

        planner_output: crate::planner::PlannerOutput::Json,

        enforce_plan_tools: crate::agent::PlanToolEnforcementMode::Off,

        mcp_pin_enforcement: crate::agent::McpPinEnforcementMode::Hard,

        planner_strict: true,

        no_planner_strict: false,
        resolved_reliability_profile_source: None,
        resolved_reliability_profile_hash_hex: None,
    }
}
