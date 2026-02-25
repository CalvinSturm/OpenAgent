use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use openagent::agent::{
    Agent, AgentExitReason, McpPinEnforcementMode, PlanStepConstraint, PlanToolEnforcementMode,
    ToolCallBudget,
};
use openagent::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
use openagent::gate::{
    compute_policy_hash_hex, ApprovalKeyVersion, ApprovalMode, AutoApproveScope, GateContext,
    NoGate, ProviderKind, ToolGate, TrustGate, TrustMode,
};
use openagent::hooks::config::HooksMode;
use openagent::hooks::runner::{HookManager, HookRuntimeConfig};
use openagent::providers::ModelProvider;
use openagent::taint::{TaintLevel, TaintMode, TaintToggle};
use openagent::target::{ExecTargetKind, HostTarget};
use openagent::tools::{builtin_tools_enabled, ToolArgsStrict, ToolRuntime};
use openagent::trust::approvals::ApprovalsStore;
use openagent::trust::audit::AuditLog;
use openagent::trust::policy::Policy;
use openagent::types::{GenerateRequest, GenerateResponse, Message, Role, ToolCall};
use serde_json::Value;
use tempfile::tempdir;

#[derive(Clone)]
enum ScriptStep {
    Tool {
        id: &'static str,
        name: &'static str,
        arguments: Value,
    },
    Final(&'static str),
}

struct ScriptedProvider {
    steps: Vec<ScriptStep>,
    next: AtomicUsize,
}

#[async_trait]
impl ModelProvider for ScriptedProvider {
    async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
        let idx = self.next.fetch_add(1, Ordering::SeqCst);
        let step = self
            .steps
            .get(idx)
            .cloned()
            .unwrap_or(ScriptStep::Final("done"));
        let response = match step {
            ScriptStep::Tool {
                id,
                name,
                arguments,
            } => GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some(String::new()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: vec![ToolCall {
                    id: id.to_string(),
                    name: name.to_string(),
                    arguments,
                }],
                usage: None,
            },
            ScriptStep::Final(text) => GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some(text.to_string()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: Vec::new(),
                usage: None,
            },
        };
        Ok(response)
    }
}

fn make_agent<P: ModelProvider + 'static>(
    provider: P,
    workdir: &Path,
    gate: Box<dyn ToolGate>,
    allow_shell: bool,
    allow_write: bool,
    enable_write_tools: bool,
) -> Agent<P> {
    Agent {
        provider,
        model: "mock-model".to_string(),
        tools: builtin_tools_enabled(enable_write_tools, allow_shell),
        max_steps: 8,
        tool_rt: ToolRuntime {
            workdir: workdir.to_path_buf(),
            allow_shell,
            allow_shell_in_workdir_only: false,
            allow_write,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            unsafe_bypass_allow_flags: false,
            tool_args_strict: ToolArgsStrict::On,
            exec_target_kind: ExecTargetKind::Host,
            exec_target: Arc::new(HostTarget),
        },
        gate,
        gate_ctx: GateContext {
            workdir: workdir.to_path_buf(),
            allow_shell,
            allow_write,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: None,
            enable_write_tools,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Mock,
            model: "mock-model".to_string(),
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: std::collections::BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
            taint_enabled: false,
            taint_mode: TaintMode::Propagate,
            taint_overall: TaintLevel::Clean,
            taint_sources: Vec::new(),
        },
        mcp_registry: None,
        stream: false,
        event_sink: None,
        compaction_settings: CompactionSettings {
            max_context_chars: 0,
            mode: CompactionMode::Off,
            keep_last: 20,
            tool_result_persist: ToolResultPersist::Digest,
        },
        hooks: HookManager::build(HookRuntimeConfig {
            mode: HooksMode::Off,
            config_path: std::env::temp_dir().join("unused_hooks.yaml"),
            strict: false,
            timeout_ms: 1_000,
            max_stdout_bytes: 200_000,
        })
        .expect("hooks"),
        policy_loaded: None,
        policy_for_taint: None,
        taint_toggle: TaintToggle::Off,
        taint_mode: TaintMode::Propagate,
        taint_digest_bytes: 4096,
        run_id_override: None,
        omit_tools_field_when_empty: false,
        plan_tool_enforcement: PlanToolEnforcementMode::Off,
        mcp_pin_enforcement: McpPinEnforcementMode::Hard,
        plan_step_constraints: Vec::<PlanStepConstraint>::new(),
        tool_call_budget: ToolCallBudget::default(),
        mcp_runtime_trace: Vec::new(),
    }
}

#[tokio::test]
async fn prompt_read_chess_html_executes_list_then_read() {
    let tmp = tempdir().expect("tempdir");
    let chess = tmp.path().join("chess.html");
    tokio::fs::write(&chess, "<html>board</html>")
        .await
        .expect("write");

    let provider = ScriptedProvider {
        steps: vec![
            ScriptStep::Tool {
                id: "tc1",
                name: "list_dir",
                arguments: serde_json::json!({"path":"."}),
            },
            ScriptStep::Tool {
                id: "tc2",
                name: "read_file",
                arguments: serde_json::json!({"path":"chess.html"}),
            },
            ScriptStep::Final("done"),
        ],
        next: AtomicUsize::new(0),
    };
    let mut agent = make_agent(
        provider,
        tmp.path(),
        Box::new(NoGate::new()),
        false,
        false,
        false,
    );
    let out = agent
        .run(
            "Read the chess html file in this directory and summarize what is broken.",
            vec![],
            Vec::new(),
        )
        .await;
    assert!(matches!(out.exit_reason, AgentExitReason::Ok));
    let tool_names = out
        .tool_calls
        .iter()
        .map(|tc| tc.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(tool_names, vec!["list_dir", "read_file"]);
}

#[tokio::test]
async fn write_file_on_existing_file_is_blocked_without_explicit_overwrite() {
    let tmp = tempdir().expect("tempdir");
    let chess = tmp.path().join("chess.html");
    tokio::fs::write(&chess, "<html>old</html>")
        .await
        .expect("write");

    let provider = ScriptedProvider {
        steps: vec![
            ScriptStep::Tool {
                id: "tc1",
                name: "write_file",
                arguments: serde_json::json!({"path":"chess.html","content":"<html>new</html>"}),
            },
            ScriptStep::Final("done"),
        ],
        next: AtomicUsize::new(0),
    };
    let mut agent = make_agent(
        provider,
        tmp.path(),
        Box::new(NoGate::new()),
        false,
        true,
        true,
    );
    let out = agent.run("Improve chess.html.", vec![], Vec::new()).await;

    assert!(matches!(out.exit_reason, AgentExitReason::PlannerError));
    assert!(out
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("write_file on 'chess.html' requires prior read_file"));
    let on_disk = tokio::fs::read_to_string(&chess).await.expect("read");
    assert_eq!(on_disk, "<html>old</html>");
}

#[tokio::test]
async fn apply_patch_edits_existing_file_in_place() {
    let tmp = tempdir().expect("tempdir");
    let chess = tmp.path().join("chess.html");
    tokio::fs::write(&chess, "old\n").await.expect("write");

    let provider = ScriptedProvider {
        steps: vec![
            ScriptStep::Tool {
                id: "tc1",
                name: "read_file",
                arguments: serde_json::json!({"path":"chess.html"}),
            },
            ScriptStep::Tool {
                id: "tc2",
                name: "apply_patch",
                arguments: serde_json::json!({"path":"chess.html","patch":"@@ -1 +1 @@\n-old\n+new\n"}),
            },
            ScriptStep::Final("done"),
        ],
        next: AtomicUsize::new(0),
    };
    let mut agent = make_agent(
        provider,
        tmp.path(),
        Box::new(NoGate::new()),
        false,
        true,
        true,
    );
    let out = agent.run("Patch chess.html.", vec![], Vec::new()).await;

    assert!(matches!(out.exit_reason, AgentExitReason::Ok));
    let on_disk = tokio::fs::read_to_string(&chess).await.expect("read");
    assert_eq!(on_disk, "new\n");
}

#[tokio::test]
async fn placeholder_only_implementation_output_is_rejected() {
    let tmp = tempdir().expect("tempdir");
    let chess = tmp.path().join("chess.html");
    tokio::fs::write(&chess, "<html>old</html>")
        .await
        .expect("write");
    let provider = ScriptedProvider {
        steps: vec![
            ScriptStep::Tool {
                id: "tc1",
                name: "read_file",
                arguments: serde_json::json!({"path":"chess.html"}),
            },
            ScriptStep::Final(
                "Same HTML structure. Additional improvements coming. ... (full implementation) ...",
            ),
        ],
        next: AtomicUsize::new(0),
    };
    let mut agent = make_agent(
        provider,
        tmp.path(),
        Box::new(NoGate::new()),
        false,
        true,
        true,
    );
    let out = agent
        .run(
            "Improve the chess game in chess.html so that it works like a proper chess game.",
            vec![],
            Vec::new(),
        )
        .await;
    assert!(matches!(out.exit_reason, AgentExitReason::PlannerError));
    assert!(out
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("placeholder artifacts"));
}

#[tokio::test]
async fn shell_call_requires_approval_in_interrupt_mode() {
    let tmp = tempdir().expect("tempdir");
    let policy_yaml = r#"
version: 1
default: deny
rules:
  - tool: "shell"
    decision: require_approval
"#;
    let policy = Policy::from_yaml(policy_yaml).expect("policy");
    let gate = TrustGate::new(
        policy,
        ApprovalsStore::new(tmp.path().join("approvals.json")),
        AuditLog::new(tmp.path().join("audit.log")),
        TrustMode::On,
        compute_policy_hash_hex(policy_yaml.as_bytes()),
    );

    let provider = ScriptedProvider {
        steps: vec![ScriptStep::Tool {
            id: "tc1",
            name: "shell",
            arguments: serde_json::json!({"cmd":"echo","args":["hi"]}),
        }],
        next: AtomicUsize::new(0),
    };
    let mut agent = make_agent(provider, tmp.path(), Box::new(gate), true, false, false);
    let out = agent.run("Run shell.", vec![], Vec::new()).await;

    assert!(matches!(out.exit_reason, AgentExitReason::ApprovalRequired));
    assert!(out
        .tool_decisions
        .iter()
        .any(|d| d.decision == "require_approval"));
}
