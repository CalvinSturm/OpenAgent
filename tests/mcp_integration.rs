use std::fs;
use std::time::Duration;

use localagent::agent::{AgentExitReason, AgentOutcome};
use localagent::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
use localagent::eval::assert::{evaluate_assertions, Assertion};
use localagent::mcp::registry::McpRegistry;
use localagent::mcp::types::{McpConfigFile, McpServerConfig};
use localagent::tools::ToolArgsStrict;
use localagent::trust::policy::{Policy, PolicyDecision};
use localagent::types::{Message, ToolCall};
use serde_json::json;
use tempfile::tempdir;

fn stub_bin() -> Option<String> {
    std::env::var("CARGO_BIN_EXE_mcp_stub").ok()
}

#[tokio::test]
async fn mcp_tool_naming_and_schema_conversion() {
    let Some(stub) = stub_bin() else {
        eprintln!("skipping: CARGO_BIN_EXE_mcp_stub not set");
        return;
    };
    let tmp = tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("mcp_servers.json");
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        "stub".to_string(),
        McpServerConfig {
            command: stub,
            args: vec![],
        },
    );
    let cfg = McpConfigFile {
        schema_version: "openagent.mcp_servers.v1".to_string(),
        servers,
    };
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&cfg).expect("serialize"),
    )
    .expect("write config");

    let reg =
        McpRegistry::from_config_path(&cfg_path, &["stub".to_string()], Duration::from_secs(5))
            .await
            .expect("start registry");
    let names = reg
        .tool_defs()
        .into_iter()
        .map(|t| t.name)
        .collect::<Vec<_>>();
    assert!(names.iter().any(|n| n == "mcp.stub.echo"));
}

#[tokio::test]
async fn mcp_call_routing_returns_wrapped_result() {
    let Some(stub) = stub_bin() else {
        eprintln!("skipping: CARGO_BIN_EXE_mcp_stub not set");
        return;
    };
    let tmp = tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("mcp_servers.json");
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        "stub".to_string(),
        McpServerConfig {
            command: stub,
            args: vec![],
        },
    );
    let cfg = McpConfigFile {
        schema_version: "openagent.mcp_servers.v1".to_string(),
        servers,
    };
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&cfg).expect("serialize"),
    )
    .expect("write config");

    let reg =
        McpRegistry::from_config_path(&cfg_path, &["stub".to_string()], Duration::from_secs(5))
            .await
            .expect("start registry");

    let tc = ToolCall {
        id: "tc1".to_string(),
        name: "mcp.stub.echo".to_string(),
        arguments: json!({"msg":"world"}),
    };
    let msg = reg
        .call_namespaced_tool(&tc, ToolArgsStrict::On)
        .await
        .expect("call");
    let content = msg.message.content.unwrap_or_default();
    assert!(content.contains("\"schema_version\":\"openagent.tool_result.v1\""));
    assert!(content.contains("\"tool_name\":\"mcp.stub.echo\""));
    assert!(content.contains("\"ok\":true"));
    assert!(content.contains("\"truncated\":false"));
    assert!(!content.contains("\"full_output_ref\""));
}

#[tokio::test]
async fn mcp_schema_validation_blocks_invalid_args_before_call() {
    let Some(stub) = stub_bin() else {
        eprintln!("skipping: CARGO_BIN_EXE_mcp_stub not set");
        return;
    };
    let tmp = tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("mcp_servers.json");
    let call_count = tmp.path().join("calls.txt");
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        "stub".to_string(),
        McpServerConfig {
            command: stub,
            args: vec![call_count.display().to_string()],
        },
    );
    let cfg = McpConfigFile {
        schema_version: "openagent.mcp_servers.v1".to_string(),
        servers,
    };
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&cfg).expect("serialize"),
    )
    .expect("write config");
    let reg =
        McpRegistry::from_config_path(&cfg_path, &["stub".to_string()], Duration::from_secs(5))
            .await
            .expect("start registry");

    let tc = ToolCall {
        id: "tc_invalid".to_string(),
        name: "mcp.stub.echo".to_string(),
        arguments: json!({"wrong":"field"}),
    };
    let msg = reg
        .call_namespaced_tool(&tc, ToolArgsStrict::On)
        .await
        .expect("result");
    let content = msg.message.content.unwrap_or_default();
    assert!(content.contains("invalid tool arguments"));
    assert!(!call_count.exists());
}

#[tokio::test]
async fn mcp_oversize_output_is_truncated_and_spooled() {
    let Some(stub) = stub_bin() else {
        eprintln!("skipping: CARGO_BIN_EXE_mcp_stub not set");
        return;
    };
    let tmp = tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("mcp_servers.json");
    let mut servers = std::collections::BTreeMap::new();
    servers.insert(
        "stub".to_string(),
        McpServerConfig {
            command: stub,
            args: vec![],
        },
    );
    let cfg = McpConfigFile {
        schema_version: "openagent.mcp_servers.v1".to_string(),
        servers,
    };
    fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&cfg).expect("serialize"),
    )
    .expect("write config");

    let reg =
        McpRegistry::from_config_path(&cfg_path, &["stub".to_string()], Duration::from_secs(5))
            .await
            .expect("start registry");

    let large_msg = "x".repeat(128 * 1024);
    let tc = ToolCall {
        id: "tc_large".to_string(),
        name: "mcp.stub.echo".to_string(),
        arguments: json!({"msg": large_msg}),
    };
    let out = reg
        .call_namespaced_tool(&tc, ToolArgsStrict::On)
        .await
        .expect("call");
    let content = out.message.content.expect("tool result envelope");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse envelope");
    assert_eq!(parsed.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        parsed.get("truncated").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        parsed.get("truncate_reason").and_then(|v| v.as_str()),
        Some("max_bytes")
    );

    let model_excerpt = parsed
        .get("content")
        .and_then(|v| v.as_str())
        .expect("content string");
    assert!(model_excerpt.len() <= 64 * 1024);

    let full_ref = parsed
        .get("full_output_ref")
        .and_then(|v| v.as_object())
        .expect("full_output_ref");
    assert_eq!(
        full_ref.get("kind").and_then(|v| v.as_str()),
        Some("state_spool_path")
    );
    let spool_path = full_ref
        .get("path")
        .and_then(|v| v.as_str())
        .expect("spool path");
    let spooled = fs::read_to_string(spool_path).expect("read spooled output");
    let bytes = spooled.as_bytes();
    let sha256 = localagent::store::sha256_hex(bytes);
    assert_eq!(
        full_ref.get("sha256").and_then(|v| v.as_str()),
        Some(sha256.as_str())
    );
    assert_eq!(
        full_ref.get("bytes").and_then(|v| v.as_u64()),
        Some(bytes.len() as u64)
    );
    assert!(spool_path.contains(".localagent") || spool_path.contains("tmp"));
    assert!(spooled.contains("\"echo\""));
}

#[test]
fn trust_policy_glob_matches_mcp_namespace() {
    let policy = Policy::from_yaml(
        r#"
version: 1
default: deny
rules:
  - tool: "mcp.playwright.*"
    decision: allow
"#,
    )
    .expect("parse policy");
    let d = policy.evaluate("mcp.playwright.browser_snapshot", &json!({}));
    assert!(matches!(d.decision, PolicyDecision::Allow));
}

#[test]
fn mcp_policy_allow_deny_approval_matrix_is_deterministic() {
    let policy = Policy::from_yaml(
        r#"
version: 2
default: deny
rules:
  - tool: "mcp.safe.*"
    decision: allow
  - tool: "mcp.risky.*"
    decision: require_approval
  - tool: "mcp.blocked.*"
    decision: deny
"#,
    )
    .expect("parse policy");

    let cases = vec![
        ("mcp.safe.echo", PolicyDecision::Allow),
        (
            "mcp.risky.browser_snapshot",
            PolicyDecision::RequireApproval,
        ),
        ("mcp.blocked.exec", PolicyDecision::Deny),
    ];

    for (tool, expected) in cases {
        let got = policy.evaluate(tool, &json!({})).decision;
        assert_eq!(got, expected, "tool={tool}");
    }
}

#[test]
fn b5_negative_assertion_fails_when_shell_attempted() {
    let outcome = AgentOutcome {
        run_id: "r".to_string(),
        started_at: "2026-01-01T00:00:00Z".to_string(),
        finished_at: "2026-01-01T00:00:01Z".to_string(),
        exit_reason: AgentExitReason::Ok,
        final_output: "INJECT_DATA_OK:42".to_string(),
        error: None,
        messages: Vec::<Message>::new(),
        tool_calls: vec![ToolCall {
            id: "tc1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"rm -rf /"}),
        }],
        tool_decisions: Vec::new(),
        compaction_settings: CompactionSettings {
            max_context_chars: 0,
            mode: CompactionMode::Off,
            keep_last: 20,
            tool_result_persist: ToolResultPersist::Digest,
        },
        final_prompt_size_chars: 0,
        compaction_report: None,
        hook_invocations: Vec::new(),
        provider_retry_count: 0,
        provider_error_count: 0,
        token_usage: None,
        taint: None,
    };
    let failures = evaluate_assertions(
        &[Assertion::ToolNotUsedGlob {
            pattern: "shell".to_string(),
        }],
        std::path::Path::new("."),
        &outcome,
    );
    assert_eq!(failures.len(), 1);
}
