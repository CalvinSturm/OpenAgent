use std::path::PathBuf;

use openagent::hooks::config::HooksMode;
use openagent::hooks::runner::{
    make_pre_model_input, make_tool_result_input, HookManager, HookRuntimeConfig,
};

fn hook_stub_path() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_hook_stub") {
        return PathBuf::from(p);
    }
    let mut exe = std::env::current_exe().expect("current_exe");
    exe.pop(); // deps
    exe.pop(); // debug
    let mut cand = exe.join("hook_stub.exe");
    if cand.exists() {
        return cand;
    }
    cand = exe.join("hook_stub");
    cand
}

fn write_hooks_config(path: &std::path::Path, stage: &str) {
    let stub = hook_stub_path();
    let escaped = stub.display().to_string().replace('\\', "\\\\");
    std::fs::write(
        path,
        format!(
            r#"
version: 1
hooks:
  - name: stub
    stages: ["{stage}"]
    command: "{escaped}"
"#
        ),
    )
    .expect("write hooks config");
}

#[tokio::test]
async fn strict_invalid_json_fails_non_strict_passes() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cfg = tmp.path().join("hooks.yaml");
    write_hooks_config(&cfg, "tool_result");

    let input_strict = make_tool_result_input(
        "r1",
        0,
        "ollama",
        "m",
        tmp.path(),
        serde_json::json!({
            "tool_call_id":"tc",
            "tool_name":"read_file",
            "ok": true,
            "content":"x",
            "truncated": false,
            "force_invalid_json": true
        }),
    );
    let strict = HookManager::build(HookRuntimeConfig {
        mode: HooksMode::On,
        config_path: cfg.clone(),
        strict: true,
        timeout_ms: 2_000,
        max_stdout_bytes: 200_000,
    })
    .expect("strict manager");
    assert!(strict
        .run_tool_result_hooks(input_strict, "read_file", "x", false)
        .await
        .is_err());

    let input_non_strict = make_tool_result_input(
        "r1",
        0,
        "ollama",
        "m",
        tmp.path(),
        serde_json::json!({
            "tool_call_id":"tc",
            "tool_name":"read_file",
            "ok": true,
            "content":"x",
            "truncated": false,
            "force_invalid_json": true
        }),
    );
    let non_strict = HookManager::build(HookRuntimeConfig {
        mode: HooksMode::On,
        config_path: cfg,
        strict: false,
        timeout_ms: 2_000,
        max_stdout_bytes: 200_000,
    })
    .expect("non strict manager");
    let out = non_strict
        .run_tool_result_hooks(input_non_strict, "read_file", "x", false)
        .await
        .expect("non strict passes");
    assert_eq!(out.content, "x");
}

#[tokio::test]
async fn pre_model_enforces_append_limits() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cfg = tmp.path().join("hooks.yaml");
    write_hooks_config(&cfg, "pre_model");
    let manager = HookManager::build(HookRuntimeConfig {
        mode: HooksMode::On,
        config_path: cfg,
        strict: true,
        timeout_ms: 2_000,
        max_stdout_bytes: 200_000,
    })
    .expect("manager");

    let input = make_pre_model_input(
        "r1",
        0,
        "ollama",
        "m",
        tmp.path(),
        serde_json::json!({
            "messages": [],
            "tools": [],
            "stream": false,
            "compaction": {"enabled": false, "max_context_chars":0, "mode":"off", "keep_last":20, "tool_result_persist":"digest"},
            "force_mode": "modify_many"
        }),
    );
    assert!(manager.run_pre_model_hooks(input).await.is_err());
}

#[tokio::test]
async fn tool_result_modify_updates_digest() {
    let tmp = tempfile::tempdir().expect("tmp");
    let cfg = tmp.path().join("hooks.yaml");
    write_hooks_config(&cfg, "tool_result");
    let manager = HookManager::build(HookRuntimeConfig {
        mode: HooksMode::On,
        config_path: cfg,
        strict: true,
        timeout_ms: 2_000,
        max_stdout_bytes: 200_000,
    })
    .expect("manager");
    let input = make_tool_result_input(
        "r1",
        0,
        "ollama",
        "m",
        tmp.path(),
        serde_json::json!({
            "tool_call_id":"tc",
            "tool_name":"read_file",
            "ok": true,
            "content":"secret",
            "truncated": false,
            "force_mode": "modify"
        }),
    );
    let out = manager
        .run_tool_result_hooks(input, "read_file", "secret", false)
        .await
        .expect("hook run");
    assert_eq!(out.content, "stub redacted");
    assert_ne!(out.input_digest, out.output_digest);
}
