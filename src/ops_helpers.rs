use anyhow::anyhow;

use crate::compaction::CompactionSettings;
use crate::hooks;
use crate::hooks::config::HooksMode;
use crate::hooks::protocol::{PreModelCompactionPayload, PreModelPayload, ToolResultPayload};
use crate::hooks::runner::{make_pre_model_input, make_tool_result_input, HookManager, HookRuntimeConfig};
use crate::trust::policy::{McpAllowSummary, Policy};
use crate::RunArgs;

pub(crate) fn compute_hooks_config_hash_hex(mode: HooksMode, path: &std::path::Path) -> Option<String> {
    if matches!(mode, HooksMode::Off) || !path.exists() {
        return None;
    }
    std::fs::read(path)
        .ok()
        .map(|bytes| crate::store::sha256_hex(&bytes))
}

pub(crate) fn handle_hooks_list(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        println!("no hooks config at {}", path.display());
        return Ok(());
    }
    let loaded = hooks::config::LoadedHooks::load(path)?;
    if loaded.hooks.is_empty() {
        println!("no hooks configured");
        return Ok(());
    }
    for hook in loaded.hooks {
        let stages = hook
            .cfg
            .stages
            .iter()
            .map(|s| format!("{:?}", s).to_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        let cmd = if hook.cfg.args.is_empty() {
            hook.cfg.command.clone()
        } else {
            format!("{} {}", hook.cfg.command, hook.cfg.args.join(" "))
        };
        println!("{}\t{}\t{}", hook.cfg.name, stages, cmd);
    }
    Ok(())
}

pub(crate) fn policy_doctor_output(policy_path: &std::path::Path) -> anyhow::Result<String> {
    let p = Policy::from_path(policy_path)?;
    let mut out = format!(
        "OK: policy loaded version={} rules={} includes={}",
        p.version(),
        p.rules_len(),
        p.includes_resolved().len()
    );
    if let Some(McpAllowSummary {
        allow_servers,
        allow_tools,
    }) = p.mcp_allowlist_summary()
    {
        out.push_str(&format!(
            "\nMCP allowlist: servers={} tools={}",
            allow_servers.len(),
            allow_tools.len()
        ));
    }
    Ok(out)
}

pub(crate) fn policy_effective_output(
    policy_path: &std::path::Path,
    as_json: bool,
) -> anyhow::Result<String> {
    let p = Policy::from_path(policy_path)?;
    let effective = p.to_effective_policy();
    if as_json {
        Ok(serde_json::to_string_pretty(&effective)?)
    } else {
        Ok(serde_yaml::to_string(&effective)?)
    }
}

pub(crate) async fn handle_hooks_doctor(
    path: &std::path::Path,
    run: &RunArgs,
    provider: String,
) -> anyhow::Result<()> {
    let manager = HookManager::build(HookRuntimeConfig {
        mode: HooksMode::On,
        config_path: path.to_path_buf(),
        strict: true,
        timeout_ms: run.hooks_timeout_ms,
        max_stdout_bytes: run.hooks_max_stdout_bytes,
    })?;
    if manager.list().is_empty() {
        println!("no hooks configured");
        return Ok(());
    }
    let run_id = uuid::Uuid::new_v4().to_string();
    for hook in manager.list() {
        if hook.has_stage(hooks::config::HookStage::PreModel) {
            let payload = PreModelPayload {
                messages: vec![],
                tools: vec![],
                stream: false,
                compaction: PreModelCompactionPayload::from(&CompactionSettings {
                    max_context_chars: run.max_context_chars,
                    mode: run.compaction_mode,
                    keep_last: run.compaction_keep_last,
                    tool_result_persist: run.tool_result_persist,
                }),
            };
            let input = make_pre_model_input(
                &run_id,
                0,
                &provider,
                run.model.as_deref().unwrap_or("doctor"),
                &run.workdir,
                serde_json::to_value(payload)?,
            );
            let one = HookManager {
                mode: manager.mode,
                strict: true,
                timeout_ms: manager.timeout_ms,
                max_stdout_bytes: manager.max_stdout_bytes,
                config_path: manager.config_path.clone(),
                hooks: vec![hook.clone()],
            };
            one.run_pre_model_hooks(input)
                .await
                .map_err(|e| anyhow!(e.message))?;
        }
        if hook.has_stage(hooks::config::HookStage::ToolResult) {
            let payload = ToolResultPayload {
                tool_call_id: "doctor_tc".to_string(),
                tool_name: "read_file".to_string(),
                ok: true,
                content: "sample".to_string(),
                truncated: false,
            };
            let input = make_tool_result_input(
                &run_id,
                0,
                &provider,
                run.model.as_deref().unwrap_or("doctor"),
                &run.workdir,
                serde_json::to_value(payload)?,
            );
            let one = HookManager {
                mode: manager.mode,
                strict: true,
                timeout_ms: manager.timeout_ms,
                max_stdout_bytes: manager.max_stdout_bytes,
                config_path: manager.config_path.clone(),
                hooks: vec![hook.clone()],
            };
            one.run_tool_result_hooks(input, "read_file", "sample", false)
                .await
                .map_err(|e| anyhow!(e.message))?;
        }
        println!("OK: hook {}", hook.cfg.name);
    }
    Ok(())
}
