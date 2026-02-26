use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;

use crate::chat_runtime;
use crate::chat_tui_runtime;
use crate::mcp::registry::McpRegistry;
use crate::provider_runtime;
use crate::providers::mock::MockProvider;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai_compat::OpenAiCompatProvider;
use crate::runtime_config;
use crate::runtime_paths;
use crate::session::SessionStore;
use crate::store;
use crate::{run_agent, AgentExitReason, ChatArgs, ProviderKind, RunArgs};

pub(crate) async fn run_chat_repl(
    chat: &ChatArgs,
    base_run: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    if chat.tui {
        return chat_tui_runtime::run_chat_tui(chat, base_run, paths).await;
    }
    let provider_kind = base_run
        .provider
        .ok_or_else(|| anyhow!("--provider is required in chat mode"))?;
    let model = base_run
        .model
        .clone()
        .ok_or_else(|| anyhow!("--model is required in chat mode"))?;
    let base_url = base_run
        .base_url
        .clone()
        .unwrap_or_else(|| provider_runtime::default_base_url(provider_kind).to_string());
    let mut active_run = base_run.clone();
    let mut pending_timeout_input = false;
    let mut pending_params_input = false;
    let mut timeout_notice_active = false;
    let mut shared_chat_mcp_registry: Option<Arc<McpRegistry>> = None;

    println!(
        "LocalAgent chat started (provider={} model={} tui={}).",
        provider_runtime::provider_cli_name(provider_kind),
        model,
        chat.tui
    );
    println!(
        "Commands: /help, /mode <safe|coding|web|custom>, /timeout [seconds|+N|-N|off], /params [key value], /tool docs <name>, /dismiss, /exit, /clear"
    );

    loop {
        print!("You> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if pending_params_input && !input.starts_with('/') {
            if input.eq_ignore_ascii_case("cancel") {
                pending_params_input = false;
                println!("params update cancelled");
                continue;
            }
            match runtime_config::apply_params_input(&mut active_run, input) {
                Ok(msg) => {
                    pending_params_input = false;
                    println!("{msg}");
                }
                Err(msg) => {
                    println!("{msg}");
                    println!("enter '<key> <value>' or 'cancel'");
                }
            }
            continue;
        }
        if pending_timeout_input && !input.starts_with('/') {
            if input.eq_ignore_ascii_case("cancel") {
                pending_timeout_input = false;
                println!("timeout update cancelled");
                continue;
            }
            match runtime_config::apply_timeout_input(&mut active_run, input) {
                Ok(msg) => {
                    pending_timeout_input = false;
                    println!("{msg}");
                }
                Err(msg) => {
                    println!("{msg}");
                    println!("enter seconds, +N, -N, or 'cancel'");
                }
            }
            continue;
        }
        if input.starts_with('/') {
            match input {
                "/exit" => break,
                "/help" => {
                    println!("/help  show commands");
                    println!("/mode  show current mode");
                    println!("/mode <safe|coding|web|custom>  switch mode");
                    println!("/timeout  show timeout settings and wait for input");
                    println!("/timeout <seconds|+N|-N|off>  set/adjust timeout (off disables request+stream idle timeout)");
                    println!(
                        "/params  show current tuning params and wait for '<key> <value>' input"
                    );
                    println!("/params <key> <value>  set a tuning param");
                    println!("/tool docs <name>  show tool docs from local MCP registry snapshot");
                    println!("/dismiss  dismiss timeout notification");
                    println!("/clear clear current session messages");
                    println!("/exit  quit chat");
                }
                "/mode" => {
                    println!(
                        "current mode: {} (use /mode <safe|coding|web|custom>)",
                        chat_runtime::chat_mode_label(&active_run)
                    );
                }
                "/timeout" => {
                    pending_timeout_input = true;
                    println!("{}", runtime_config::timeout_settings_summary(&active_run));
                    println!("enter seconds, +N, -N, or 'cancel'");
                }
                "/params" => {
                    pending_params_input = true;
                    println!("{}", runtime_config::params_settings_summary(&active_run));
                    println!(
                        "editable keys: max_steps, max_context_chars, compaction_mode(off|summary), compaction_keep_last, tool_result_persist(all|digest|none), max_tool_output_bytes, max_read_bytes, stream(on|off), allow_shell(on|off), allow_write(on|off), enable_write_tools(on|off), allow_shell_in_workdir(on|off)"
                    );
                    println!("enter '<key> <value>' or 'cancel'");
                }
                "/dismiss" => {
                    if timeout_notice_active {
                        timeout_notice_active = false;
                        println!("timeout notification dismissed");
                    } else {
                        println!("no active timeout notification");
                    }
                }
                "/tool docs" => {
                    println!("usage: /tool docs <name> (example: /tool docs mcp.stub.echo)");
                }
                "/clear" => {
                    if active_run.no_session {
                        println!("sessions are disabled (--no-session), nothing to clear");
                    } else {
                        let session_path = paths
                            .sessions_dir
                            .join(format!("{}.json", active_run.session));
                        let store = SessionStore::new(session_path, active_run.session.clone());
                        store.reset()?;
                        println!("session '{}' cleared", active_run.session);
                    }
                }
                _ if input.starts_with("/mode ") => {
                    let mode = input["/mode ".len()..].trim();
                    if runtime_config::apply_chat_mode(&mut active_run, mode).is_some() {
                        println!(
                            "mode switched to {}",
                            chat_runtime::chat_mode_label(&active_run)
                        );
                    } else {
                        println!("unknown mode: {mode}. expected safe|coding|web|custom");
                    }
                }
                _ if input.starts_with("/timeout ") => {
                    let value = input["/timeout ".len()..].trim();
                    match runtime_config::apply_timeout_input(&mut active_run, value) {
                        Ok(msg) => println!("{msg}"),
                        Err(msg) => println!("{msg}"),
                    }
                }
                _ if input.starts_with("/params ") => {
                    let value = input["/params ".len()..].trim();
                    match runtime_config::apply_params_input(&mut active_run, value) {
                        Ok(msg) => println!("{msg}"),
                        Err(msg) => println!("{msg}"),
                    }
                }
                _ if input.starts_with("/tool docs ") => {
                    let tool_name = input["/tool docs ".len()..].trim();
                    if tool_name.is_empty() {
                        println!("usage: /tool docs <name> (example: /tool docs mcp.stub.echo)");
                        continue;
                    }
                    if active_run.mcp.is_empty() {
                        println!("MCP registry unavailable: no MCP servers enabled for this chat session");
                        continue;
                    }
                    if shared_chat_mcp_registry.is_none() {
                        let mcp_config_path =
                            runtime_paths::resolved_mcp_config_path(&active_run, &paths.state_dir);
                        match McpRegistry::from_config_path(
                            &mcp_config_path,
                            &active_run.mcp,
                            Duration::from_secs(30),
                        )
                        .await
                        {
                            Ok(reg) => shared_chat_mcp_registry = Some(Arc::new(reg)),
                            Err(e) => {
                                println!("failed to initialize MCP session: {e}");
                                continue;
                            }
                        }
                    }
                    if let Some(reg) = shared_chat_mcp_registry.as_ref() {
                        println!("{}", reg.render_tool_docs_text(tool_name));
                    } else {
                        println!("MCP registry unavailable: failed to initialize");
                    }
                }
                _ => println!("unknown command: {input}"),
            }
            continue;
        }

        let mut turn_args = active_run.clone();
        turn_args.prompt = Some(input.to_string());
        turn_args.tui = chat.tui;
        if !chat.tui && !turn_args.stream {
            turn_args.stream = true;
        }

        match provider_kind {
            ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
                let provider = OpenAiCompatProvider::new(
                    base_url.clone(),
                    turn_args.api_key.clone(),
                    provider_runtime::http_config_from_run_args(&turn_args),
                )?;
                let res = run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    input,
                    &turn_args,
                    paths,
                )
                .await?;
                if matches!(res.outcome.exit_reason, AgentExitReason::ProviderError) {
                    let err = res
                        .outcome
                        .error
                        .unwrap_or_else(|| "provider error".to_string());
                    eprintln!(
                        "{}\nHint: run `localagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
                        err,
                        provider_runtime::provider_cli_name(provider_kind),
                        base_url,
                        provider_runtime::provider_cli_name(provider_kind),
                        provider_runtime::default_base_url(provider_kind)
                    );
                    if runtime_config::is_timeout_error_text(&err) && !timeout_notice_active {
                        timeout_notice_active = true;
                        eprintln!("{}", runtime_config::timeout_notice_text(&active_run));
                    }
                }
            }
            ProviderKind::Ollama => {
                let provider = OllamaProvider::new(
                    base_url.clone(),
                    provider_runtime::http_config_from_run_args(&turn_args),
                )?;
                let res = run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    input,
                    &turn_args,
                    paths,
                )
                .await?;
                if matches!(res.outcome.exit_reason, AgentExitReason::ProviderError) {
                    let err = res
                        .outcome
                        .error
                        .unwrap_or_else(|| "provider error".to_string());
                    eprintln!(
                        "{}\nHint: run `localagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
                        err,
                        provider_runtime::provider_cli_name(provider_kind),
                        base_url,
                        provider_runtime::provider_cli_name(provider_kind),
                        provider_runtime::default_base_url(provider_kind)
                    );
                    if runtime_config::is_timeout_error_text(&err) && !timeout_notice_active {
                        timeout_notice_active = true;
                        eprintln!("{}", runtime_config::timeout_notice_text(&active_run));
                    }
                }
            }
            ProviderKind::Mock => {
                let provider = MockProvider::new();
                let _ = run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    input,
                    &turn_args,
                    paths,
                )
                .await?;
            }
        }
    }
    Ok(())
}
