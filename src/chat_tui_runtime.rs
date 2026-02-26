use std::time::{Duration, Instant};

use anyhow::anyhow;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event as CEvent, KeyCode, KeyEventKind, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::agent::{self, AgentExitReason};
use crate::chat_commands;
use crate::chat_runtime;
use crate::chat_ui;
use crate::chat_view_utils;
use crate::events::{Event, EventKind};
use crate::gate::ProviderKind;
use crate::mcp::registry::McpRegistry;
use crate::provider_runtime;
use crate::providers::mock::MockProvider;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai_compat::OpenAiCompatProvider;
use crate::runtime_config;
use crate::runtime_paths;
use crate::session::SessionStore;
use crate::store;
use crate::trust::approvals::ApprovalsStore;
use crate::tui::state::UiState;
use crate::{run_agent_with_ui, ChatArgs, RunArgs, RunExecutionResult};
pub(crate) async fn run_chat_tui(
    chat: &ChatArgs,
    base_run: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
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
    let cwd_label = chat_runtime::normalize_path_for_display(
        std::fs::canonicalize(&base_run.workdir)
            .or_else(|_| std::env::current_dir())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| base_run.workdir.display().to_string()),
    );
    let mut active_run = base_run.clone();

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    if chat.plain_tui {
        execute!(stdout, DisableMouseCapture, EnableBracketedPaste)?;
    } else {
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste
        )?;
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input = String::new();
    let mut prompt_history: Vec<String> = Vec::new();
    let mut history_idx: Option<usize> = None;
    let mut transcript: Vec<(String, String)> = vec![];
    let show_banner = !chat.no_banner;
    let mut logs: Vec<String> = Vec::new();
    let max_logs = base_run.tui_max_log_lines;
    let mut status = "idle".to_string();
    let mut status_detail = String::new();
    let mut provider_connected = true;
    let mut think_tick: u64 = 0;
    let mut ui_tick: u64 = 0;
    let mut approvals_selected = 0usize;
    let mut show_tools = false;
    let mut show_approvals = false;
    let mut show_logs = false;
    let mut transcript_scroll: usize = 0;
    let mut follow_output = true;
    let mut compact_tools = true;
    let mut tools_selected = 0usize;
    let mut tools_focus = true;
    let mut show_tool_details = false;
    let palette_items = [
        "toggle tools pane",
        "toggle approvals pane",
        "toggle logs pane",
        "toggle tool row density",
        "clear transcript",
        "jump to latest",
    ];
    let mut palette_open = false;
    let mut palette_selected = 0usize;
    let mut search_mode = false;
    let mut search_query = String::new();
    let mut search_line_cursor = 0usize;
    let mut slash_menu_index: usize = 0;
    let mut shared_chat_mcp_registry: Option<std::sync::Arc<McpRegistry>> = None;
    let mut pending_timeout_input = false;
    let mut pending_params_input = false;
    let mut timeout_notice_active = false;
    let mut ui_state = UiState::new(max_logs);
    ui_state.provider = provider_runtime::provider_cli_name(provider_kind).to_string();
    ui_state.model = model.clone();
    ui_state.caps_source = format!("{:?}", base_run.caps).to_lowercase();
    ui_state.policy_hash = "-".to_string();
    let mut streaming_assistant = String::new();

    let run_result: anyhow::Result<()> = async {
        loop {
            ui_state.on_tick(Instant::now());
            let tool_row_count = if compact_tools { 20 } else { 12 };
            let visible_tool_count = ui_state.tool_calls.len().min(tool_row_count);
            if visible_tool_count == 0 {
                tools_selected = 0;
                show_tool_details = false;
            } else {
                tools_selected = tools_selected.min(visible_tool_count.saturating_sub(1));
            }
            if ui_state.pending_approvals.is_empty() {
                approvals_selected = 0;
            } else {
                approvals_selected =
                    approvals_selected.min(ui_state.pending_approvals.len().saturating_sub(1));
            }
            if show_tools && !show_approvals {
                tools_focus = true;
            } else if show_approvals && !show_tools {
                tools_focus = false;
            }
            if !show_tools {
                show_tool_details = false;
            }

            terminal.draw(|f| {
                chat_ui::draw_chat_frame(
                    f,
                    chat_runtime::chat_mode_label(&active_run),
                    provider_runtime::provider_cli_name(provider_kind),
                    provider_connected,
                    &model,
                    &status,
                    &status_detail,
                    &transcript,
                    &streaming_assistant,
                    &ui_state,
                    tools_selected,
                    tools_focus,
                    show_tool_details,
                    approvals_selected,
                    &cwd_label,
                    &input,
                    &logs,
                    think_tick,
                    base_run.tui_refresh_ms,
                    show_tools,
                    show_approvals,
                    show_logs,
                    transcript_scroll,
                    compact_tools,
                    show_banner,
                    ui_tick,
                    if palette_open {
                        Some(format!(
                            "⌘ {}  (Up/Down, Enter, Esc)",
                            palette_items[palette_selected]
                        ))
                    } else if search_mode {
                        Some(format!(
                            "🔎 {}  (Enter next, Esc close)",
                            search_query
                        ))
                    } else if input.starts_with('/') {
                        chat_commands::slash_overlay_text(&input, slash_menu_index)
                    } else if input.starts_with('?') {
                        chat_commands::keybinds_overlay_text()
                    } else {
                        None
                    },
                );
            })?;

            if event::poll(Duration::from_millis(base_run.tui_refresh_ms))? {
                match event::read()? {
                    CEvent::Mouse(me) => {
                        if let Some(delta) = chat_runtime::mouse_scroll_delta(&me) {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, delta, max_scroll);
                            follow_output = false;
                        }
                    }
                    CEvent::Paste(pasted) => {
                        input.push_str(&chat_runtime::normalize_pasted_text(&pasted));
                        history_idx = None;
                        slash_menu_index = 0;
                    }
                    CEvent::Key(key) => {
                    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    if key.code == KeyCode::Esc {
                        break;
                    }
                    if key.code == KeyCode::End {
                        follow_output = true;
                        transcript_scroll = usize::MAX;
                        continue;
                    }
                    if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        palette_open = !palette_open;
                        search_mode = false;
                        continue;
                    }
                    if key.code == KeyCode::Char('f') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        search_mode = true;
                        palette_open = false;
                        continue;
                    }
                    if palette_open {
                        match key.code {
                            KeyCode::Esc => palette_open = false,
                            KeyCode::Up => {
                                palette_selected = palette_selected.saturating_sub(1);
                            }
                            KeyCode::Down => {
                                if palette_selected + 1 < palette_items.len() {
                                    palette_selected += 1;
                                }
                            }
                            KeyCode::Enter => {
                                match palette_selected {
                                    0 => show_tools = !show_tools,
                                    1 => show_approvals = !show_approvals,
                                    2 => show_logs = !show_logs,
                                    3 => compact_tools = !compact_tools,
                                    4 => {
                                        transcript.clear();
                                        ui_state.tool_calls.clear();
                                        streaming_assistant.clear();
                                        transcript_scroll = 0;
                                        follow_output = true;
                                    }
                                    5 => {
                                        follow_output = true;
                                        transcript_scroll = usize::MAX;
                                    }
                                    _ => {}
                                }
                                palette_open = false;
                            }
                            _ => {}
                        }
                        continue;
                    }
                    if search_mode {
                        let mut do_search = false;
                        match key.code {
                            KeyCode::Esc => search_mode = false,
                            KeyCode::Backspace => {
                                search_query.pop();
                                search_line_cursor = 0;
                                do_search = true;
                            }
                            KeyCode::Enter => {
                                do_search = true;
                                search_line_cursor = search_line_cursor.saturating_add(1);
                            }
                            KeyCode::Char(c) if chat_runtime::is_text_input_mods(key.modifiers) => {
                                search_query.push(c);
                                search_line_cursor = 0;
                                do_search = true;
                            }
                            _ => {}
                        }
                        if do_search && !search_query.is_empty() {
                            let hay = transcript
                                .iter()
                                .map(|(role, text)| format!("{}: {}", role.to_uppercase(), text))
                                .collect::<Vec<_>>()
                                .join("\n\n");
                            let lines: Vec<&str> = hay.lines().collect();
                            let query = search_query.to_lowercase();
                            let mut found = None;
                            for (idx, line) in lines.iter().enumerate().skip(search_line_cursor) {
                                if line.to_lowercase().contains(&query) {
                                    found = Some(idx);
                                    break;
                                }
                            }
                            if found.is_none() {
                                for (idx, line) in lines.iter().enumerate().take(search_line_cursor) {
                                    if line.to_lowercase().contains(&query) {
                                        found = Some(idx);
                                        break;
                                    }
                                }
                            }
                            if let Some(idx) = found {
                                transcript_scroll = idx;
                                follow_output = false;
                                search_line_cursor = idx;
                            }
                        }
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                        KeyCode::Up => {
                            if input.starts_with('/') {
                                let matches_len = chat_commands::slash_match_count(&input);
                                if matches_len > 0 {
                                    slash_menu_index = if slash_menu_index == 0 {
                                        matches_len - 1
                                    } else {
                                        slash_menu_index - 1
                                    };
                                }
                                continue;
                            }
                            if !prompt_history.is_empty() {
                                let next = match history_idx {
                                    None => prompt_history.len().saturating_sub(1),
                                    Some(i) => i.saturating_sub(1),
                                };
                                history_idx = Some(next);
                                input = prompt_history[next].clone();
                            }
                        }
                        KeyCode::Down => {
                            if input.starts_with('/') {
                                let matches_len = chat_commands::slash_match_count(&input);
                                if matches_len > 0 {
                                    slash_menu_index = (slash_menu_index + 1) % matches_len;
                                }
                                continue;
                            }
                            if !prompt_history.is_empty() {
                                if let Some(i) = history_idx {
                                    let next = (i + 1).min(prompt_history.len());
                                    if next >= prompt_history.len() {
                                        history_idx = None;
                                        input.clear();
                                    } else {
                                        history_idx = Some(next);
                                        input = prompt_history[next].clone();
                                    }
                                }
                            }
                        }
                        KeyCode::PageUp => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, -12, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::PageDown => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, 12, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, -10, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, 10, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_tools = !show_tools;
                        }
                        KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_approvals = !show_approvals;
                        }
                        KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_logs = !show_logs;
                        }
                        KeyCode::Tab => {
                            if show_tools && show_approvals {
                                tools_focus = !tools_focus;
                            }
                        }
                        KeyCode::Char('1') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_tools = !show_tools;
                        }
                        KeyCode::Char('2') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_approvals = !show_approvals;
                        }
                        KeyCode::Char('3') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_logs = !show_logs;
                        }
                        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if show_tools && (!show_approvals || tools_focus) {
                                if tools_selected + 1 < visible_tool_count {
                                    tools_selected += 1;
                                }
                            } else if approvals_selected + 1 < ui_state.pending_approvals.len() {
                                approvals_selected += 1;
                            }
                        }
                        KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if show_tools && (!show_approvals || tools_focus) {
                                tools_selected = tools_selected.saturating_sub(1);
                            } else {
                                approvals_selected = approvals_selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Err(e) = ui_state.refresh_approvals(&paths.approvals_path) {
                                logs.push(format!("approvals refresh failed: {e}"));
                            }
                        }
                        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(row) = ui_state.pending_approvals.get(approvals_selected) {
                                let store = ApprovalsStore::new(paths.approvals_path.clone());
                                if let Err(e) = store.approve(&row.id, None, None) {
                                    logs.push(format!("approve failed: {e}"));
                                } else {
                                    logs.push(format!("approved {}", row.id));
                                }
                                let _ = ui_state.refresh_approvals(&paths.approvals_path);
                            }
                        }
                        KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(row) = ui_state.pending_approvals.get(approvals_selected) {
                                let store = ApprovalsStore::new(paths.approvals_path.clone());
                                if let Err(e) = store.deny(&row.id) {
                                    logs.push(format!("deny failed: {e}"));
                                } else {
                                    logs.push(format!("denied {}", row.id));
                                }
                                let _ = ui_state.refresh_approvals(&paths.approvals_path);
                            }
                        }
                        KeyCode::Enter => {
                            let line = input.trim().to_string();
                            input.clear();
                            history_idx = None;
                            slash_menu_index = 0;
                            if line.is_empty() {
                                continue;
                            }
                            if pending_params_input && !line.starts_with('/') {
                                if line.eq_ignore_ascii_case("cancel") {
                                    pending_params_input = false;
                                    logs.push("params update cancelled".to_string());
                                } else {
                                    match runtime_config::apply_params_input(&mut active_run, &line) {
                                        Ok(msg) => {
                                            pending_params_input = false;
                                            logs.push(msg);
                                        }
                                        Err(msg) => logs.push(msg),
                                    }
                                }
                                show_logs = true;
                                continue;
                            }
                            if pending_timeout_input && !line.starts_with('/') {
                                if line.eq_ignore_ascii_case("cancel") {
                                    pending_timeout_input = false;
                                    logs.push("timeout update cancelled".to_string());
                                    show_logs = false;
                                } else {
                                    match runtime_config::apply_timeout_input(&mut active_run, &line) {
                                        Ok(msg) => {
                                            pending_timeout_input = false;
                                            logs.push(msg);
                                            show_logs = false;
                                        }
                                        Err(msg) => {
                                            logs.push(msg);
                                            show_logs = true;
                                        }
                                    }
                                }
                                continue;
                            }
                            if line.starts_with('/') {
                                let resolved = chat_commands::selected_slash_command(&line, slash_menu_index)
                                    .or_else(|| chat_commands::resolve_slash_command(&line))
                                    .unwrap_or(line.as_str());
                                match resolved {
                                    "/exit" => break,
                                    "/help" => {
                                        logs.push(
                                            "commands: /help /mode <safe|coding|web|custom> /timeout [seconds|+N|-N|off] /params [key value] /tool docs <name> /dismiss /clear /exit /hide tools|approvals|logs /show tools|approvals|logs|all ; slash dropdown: type / then Up/Down + Enter ; panes: Ctrl+T/Ctrl+Y/Ctrl+G (Ctrl+1/2/3 aliases, terminal-dependent) ; scroll: PgUp/PgDn, Ctrl+U/Ctrl+D, mouse wheel ; approvals: Ctrl+J/K select, Ctrl+A approve, Ctrl+X deny, Ctrl+R refresh ; history: Up/Down ; Esc quits"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/mode" => {
                                        logs.push(format!(
                                            "current mode: {} (use /mode <safe|coding|web|custom>)",
                                            chat_runtime::chat_mode_label(&active_run)
                                        ));
                                        show_logs = true;
                                    }
                                    "/timeout" => {
                                        pending_timeout_input = true;
                                        logs.push(runtime_config::timeout_settings_summary(&active_run));
                                        logs.push(
                                            "enter seconds, +N, -N, or 'cancel' on the next line"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/params" => {
                                        pending_params_input = true;
                                        logs.push(runtime_config::params_settings_summary(&active_run));
                                        logs.push(
                                            "editable keys: max_steps, max_context_chars, compaction_mode(off|summary), compaction_keep_last, tool_result_persist(all|digest|none), max_tool_output_bytes, max_read_bytes, stream(on|off), allow_shell(on|off), allow_write(on|off), enable_write_tools(on|off), allow_shell_in_workdir(on|off)"
                                                .to_string(),
                                        );
                                        logs.push(
                                            "enter '<key> <value>' or 'cancel' on the next line"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/dismiss" => {
                                        if timeout_notice_active {
                                            timeout_notice_active = false;
                                            logs.retain(|l| !l.starts_with("[timeout-notice]"));
                                            logs.push("timeout notification dismissed".to_string());
                                        } else {
                                            logs.push("no active timeout notification".to_string());
                                        }
                                        show_logs = true;
                                    }
                                    "/tool docs" => {
                                        logs.push(
                                            "usage: /tool docs <name> (example: /tool docs mcp.stub.echo)"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/clear" => {
                                        if active_run.no_session {
                                            transcript.clear();
                                            ui_state.tool_calls.clear();
                                            streaming_assistant.clear();
                                            transcript_scroll = 0;
                                            follow_output = true;
                                            logs.push("cleared chat transcript".to_string());
                                        } else {
                                            let session_path =
                                                paths.sessions_dir.join(format!("{}.json", active_run.session));
                                            let store = SessionStore::new(session_path, active_run.session.clone());
                                            store.reset()?;
                                            transcript.clear();
                                            ui_state.tool_calls.clear();
                                            streaming_assistant.clear();
                                            transcript_scroll = 0;
                                            follow_output = true;
                                            logs.push(format!(
                                                "session '{}' and transcript cleared",
                                                active_run.session
                                            ));
                                        }
                                    }
                                    "/hide tools" => show_tools = false,
                                    "/hide approvals" => show_approvals = false,
                                    "/hide logs" => show_logs = false,
                                    "/show tools" => show_tools = true,
                                    "/show approvals" => show_approvals = true,
                                    "/show logs" => show_logs = true,
                                    "/show all" => {
                                        show_tools = true;
                                        show_approvals = true;
                                        show_logs = true;
                                    }
                                    _ if resolved.starts_with("/mode ") => {
                                        let mode = resolved["/mode ".len()..].trim();
                                        if runtime_config::apply_chat_mode(&mut active_run, mode).is_some() {
                                            logs.push(format!(
                                                "mode switched to {}",
                                                chat_runtime::chat_mode_label(&active_run)
                                            ));
                                        } else {
                                            logs.push(format!(
                                                "unknown mode: {mode}. expected safe|coding|web|custom"
                                            ));
                                        }
                                        show_logs = true;
                                    }
                                    _ if resolved.starts_with("/timeout ") => {
                                        let value = resolved["/timeout ".len()..].trim();
                                        match runtime_config::apply_timeout_input(&mut active_run, value) {
                                            Ok(msg) => {
                                                logs.push(msg);
                                                show_logs = false;
                                            }
                                            Err(msg) => {
                                                logs.push(msg);
                                                show_logs = true;
                                            }
                                        }
                                    }
                                    _ if resolved.starts_with("/params ") => {
                                        let value = resolved["/params ".len()..].trim();
                                        match runtime_config::apply_params_input(&mut active_run, value) {
                                            Ok(msg) => logs.push(msg),
                                            Err(msg) => logs.push(msg),
                                        }
                                        show_logs = true;
                                    }
                                    _ if line.starts_with("/tool docs ") => {
                                        let tool_name = line["/tool docs ".len()..].trim();
                                        if tool_name.is_empty() {
                                            logs.push(
                                                "usage: /tool docs <name> (example: /tool docs mcp.stub.echo)"
                                                    .to_string(),
                                            );
                                            show_logs = true;
                                            continue;
                                        }
                                        if active_run.mcp.is_empty() {
                                            logs.push(
                                                "MCP registry unavailable: no MCP servers enabled for this chat session"
                                                    .to_string(),
                                            );
                                            show_logs = true;
                                            continue;
                                        }
                                        if shared_chat_mcp_registry.is_none() {
                                            let mcp_config_path = runtime_paths::resolved_mcp_config_path(
                                                &active_run,
                                                &paths.state_dir,
                                            );
                                            match McpRegistry::from_config_path(
                                                &mcp_config_path,
                                                &active_run.mcp,
                                                Duration::from_secs(30),
                                            )
                                            .await
                                            {
                                                Ok(reg) => {
                                                    shared_chat_mcp_registry =
                                                        Some(std::sync::Arc::new(reg));
                                                }
                                                Err(e) => {
                                                    logs.push(format!(
                                                        "failed to initialize MCP session: {e}"
                                                    ));
                                                    show_logs = true;
                                                    continue;
                                                }
                                            }
                                        }
                                        if let Some(reg) = shared_chat_mcp_registry.as_ref() {
                                            logs.push(reg.render_tool_docs_text(tool_name));
                                        } else {
                                            logs.push(
                                                "MCP registry unavailable: failed to initialize"
                                                    .to_string(),
                                            );
                                        }
                                        show_logs = true;
                                    }
                                    _ => logs.push(format!("unknown command: {}", line)),
                                }
                                continue;
                            }

                            if line.is_empty() && show_tools && (!show_approvals || tools_focus) {
                                if visible_tool_count > 0 {
                                    show_tool_details = !show_tool_details;
                                    if show_tool_details {
                                        show_logs = false;
                                    }
                                }
                                continue;
                            }

                            prompt_history.push(line.clone());
                            // Sending a new prompt should always re-anchor the transcript to latest.
                            follow_output = true;
                            transcript_scroll = usize::MAX;
                            transcript.push(("user".to_string(), line.clone()));
                            if line.starts_with('?') {
                                show_logs = true;
                                continue;
                            }
                            status = "running".to_string();
                            status_detail.clear();
                            streaming_assistant.clear();
                            think_tick = 0;
                            terminal.draw(|f| {
                                chat_ui::draw_chat_frame(
                                    f,
                                    chat_runtime::chat_mode_label(&active_run),
                                    provider_runtime::provider_cli_name(provider_kind),
                                    provider_connected,
                                    &model,
                                    &status,
                                    &status_detail,
                                    &transcript,
                                    &streaming_assistant,
                                    &ui_state,
                                    tools_selected,
                                    tools_focus,
                                    show_tool_details,
                                    approvals_selected,
                                    &cwd_label,
                                    &input,
                                    &logs,
                                    think_tick,
                                    base_run.tui_refresh_ms,
                                    show_tools,
                                    show_approvals,
                                    show_logs,
                                    transcript_scroll,
                                    compact_tools,
                                    show_banner,
                                    ui_tick,
                                    if palette_open {
                                        Some(format!(
                                            "⌘ {}  (Up/Down, Enter, Esc)",
                                            palette_items[palette_selected]
                                        ))
                                    } else if search_mode {
                                        Some(format!(
                                            "🔎 {}  (Enter next, Esc close)",
                                            search_query
                                        ))
                                    } else if input.starts_with('/') {
                                        chat_commands::slash_overlay_text(&input, slash_menu_index)
                                    } else if input.starts_with('?') {
                                        chat_commands::keybinds_overlay_text()
                                    } else {
                                        None
                                    },
                                );
                            })?;
                            ui_tick = ui_tick.saturating_add(1);

                            let (tx, rx) = std::sync::mpsc::channel::<Event>();
                            let mut turn_args = active_run.clone();
                            turn_args.prompt = Some(line.clone());
                            turn_args.tui = false;
                            turn_args.stream = true;

                            if !turn_args.mcp.is_empty() && shared_chat_mcp_registry.is_none() {
                                let mcp_config_path =
                                    runtime_paths::resolved_mcp_config_path(&turn_args, &paths.state_dir);
                                match McpRegistry::from_config_path(
                                    &mcp_config_path,
                                    &turn_args.mcp,
                                    Duration::from_secs(30),
                                )
                                .await
                                {
                                    Ok(reg) => {
                                        shared_chat_mcp_registry = Some(std::sync::Arc::new(reg));
                                    }
                                    Err(e) => {
                                        let msg = format!("failed to initialize MCP session: {e}");
                                        logs.push(msg.clone());
                                        show_logs = true;
                                        transcript.push(("system".to_string(), msg));
                                        status = "idle".to_string();
                                        status_detail = "mcp init failed".to_string();
                                        if follow_output {
                                            transcript_scroll = usize::MAX;
                                        }
                                        continue;
                                    }
                                }
                            }

                            let mut fut: std::pin::Pin<
                                Box<
                                    dyn std::future::Future<
                                            Output = anyhow::Result<RunExecutionResult>,
                                        > + Send,
                                >,
                            > = match provider_kind {
                                ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
                                    let provider = OpenAiCompatProvider::new(
                                        base_url.clone(),
                                        turn_args.api_key.clone(),
                                        provider_runtime::http_config_from_run_args(&turn_args),
                                    )?;
                                    Box::pin(run_agent_with_ui(
                                        provider,
                                        provider_kind,
                                        &base_url,
                                        &model,
                                        &line,
                                        &turn_args,
                                        paths,
                                        Some(tx),
                                        shared_chat_mcp_registry.clone(),
                                        true,
                                    ))
                                }
                                ProviderKind::Ollama => {
                                    let provider = OllamaProvider::new(
                                        base_url.clone(),
                                        provider_runtime::http_config_from_run_args(&turn_args),
                                    )?;
                                    Box::pin(run_agent_with_ui(
                                        provider,
                                        provider_kind,
                                        &base_url,
                                        &model,
                                        &line,
                                        &turn_args,
                                        paths,
                                        Some(tx),
                                        shared_chat_mcp_registry.clone(),
                                        true,
                                    ))
                                }
                                ProviderKind::Mock => {
                                    let provider = MockProvider::new();
                                    Box::pin(run_agent_with_ui(
                                        provider,
                                        provider_kind,
                                        &base_url,
                                        &model,
                                        &line,
                                        &turn_args,
                                        paths,
                                        Some(tx),
                                        shared_chat_mcp_registry.clone(),
                                        true,
                                    ))
                                }
                            };

                            loop {
                                ui_state.on_tick(Instant::now());
                                while let Ok(ev) = rx.try_recv() {
                                    ui_state.apply_event(&ev);
                                    match ev.kind {
                                        EventKind::ModelDelta => {
                                            if let Some(d) = ev.data.get("delta").and_then(|v| v.as_str()) {
                                                streaming_assistant.push_str(d);
                                                if follow_output {
                                                    transcript_scroll = usize::MAX;
                                                }
                                            }
                                        }
                                        EventKind::ModelResponseEnd => {
                                            if streaming_assistant.is_empty() {
                                                if let Some(c) = ev.data.get("content").and_then(|v| v.as_str()) {
                                                    streaming_assistant.push_str(c);
                                                    if follow_output {
                                                        transcript_scroll = usize::MAX;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                while event::poll(Duration::from_millis(0))? {
                                    match event::read()? {
                                        CEvent::Mouse(me) => {
                                            if let Some(delta) = chat_runtime::mouse_scroll_delta(&me) {
                                                let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                    &transcript,
                                                    &streaming_assistant,
                                                );
                                                transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                    transcript_scroll,
                                                    delta,
                                                    max_scroll,
                                                );
                                                follow_output = false;
                                            }
                                        }
                                        CEvent::Paste(pasted) => {
                                            input.push_str(&chat_runtime::normalize_pasted_text(&pasted));
                                            history_idx = None;
                                            slash_menu_index = 0;
                                        }
                                        CEvent::Key(key)
                                            if matches!(
                                                key.kind,
                                                KeyEventKind::Press | KeyEventKind::Repeat
                                            ) =>
                                        {
                                            match key.code {
                                                KeyCode::Esc => {
                                                    let partial = agent::sanitize_user_visible_output(
                                                        &streaming_assistant,
                                                    );
                                                    if !partial.trim().is_empty() {
                                                        transcript.push((
                                                            "assistant".to_string(),
                                                            format!("{partial}\n\n[cancelled]"),
                                                        ));
                                                    }
                                                    logs.push(
                                                        "run cancelled by user (Esc/Ctrl+C)"
                                                            .to_string(),
                                                    );
                                                    show_logs = true;
                                                    streaming_assistant.clear();
                                                    status = "idle".to_string();
                                                    status_detail = "cancelled by user".to_string();
                                                    if follow_output {
                                                        transcript_scroll = usize::MAX;
                                                    }
                                                    break;
                                                }
                                                KeyCode::Char('c')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    let partial = agent::sanitize_user_visible_output(
                                                        &streaming_assistant,
                                                    );
                                                    if !partial.trim().is_empty() {
                                                        transcript.push((
                                                            "assistant".to_string(),
                                                            format!("{partial}\n\n[cancelled]"),
                                                        ));
                                                    }
                                                    logs.push(
                                                        "run cancelled by user (Esc/Ctrl+C)"
                                                            .to_string(),
                                                    );
                                                    show_logs = true;
                                                    streaming_assistant.clear();
                                                    status = "idle".to_string();
                                                    status_detail = "cancelled by user".to_string();
                                                    if follow_output {
                                                        transcript_scroll = usize::MAX;
                                                    }
                                                    break;
                                                }
                                                KeyCode::PageUp => {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        -12,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::PageDown => {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        12,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::Char('u')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        -10,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::Char('d')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        10,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::Char('t')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_tools = !show_tools;
                                                }
                                                KeyCode::Char('y')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_approvals = !show_approvals;
                                                }
                                                KeyCode::Char('g')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_logs = !show_logs;
                                                }
                                                KeyCode::Tab => {
                                                    if show_tools && show_approvals {
                                                        tools_focus = !tools_focus;
                                                    }
                                                }
                                                KeyCode::Char('1')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_tools = !show_tools;
                                                }
                                                KeyCode::Char('2')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_approvals = !show_approvals;
                                                }
                                                KeyCode::Char('3')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_logs = !show_logs;
                                                }
                                                KeyCode::Char('j')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if show_tools && (!show_approvals || tools_focus) {
                                                        if tools_selected + 1 < visible_tool_count {
                                                            tools_selected += 1;
                                                        }
                                                    } else if approvals_selected + 1
                                                        < ui_state.pending_approvals.len()
                                                    {
                                                        approvals_selected += 1;
                                                    }
                                                }
                                                KeyCode::Char('k')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if show_tools && (!show_approvals || tools_focus) {
                                                        tools_selected = tools_selected.saturating_sub(1);
                                                    } else {
                                                        approvals_selected =
                                                            approvals_selected.saturating_sub(1);
                                                    }
                                                }
                                                KeyCode::Char('r')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if let Err(e) =
                                                        ui_state.refresh_approvals(&paths.approvals_path)
                                                    {
                                                        logs.push(format!(
                                                            "approvals refresh failed: {e}"
                                                        ));
                                                    }
                                                }
                                                KeyCode::Char('a')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if let Some(row) =
                                                        ui_state.pending_approvals.get(approvals_selected)
                                                    {
                                                        let store = ApprovalsStore::new(
                                                            paths.approvals_path.clone(),
                                                        );
                                                        if let Err(e) = store.approve(&row.id, None, None)
                                                        {
                                                            logs.push(format!("approve failed: {e}"));
                                                        } else {
                                                            logs.push(format!("approved {}", row.id));
                                                        }
                                                        let _ =
                                                            ui_state.refresh_approvals(&paths.approvals_path);
                                                    }
                                                }
                                                KeyCode::Char('x')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if let Some(row) =
                                                        ui_state.pending_approvals.get(approvals_selected)
                                                    {
                                                        let store = ApprovalsStore::new(
                                                            paths.approvals_path.clone(),
                                                        );
                                                        if let Err(e) = store.deny(&row.id) {
                                                            logs.push(format!("deny failed: {e}"));
                                                        } else {
                                                            logs.push(format!("denied {}", row.id));
                                                        }
                                                        let _ =
                                                            ui_state.refresh_approvals(&paths.approvals_path);
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                if status == "idle" {
                                    break;
                                }

                                terminal.draw(|f| {
                                    chat_ui::draw_chat_frame(
                                        f,
                                        chat_runtime::chat_mode_label(&active_run),
                                        provider_runtime::provider_cli_name(provider_kind),
                                        provider_connected,
                                        &model,
                                        &status,
                                        &status_detail,
                                        &transcript,
                                        &streaming_assistant,
                                        &ui_state,
                                        tools_selected,
                                        tools_focus,
                                        show_tool_details,
                                        approvals_selected,
                                        &cwd_label,
                                        &input,
                                        &logs,
                                        think_tick,
                                        base_run.tui_refresh_ms,
                                        show_tools,
                                        show_approvals,
                                        show_logs,
                                        transcript_scroll,
                                        compact_tools,
                                        show_banner,
                                        ui_tick,
                                        if palette_open {
                                            Some(format!(
                                                "⌘ {}  (Up/Down, Enter, Esc)",
                                                palette_items[palette_selected]
                                            ))
                                        } else if search_mode {
                                            Some(format!(
                                                "🔎 {}  (Enter next, Esc close)",
                                                search_query
                                            ))
                                        } else if input.starts_with('/') {
                                            chat_commands::slash_overlay_text(&input, slash_menu_index)
                                        } else if input.starts_with('?') {
                                            chat_commands::keybinds_overlay_text()
                                        } else {
                                            None
                                        },
                                    );
                                })?;

                                let maybe_res = tokio::select! {
                                    r = &mut fut => Some(r),
                                    _ = tokio::time::sleep(Duration::from_millis(base_run.tui_refresh_ms)) => None,
                                };
                                if let Some(res) = maybe_res {
                                    match res {
                                        Ok(out) => {
                                            let outcome = out.outcome;
                                            let exit_reason = outcome.exit_reason;
                                            let outcome_error =
                                                outcome.error.unwrap_or_else(String::new);
                                            let final_text = if outcome.final_output.is_empty() {
                                                agent::sanitize_user_visible_output(
                                                    &streaming_assistant,
                                                )
                                            } else {
                                                outcome.final_output
                                            };
                                            if matches!(exit_reason, AgentExitReason::ProviderError) {
                                                let err = if outcome_error.trim().is_empty() {
                                                    "provider error".to_string()
                                                } else {
                                                    outcome_error.clone()
                                                };
                                                provider_connected = false;
                                                logs.push(err.clone());
                                                if runtime_config::is_timeout_error_text(&err) && !timeout_notice_active {
                                                    timeout_notice_active = true;
                                                    logs.push(runtime_config::timeout_notice_text(&active_run));
                                                }
                                                show_logs = true;
                                                status_detail = format!(
                                                    "{}: {}",
                                                    exit_reason.as_str(),
                                                    chat_view_utils::compact_status_detail(&err, 120)
                                                );
                                                transcript.push((
                                                    "system".to_string(),
                                                    format!("Provider error: {err}"),
                                                ));
                                                if let Some(hint) = runtime_config::protocol_remediation_hint(&err) {
                                                    logs.push(hint.clone());
                                                    transcript.push((
                                                        "system".to_string(),
                                                        hint,
                                                    ));
                                                    show_logs = true;
                                                }
                                            } else {
                                                provider_connected = true;
                                                if matches!(exit_reason, AgentExitReason::Ok) {
                                                    status_detail.clear();
                                                } else {
                                                    let reason_text = if !outcome_error.trim().is_empty() {
                                                        outcome_error.clone()
                                                    } else if !final_text.trim().is_empty() {
                                                        final_text.clone()
                                                    } else {
                                                        exit_reason.as_str().to_string()
                                                    };
                                                    let reason_short =
                                                        chat_view_utils::compact_status_detail(&reason_text, 120);
                                                    status_detail = format!(
                                                        "{}: {}",
                                                        exit_reason.as_str(),
                                                        reason_short
                                                    );
                                                    transcript.push((
                                                        "system".to_string(),
                                                        format!(
                                                            "Run ended with {}: {}",
                                                            exit_reason.as_str(),
                                                            chat_view_utils::compact_status_detail(&reason_text, 220)
                                                        ),
                                                    ));
                                                    if let Some(hint) =
                                                        runtime_config::protocol_remediation_hint(&reason_text)
                                                    {
                                                        logs.push(hint.clone());
                                                        transcript.push((
                                                            "system".to_string(),
                                                            hint,
                                                        ));
                                                        show_logs = true;
                                                    }
                                                }
                                            }
                                            if !final_text.trim().is_empty() {
                                                transcript.push(("assistant".to_string(), final_text));
                                            }
                                            if follow_output {
                                                transcript_scroll = usize::MAX;
                                            }
                                        }
                                        Err(e) => {
                                            let msg = format!("run failed: {e}");
                                            if runtime_config::is_timeout_error_text(&msg) {
                                                provider_connected = false;
                                            }
                                            logs.push(msg.clone());
                                            show_logs = true;
                                            transcript.push(("system".to_string(), msg));
                                            status_detail = format!(
                                                "run failed: {}",
                                                chat_view_utils::compact_status_detail(&e.to_string(), 120)
                                            );
                                            if let Some(hint) = runtime_config::protocol_remediation_hint(
                                                &format!("{e}"),
                                            ) {
                                                logs.push(hint.clone());
                                                transcript.push(("system".to_string(), hint));
                                                show_logs = true;
                                            }
                                            if follow_output {
                                                transcript_scroll = usize::MAX;
                                            }
                                        }
                                    }
                                    streaming_assistant.clear();
                                    status = "idle".to_string();
                                    break;
                                }
                                think_tick = think_tick.saturating_add(1);
                                ui_tick = ui_tick.saturating_add(1);
                            }
                        }
                        KeyCode::Backspace => {
                            input.pop();
                            slash_menu_index = 0;
                        }
                        KeyCode::Char(c) => {
                            if chat_runtime::is_text_input_mods(key.modifiers) {
                                input.push(c);
                                if c == '/' && input.len() == 1 {
                                    slash_menu_index = 0;
                                }
                            }
                        }
                        _ => {}
                    }
                    if logs.len() > max_logs {
                        let drop_n = logs.len() - max_logs;
                        logs.drain(0..drop_n);
                    }
                    ui_tick = ui_tick.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
    .await;

    disable_raw_mode()?;
    if chat.plain_tui {
        execute!(
            terminal.backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture
        )?;
    } else {
        execute!(
            terminal.backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen
        )?;
    }
    terminal.show_cursor()?;
    run_result
}
