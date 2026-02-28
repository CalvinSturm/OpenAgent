use std::collections::BTreeMap;
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
use crate::project_guidance;
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

enum SlashCommandDispatchOutcome {
    Handled,
    ExitRequested,
}

enum TuiNormalSubmitPrepOutcome {
    ContinueToRun,
    HandledNoRun,
}

enum TuiOuterKeyPreludeOutcome {
    BreakLoop,
    ContinueLoop,
    Proceed,
}

enum TuiOuterKeyDispatchOutcome {
    BreakLoop,
    ContinueLoop,
    Handled,
    EnterInline,
}

enum TuiOuterEventDispatchOutcome {
    BreakLoop,
    ContinueLoop,
    EnterInline,
    HandledKey,
    Noop,
}

enum TuiEnterSubmitOutcome {
    Handled,
    ContinueLoop,
    ExitRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LearnOverlayInputFocus {
    CaptureSummary,
    ReviewId,
    PromoteId,
    PromoteSlug,
    PromotePackId,
}

#[derive(Debug, Clone)]
struct LearnOverlayState {
    tab: crate::chat_ui::LearnOverlayTab,
    category_idx: usize,
    summary: String,
    review_id: String,
    promote_id: String,
    promote_target_idx: usize,
    promote_slug: String,
    promote_pack_id: String,
    promote_force: bool,
    input_focus: LearnOverlayInputFocus,
    inline_message: Option<String>,
    review_rows: Vec<String>,
    review_selected_idx: usize,
    assist_on: bool,
    write_armed: bool,
    logs: Vec<String>,
    pending_submit_line: Option<String>,
    assist_summary: Option<String>,
    summary_choice: crate::chat_ui::LearnOverlaySummaryChoice,
    selected_summary: Option<String>,
}

impl Default for LearnOverlayState {
    fn default() -> Self {
        Self {
            tab: crate::chat_ui::LearnOverlayTab::Capture,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec!["info: Preflight check complete. Waiting for user action.".to_string()],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        }
    }
}

fn cycle_overlay_focus(overlay: &mut LearnOverlayState, reverse: bool) {
    use LearnOverlayInputFocus as F;
    overlay.input_focus = match overlay.tab {
        crate::chat_ui::LearnOverlayTab::Capture => F::CaptureSummary,
        crate::chat_ui::LearnOverlayTab::Review => F::ReviewId,
        crate::chat_ui::LearnOverlayTab::Promote => {
            let order = [F::PromoteId, F::PromoteSlug, F::PromotePackId];
            let idx = order
                .iter()
                .position(|v| *v == overlay.input_focus)
                .unwrap_or(0);
            let next = if reverse {
                if idx == 0 {
                    order.len() - 1
                } else {
                    idx - 1
                }
            } else {
                (idx + 1) % order.len()
            };
            order[next]
        }
    };
}

fn push_overlay_log_dedup(overlay: &mut LearnOverlayState, msg: &str) {
    if overlay.logs.last().map(|s| s.as_str()) != Some(msg) {
        overlay.logs.push(msg.to_string());
    }
}

fn push_overlay_log_unique(overlay: &mut LearnOverlayState, msg: &str) {
    if !overlay.logs.iter().any(|s| s == msg) {
        overlay.logs.push(msg.to_string());
    }
}

fn set_overlay_next_steps_capture(overlay: &mut LearnOverlayState) {
    let step_2 = if overlay.write_armed && overlay.assist_on {
        "Press Enter to run write with Assist ON (calls LLM, uses tokens). Ctrl+A disables Assist."
    } else if overlay.write_armed {
        "Press Enter to run write locally (no LLM assist call)."
    } else {
        "Press Enter for preview only (no write, no token use). Ctrl+W arms write."
    };
    let assist = if overlay.assist_on { "ON" } else { "OFF" };
    overlay.inline_message = Some(format!("Assist {assist}. {step_2} Esc closes."));
}

fn set_overlay_next_steps_promote(overlay: &mut LearnOverlayState) {
    let step_2 = if overlay.write_armed {
        "Step 2: Press Enter to run promote."
    } else {
        "Step 2: Press Ctrl+W to arm write."
    };
    overlay.inline_message = Some(format!(
        "Step 1: Confirm target + required fields. {step_2} Step 3: Press Esc to close."
    ));
}

fn assist_summary_stub(summary: &str) -> String {
    if summary.trim().is_empty() {
        String::new()
    } else {
        format!(
            "Refined summary: {}",
            summary.trim().replace('"', "'").replace("\\", "")
        )
    }
}

fn overlay_effective_summary(overlay: &LearnOverlayState) -> String {
    match overlay.summary_choice {
        crate::chat_ui::LearnOverlaySummaryChoice::Assist => overlay
            .assist_summary
            .as_ref()
            .cloned()
            .unwrap_or_else(|| overlay.summary.clone()),
        _ => overlay.summary.clone(),
    }
}

type TuiRunFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<RunExecutionResult>> + Send>>;

struct TuiSubmitLaunch {
    rx: std::sync::mpsc::Receiver<Event>,
    queue_tx: std::sync::mpsc::Sender<crate::operator_queue::QueueSubmitRequest>,
    fut: TuiRunFuture,
}

struct TuiEnterSubmitInput<'a> {
    terminal: &'a mut Terminal<CrosstermBackend<std::io::Stdout>>,
    input: &'a mut String,
    history_idx: &'a mut Option<usize>,
    slash_menu_index: &'a mut usize,
    pending_timeout_input: &'a mut bool,
    pending_params_input: &'a mut bool,
    timeout_notice_active: &'a mut bool,
    active_run: &'a mut RunArgs,
    base_run: &'a RunArgs,
    paths: &'a store::StatePaths,
    provider_kind: ProviderKind,
    provider_connected: &'a mut bool,
    base_url: &'a str,
    model: &'a str,
    cwd_label: &'a str,
    logs: &'a mut Vec<String>,
    max_logs: usize,
    show_logs: &'a mut bool,
    show_tools: &'a mut bool,
    show_approvals: &'a mut bool,
    show_tool_details: &'a mut bool,
    tools_focus: &'a mut bool,
    visible_tool_count: usize,
    prompt_history: &'a mut Vec<String>,
    transcript: &'a mut Vec<(String, String)>,
    streaming_assistant: &'a mut String,
    status: &'a mut String,
    status_detail: &'a mut String,
    think_tick: &'a mut u64,
    ui_tick: &'a mut u64,
    follow_output: &'a mut bool,
    transcript_scroll: &'a mut usize,
    ui_state: &'a mut UiState,
    tools_selected: &'a mut usize,
    approvals_selected: &'a mut usize,
    compact_tools: bool,
    show_banner: bool,
    palette_open: bool,
    palette_items: &'a [&'a str],
    palette_selected: usize,
    search_mode: bool,
    search_query: &'a str,
    shared_chat_mcp_registry: &'a mut Option<std::sync::Arc<McpRegistry>>,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    input_cursor: &'a mut usize,
    search_input_cursor: &'a mut usize,
    learn_overlay_cursor: &'a mut usize,
}

#[derive(Clone)]
struct ActiveQueueRow {
    sequence_no: u64,
    kind: String,
    status: String,
    delivery_phrase: String,
}

struct TuiActiveTurnLoopInput<'a> {
    terminal: &'a mut Terminal<CrosstermBackend<std::io::Stdout>>,
    fut: TuiRunFuture,
    rx: std::sync::mpsc::Receiver<Event>,
    queue_tx: std::sync::mpsc::Sender<crate::operator_queue::QueueSubmitRequest>,
    ui_state: &'a mut UiState,
    paths: &'a store::StatePaths,
    active_run: &'a RunArgs,
    base_run: &'a RunArgs,
    provider_kind: ProviderKind,
    provider_connected: &'a mut bool,
    model: &'a str,
    cwd_label: &'a str,
    input: &'a mut String,
    logs: &'a mut Vec<String>,
    transcript: &'a mut Vec<(String, String)>,
    streaming_assistant: &'a mut String,
    status: &'a mut String,
    status_detail: &'a mut String,
    think_tick: &'a mut u64,
    ui_tick: &'a mut u64,
    approvals_selected: &'a mut usize,
    show_tools: &'a mut bool,
    show_approvals: &'a mut bool,
    show_logs: &'a mut bool,
    timeout_notice_active: &'a mut bool,
    transcript_scroll: &'a mut usize,
    follow_output: &'a mut bool,
    compact_tools: bool,
    tools_selected: &'a mut usize,
    tools_focus: &'a mut bool,
    show_tool_details: &'a mut bool,
    show_banner: bool,
    palette_open: bool,
    palette_items: &'a [&'a str],
    palette_selected: usize,
    search_mode: bool,
    search_query: &'a str,
    slash_menu_index: &'a mut usize,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    input_cursor: &'a mut usize,
    learn_overlay_cursor: &'a mut usize,
}

async fn drive_tui_active_turn_loop(input: TuiActiveTurnLoopInput<'_>) -> anyhow::Result<()> {
    let TuiActiveTurnLoopInput {
        terminal,
        mut fut,
        rx,
        queue_tx,
        ui_state,
        paths,
        active_run,
        base_run,
        provider_kind,
        provider_connected,
        model,
        cwd_label,
        input: input_buf,
        logs,
        transcript,
        streaming_assistant,
        status,
        status_detail,
        think_tick,
        ui_tick,
        approvals_selected,
        show_tools,
        show_approvals,
        show_logs,
        timeout_notice_active,
        transcript_scroll,
        follow_output,
        compact_tools,
        tools_selected,
        tools_focus,
        show_tool_details,
        show_banner,
        palette_open,
        palette_items,
        palette_selected,
        search_mode,
        search_query,
        slash_menu_index,
        learn_overlay,
        input_cursor,
        learn_overlay_cursor,
    } = input;

    let tool_row_count = if compact_tools { 20 } else { 12 };
    let mut active_queue_rows: BTreeMap<String, ActiveQueueRow> = BTreeMap::new();

    loop {
        ui_state.on_tick(Instant::now());
        while let Ok(ev) = rx.try_recv() {
            ui_state.apply_event(&ev);
            match ev.kind {
                EventKind::QueueSubmitted => {
                    if let Some(queue_id) = ev.data.get("queue_id").and_then(|v| v.as_str()) {
                        let sequence_no = ev
                            .data
                            .get("sequence_no")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let kind = ev
                            .data
                            .get("kind")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let delivery_phrase = ev
                            .data
                            .get("next_delivery")
                            .and_then(|v| v.as_str())
                            .unwrap_or("pending")
                            .to_string();
                        active_queue_rows.insert(
                            queue_id.to_string(),
                            ActiveQueueRow {
                                sequence_no,
                                kind,
                                status: "pending".to_string(),
                                delivery_phrase,
                            },
                        );
                    }
                }
                EventKind::QueueDelivered => {
                    if let Some(queue_id) = ev.data.get("queue_id").and_then(|v| v.as_str()) {
                        if let Some(row) = active_queue_rows.get_mut(queue_id) {
                            row.status = "delivered".to_string();
                            row.delivery_phrase =
                                match ev.data.get("delivery_boundary").and_then(|v| v.as_str()) {
                                    Some("post_tool") => "after current tool finishes".to_string(),
                                    Some("post_step") => "after current step finishes".to_string(),
                                    Some("turn_idle") => "after this turn completes".to_string(),
                                    _ => "delivered".to_string(),
                                };
                        }
                    }
                }
                EventKind::QueueInterrupt => {
                    if let Some(queue_id) = ev.data.get("queue_id").and_then(|v| v.as_str()) {
                        if let Some(row) = active_queue_rows.get_mut(queue_id) {
                            row.status = "interrupted".to_string();
                        }
                    }
                }
                _ => {}
            }
            match ev.kind {
                EventKind::ModelDelta => {
                    if let Some(d) = ev.data.get("delta").and_then(|v| v.as_str()) {
                        streaming_assistant.push_str(d);
                        if *follow_output {
                            *transcript_scroll = usize::MAX;
                        }
                    }
                }
                EventKind::ModelResponseEnd => {
                    if streaming_assistant.is_empty() {
                        if let Some(c) = ev.data.get("content").and_then(|v| v.as_str()) {
                            streaming_assistant.push_str(c);
                            if *follow_output {
                                *transcript_scroll = usize::MAX;
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
                            transcript,
                            streaming_assistant,
                        );
                        *transcript_scroll = chat_runtime::adjust_transcript_scroll(
                            *transcript_scroll,
                            delta,
                            max_scroll,
                        );
                        *follow_output = false;
                    }
                }
                CEvent::Paste(pasted) => {
                    insert_text_bounded(
                        input_buf,
                        input_cursor,
                        &chat_runtime::normalize_pasted_text(&pasted),
                        usize::MAX,
                    );
                    *slash_menu_index = 0;
                }
                CEvent::Key(key)
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    if learn_overlay.is_some()
                        && !(matches!(key.code, KeyCode::Char('c'))
                            && key.modifiers.contains(KeyModifiers::CONTROL))
                    {
                        let mut prompt_history_dummy = Vec::new();
                        let mut history_idx_dummy = None;
                        let mut palette_open_dummy = false;
                        let palette_items_dummy = ["overlay"];
                        let mut palette_selected_dummy = 0usize;
                        let mut search_mode_dummy = false;
                        let mut search_query_dummy = String::new();
                        let mut search_line_cursor_dummy = 0usize;
                        let mut search_input_cursor_dummy = 0usize;
                        let mut compact_tools_dummy = false;
                        let visible_tool_count_dummy = ui_state.tool_calls.len().min(tool_row_count);
                        let _ = handle_tui_outer_key_dispatch(TuiOuterKeyDispatchInput {
                            key,
                            learn_overlay,
                            run_busy: true,
                            input: input_buf,
                            input_cursor,
                            prompt_history: &mut prompt_history_dummy,
                            history_idx: &mut history_idx_dummy,
                            slash_menu_index,
                            palette_open: &mut palette_open_dummy,
                            palette_items: &palette_items_dummy,
                            palette_selected: &mut palette_selected_dummy,
                            search_mode: &mut search_mode_dummy,
                            search_query: &mut search_query_dummy,
                            search_line_cursor: &mut search_line_cursor_dummy,
                            search_input_cursor: &mut search_input_cursor_dummy,
                            transcript,
                            streaming_assistant,
                            transcript_scroll,
                            follow_output,
                            ui_state,
                            visible_tool_count: visible_tool_count_dummy,
                            show_tools,
                            show_approvals,
                            show_logs,
                            compact_tools: &mut compact_tools_dummy,
                            tools_selected,
                            tools_focus,
                            approvals_selected,
                            paths,
                            logs,
                            learn_overlay_cursor,
                        });
                        continue;
                    }
                    match key.code {
                        KeyCode::Esc => {
                            let partial = agent::sanitize_user_visible_output(streaming_assistant);
                            if !partial.trim().is_empty() {
                                transcript.push((
                                    "assistant".to_string(),
                                    format!("{partial}\n\n[cancelled]"),
                                ));
                            }
                            logs.push("run cancelled by user (Esc/Ctrl+C)".to_string());
                            *show_logs = true;
                            streaming_assistant.clear();
                            *status = "idle".to_string();
                            *status_detail = "cancelled by user".to_string();
                            if *follow_output {
                                *transcript_scroll = usize::MAX;
                            }
                            break;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let partial = agent::sanitize_user_visible_output(streaming_assistant);
                            if !partial.trim().is_empty() {
                                transcript.push((
                                    "assistant".to_string(),
                                    format!("{partial}\n\n[cancelled]"),
                                ));
                            }
                            logs.push("run cancelled by user (Esc/Ctrl+C)".to_string());
                            *show_logs = true;
                            streaming_assistant.clear();
                            *status = "idle".to_string();
                            *status_detail = "cancelled by user".to_string();
                            if *follow_output {
                                *transcript_scroll = usize::MAX;
                            }
                            break;
                        }
                        KeyCode::PageUp => {
                            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                transcript,
                                streaming_assistant,
                            );
                            *transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                *transcript_scroll,
                                -12,
                                max_scroll,
                            );
                            *follow_output = false;
                        }
                        KeyCode::PageDown => {
                            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                transcript,
                                streaming_assistant,
                            );
                            *transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                *transcript_scroll,
                                12,
                                max_scroll,
                            );
                            *follow_output = false;
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                transcript,
                                streaming_assistant,
                            );
                            *transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                *transcript_scroll,
                                -10,
                                max_scroll,
                            );
                            *follow_output = false;
                        }
                        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                transcript,
                                streaming_assistant,
                            );
                            *transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                *transcript_scroll,
                                10,
                                max_scroll,
                            );
                            *follow_output = false;
                        }
                        KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            *show_tools = !*show_tools;
                        }
                        KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            *show_approvals = !*show_approvals;
                        }
                        KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            *show_logs = !*show_logs;
                        }
                        KeyCode::Tab => {
                            if *show_tools && *show_approvals {
                                *tools_focus = !*tools_focus;
                            }
                        }
                        KeyCode::Char('1') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            *show_tools = !*show_tools;
                        }
                        KeyCode::Char('2') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            *show_approvals = !*show_approvals;
                        }
                        KeyCode::Char('3') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            *show_logs = !*show_logs;
                        }
                        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let visible_tool_count = ui_state.tool_calls.len().min(tool_row_count);
                            if *show_tools && (!*show_approvals || *tools_focus) {
                                if *tools_selected + 1 < visible_tool_count {
                                    *tools_selected += 1;
                                }
                            } else if *approvals_selected + 1 < ui_state.pending_approvals.len() {
                                *approvals_selected += 1;
                            }
                        }
                        KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if *show_tools && (!*show_approvals || *tools_focus) {
                                *tools_selected = tools_selected.saturating_sub(1);
                            } else {
                                *approvals_selected = approvals_selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Err(e) = ui_state.refresh_approvals(&paths.approvals_path) {
                                logs.push(format!("approvals refresh failed: {e}"));
                            }
                        }
                        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(row) = ui_state.pending_approvals.get(*approvals_selected) {
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
                            if let Some(row) = ui_state.pending_approvals.get(*approvals_selected) {
                                let store = ApprovalsStore::new(paths.approvals_path.clone());
                                if let Err(e) = store.deny(&row.id) {
                                    logs.push(format!("deny failed: {e}"));
                                } else {
                                    logs.push(format!("denied {}", row.id));
                                }
                                let _ = ui_state.refresh_approvals(&paths.approvals_path);
                            }
                        }
                        KeyCode::Backspace => {
                            delete_char_before_cursor(input_buf, input_cursor);
                            *slash_menu_index = 0;
                        }
                        KeyCode::Left => {
                            *input_cursor = input_cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            *input_cursor = (*input_cursor + 1).min(char_len(input_buf));
                        }
                        KeyCode::Char(c) if chat_runtime::is_text_input_mods(key.modifiers) => {
                            insert_text_bounded(
                                input_buf,
                                input_cursor,
                                &c.to_string(),
                                usize::MAX,
                            );
                            *slash_menu_index = 0;
                        }
                        KeyCode::Enter => {
                            let line = input_buf.trim().to_string();
                            if let Some(rest) = line.strip_prefix("/interrupt ") {
                                let msg = rest.trim();
                                if msg.is_empty() {
                                    logs.push("usage: /interrupt <message>".to_string());
                                } else {
                                    let req = crate::operator_queue::QueueSubmitRequest {
                                        kind: crate::operator_queue::QueueMessageKind::Steer,
                                        content: msg.to_string(),
                                    };
                                    match queue_tx.send(req) {
                                        Ok(_) => logs.push(
                                            "queued Interrupt: will apply after current tool finishes"
                                                .to_string(),
                                        ),
                                        Err(_) => logs.push(
                                            "queue unavailable: run is ending".to_string(),
                                        ),
                                    }
                                    input_buf.clear();
                                    *input_cursor = 0;
                                    *slash_menu_index = 0;
                                }
                            } else if let Some(rest) = line.strip_prefix("/next ") {
                                let msg = rest.trim();
                                if msg.is_empty() {
                                    logs.push("usage: /next <message>".to_string());
                                } else {
                                    let req = crate::operator_queue::QueueSubmitRequest {
                                        kind: crate::operator_queue::QueueMessageKind::FollowUp,
                                        content: msg.to_string(),
                                    };
                                    match queue_tx.send(req) {
                                        Ok(_) => logs.push(
                                            "queued Next: will apply after this turn completes"
                                                .to_string(),
                                        ),
                                        Err(_) => logs
                                            .push("queue unavailable: run is ending".to_string()),
                                    }
                                    input_buf.clear();
                                    *input_cursor = 0;
                                    *slash_menu_index = 0;
                                }
                            } else if line == "/queue" {
                                let mut rows = active_queue_rows
                                    .iter()
                                    .map(|(id, row)| {
                                        (
                                            row.sequence_no,
                                            id.clone(),
                                            row.kind.clone(),
                                            row.status.clone(),
                                            row.delivery_phrase.clone(),
                                        )
                                    })
                                    .collect::<Vec<_>>();
                                rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                                if rows.is_empty() {
                                    logs.push("queue: empty".to_string());
                                } else {
                                    logs.push(format!("queue: {} item(s)", rows.len()));
                                    for (seq, id, kind, status_row, when) in
                                        rows.into_iter().take(8)
                                    {
                                        let label = match kind.as_str() {
                                            "steer" => "Interrupt",
                                            "follow_up" => "Next",
                                            _ => "Unknown",
                                        };
                                        logs.push(format!(
                                            "  #{seq} {label} [{status_row}] id={id} ({when})"
                                        ));
                                    }
                                }
                                input_buf.clear();
                                *input_cursor = 0;
                                *slash_menu_index = 0;
                            } else if line == "/help" {
                                logs.push(
                                    "active-run commands: /interrupt <message>, /next <message>, /queue ; /learn opens overlay but submit stays blocked while run is active"
                                        .to_string(),
                                );
                                input_buf.clear();
                                *input_cursor = 0;
                                *slash_menu_index = 0;
                            } else if line.starts_with("/learn") {
                                if line == "/learn" {
                                    *learn_overlay = Some(LearnOverlayState::default());
                                    *learn_overlay_cursor = 0;
                                } else {
                                    logs.push("System busy. Operation deferred.".to_string());
                                    logs.push("ERR_TUI_BUSY_TRY_AGAIN".to_string());
                                }
                                input_buf.clear();
                                *input_cursor = 0;
                                *slash_menu_index = 0;
                            } else if !line.is_empty() {
                                logs.push(
                                    "during an active run, supported commands are: /interrupt <message>, /next <message>, /queue, /help"
                                        .to_string(),
                                );
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        if *status == "idle" {
            break;
        }

        let cursor_visible = (*ui_tick / 6) % 2 == 0;
        let learn_overlay_model = learn_overlay.as_ref().map(|s| {
            build_learn_overlay_render_model_with_cursor(s, *learn_overlay_cursor, *ui_tick)
        });
        terminal.draw(|f| {
            chat_ui::draw_chat_frame(
                f,
                chat_runtime::chat_mode_label(active_run),
                provider_runtime::provider_cli_name(provider_kind),
                *provider_connected,
                model,
                status,
                status_detail,
                transcript,
                streaming_assistant,
                ui_state,
                *tools_selected,
                *tools_focus,
                *show_tool_details,
                *approvals_selected,
                cwd_label,
                input_buf,
                *input_cursor,
                cursor_visible,
                logs,
                *think_tick,
                base_run.tui_refresh_ms,
                *show_tools,
                *show_approvals,
                *show_logs,
                *transcript_scroll,
                compact_tools,
                show_banner,
                *ui_tick,
                if learn_overlay_model.is_some() {
                    None
                } else if palette_open {
                    Some(format!(
                        "⌘ {}  (Up/Down, Enter, Esc)",
                        palette_items[palette_selected]
                    ))
                } else if search_mode {
                    Some(format!(
                        "🔎 {}  (Enter next, Esc close)",
                        render_with_optional_caret(search_query, 0, cursor_visible)
                    ))
                } else if input_buf.starts_with('/') {
                    chat_commands::slash_overlay_text(input_buf, *slash_menu_index)
                } else if input_buf.starts_with('?') {
                    chat_commands::keybinds_overlay_text()
                } else {
                    None
                },
                learn_overlay_model.as_ref(),
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
                    let outcome_error = outcome.error.unwrap_or_else(String::new);
                    let final_text = if outcome.final_output.is_empty() {
                        agent::sanitize_user_visible_output(streaming_assistant)
                    } else {
                        outcome.final_output
                    };
                    if matches!(exit_reason, AgentExitReason::ProviderError) {
                        let err = if outcome_error.trim().is_empty() {
                            "provider error".to_string()
                        } else {
                            outcome_error.clone()
                        };
                        *provider_connected = false;
                        logs.push(err.clone());
                        if runtime_config::is_timeout_error_text(&err) && !*timeout_notice_active {
                            *timeout_notice_active = true;
                            logs.push(runtime_config::timeout_notice_text(active_run));
                        }
                        *show_logs = true;
                        *status_detail = format!(
                            "{}: {}",
                            exit_reason.as_str(),
                            chat_view_utils::compact_status_detail(&err, 120)
                        );
                        transcript.push(("system".to_string(), format!("Provider error: {err}")));
                        if let Some(hint) = runtime_config::protocol_remediation_hint(&err) {
                            logs.push(hint.clone());
                            transcript.push(("system".to_string(), hint));
                            *show_logs = true;
                        }
                    } else {
                        *provider_connected = true;
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
                            *status_detail = format!("{}: {}", exit_reason.as_str(), reason_short);
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
                                transcript.push(("system".to_string(), hint));
                                *show_logs = true;
                            }
                        }
                    }
                    if !final_text.trim().is_empty() {
                        transcript.push(("assistant".to_string(), final_text));
                    }
                    if *follow_output {
                        *transcript_scroll = usize::MAX;
                    }
                }
                Err(e) => {
                    let msg = format!("run failed: {e}");
                    if runtime_config::is_timeout_error_text(&msg) {
                        *provider_connected = false;
                    }
                    logs.push(msg.clone());
                    *show_logs = true;
                    transcript.push(("system".to_string(), msg));
                    *status_detail = format!(
                        "run failed: {}",
                        chat_view_utils::compact_status_detail(&e.to_string(), 120)
                    );
                    if let Some(hint) = runtime_config::protocol_remediation_hint(&format!("{e}")) {
                        logs.push(hint.clone());
                        transcript.push(("system".to_string(), hint));
                        *show_logs = true;
                    }
                    if *follow_output {
                        *transcript_scroll = usize::MAX;
                    }
                }
            }
            streaming_assistant.clear();
            *status = "idle".to_string();
            break;
        }
        *think_tick = think_tick.saturating_add(1);
        *ui_tick = ui_tick.saturating_add(1);
    }

    Ok(())
}

struct TuiSlashCommandDispatchInput<'a> {
    line: &'a str,
    slash_menu_index: usize,
    run_busy: bool,
    active_run: &'a mut RunArgs,
    paths: &'a store::StatePaths,
    logs: &'a mut Vec<String>,
    show_logs: &'a mut bool,
    show_tools: &'a mut bool,
    show_approvals: &'a mut bool,
    timeout_notice_active: &'a mut bool,
    pending_timeout_input: &'a mut bool,
    pending_params_input: &'a mut bool,
    transcript: &'a mut Vec<(String, String)>,
    ui_state: &'a mut UiState,
    streaming_assistant: &'a mut String,
    transcript_scroll: &'a mut usize,
    follow_output: &'a mut bool,
    shared_chat_mcp_registry: &'a mut Option<std::sync::Arc<McpRegistry>>,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    learn_overlay_cursor: &'a mut usize,
}

struct TuiNormalSubmitPrepInput<'a> {
    line: &'a str,
    prompt_history: &'a mut Vec<String>,
    transcript: &'a mut Vec<(String, String)>,
    show_logs: &'a mut bool,
    follow_output: &'a mut bool,
    transcript_scroll: &'a mut usize,
    status: &'a mut String,
    status_detail: &'a mut String,
    streaming_assistant: &'a mut String,
    think_tick: &'a mut u64,
}

struct TuiOuterKeyPreludeInput<'a> {
    key: crossterm::event::KeyEvent,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    palette_open: &'a mut bool,
    search_mode: &'a mut bool,
    search_query: &'a String,
    search_input_cursor: &'a mut usize,
    follow_output: &'a mut bool,
    transcript_scroll: &'a mut usize,
}

fn handle_tui_outer_key_prelude(input: TuiOuterKeyPreludeInput<'_>) -> TuiOuterKeyPreludeOutcome {
    if !matches!(input.key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return TuiOuterKeyPreludeOutcome::ContinueLoop;
    }
    if input.learn_overlay.is_some() {
        return TuiOuterKeyPreludeOutcome::Proceed;
    }
    if input.key.code == KeyCode::Esc {
        return TuiOuterKeyPreludeOutcome::BreakLoop;
    }
    if input.key.code == KeyCode::End {
        *input.follow_output = true;
        *input.transcript_scroll = usize::MAX;
        return TuiOuterKeyPreludeOutcome::ContinueLoop;
    }
    if input.key.code == KeyCode::Char('p') && input.key.modifiers.contains(KeyModifiers::CONTROL) {
        *input.palette_open = !*input.palette_open;
        *input.search_mode = false;
        return TuiOuterKeyPreludeOutcome::ContinueLoop;
    }
    if input.key.code == KeyCode::Char('f') && input.key.modifiers.contains(KeyModifiers::CONTROL) {
        *input.search_mode = true;
        *input.search_input_cursor = char_len(input.search_query);
        *input.palette_open = false;
        return TuiOuterKeyPreludeOutcome::ContinueLoop;
    }
    TuiOuterKeyPreludeOutcome::Proceed
}

struct TuiOuterKeyDispatchInput<'a> {
    key: crossterm::event::KeyEvent,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    run_busy: bool,
    input: &'a mut String,
    input_cursor: &'a mut usize,
    prompt_history: &'a mut Vec<String>,
    history_idx: &'a mut Option<usize>,
    slash_menu_index: &'a mut usize,
    palette_open: &'a mut bool,
    palette_items: &'a [&'a str],
    palette_selected: &'a mut usize,
    search_mode: &'a mut bool,
    search_query: &'a mut String,
    search_line_cursor: &'a mut usize,
    search_input_cursor: &'a mut usize,
    transcript: &'a mut Vec<(String, String)>,
    streaming_assistant: &'a mut String,
    transcript_scroll: &'a mut usize,
    follow_output: &'a mut bool,
    ui_state: &'a mut UiState,
    visible_tool_count: usize,
    show_tools: &'a mut bool,
    show_approvals: &'a mut bool,
    show_logs: &'a mut bool,
    compact_tools: &'a mut bool,
    tools_selected: &'a mut usize,
    tools_focus: &'a mut bool,
    approvals_selected: &'a mut usize,
    paths: &'a store::StatePaths,
    logs: &'a mut Vec<String>,
    learn_overlay_cursor: &'a mut usize,
}

struct TuiOuterMouseInput<'a> {
    me: &'a crossterm::event::MouseEvent,
    transcript: &'a Vec<(String, String)>,
    streaming_assistant: &'a str,
    transcript_scroll: &'a mut usize,
    follow_output: &'a mut bool,
}

fn handle_tui_outer_mouse_event(input: TuiOuterMouseInput<'_>) {
    if let Some(delta) = chat_runtime::mouse_scroll_delta(input.me) {
        let max_scroll =
            chat_runtime::transcript_max_scroll_lines(input.transcript, input.streaming_assistant);
        *input.transcript_scroll =
            chat_runtime::adjust_transcript_scroll(*input.transcript_scroll, delta, max_scroll);
        *input.follow_output = false;
    }
}

struct TuiOuterPasteInput<'a> {
    pasted: &'a str,
    input: &'a mut String,
    input_cursor: &'a mut usize,
    history_idx: &'a mut Option<usize>,
    slash_menu_index: &'a mut usize,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    learn_overlay_cursor: &'a mut usize,
}

const OVERLAY_CAPTURE_SUMMARY_MAX_CHARS: usize = 360;
const OVERLAY_ID_MAX_CHARS: usize = 96;

fn char_len(s: &str) -> usize {
    s.chars().count()
}

fn byte_index_for_char(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(idx, _)| idx)
        .unwrap_or(s.len())
}

fn clamp_cursor(s: &str, cursor: &mut usize) {
    *cursor = (*cursor).min(char_len(s));
}

fn insert_text_bounded(dst: &mut String, cursor: &mut usize, src: &str, max_chars: usize) {
    if src.is_empty() {
        return;
    }
    let used = char_len(dst);
    if used >= max_chars {
        return;
    }
    clamp_cursor(dst, cursor);
    let take_n = max_chars - used;
    let chunk: String = src.chars().take(take_n).collect();
    let at = byte_index_for_char(dst, *cursor);
    dst.insert_str(at, &chunk);
    *cursor += char_len(&chunk);
}

fn delete_char_before_cursor(dst: &mut String, cursor: &mut usize) {
    clamp_cursor(dst, cursor);
    if *cursor == 0 {
        return;
    }
    let end = byte_index_for_char(dst, *cursor);
    let start = byte_index_for_char(dst, *cursor - 1);
    dst.replace_range(start..end, "");
    *cursor = cursor.saturating_sub(1);
}

fn normalize_overlay_paste(pasted: &str, single_token: bool) -> String {
    let normalized = chat_runtime::normalize_pasted_text(pasted);
    let first_line = normalized
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();
    if first_line.is_empty() {
        return String::new();
    }
    let cooked = if single_token {
        first_line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    } else {
        first_line
    };
    cooked.chars().take(180).collect::<String>()
}

fn handle_tui_outer_paste_event(input: TuiOuterPasteInput<'_>) {
    if let Some(overlay) = input.learn_overlay.as_mut() {
        match overlay.input_focus {
            LearnOverlayInputFocus::CaptureSummary => {
                let s = normalize_overlay_paste(input.pasted, false);
                insert_text_bounded(
                    &mut overlay.summary,
                    input.learn_overlay_cursor,
                    &s,
                    OVERLAY_CAPTURE_SUMMARY_MAX_CHARS,
                );
            }
            LearnOverlayInputFocus::ReviewId => {
                let s = normalize_overlay_paste(input.pasted, true);
                if !s.is_empty() && !overlay.review_id.ends_with(&s) {
                    insert_text_bounded(
                        &mut overlay.review_id,
                        input.learn_overlay_cursor,
                        &s,
                        OVERLAY_ID_MAX_CHARS,
                    );
                    overlay.review_selected_idx = usize::MAX;
                }
            }
            LearnOverlayInputFocus::PromoteId => {
                let s = normalize_overlay_paste(input.pasted, true);
                if !s.is_empty() && !overlay.promote_id.ends_with(&s) {
                    insert_text_bounded(
                        &mut overlay.promote_id,
                        input.learn_overlay_cursor,
                        &s,
                        OVERLAY_ID_MAX_CHARS,
                    );
                }
            }
            LearnOverlayInputFocus::PromoteSlug => {
                let s = normalize_overlay_paste(input.pasted, true);
                if !s.is_empty() && !overlay.promote_slug.ends_with(&s) {
                    insert_text_bounded(
                        &mut overlay.promote_slug,
                        input.learn_overlay_cursor,
                        &s,
                        OVERLAY_ID_MAX_CHARS,
                    );
                }
            }
            LearnOverlayInputFocus::PromotePackId => {
                let s = normalize_overlay_paste(input.pasted, true);
                if !s.is_empty() && !overlay.promote_pack_id.ends_with(&s) {
                    insert_text_bounded(
                        &mut overlay.promote_pack_id,
                        input.learn_overlay_cursor,
                        &s,
                        OVERLAY_ID_MAX_CHARS,
                    );
                }
            }
        }
        return;
    }
    let normalized = chat_runtime::normalize_pasted_text(input.pasted);
    insert_text_bounded(input.input, input.input_cursor, &normalized, usize::MAX);
    *input.history_idx = None;
    *input.slash_menu_index = 0;
}

struct TuiOuterEventDispatchInput<'a> {
    event: CEvent,
    status: &'a str,
    prompt_history: &'a mut Vec<String>,
    transcript: &'a mut Vec<(String, String)>,
    streaming_assistant: &'a mut String,
    transcript_scroll: &'a mut usize,
    follow_output: &'a mut bool,
    input: &'a mut String,
    input_cursor: &'a mut usize,
    history_idx: &'a mut Option<usize>,
    slash_menu_index: &'a mut usize,
    palette_open: &'a mut bool,
    palette_items: &'a [&'a str],
    palette_selected: &'a mut usize,
    search_mode: &'a mut bool,
    search_query: &'a mut String,
    search_line_cursor: &'a mut usize,
    search_input_cursor: &'a mut usize,
    ui_state: &'a mut UiState,
    visible_tool_count: usize,
    show_tools: &'a mut bool,
    show_approvals: &'a mut bool,
    show_logs: &'a mut bool,
    compact_tools: &'a mut bool,
    tools_selected: &'a mut usize,
    tools_focus: &'a mut bool,
    approvals_selected: &'a mut usize,
    paths: &'a store::StatePaths,
    logs: &'a mut Vec<String>,
    learn_overlay: &'a mut Option<LearnOverlayState>,
    learn_overlay_cursor: &'a mut usize,
}

fn overlay_field_mut_and_max(
    overlay: &mut LearnOverlayState,
) -> (&mut String, usize, bool) {
    match overlay.input_focus {
        LearnOverlayInputFocus::CaptureSummary => {
            (&mut overlay.summary, OVERLAY_CAPTURE_SUMMARY_MAX_CHARS, false)
        }
        LearnOverlayInputFocus::ReviewId => (&mut overlay.review_id, OVERLAY_ID_MAX_CHARS, true),
        LearnOverlayInputFocus::PromoteId => (&mut overlay.promote_id, OVERLAY_ID_MAX_CHARS, false),
        LearnOverlayInputFocus::PromoteSlug => {
            (&mut overlay.promote_slug, OVERLAY_ID_MAX_CHARS, false)
        }
        LearnOverlayInputFocus::PromotePackId => {
            (&mut overlay.promote_pack_id, OVERLAY_ID_MAX_CHARS, false)
        }
    }
}

fn sync_overlay_cursor_to_focus(overlay: &LearnOverlayState, cursor: &mut usize) {
    let len = match overlay.input_focus {
        LearnOverlayInputFocus::CaptureSummary => char_len(&overlay.summary),
        LearnOverlayInputFocus::ReviewId => char_len(&overlay.review_id),
        LearnOverlayInputFocus::PromoteId => char_len(&overlay.promote_id),
        LearnOverlayInputFocus::PromoteSlug => char_len(&overlay.promote_slug),
        LearnOverlayInputFocus::PromotePackId => char_len(&overlay.promote_pack_id),
    };
    *cursor = (*cursor).min(len);
}

fn handle_tui_outer_event_dispatch(
    input: TuiOuterEventDispatchInput<'_>,
) -> TuiOuterEventDispatchOutcome {
    match input.event {
        CEvent::Mouse(me) => {
            handle_tui_outer_mouse_event(TuiOuterMouseInput {
                me: &me,
                transcript: input.transcript,
                streaming_assistant: input.streaming_assistant,
                transcript_scroll: input.transcript_scroll,
                follow_output: input.follow_output,
            });
            TuiOuterEventDispatchOutcome::Noop
        }
        CEvent::Paste(pasted) => {
            handle_tui_outer_paste_event(TuiOuterPasteInput {
                pasted: &pasted,
                input: input.input,
                input_cursor: input.input_cursor,
                history_idx: input.history_idx,
                slash_menu_index: input.slash_menu_index,
                learn_overlay: input.learn_overlay,
                learn_overlay_cursor: input.learn_overlay_cursor,
            });
            TuiOuterEventDispatchOutcome::Noop
        }
        CEvent::Key(key) => {
            match handle_tui_outer_key_prelude(TuiOuterKeyPreludeInput {
                key,
                learn_overlay: input.learn_overlay,
                palette_open: input.palette_open,
                search_mode: input.search_mode,
                search_query: input.search_query,
                search_input_cursor: input.search_input_cursor,
                follow_output: input.follow_output,
                transcript_scroll: input.transcript_scroll,
            }) {
                TuiOuterKeyPreludeOutcome::BreakLoop => {
                    return TuiOuterEventDispatchOutcome::BreakLoop
                }
                TuiOuterKeyPreludeOutcome::ContinueLoop => {
                    return TuiOuterEventDispatchOutcome::ContinueLoop
                }
                TuiOuterKeyPreludeOutcome::Proceed => {}
            }
            match handle_tui_outer_key_dispatch(TuiOuterKeyDispatchInput {
                key,
                learn_overlay: input.learn_overlay,
                run_busy: input.status == "running",
                input: input.input,
                input_cursor: input.input_cursor,
                prompt_history: input.prompt_history,
                history_idx: input.history_idx,
                slash_menu_index: input.slash_menu_index,
                palette_open: input.palette_open,
                palette_items: input.palette_items,
                palette_selected: input.palette_selected,
                search_mode: input.search_mode,
                search_query: input.search_query,
                search_line_cursor: input.search_line_cursor,
                search_input_cursor: input.search_input_cursor,
                transcript: input.transcript,
                streaming_assistant: input.streaming_assistant,
                transcript_scroll: input.transcript_scroll,
                follow_output: input.follow_output,
                ui_state: input.ui_state,
                visible_tool_count: input.visible_tool_count,
                show_tools: input.show_tools,
                show_approvals: input.show_approvals,
                show_logs: input.show_logs,
                compact_tools: input.compact_tools,
                tools_selected: input.tools_selected,
                tools_focus: input.tools_focus,
                approvals_selected: input.approvals_selected,
                paths: input.paths,
                logs: input.logs,
                learn_overlay_cursor: input.learn_overlay_cursor,
            }) {
                TuiOuterKeyDispatchOutcome::BreakLoop => TuiOuterEventDispatchOutcome::BreakLoop,
                TuiOuterKeyDispatchOutcome::ContinueLoop => {
                    TuiOuterEventDispatchOutcome::ContinueLoop
                }
                TuiOuterKeyDispatchOutcome::Handled => TuiOuterEventDispatchOutcome::HandledKey,
                TuiOuterKeyDispatchOutcome::EnterInline => {
                    TuiOuterEventDispatchOutcome::EnterInline
                }
            }
        }
        _ => TuiOuterEventDispatchOutcome::Noop,
    }
}

struct TuiRenderFrameInput<'a> {
    mode_label: &'a str,
    provider_label: &'a str,
    provider_connected: bool,
    model: &'a str,
    status: &'a str,
    status_detail: &'a str,
    transcript: &'a Vec<(String, String)>,
    streaming_assistant: &'a str,
    ui_state: &'a UiState,
    tools_selected: usize,
    tools_focus: bool,
    show_tool_details: bool,
    approvals_selected: usize,
    cwd_label: &'a str,
    input: &'a str,
    input_cursor: usize,
    input_cursor_visible: bool,
    logs: &'a Vec<String>,
    think_tick: u64,
    tui_refresh_ms: u64,
    show_tools: bool,
    show_approvals: bool,
    show_logs: bool,
    transcript_scroll: usize,
    compact_tools: bool,
    show_banner: bool,
    ui_tick: u64,
    overlay_text: Option<String>,
    learn_overlay: Option<crate::chat_ui::LearnOverlayRenderModel>,
}

struct TuiRenderFrameBuildInput<'a> {
    active_run: &'a RunArgs,
    provider_kind: ProviderKind,
    provider_connected: bool,
    model: &'a str,
    status: &'a str,
    status_detail: &'a str,
    transcript: &'a Vec<(String, String)>,
    streaming_assistant: &'a str,
    ui_state: &'a UiState,
    tools_selected: &'a mut usize,
    tools_focus: &'a mut bool,
    show_tool_details: &'a mut bool,
    approvals_selected: &'a mut usize,
    cwd_label: &'a str,
    input: &'a str,
    input_cursor: usize,
    logs: &'a Vec<String>,
    think_tick: u64,
    tui_refresh_ms: u64,
    show_tools: &'a mut bool,
    show_approvals: &'a mut bool,
    show_logs: bool,
    transcript_scroll: usize,
    compact_tools: bool,
    show_banner: bool,
    ui_tick: u64,
    palette_open: bool,
    palette_items: &'a [&'a str],
    palette_selected: usize,
    search_mode: bool,
    search_query: &'a str,
    search_input_cursor: usize,
    slash_menu_index: usize,
    learn_overlay: &'a Option<LearnOverlayState>,
    learn_overlay_cursor: usize,
}

fn build_tui_render_frame_input(input: TuiRenderFrameBuildInput<'_>) -> TuiRenderFrameInput<'_> {
    let tool_row_count = if input.compact_tools { 20 } else { 12 };
    let visible_tool_count = input.ui_state.tool_calls.len().min(tool_row_count);
    if visible_tool_count == 0 {
        *input.tools_selected = 0;
        *input.show_tool_details = false;
    } else {
        *input.tools_selected = (*input.tools_selected).min(visible_tool_count.saturating_sub(1));
    }
    if input.ui_state.pending_approvals.is_empty() {
        *input.approvals_selected = 0;
    } else {
        *input.approvals_selected = (*input.approvals_selected)
            .min(input.ui_state.pending_approvals.len().saturating_sub(1));
    }
    if *input.show_tools && !*input.show_approvals {
        *input.tools_focus = true;
    } else if *input.show_approvals && !*input.show_tools {
        *input.tools_focus = false;
    }
    if !*input.show_tools {
        *input.show_tool_details = false;
    }

    let overlay_text = if input.learn_overlay.is_some() {
        None
    } else if input.palette_open {
        Some(format!(
            "⌘ {}  (Up/Down, Enter, Esc)",
            input.palette_items[input.palette_selected]
        ))
    } else if input.search_mode {
        Some(format!(
            "🔎 {}  (Enter next, Esc close)",
            render_with_optional_caret(input.search_query, input.search_input_cursor, true)
        ))
    } else if input.input.starts_with('/') {
        chat_commands::slash_overlay_text(input.input, input.slash_menu_index)
    } else if input.input.starts_with('?') {
        chat_commands::keybinds_overlay_text()
    } else {
        None
    };

    let learn_overlay = input
        .learn_overlay
        .as_ref()
        .map(|s| {
            build_learn_overlay_render_model_with_cursor(
                s,
                input.learn_overlay_cursor,
                input.ui_tick,
            )
        });

    TuiRenderFrameInput {
        mode_label: chat_runtime::chat_mode_label(input.active_run),
        provider_label: provider_runtime::provider_cli_name(input.provider_kind),
        provider_connected: input.provider_connected,
        model: input.model,
        status: input.status,
        status_detail: input.status_detail,
        transcript: input.transcript,
        streaming_assistant: input.streaming_assistant,
        ui_state: input.ui_state,
        tools_selected: *input.tools_selected,
        tools_focus: *input.tools_focus,
        show_tool_details: *input.show_tool_details,
        approvals_selected: *input.approvals_selected,
        cwd_label: input.cwd_label,
        input: input.input,
        input_cursor: input.input_cursor,
        input_cursor_visible: ((input.ui_tick / 6) % 2) == 0,
        logs: input.logs,
        think_tick: input.think_tick,
        tui_refresh_ms: input.tui_refresh_ms,
        show_tools: *input.show_tools,
        show_approvals: *input.show_approvals,
        show_logs: input.show_logs,
        transcript_scroll: input.transcript_scroll,
        compact_tools: input.compact_tools,
        show_banner: input.show_banner,
        ui_tick: input.ui_tick,
        overlay_text,
        learn_overlay,
    }
}

#[cfg(test)]
fn build_learn_overlay_render_model(s: &LearnOverlayState) -> crate::chat_ui::LearnOverlayRenderModel {
    build_learn_overlay_render_model_with_cursor(s, 0, 0)
}

fn build_learn_overlay_render_model_with_cursor(
    s: &LearnOverlayState,
    active_input_cursor: usize,
    ui_tick: u64,
) -> crate::chat_ui::LearnOverlayRenderModel {
    let write_state = if s.write_armed {
        crate::chat_ui::LearnOverlayWriteState::Armed
    } else {
        crate::chat_ui::LearnOverlayWriteState::Preview
    };
    let (equivalent_cli, writes_to, target_path) = match s.tab {
        crate::chat_ui::LearnOverlayTab::Capture => {
            let category = match s.category_idx {
                0 => "workflow_hint",
                1 => "prompt_guidance",
                _ => "check_candidate",
            };
            let mut cli = format!("learn capture --category {category} --summary ");
            if s.summary.trim().is_empty() {
                cli.push_str("<required>");
            } else {
                cli.push('"');
                cli.push_str(&s.summary);
                cli.push('"');
            }
            if s.assist_on {
                cli.push_str(" --assist");
            }
            let writes = if s.write_armed {
                vec![
                    ".localagent/learn/entries/<new_ulid>.json (staged)".to_string(),
                    ".localagent/learn/events.jsonl (staged)".to_string(),
                ]
            } else {
                Vec::new()
            };
            (cli, writes, "N/A".to_string())
        }
        crate::chat_ui::LearnOverlayTab::Review => {
            let cli = if s.review_id.trim().is_empty() {
                "learn list".to_string()
            } else {
                format!("learn show {}", s.review_id)
            };
            (cli, Vec::new(), "N/A".to_string())
        }
        crate::chat_ui::LearnOverlayTab::Promote => {
            let target = match s.promote_target_idx {
                0 => "check",
                1 => "pack",
                _ => "agents",
            };
            let mut cli = if s.promote_id.trim().is_empty() {
                format!("learn promote <required_id> --to {target}")
            } else {
                format!("learn promote {} --to {target}", s.promote_id)
            };
            if target == "check" {
                if s.promote_slug.trim().is_empty() {
                    cli.push_str(" --slug <required>");
                } else {
                    cli.push_str(&format!(" --slug {}", s.promote_slug));
                }
            }
            if target == "pack" {
                if s.promote_pack_id.trim().is_empty() {
                    cli.push_str(" --pack-id <required>");
                } else {
                    cli.push_str(&format!(" --pack-id {}", s.promote_pack_id));
                }
            }
            if s.promote_force {
                cli.push_str(" --force");
            }
            let writes = if s.write_armed {
                match target {
                    "check" => vec![
                        ".localagent/checks/<slug>.md (staged)".to_string(),
                        ".localagent/learn/entries/<id>.json (staged)".to_string(),
                        ".localagent/learn/events.jsonl (staged)".to_string(),
                    ],
                    "pack" => vec![
                        ".localagent/packs/<pack_id>/PACK.md (staged)".to_string(),
                        ".localagent/learn/entries/<id>.json (staged)".to_string(),
                        ".localagent/learn/events.jsonl (staged)".to_string(),
                    ],
                    _ => vec![
                        "AGENTS.md (staged)".to_string(),
                        ".localagent/learn/entries/<id>.json (staged)".to_string(),
                        ".localagent/learn/events.jsonl (staged)".to_string(),
                    ],
                }
            } else {
                Vec::new()
            };
            let target_path = match target {
                "check" => ".localagent/checks/<slug>.md",
                "pack" => ".localagent/packs/<pack_id>/PACK.md",
                _ => "AGENTS.md",
            };
            (cli, writes, target_path.to_string())
        }
    };
    crate::chat_ui::LearnOverlayRenderModel {
        tab: s.tab,
        selected_category_idx: s.category_idx,
        summary: s.summary.clone(),
        review_id: s.review_id.clone(),
        promote_id: s.promote_id.clone(),
        promote_target_idx: s.promote_target_idx,
        promote_slug: s.promote_slug.clone(),
        promote_pack_id: s.promote_pack_id.clone(),
        promote_force: s.promote_force,
        input_focus: learn_overlay_focus_label(s.input_focus).to_string(),
        inline_message: s.inline_message.clone(),
        review_rows: s.review_rows.clone(),
        review_selected_idx: s.review_selected_idx,
        assist_on: s.assist_on,
        write_state,
        equivalent_cli,
        will_write: s.write_armed,
        writes_to,
        target_path,
        sensitivity_paths: false,
        sensitivity_secrets: false,
        sensitivity_userdata: false,
        overlay_logs: s.logs.clone(),
        assist_summary: s.assist_summary.clone(),
        summary_choice: s.summary_choice,
        selected_summary: s.selected_summary.clone(),
        active_input_cursor,
        cursor_visible: ((ui_tick / 6) % 2) == 0,
    }
}

fn render_with_optional_caret(input: &str, cursor: usize, visible: bool) -> String {
    if !visible {
        return input.to_string();
    }
    let mut chars: Vec<char> = input.chars().collect();
    let idx = cursor.min(chars.len());
    chars.insert(idx, '|');
    chars.into_iter().collect()
}

fn learn_overlay_focus_label(focus: LearnOverlayInputFocus) -> &'static str {
    match focus {
        LearnOverlayInputFocus::CaptureSummary => "capture.summary",
        LearnOverlayInputFocus::ReviewId => "review.id",
        LearnOverlayInputFocus::PromoteId => "promote.id",
        LearnOverlayInputFocus::PromoteSlug => "promote.slug",
        LearnOverlayInputFocus::PromotePackId => "promote.pack_id",
    }
}

fn build_overlay_promote_submit_line(overlay: &LearnOverlayState) -> Result<String, String> {
    if overlay.promote_id.trim().is_empty() {
        return Err("promote id: <required>".to_string());
    }
    let target = match overlay.promote_target_idx {
        0 => "check",
        1 => "pack",
        _ => "agents",
    };
    let mut line = format!("/learn promote {} --to {target}", overlay.promote_id);
    if target == "check" {
        if overlay.promote_slug.trim().is_empty() {
            return Err("slug: <required for check>".to_string());
        }
        line.push_str(&format!(" --slug {}", overlay.promote_slug));
    }
    if target == "pack" {
        if overlay.promote_pack_id.trim().is_empty() {
            return Err("pack_id: <required for pack>".to_string());
        }
        line.push_str(&format!(" --pack-id {}", overlay.promote_pack_id));
    }
    if overlay.promote_force {
        line.push_str(" --force");
    }
    Ok(line)
}

fn handle_tui_outer_key_dispatch(
    input: TuiOuterKeyDispatchInput<'_>,
) -> TuiOuterKeyDispatchOutcome {
    if let Some(overlay) = input.learn_overlay.as_mut() {
        match input.key.code {
            KeyCode::Esc => {
                *input.learn_overlay = None;
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('c') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                *input.learn_overlay = None;
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('1') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                overlay.tab = crate::chat_ui::LearnOverlayTab::Capture;
                overlay.input_focus = LearnOverlayInputFocus::CaptureSummary;
                *input.learn_overlay_cursor = char_len(&overlay.summary);
                overlay.inline_message = None;
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('2') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                overlay.tab = crate::chat_ui::LearnOverlayTab::Review;
                overlay.input_focus = LearnOverlayInputFocus::ReviewId;
                *input.learn_overlay_cursor = char_len(&overlay.review_id);
                overlay.inline_message = None;
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('3') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                overlay.tab = crate::chat_ui::LearnOverlayTab::Promote;
                overlay.input_focus = LearnOverlayInputFocus::PromoteId;
                *input.learn_overlay_cursor = char_len(&overlay.promote_id);
                overlay.inline_message = None;
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Tab => {
                let reverse = input.key.modifiers.contains(KeyModifiers::SHIFT);
                cycle_overlay_focus(overlay, reverse);
                sync_overlay_cursor_to_focus(overlay, input.learn_overlay_cursor);
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Up => {
                if overlay.tab == crate::chat_ui::LearnOverlayTab::Capture {
                    overlay.category_idx = overlay.category_idx.saturating_sub(1);
                } else if overlay.tab == crate::chat_ui::LearnOverlayTab::Review
                    && !overlay.review_rows.is_empty()
                {
                    overlay.review_selected_idx = overlay.review_selected_idx.saturating_sub(1);
                    if let Some(row) = overlay.review_rows.get(overlay.review_selected_idx) {
                        overlay.review_id = row.split(" | ").next().unwrap_or("").to_string();
                        *input.learn_overlay_cursor = char_len(&overlay.review_id);
                    }
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Down => {
                if overlay.tab == crate::chat_ui::LearnOverlayTab::Capture {
                    overlay.category_idx = (overlay.category_idx + 1).min(2);
                } else if overlay.tab == crate::chat_ui::LearnOverlayTab::Review
                    && !overlay.review_rows.is_empty()
                {
                    overlay.review_selected_idx =
                        (overlay.review_selected_idx + 1).min(overlay.review_rows.len() - 1);
                    if let Some(row) = overlay.review_rows.get(overlay.review_selected_idx) {
                        overlay.review_id = row.split(" | ").next().unwrap_or("").to_string();
                        *input.learn_overlay_cursor = char_len(&overlay.review_id);
                    }
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Left => {
                *input.learn_overlay_cursor = input.learn_overlay_cursor.saturating_sub(1);
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Right => {
                sync_overlay_cursor_to_focus(overlay, input.learn_overlay_cursor);
                *input.learn_overlay_cursor = input.learn_overlay_cursor.saturating_add(1);
                sync_overlay_cursor_to_focus(overlay, input.learn_overlay_cursor);
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Home => {
                *input.learn_overlay_cursor = 0;
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::End => {
                *input.learn_overlay_cursor = usize::MAX;
                sync_overlay_cursor_to_focus(overlay, input.learn_overlay_cursor);
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Backspace => {
                let (field, _max_chars, reset_review_select) = overlay_field_mut_and_max(overlay);
                delete_char_before_cursor(field, input.learn_overlay_cursor);
                if reset_review_select {
                    overlay.review_selected_idx = usize::MAX;
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('a') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                if overlay.tab == crate::chat_ui::LearnOverlayTab::Capture {
                    overlay.assist_on = !overlay.assist_on;
                    set_overlay_next_steps_capture(overlay);
                } else {
                    overlay.inline_message = None;
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('g') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                if overlay.summary.trim().is_empty() {
                    overlay.inline_message =
                        Some("Enter a summary first before asking for an assist.".to_string());
                } else {
                    overlay.assist_summary = Some(assist_summary_stub(&overlay.summary));
                    overlay.summary_choice = crate::chat_ui::LearnOverlaySummaryChoice::Assist;
                    overlay.inline_message =
                        Some("Assist rewrite ready; use Ctrl+O or Ctrl+R to compare.".to_string());
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('o') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                overlay.summary_choice = crate::chat_ui::LearnOverlaySummaryChoice::Original;
                overlay.inline_message = Some("Original summary selected.".to_string());
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('r') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                if overlay.assist_summary.is_some() {
                    overlay.summary_choice = crate::chat_ui::LearnOverlaySummaryChoice::Assist;
                    overlay.inline_message = Some("Assist summary selected.".to_string());
                } else {
                    overlay.inline_message = Some(
                        "Generate an assist summary with Ctrl+G before selecting it.".to_string(),
                    );
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Char('w') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
                overlay.write_armed = !overlay.write_armed;
                if overlay.write_armed {
                    push_overlay_log_dedup(overlay, "info: Write state armed.");
                } else {
                    push_overlay_log_dedup(overlay, "info: Write state returned to preview.");
                }
                match overlay.tab {
                    crate::chat_ui::LearnOverlayTab::Capture => {
                        set_overlay_next_steps_capture(overlay)
                    }
                    crate::chat_ui::LearnOverlayTab::Promote => {
                        set_overlay_next_steps_promote(overlay)
                    }
                    crate::chat_ui::LearnOverlayTab::Review => {
                        overlay.inline_message = Some(
                            "Step 1: Enter/select ID. Step 2: Press Enter to preview. Step 3: Esc to close."
                                .to_string(),
                        );
                    }
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            KeyCode::Enter => {
                if input.run_busy {
                    push_overlay_log_unique(overlay, "System busy. Operation deferred.");
                    push_overlay_log_unique(overlay, "ERR_TUI_BUSY_TRY_AGAIN");
                    overlay.inline_message = Some("System busy. Operation deferred.".to_string());
                    return TuiOuterKeyDispatchOutcome::Handled;
                }
                return match overlay.tab {
                    crate::chat_ui::LearnOverlayTab::Capture => {
                        if overlay.summary.trim().is_empty() {
                            push_overlay_log_dedup(overlay, "summary: <required>");
                            overlay.inline_message = Some("summary: <required>".to_string());
                            return TuiOuterKeyDispatchOutcome::Handled;
                        }
                        overlay.selected_summary = Some(overlay_effective_summary(overlay));
                        if overlay.write_armed {
                            let category = match overlay.category_idx {
                                0 => "workflow-hint",
                                1 => "prompt-guidance",
                                _ => "check-candidate",
                            };
                            let assist = if overlay.assist_on { " --assist" } else { "" };
                            let write = if overlay.assist_on { " --write" } else { "" };
                            overlay.pending_submit_line = Some(format!(
                                "/learn capture --category {category} --summary \"{}\"{assist}{write}",
                                overlay.summary.replace('"', "\\\"")
                            ));
                            set_overlay_next_steps_capture(overlay);
                            return TuiOuterKeyDispatchOutcome::Handled;
                        }
                        push_overlay_log_unique(
                            overlay,
                            "info: Preflight check complete. Waiting for user action.",
                        );
                        set_overlay_next_steps_capture(overlay);
                        TuiOuterKeyDispatchOutcome::Handled
                    }
                    crate::chat_ui::LearnOverlayTab::Review => {
                        if overlay.review_id.trim().is_empty() {
                            let entries =
                                crate::learning::list_learning_entries(&input.paths.state_dir)
                                    .unwrap_or_default();
                            overlay.review_rows = entries
                                .iter()
                                .map(|e| {
                                    format!(
                                        "{} | {} | {}",
                                        e.id,
                                        match e.status {
                                            crate::learning::LearningStatusV1::Captured => {
                                                "captured"
                                            }
                                            crate::learning::LearningStatusV1::Promoted => {
                                                "promoted"
                                            }
                                            crate::learning::LearningStatusV1::Archived => {
                                                "archived"
                                            }
                                        },
                                        e.summary
                                    )
                                })
                                .collect();
                            overlay.review_selected_idx = 0;
                            if let Some(row) = overlay.review_rows.first() {
                                overlay.review_id =
                                    row.split(" | ").next().unwrap_or("").to_string();
                                *input.learn_overlay_cursor = char_len(&overlay.review_id);
                            }
                            overlay.pending_submit_line = Some("/learn list".to_string());
                            overlay.inline_message = Some(
                                "Step 1: Review rows. Step 2: Set review ID (optional). Step 3: Enter to preview."
                                    .to_string(),
                            );
                        } else {
                            overlay.pending_submit_line =
                                Some(format!("/learn show {}", overlay.review_id));
                            overlay.inline_message = Some(
                                "Step 1: Review output in logs. Step 2: adjust ID if needed. Step 3: Enter again."
                                    .to_string(),
                            );
                        }
                        TuiOuterKeyDispatchOutcome::Handled
                    }
                    crate::chat_ui::LearnOverlayTab::Promote => {
                        if !overlay.write_armed {
                            push_overlay_log_unique(
                                overlay,
                                "info: Preflight check complete. Waiting for user action.",
                            );
                            set_overlay_next_steps_promote(overlay);
                            return TuiOuterKeyDispatchOutcome::Handled;
                        }
                        match build_overlay_promote_submit_line(overlay) {
                            Ok(line) => {
                                overlay.pending_submit_line = Some(line);
                                set_overlay_next_steps_promote(overlay);
                            }
                            Err(msg) => {
                                push_overlay_log_dedup(overlay, &msg);
                                overlay.inline_message = Some(msg);
                                return TuiOuterKeyDispatchOutcome::Handled;
                            }
                        }
                        TuiOuterKeyDispatchOutcome::Handled
                    }
                };
            }
            KeyCode::Char(c) if chat_runtime::is_text_input_mods(input.key.modifiers) => {
                let (field, max_chars, reset_review_select) = overlay_field_mut_and_max(overlay);
                insert_text_bounded(
                    field,
                    input.learn_overlay_cursor,
                    &c.to_string(),
                    max_chars,
                );
                if overlay.input_focus == LearnOverlayInputFocus::CaptureSummary {
                    overlay.assist_summary = None;
                    overlay.summary_choice = crate::chat_ui::LearnOverlaySummaryChoice::Original;
                    overlay.selected_summary = None;
                }
                if reset_review_select {
                    overlay.review_selected_idx = usize::MAX;
                }
                return TuiOuterKeyDispatchOutcome::Handled;
            }
            _ => return TuiOuterKeyDispatchOutcome::Handled,
        }
    }

    if *input.palette_open {
        match input.key.code {
            KeyCode::Esc => *input.palette_open = false,
            KeyCode::Up => {
                *input.palette_selected = input.palette_selected.saturating_sub(1);
            }
            KeyCode::Down => {
                if *input.palette_selected + 1 < input.palette_items.len() {
                    *input.palette_selected += 1;
                }
            }
            KeyCode::Enter => {
                match *input.palette_selected {
                    0 => *input.show_tools = !*input.show_tools,
                    1 => *input.show_approvals = !*input.show_approvals,
                    2 => *input.show_logs = !*input.show_logs,
                    3 => *input.compact_tools = !*input.compact_tools,
                    4 => {
                        input.transcript.clear();
                        input.ui_state.tool_calls.clear();
                        input.streaming_assistant.clear();
                        *input.transcript_scroll = 0;
                        *input.follow_output = true;
                    }
                    5 => {
                        *input.follow_output = true;
                        *input.transcript_scroll = usize::MAX;
                    }
                    _ => {}
                }
                *input.palette_open = false;
            }
            _ => {}
        }
        return TuiOuterKeyDispatchOutcome::ContinueLoop;
    }
    if *input.search_mode {
        let mut do_search = false;
        match input.key.code {
            KeyCode::Esc => *input.search_mode = false,
            KeyCode::Backspace => {
                delete_char_before_cursor(input.search_query, input.search_input_cursor);
                *input.search_line_cursor = 0;
                do_search = true;
            }
            KeyCode::Left => {
                *input.search_input_cursor = input.search_input_cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                *input.search_input_cursor =
                    (*input.search_input_cursor + 1).min(char_len(input.search_query));
            }
            KeyCode::Enter => {
                do_search = true;
                *input.search_line_cursor = input.search_line_cursor.saturating_add(1);
            }
            KeyCode::Char(c) if chat_runtime::is_text_input_mods(input.key.modifiers) => {
                insert_text_bounded(
                    input.search_query,
                    input.search_input_cursor,
                    &c.to_string(),
                    usize::MAX,
                );
                *input.search_line_cursor = 0;
                do_search = true;
            }
            _ => {}
        }
        if do_search && !input.search_query.is_empty() {
            let hay = input
                .transcript
                .iter()
                .map(|(role, text)| format!("{}: {}", role.to_uppercase(), text))
                .collect::<Vec<_>>()
                .join("\n\n");
            let lines: Vec<&str> = hay.lines().collect();
            let query = input.search_query.to_lowercase();
            let mut found = None;
            for (idx, line) in lines.iter().enumerate().skip(*input.search_line_cursor) {
                if line.to_lowercase().contains(&query) {
                    found = Some(idx);
                    break;
                }
            }
            if found.is_none() {
                for (idx, line) in lines.iter().enumerate().take(*input.search_line_cursor) {
                    if line.to_lowercase().contains(&query) {
                        found = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = found {
                *input.transcript_scroll = idx;
                *input.follow_output = false;
                *input.search_line_cursor = idx;
            }
        }
        return TuiOuterKeyDispatchOutcome::ContinueLoop;
    }

    match input.key.code {
        KeyCode::Char('c') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            TuiOuterKeyDispatchOutcome::BreakLoop
        }
        KeyCode::Up => {
            if input.input.starts_with('/') {
                let matches_len = chat_commands::slash_match_count(input.input);
                if matches_len > 0 {
                    *input.slash_menu_index = if *input.slash_menu_index == 0 {
                        matches_len - 1
                    } else {
                        *input.slash_menu_index - 1
                    };
                }
                return TuiOuterKeyDispatchOutcome::ContinueLoop;
            }
            if !input.prompt_history.is_empty() {
                let next = match *input.history_idx {
                    None => input.prompt_history.len().saturating_sub(1),
                    Some(i) => i.saturating_sub(1),
                };
                *input.history_idx = Some(next);
                *input.input = input.prompt_history[next].clone();
                *input.input_cursor = char_len(input.input);
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Down => {
            if input.input.starts_with('/') {
                let matches_len = chat_commands::slash_match_count(input.input);
                if matches_len > 0 {
                    *input.slash_menu_index = (*input.slash_menu_index + 1) % matches_len;
                }
                return TuiOuterKeyDispatchOutcome::ContinueLoop;
            }
            if !input.prompt_history.is_empty() {
                if let Some(i) = *input.history_idx {
                    let next = (i + 1).min(input.prompt_history.len());
                    if next >= input.prompt_history.len() {
                        *input.history_idx = None;
                        input.input.clear();
                        *input.input_cursor = 0;
                    } else {
                        *input.history_idx = Some(next);
                        *input.input = input.prompt_history[next].clone();
                        *input.input_cursor = char_len(input.input);
                    }
                }
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::PageUp => {
            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                input.transcript,
                input.streaming_assistant,
            );
            *input.transcript_scroll =
                chat_runtime::adjust_transcript_scroll(*input.transcript_scroll, -12, max_scroll);
            *input.follow_output = false;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::PageDown => {
            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                input.transcript,
                input.streaming_assistant,
            );
            *input.transcript_scroll =
                chat_runtime::adjust_transcript_scroll(*input.transcript_scroll, 12, max_scroll);
            *input.follow_output = false;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('u') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                input.transcript,
                input.streaming_assistant,
            );
            *input.transcript_scroll =
                chat_runtime::adjust_transcript_scroll(*input.transcript_scroll, -10, max_scroll);
            *input.follow_output = false;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('d') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            let max_scroll = chat_runtime::transcript_max_scroll_lines(
                input.transcript,
                input.streaming_assistant,
            );
            *input.transcript_scroll =
                chat_runtime::adjust_transcript_scroll(*input.transcript_scroll, 10, max_scroll);
            *input.follow_output = false;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('t') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            *input.show_tools = !*input.show_tools;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('y') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            *input.show_approvals = !*input.show_approvals;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('g') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            *input.show_logs = !*input.show_logs;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Tab => {
            if *input.show_tools && (*input.show_approvals) {
                *input.tools_focus = !*input.tools_focus;
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('1') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            *input.show_tools = !*input.show_tools;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('2') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            *input.show_approvals = !*input.show_approvals;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('3') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            *input.show_logs = !*input.show_logs;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('j') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            if *input.show_tools && (!*input.show_approvals || *input.tools_focus) {
                if *input.tools_selected + 1 < input.visible_tool_count {
                    *input.tools_selected += 1;
                }
            } else if *input.approvals_selected + 1 < input.ui_state.pending_approvals.len() {
                *input.approvals_selected += 1;
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('k') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            if *input.show_tools && (!*input.show_approvals || *input.tools_focus) {
                *input.tools_selected = input.tools_selected.saturating_sub(1);
            } else {
                *input.approvals_selected = input.approvals_selected.saturating_sub(1);
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('r') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Err(e) = input
                .ui_state
                .refresh_approvals(&input.paths.approvals_path)
            {
                input.logs.push(format!("approvals refresh failed: {e}"));
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('a') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(row) = input
                .ui_state
                .pending_approvals
                .get(*input.approvals_selected)
            {
                let store = ApprovalsStore::new(input.paths.approvals_path.clone());
                if let Err(e) = store.approve(&row.id, None, None) {
                    input.logs.push(format!("approve failed: {e}"));
                } else {
                    input.logs.push(format!("approved {}", row.id));
                }
                let _ = input
                    .ui_state
                    .refresh_approvals(&input.paths.approvals_path);
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char('x') if input.key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(row) = input
                .ui_state
                .pending_approvals
                .get(*input.approvals_selected)
            {
                let store = ApprovalsStore::new(input.paths.approvals_path.clone());
                if let Err(e) = store.deny(&row.id) {
                    input.logs.push(format!("deny failed: {e}"));
                } else {
                    input.logs.push(format!("denied {}", row.id));
                }
                let _ = input
                    .ui_state
                    .refresh_approvals(&input.paths.approvals_path);
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Enter => TuiOuterKeyDispatchOutcome::EnterInline,
        KeyCode::Left => {
            *input.input_cursor = input.input_cursor.saturating_sub(1);
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Right => {
            *input.input_cursor = (*input.input_cursor + 1).min(char_len(input.input));
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Backspace => {
            delete_char_before_cursor(input.input, input.input_cursor);
            *input.slash_menu_index = 0;
            TuiOuterKeyDispatchOutcome::Handled
        }
        KeyCode::Char(c) => {
            if chat_runtime::is_text_input_mods(input.key.modifiers) {
                insert_text_bounded(input.input, input.input_cursor, &c.to_string(), usize::MAX);
                if c == '/' && input.input.len() == 1 {
                    *input.slash_menu_index = 0;
                }
            }
            TuiOuterKeyDispatchOutcome::Handled
        }
        _ => TuiOuterKeyDispatchOutcome::Handled,
    }
}

fn prepare_tui_normal_submit_state(
    input: TuiNormalSubmitPrepInput<'_>,
) -> TuiNormalSubmitPrepOutcome {
    input.prompt_history.push(input.line.to_string());
    *input.follow_output = true;
    *input.transcript_scroll = usize::MAX;
    input
        .transcript
        .push(("user".to_string(), input.line.to_string()));
    if input.line.starts_with('?') {
        *input.show_logs = true;
        return TuiNormalSubmitPrepOutcome::HandledNoRun;
    }
    *input.status = "running".to_string();
    input.status_detail.clear();
    input.streaming_assistant.clear();
    *input.think_tick = 0;
    TuiNormalSubmitPrepOutcome::ContinueToRun
}

struct TuiNormalSubmitLaunchInput<'a> {
    provider_kind: ProviderKind,
    base_url: &'a str,
    model: &'a str,
    line: &'a str,
    active_run: &'a RunArgs,
    paths: &'a store::StatePaths,
    logs: &'a mut Vec<String>,
    show_logs: &'a mut bool,
    transcript: &'a mut Vec<(String, String)>,
    status: &'a mut String,
    status_detail: &'a mut String,
    follow_output: &'a bool,
    transcript_scroll: &'a mut usize,
    shared_chat_mcp_registry: &'a mut Option<std::sync::Arc<McpRegistry>>,
}

async fn build_tui_normal_submit_launch(
    input: TuiNormalSubmitLaunchInput<'_>,
) -> anyhow::Result<Option<TuiSubmitLaunch>> {
    let (tx, rx) = std::sync::mpsc::channel::<Event>();
    let (queue_tx, queue_rx) =
        std::sync::mpsc::channel::<crate::operator_queue::QueueSubmitRequest>();
    let mut queue_rx_opt = Some(queue_rx);

    let mut turn_args = input.active_run.clone();
    turn_args.prompt = Some(input.line.to_string());
    turn_args.tui = false;
    turn_args.stream = true;

    if !turn_args.mcp.is_empty() && input.shared_chat_mcp_registry.is_none() {
        let mcp_config_path =
            runtime_paths::resolved_mcp_config_path(&turn_args, &input.paths.state_dir);
        match McpRegistry::from_config_path(
            &mcp_config_path,
            &turn_args.mcp,
            Duration::from_secs(30),
        )
        .await
        {
            Ok(reg) => {
                *input.shared_chat_mcp_registry = Some(std::sync::Arc::new(reg));
            }
            Err(e) => {
                let msg = format!("failed to initialize MCP session: {e}");
                input.logs.push(msg.clone());
                *input.show_logs = true;
                input.transcript.push(("system".to_string(), msg));
                *input.status = "idle".to_string();
                *input.status_detail = "mcp init failed".to_string();
                if *input.follow_output {
                    *input.transcript_scroll = usize::MAX;
                }
                return Ok(None);
            }
        }
    }

    let provider_kind = input.provider_kind;
    let base_url = input.base_url.to_string();
    let model = input.model.to_string();
    let line = input.line.to_string();
    let paths = input.paths.clone();
    let shared_chat_mcp_registry = input.shared_chat_mcp_registry.clone();
    let queue_rx = queue_rx_opt.take().expect("queue rx once");
    let fut: TuiRunFuture = Box::pin(async move {
        match provider_kind {
            ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
                let provider = OpenAiCompatProvider::new(
                    base_url.clone(),
                    turn_args.api_key.clone(),
                    provider_runtime::http_config_from_run_args(&turn_args),
                )?;
                run_agent_with_ui(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    &line,
                    &turn_args,
                    &paths,
                    Some(tx),
                    Some(queue_rx),
                    shared_chat_mcp_registry,
                    true,
                )
                .await
            }
            ProviderKind::Ollama => {
                let provider = OllamaProvider::new(
                    base_url.clone(),
                    provider_runtime::http_config_from_run_args(&turn_args),
                )?;
                run_agent_with_ui(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    &line,
                    &turn_args,
                    &paths,
                    Some(tx),
                    Some(queue_rx),
                    shared_chat_mcp_registry,
                    true,
                )
                .await
            }
            ProviderKind::Mock => {
                let provider = MockProvider::new();
                run_agent_with_ui(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    &line,
                    &turn_args,
                    &paths,
                    Some(tx),
                    Some(queue_rx),
                    shared_chat_mcp_registry,
                    true,
                )
                .await
            }
        }
    });

    Ok(Some(TuiSubmitLaunch { rx, queue_tx, fut }))
}

async fn handle_tui_enter_submit(
    input: TuiEnterSubmitInput<'_>,
) -> anyhow::Result<TuiEnterSubmitOutcome> {
    let TuiEnterSubmitInput {
        terminal,
        input: input_buf,
        history_idx,
        slash_menu_index,
        pending_timeout_input,
        pending_params_input,
        timeout_notice_active,
        active_run,
        base_run,
        paths,
        provider_kind,
        provider_connected,
        base_url,
        model,
        cwd_label,
        logs,
        max_logs,
        show_logs,
        show_tools,
        show_approvals,
        show_tool_details,
        tools_focus,
        visible_tool_count,
        prompt_history,
        transcript,
        streaming_assistant,
        status,
        status_detail,
        think_tick,
        ui_tick,
        follow_output,
        transcript_scroll,
        ui_state,
        tools_selected,
        approvals_selected,
        compact_tools,
        show_banner,
        palette_open,
        palette_items,
        palette_selected,
        search_mode,
        search_query,
        shared_chat_mcp_registry,
        learn_overlay,
        input_cursor,
        search_input_cursor,
        learn_overlay_cursor,
    } = input;

    let line = input_buf.trim().to_string();
    input_buf.clear();
    *input_cursor = 0;
    *history_idx = None;
    *slash_menu_index = 0;
    if line.is_empty() {
        return Ok(TuiEnterSubmitOutcome::ContinueLoop);
    }
    if *pending_params_input && !line.starts_with('/') {
        if line.eq_ignore_ascii_case("cancel") {
            *pending_params_input = false;
            logs.push("params update cancelled".to_string());
        } else {
            match runtime_config::apply_params_input(active_run, &line) {
                Ok(msg) => {
                    *pending_params_input = false;
                    logs.push(msg);
                }
                Err(msg) => logs.push(msg),
            }
        }
        *show_logs = true;
        return Ok(TuiEnterSubmitOutcome::ContinueLoop);
    }
    if *pending_timeout_input && !line.starts_with('/') {
        if line.eq_ignore_ascii_case("cancel") {
            *pending_timeout_input = false;
            logs.push("timeout update cancelled".to_string());
            *show_logs = false;
        } else {
            match runtime_config::apply_timeout_input(active_run, &line) {
                Ok(msg) => {
                    *pending_timeout_input = false;
                    logs.push(msg);
                    *show_logs = false;
                }
                Err(msg) => {
                    logs.push(msg);
                    *show_logs = true;
                }
            }
        }
        return Ok(TuiEnterSubmitOutcome::ContinueLoop);
    }
    if line.starts_with('/') {
        match handle_tui_slash_command(TuiSlashCommandDispatchInput {
            line: &line,
            slash_menu_index: *slash_menu_index,
            run_busy: status.as_str() == "running",
            active_run,
            paths,
            logs,
            show_logs,
            show_tools,
            show_approvals,
            timeout_notice_active,
            pending_timeout_input,
            pending_params_input,
            transcript,
            ui_state,
            streaming_assistant,
            transcript_scroll,
            follow_output,
            shared_chat_mcp_registry,
            learn_overlay,
            learn_overlay_cursor,
        })
        .await?
        {
            SlashCommandDispatchOutcome::ExitRequested => {
                return Ok(TuiEnterSubmitOutcome::ExitRequested)
            }
            SlashCommandDispatchOutcome::Handled => return Ok(TuiEnterSubmitOutcome::ContinueLoop),
        }
    }

    if line.is_empty() && *show_tools && (!*show_approvals || *tools_focus) {
        if visible_tool_count > 0 {
            *show_tool_details = !*show_tool_details;
            if *show_tool_details {
                *show_logs = false;
            }
        }
        return Ok(TuiEnterSubmitOutcome::ContinueLoop);
    }

    match prepare_tui_normal_submit_state(TuiNormalSubmitPrepInput {
        line: &line,
        prompt_history,
        transcript,
        show_logs,
        follow_output,
        transcript_scroll,
        status,
        status_detail,
        streaming_assistant,
        think_tick,
    }) {
        TuiNormalSubmitPrepOutcome::HandledNoRun => return Ok(TuiEnterSubmitOutcome::ContinueLoop),
        TuiNormalSubmitPrepOutcome::ContinueToRun => {}
    }

    terminal.draw(|f| {
        chat_ui::draw_chat_frame(
            f,
            chat_runtime::chat_mode_label(active_run),
            provider_runtime::provider_cli_name(provider_kind),
            *provider_connected,
            model,
            status,
            status_detail,
            transcript,
            streaming_assistant,
            ui_state,
            *tools_selected,
            *tools_focus,
            *show_tool_details,
            *approvals_selected,
            cwd_label,
            input_buf,
            *input_cursor,
            true,
            logs,
            *think_tick,
            base_run.tui_refresh_ms,
            *show_tools,
            *show_approvals,
            *show_logs,
            *transcript_scroll,
            compact_tools,
            show_banner,
            *ui_tick,
            if palette_open {
                Some(format!(
                    "⌘ {}  (Up/Down, Enter, Esc)",
                    palette_items[palette_selected]
                ))
            } else if search_mode {
                Some(format!(
                    "🔎 {}  (Enter next, Esc close)",
                    render_with_optional_caret(search_query, *search_input_cursor, true)
                ))
            } else if input_buf.starts_with('/') {
                chat_commands::slash_overlay_text(input_buf, *slash_menu_index)
            } else if input_buf.starts_with('?') {
                chat_commands::keybinds_overlay_text()
            } else {
                None
            },
            None,
        );
    })?;
    *ui_tick = ui_tick.saturating_add(1);

    let TuiSubmitLaunch { rx, queue_tx, fut } =
        match build_tui_normal_submit_launch(TuiNormalSubmitLaunchInput {
            provider_kind,
            base_url,
            model,
            line: &line,
            active_run,
            paths,
            logs,
            show_logs,
            transcript,
            status,
            status_detail,
            follow_output,
            transcript_scroll,
            shared_chat_mcp_registry,
        })
        .await?
        {
            Some(launch) => launch,
            None => return Ok(TuiEnterSubmitOutcome::ContinueLoop),
        };

    drive_tui_active_turn_loop(TuiActiveTurnLoopInput {
        terminal,
        fut,
        rx,
        queue_tx,
        ui_state,
        paths,
        active_run,
        base_run,
        provider_kind,
        provider_connected,
        model,
        cwd_label,
        input: input_buf,
        logs,
        transcript,
        streaming_assistant,
        status,
        status_detail,
        think_tick,
        ui_tick,
        approvals_selected,
        show_tools,
        show_approvals,
        show_logs,
        timeout_notice_active,
        transcript_scroll,
        follow_output,
        compact_tools,
        tools_selected,
        tools_focus,
        show_tool_details,
        show_banner,
        palette_open,
        palette_items,
        palette_selected,
        search_mode,
        search_query,
        slash_menu_index,
        learn_overlay,
        input_cursor,
        learn_overlay_cursor,
    })
    .await?;
    if logs.len() > max_logs {
        let drop_n = logs.len() - max_logs;
        logs.drain(0..drop_n);
    }
    *ui_tick = ui_tick.saturating_add(1);
    Ok(TuiEnterSubmitOutcome::Handled)
}

async fn handle_tui_slash_command(
    input: TuiSlashCommandDispatchInput<'_>,
) -> anyhow::Result<SlashCommandDispatchOutcome> {
    let line = input.line;
    if line.trim() == "/learn" {
        *input.learn_overlay = Some(LearnOverlayState::default());
        *input.learn_overlay_cursor = 0;
        *input.show_logs = false;
        return Ok(SlashCommandDispatchOutcome::Handled);
    }
    if line.starts_with("/learn") {
        if input.run_busy {
            input.logs.push("ERR_TUI_BUSY_TRY_AGAIN".to_string());
            *input.show_logs = true;
            return Ok(SlashCommandDispatchOutcome::Handled);
        }
        match crate::chat_tui_learn_adapter::parse_and_dispatch_learn_slash(
            line,
            input.active_run,
            input.paths,
        )
        .await
        {
            Ok(output) => {
                if !output.is_empty() {
                    input.logs.push(output);
                }
            }
            Err(e) => input.logs.push(format!("learn command failed: {e}")),
        }
        *input.show_logs = true;
        return Ok(SlashCommandDispatchOutcome::Handled);
    }
    let resolved = chat_commands::selected_slash_command(line, input.slash_menu_index)
        .or_else(|| chat_commands::resolve_slash_command(line))
        .unwrap_or(line);
    match resolved {
        "/exit" => return Ok(SlashCommandDispatchOutcome::ExitRequested),
        "/help" => {
            input.logs.push(
                "commands: /help /mode <safe|coding|web|custom> /timeout [seconds|+N|-N|off] /params [key value] /project guidance /tool docs <name> /learn help|list|show|archive|capture|promote /dismiss /clear /exit /hide tools|approvals|logs /show tools|approvals|logs|all ; slash dropdown: type / then Up/Down + Enter ; panes: Ctrl+T/Ctrl+Y/Ctrl+G (Ctrl+1/2/3 aliases, terminal-dependent) ; scroll: PgUp/PgDn, Ctrl+U/Ctrl+D, mouse wheel ; approvals: Ctrl+J/K select, Ctrl+A approve, Ctrl+X deny, Ctrl+R refresh ; history: Up/Down ; Esc quits"
                    .to_string(),
            );
            *input.show_logs = true;
        }
        "/mode" => {
            input.logs.push(format!(
                "current mode: {} (use /mode <safe|coding|web|custom>)",
                chat_runtime::chat_mode_label(input.active_run)
            ));
            *input.show_logs = true;
        }
        "/timeout" => {
            *input.pending_timeout_input = true;
            input
                .logs
                .push(runtime_config::timeout_settings_summary(input.active_run));
            input
                .logs
                .push("enter seconds, +N, -N, or 'cancel' on the next line".to_string());
            *input.show_logs = true;
        }
        "/params" => {
            *input.pending_params_input = true;
            input
                .logs
                .push(runtime_config::params_settings_summary(input.active_run));
            input.logs.push(
                "editable keys: max_steps, max_context_chars, compaction_mode(off|summary), compaction_keep_last, tool_result_persist(all|digest|none), max_tool_output_bytes, max_read_bytes, stream(on|off), allow_shell(on|off), allow_write(on|off), enable_write_tools(on|off), allow_shell_in_workdir(on|off)"
                    .to_string(),
            );
            input
                .logs
                .push("enter '<key> <value>' or 'cancel' on the next line".to_string());
            *input.show_logs = true;
        }
        "/dismiss" => {
            if *input.timeout_notice_active {
                *input.timeout_notice_active = false;
                input.logs.retain(|l| !l.starts_with("[timeout-notice]"));
                input
                    .logs
                    .push("timeout notification dismissed".to_string());
            } else {
                input
                    .logs
                    .push("no active timeout notification".to_string());
            }
            *input.show_logs = true;
        }
        "/tool docs" => {
            input
                .logs
                .push("usage: /tool docs <name> (example: /tool docs mcp.stub.echo)".to_string());
            *input.show_logs = true;
        }
        "/project guidance" => {
            match project_guidance::resolve_project_guidance(
                &input.active_run.workdir,
                project_guidance::ProjectGuidanceLimits::default(),
            ) {
                Ok(g) => input
                    .logs
                    .push(project_guidance::render_project_guidance_text(&g)),
                Err(e) => input
                    .logs
                    .push(format!("project guidance unavailable: {e}")),
            }
            *input.show_logs = true;
        }
        "/clear" => {
            if input.active_run.no_session {
                input.transcript.clear();
                input.ui_state.tool_calls.clear();
                input.streaming_assistant.clear();
                *input.transcript_scroll = 0;
                *input.follow_output = true;
                input.logs.push("cleared chat transcript".to_string());
            } else {
                let session_path = input
                    .paths
                    .sessions_dir
                    .join(format!("{}.json", input.active_run.session));
                let store = SessionStore::new(session_path, input.active_run.session.clone());
                store.reset()?;
                input.transcript.clear();
                input.ui_state.tool_calls.clear();
                input.streaming_assistant.clear();
                *input.transcript_scroll = 0;
                *input.follow_output = true;
                input.logs.push(format!(
                    "session '{}' and transcript cleared",
                    input.active_run.session
                ));
            }
        }
        "/hide tools" => *input.show_tools = false,
        "/hide approvals" => *input.show_approvals = false,
        "/hide logs" => *input.show_logs = false,
        "/show tools" => *input.show_tools = true,
        "/show approvals" => *input.show_approvals = true,
        "/show logs" => *input.show_logs = true,
        "/show all" => {
            *input.show_tools = true;
            *input.show_approvals = true;
            *input.show_logs = true;
        }
        _ if resolved.starts_with("/mode ") => {
            let mode = resolved["/mode ".len()..].trim();
            if runtime_config::apply_chat_mode(input.active_run, mode).is_some() {
                input.logs.push(format!(
                    "mode switched to {}",
                    chat_runtime::chat_mode_label(input.active_run)
                ));
            } else {
                input.logs.push(format!(
                    "unknown mode: {mode}. expected safe|coding|web|custom"
                ));
            }
            *input.show_logs = true;
        }
        _ if resolved.starts_with("/timeout ") => {
            let value = resolved["/timeout ".len()..].trim();
            match runtime_config::apply_timeout_input(input.active_run, value) {
                Ok(msg) => {
                    input.logs.push(msg);
                    *input.show_logs = false;
                }
                Err(msg) => {
                    input.logs.push(msg);
                    *input.show_logs = true;
                }
            }
        }
        _ if resolved.starts_with("/params ") => {
            let value = resolved["/params ".len()..].trim();
            match runtime_config::apply_params_input(input.active_run, value) {
                Ok(msg) => input.logs.push(msg),
                Err(msg) => input.logs.push(msg),
            }
            *input.show_logs = true;
        }
        _ if line.starts_with("/tool docs ") => {
            let tool_name = line["/tool docs ".len()..].trim();
            if tool_name.is_empty() {
                input.logs.push(
                    "usage: /tool docs <name> (example: /tool docs mcp.stub.echo)".to_string(),
                );
                *input.show_logs = true;
                return Ok(SlashCommandDispatchOutcome::Handled);
            }
            if input.active_run.mcp.is_empty() {
                input.logs.push(
                    "MCP registry unavailable: no MCP servers enabled for this chat session"
                        .to_string(),
                );
                *input.show_logs = true;
                return Ok(SlashCommandDispatchOutcome::Handled);
            }
            if input.shared_chat_mcp_registry.is_none() {
                let mcp_config_path = runtime_paths::resolved_mcp_config_path(
                    input.active_run,
                    &input.paths.state_dir,
                );
                match McpRegistry::from_config_path(
                    &mcp_config_path,
                    &input.active_run.mcp,
                    Duration::from_secs(30),
                )
                .await
                {
                    Ok(reg) => {
                        *input.shared_chat_mcp_registry = Some(std::sync::Arc::new(reg));
                    }
                    Err(e) => {
                        input
                            .logs
                            .push(format!("failed to initialize MCP session: {e}"));
                        *input.show_logs = true;
                        return Ok(SlashCommandDispatchOutcome::Handled);
                    }
                }
            }
            if let Some(reg) = input.shared_chat_mcp_registry.as_ref() {
                input.logs.push(reg.render_tool_docs_text(tool_name));
            } else {
                input
                    .logs
                    .push("MCP registry unavailable: failed to initialize".to_string());
            }
            *input.show_logs = true;
        }
        _ => input.logs.push(format!("unknown command: {}", line)),
    }
    Ok(SlashCommandDispatchOutcome::Handled)
}

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
    let mut search_input_cursor = 0usize;
    let mut slash_menu_index: usize = 0;
    let mut learn_overlay: Option<LearnOverlayState> = None;
    let mut learn_overlay_cursor = 0usize;
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
    let mut input_cursor = char_len(&input);

    let run_result: anyhow::Result<()> = async {
        loop {
            ui_state.on_tick(Instant::now());
            let frame = build_tui_render_frame_input(TuiRenderFrameBuildInput {
                active_run: &active_run,
                provider_kind,
                provider_connected,
                model: &model,
                status: &status,
                status_detail: &status_detail,
                transcript: &transcript,
                streaming_assistant: &streaming_assistant,
                ui_state: &ui_state,
                tools_selected: &mut tools_selected,
                tools_focus: &mut tools_focus,
                show_tool_details: &mut show_tool_details,
                approvals_selected: &mut approvals_selected,
                cwd_label: &cwd_label,
                input: &input,
                input_cursor,
                logs: &logs,
                think_tick,
                tui_refresh_ms: base_run.tui_refresh_ms,
                show_tools: &mut show_tools,
                show_approvals: &mut show_approvals,
                show_logs,
                transcript_scroll,
                compact_tools,
                show_banner,
                ui_tick,
                palette_open,
                palette_items: &palette_items,
                palette_selected,
                search_mode,
                search_query: &search_query,
                search_input_cursor,
                slash_menu_index,
                learn_overlay: &learn_overlay,
                learn_overlay_cursor,
            });
            let visible_tool_count =
                frame
                    .ui_state
                    .tool_calls
                    .len()
                    .min(if frame.compact_tools { 20 } else { 12 });

            terminal.draw(|f| {
                chat_ui::draw_chat_frame(
                    f,
                    frame.mode_label,
                    frame.provider_label,
                    frame.provider_connected,
                    frame.model,
                    frame.status,
                    frame.status_detail,
                    frame.transcript,
                    frame.streaming_assistant,
                    frame.ui_state,
                    frame.tools_selected,
                    frame.tools_focus,
                    frame.show_tool_details,
                    frame.approvals_selected,
                    frame.cwd_label,
                    frame.input,
                    frame.input_cursor,
                    frame.input_cursor_visible,
                    frame.logs,
                    frame.think_tick,
                    frame.tui_refresh_ms,
                    frame.show_tools,
                    frame.show_approvals,
                    frame.show_logs,
                    frame.transcript_scroll,
                    frame.compact_tools,
                    frame.show_banner,
                    frame.ui_tick,
                    frame.overlay_text.clone(),
                    frame.learn_overlay.as_ref(),
                );
            })?;

            if event::poll(Duration::from_millis(base_run.tui_refresh_ms))? {
                match handle_tui_outer_event_dispatch(TuiOuterEventDispatchInput {
                    event: event::read()?,
                    status: &status,
                    prompt_history: &mut prompt_history,
                    transcript: &mut transcript,
                    streaming_assistant: &mut streaming_assistant,
                    transcript_scroll: &mut transcript_scroll,
                    follow_output: &mut follow_output,
                    input: &mut input,
                    input_cursor: &mut input_cursor,
                    history_idx: &mut history_idx,
                    slash_menu_index: &mut slash_menu_index,
                    palette_open: &mut palette_open,
                    palette_items: &palette_items,
                    palette_selected: &mut palette_selected,
                    search_mode: &mut search_mode,
                    search_query: &mut search_query,
                    search_line_cursor: &mut search_line_cursor,
                    search_input_cursor: &mut search_input_cursor,
                    ui_state: &mut ui_state,
                    visible_tool_count,
                    show_tools: &mut show_tools,
                    show_approvals: &mut show_approvals,
                    show_logs: &mut show_logs,
                    compact_tools: &mut compact_tools,
                    tools_selected: &mut tools_selected,
                    tools_focus: &mut tools_focus,
                    approvals_selected: &mut approvals_selected,
                    paths,
                    logs: &mut logs,
                    learn_overlay: &mut learn_overlay,
                    learn_overlay_cursor: &mut learn_overlay_cursor,
                }) {
                    TuiOuterEventDispatchOutcome::BreakLoop => break,
                    TuiOuterEventDispatchOutcome::ContinueLoop => continue,
                    TuiOuterEventDispatchOutcome::HandledKey => {
                        if let Some(overlay) = learn_overlay.as_mut() {
                            if let Some(line) = overlay.pending_submit_line.take() {
                                match crate::chat_tui_learn_adapter::parse_and_dispatch_learn_slash(
                                    &line,
                                    &active_run,
                                    paths,
                                )
                                .await
                                {
                                    Ok(output) => {
                                        if !output.is_empty() {
                                            push_overlay_log_dedup(overlay, &output);
                                        }
                                        overlay.write_armed = false;
                                        overlay.inline_message = Some(
                                            "Completed. Step 1: Review logs/output. Step 2: edit fields if needed. Step 3: Ctrl+W then Enter to run again."
                                                .to_string(),
                                        );
                                    }
                                    Err(e) => {
                                        push_overlay_log_dedup(
                                            overlay,
                                            &format!("learn command failed: {e}"),
                                        );
                                        overlay.write_armed = false;
                                        overlay.inline_message = Some(
                                            "Run failed. Step 1: Review error in logs. Step 2: fix inputs/flags. Step 3: Ctrl+W then Enter."
                                                .to_string(),
                                        );
                                    }
                                }
                            }
                        }
                        if logs.len() > max_logs {
                            let drop_n = logs.len() - max_logs;
                            logs.drain(0..drop_n);
                        }
                        ui_tick = ui_tick.saturating_add(1);
                    }
                    TuiOuterEventDispatchOutcome::Noop => {}
                    TuiOuterEventDispatchOutcome::EnterInline => {
                        match handle_tui_enter_submit(TuiEnterSubmitInput {
                            terminal: &mut terminal,
                            input: &mut input,
                            history_idx: &mut history_idx,
                            slash_menu_index: &mut slash_menu_index,
                            pending_timeout_input: &mut pending_timeout_input,
                            pending_params_input: &mut pending_params_input,
                            timeout_notice_active: &mut timeout_notice_active,
                            active_run: &mut active_run,
                            base_run,
                            paths,
                            provider_kind,
                            provider_connected: &mut provider_connected,
                            base_url: &base_url,
                            model: &model,
                            cwd_label: &cwd_label,
                            logs: &mut logs,
                            max_logs,
                            show_logs: &mut show_logs,
                            show_tools: &mut show_tools,
                            show_approvals: &mut show_approvals,
                            show_tool_details: &mut show_tool_details,
                            tools_focus: &mut tools_focus,
                            visible_tool_count,
                            prompt_history: &mut prompt_history,
                            transcript: &mut transcript,
                            streaming_assistant: &mut streaming_assistant,
                            status: &mut status,
                            status_detail: &mut status_detail,
                            think_tick: &mut think_tick,
                            ui_tick: &mut ui_tick,
                            follow_output: &mut follow_output,
                            transcript_scroll: &mut transcript_scroll,
                            ui_state: &mut ui_state,
                            tools_selected: &mut tools_selected,
                            approvals_selected: &mut approvals_selected,
                            compact_tools,
                            show_banner,
                            palette_open,
                            palette_items: &palette_items,
                            palette_selected,
                            search_mode,
                            search_query: &search_query,
                            shared_chat_mcp_registry: &mut shared_chat_mcp_registry,
                            learn_overlay: &mut learn_overlay,
                            input_cursor: &mut input_cursor,
                            search_input_cursor: &mut search_input_cursor,
                            learn_overlay_cursor: &mut learn_overlay_cursor,
                        })
                        .await?
                        {
                            TuiEnterSubmitOutcome::Handled => {}
                            TuiEnterSubmitOutcome::ContinueLoop => continue,
                            TuiEnterSubmitOutcome::ExitRequested => break,
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::{build_learn_overlay_render_model, LearnOverlayInputFocus, LearnOverlayState};
    use crate::chat_ui::{LearnOverlayTab, LearnOverlayWriteState};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use tempfile::tempdir;

    #[test]
    fn learn_overlay_preview_mode_shows_no_writes() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let model = build_learn_overlay_render_model(&s);
        assert_eq!(model.write_state, LearnOverlayWriteState::Preview);
        assert!(!model.will_write);
        assert!(model.writes_to.is_empty());
        assert!(model.equivalent_cli.contains("<required>"));
    }

    #[test]
    fn learn_overlay_armed_mode_shows_staged_writes() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 1,
            summary: "hello".to_string(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: true,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let model = build_learn_overlay_render_model(&s);
        assert_eq!(model.write_state, LearnOverlayWriteState::Armed);
        assert!(model.will_write);
        assert_eq!(model.writes_to.len(), 2);
        assert!(model.equivalent_cli.contains("prompt_guidance"));
        assert!(model.equivalent_cli.contains("--assist"));
    }

    #[test]
    fn learn_overlay_promote_preview_shows_no_writes() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "01ABC".to_string(),
            promote_target_idx: 0,
            promote_slug: "my_slug".to_string(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::PromoteId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let model = build_learn_overlay_render_model(&s);
        assert!(!model.will_write);
        assert!(model.writes_to.is_empty());
        assert!(model
            .equivalent_cli
            .contains("learn promote 01ABC --to check"));
        assert_eq!(model.target_path, ".localagent/checks/<slug>.md");
    }

    #[test]
    fn learn_overlay_promote_armed_pack_shows_pack_writes() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "01ABC".to_string(),
            promote_target_idx: 1,
            promote_slug: String::new(),
            promote_pack_id: "core".to_string(),
            promote_force: true,
            input_focus: LearnOverlayInputFocus::PromotePackId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: true,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let model = build_learn_overlay_render_model(&s);
        assert!(model.will_write);
        assert_eq!(model.writes_to.len(), 3);
        assert_eq!(model.target_path, ".localagent/packs/<pack_id>/PACK.md");
        assert!(model.equivalent_cli.contains("--pack-id core"));
        assert!(model.equivalent_cli.contains("--force"));
    }

    #[test]
    fn promote_submit_line_requires_slug_for_check() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "01ABC".to_string(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::PromoteSlug,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: true,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let err = super::build_overlay_promote_submit_line(&s).expect_err("slug required");
        assert!(err.contains("slug"));
    }

    #[test]
    fn promote_submit_line_builds_agents_command_with_flags() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "01ABC".to_string(),
            promote_target_idx: 2,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: true,
            input_focus: LearnOverlayInputFocus::PromoteId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: true,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let line = super::build_overlay_promote_submit_line(&s).expect("line");
        assert!(line.contains("/learn promote 01ABC --to agents"));
        assert!(line.contains("--force"));
    }

    #[test]
    fn promote_submit_line_requires_pack_id_for_pack() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "01ABC".to_string(),
            promote_target_idx: 1,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::PromotePackId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: true,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let err = super::build_overlay_promote_submit_line(&s).expect_err("pack_id required");
        assert!(err.contains("pack_id"));
    }

    #[test]
    fn learn_overlay_review_preview_shows_no_writes() {
        let s = LearnOverlayState {
            tab: LearnOverlayTab::Review,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::ReviewId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        let model = build_learn_overlay_render_model(&s);
        assert_eq!(model.tab, LearnOverlayTab::Review);
        assert!(!model.will_write);
        assert!(model.writes_to.is_empty());
        assert_eq!(model.equivalent_cli, "learn list");
    }

    #[test]
    fn focus_cycle_promote_wraps() {
        let mut s = LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::PromotePackId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        };
        super::cycle_overlay_focus(&mut s, false);
        assert_eq!(s.input_focus, LearnOverlayInputFocus::PromoteId);
    }

    #[test]
    fn busy_enter_logs_busy_token_for_review() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Review,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::ReviewId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 3usize;
        let mut transcript: Vec<(String, String)> = Vec::new();
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();
        let out = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: true,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        assert!(matches!(out, super::TuiOuterKeyDispatchOutcome::Handled));
        let ov = overlay.expect("overlay");
        assert!(ov.logs.iter().any(|l| l.contains("ERR_TUI_BUSY_TRY_AGAIN")));
    }

    #[test]
    fn busy_enter_logs_busy_token_for_promote() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "01ABC".to_string(),
            promote_target_idx: 2,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::PromoteId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: false,
            write_armed: true,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut transcript: Vec<(String, String)> = Vec::new();
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();
        let out = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: true,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        assert!(matches!(out, super::TuiOuterKeyDispatchOutcome::Handled));
        let ov = overlay.expect("overlay");
        assert!(ov.logs.iter().any(|l| l.contains("ERR_TUI_BUSY_TRY_AGAIN")));
    }

    #[test]
    fn capture_preview_enter_does_not_set_submit_line() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: "hello".to_string(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut transcript: Vec<(String, String)> = vec![("user".to_string(), "hi".to_string())];
        let before = transcript.clone();
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();
        let out = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: false,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        assert!(matches!(out, super::TuiOuterKeyDispatchOutcome::Handled));
        let ov = overlay.expect("overlay");
        assert!(ov.pending_submit_line.is_none());
        assert!(ov
            .inline_message
            .as_deref()
            .unwrap_or("")
            .contains("Press Enter for preview only"));
        assert_eq!(transcript, before);
    }

    #[test]
    fn capture_preview_enter_dedups_preflight_log() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: "hello".to_string(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut transcript: Vec<(String, String)> = vec![("user".to_string(), "hi".to_string())];
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();

        for _ in 0..3 {
            let out = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
                key: KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                learn_overlay: &mut overlay,
                run_busy: false,
                input: &mut input_buf,
            input_cursor: &mut input_cursor,
                prompt_history: &mut prompt_history,
                history_idx: &mut history_idx,
                slash_menu_index: &mut slash_menu_index,
                palette_open: &mut palette_open,
                palette_items: &palette_items,
                palette_selected: &mut palette_selected,
                search_mode: &mut search_mode,
                search_query: &mut search_query,
                search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
                transcript: &mut transcript,
                streaming_assistant: &mut streaming,
                transcript_scroll: &mut transcript_scroll,
                follow_output: &mut follow_output,
                ui_state: &mut ui_state,
                visible_tool_count: 0,
                show_tools: &mut show_tools,
                show_approvals: &mut show_approvals,
                show_logs: &mut show_logs,
                compact_tools: &mut compact_tools,
                tools_selected: &mut tools_selected,
                tools_focus: &mut tools_focus,
                approvals_selected: &mut approvals_selected,
                paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
            });
            assert!(matches!(out, super::TuiOuterKeyDispatchOutcome::Handled));
        }

        let ov = overlay.expect("overlay");
        let preflight = "info: Preflight check complete. Waiting for user action.";
        let count = ov.logs.iter().filter(|l| l.as_str() == preflight).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn esc_closes_overlay_even_when_run_busy() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: "hello".to_string(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut transcript: Vec<(String, String)> = vec![];
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();
        let out = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: true,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        assert!(matches!(out, super::TuiOuterKeyDispatchOutcome::Handled));
        assert!(overlay.is_none());
    }

    #[test]
    fn ctrl_1_switches_to_capture_but_plain_1_is_text_input() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Promote,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: "abc".to_string(),
            promote_target_idx: 2,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::PromoteId,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 3usize;
        let mut transcript: Vec<(String, String)> = vec![];
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();

        let out_plain = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: false,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        assert!(matches!(
            out_plain,
            super::TuiOuterKeyDispatchOutcome::Handled
        ));
        let ov_plain = overlay.as_ref().expect("overlay");
        assert_eq!(ov_plain.tab, LearnOverlayTab::Promote);
        assert_eq!(ov_plain.promote_id, "abc1");

        let out_ctrl = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Char('1'), KeyModifiers::CONTROL),
            learn_overlay: &mut overlay,
            run_busy: false,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        assert!(matches!(
            out_ctrl,
            super::TuiOuterKeyDispatchOutcome::Handled
        ));
        let ov_ctrl = overlay.as_ref().expect("overlay");
        assert_eq!(ov_ctrl.tab, LearnOverlayTab::Capture);
    }

    #[test]
    fn overlay_paste_is_bounded_and_deduped_for_summary() {
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input = String::new();
        let mut input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let spam = "'FastVideoProcessor' object has no attribute '_artifact_manager'";

        for _ in 0..10 {
            super::handle_tui_outer_paste_event(super::TuiOuterPasteInput {
                pasted: spam,
                input: &mut input,
                input_cursor: &mut input_cursor,
                history_idx: &mut history_idx,
                slash_menu_index: &mut slash_menu_index,
                learn_overlay: &mut overlay,
                learn_overlay_cursor: &mut learn_overlay_cursor,
            });
        }

        let ov = overlay.expect("overlay");
        assert!(ov.summary.len() <= super::OVERLAY_CAPTURE_SUMMARY_MAX_CHARS);
        assert!(ov.summary.contains("_artifact_manager"));
    }

    #[test]
    fn overlay_text_input_allows_consecutive_same_chars() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut transcript: Vec<(String, String)> = vec![];
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();

        let _ = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: false,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });
        let _ = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: false,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });

        let ov = overlay.expect("overlay");
        assert_eq!(ov.summary, "aa");
    }

    #[test]
    fn overlay_plain_q_is_text_not_close_shortcut() {
        let tmp = tempdir().expect("tempdir");
        let paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut overlay = Some(LearnOverlayState {
            tab: LearnOverlayTab::Capture,
            category_idx: 0,
            summary: String::new(),
            review_id: String::new(),
            promote_id: String::new(),
            promote_target_idx: 0,
            promote_slug: String::new(),
            promote_pack_id: String::new(),
            promote_force: false,
            input_focus: LearnOverlayInputFocus::CaptureSummary,
            inline_message: None,
            review_rows: Vec::new(),
            review_selected_idx: 0,
            assist_on: true,
            write_armed: false,
            logs: vec![],
            pending_submit_line: None,
            assist_summary: None,
            summary_choice: crate::chat_ui::LearnOverlaySummaryChoice::Original,
            selected_summary: None,
        });
        let mut input_buf = String::new();
        let mut input_cursor = 0usize;
        let mut prompt_history = Vec::new();
        let mut history_idx = None;
        let mut slash_menu_index = 0usize;
        let mut palette_open = false;
        let palette_items = ["a"];
        let mut palette_selected = 0usize;
        let mut search_mode = false;
        let mut search_query = String::new();
        let mut search_line_cursor = 0usize;
        let mut search_input_cursor = 0usize;
        let mut learn_overlay_cursor = 0usize;
        let mut transcript: Vec<(String, String)> = vec![];
        let mut streaming = String::new();
        let mut transcript_scroll = 0usize;
        let mut follow_output = true;
        let mut ui_state = crate::tui::state::UiState::new(100);
        let mut show_tools = false;
        let mut show_approvals = false;
        let mut show_logs = false;
        let mut compact_tools = true;
        let mut tools_selected = 0usize;
        let mut tools_focus = true;
        let mut approvals_selected = 0usize;
        let mut logs = Vec::new();

        let _ = super::handle_tui_outer_key_dispatch(super::TuiOuterKeyDispatchInput {
            key: KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            learn_overlay: &mut overlay,
            run_busy: false,
            input: &mut input_buf,
            input_cursor: &mut input_cursor,
            prompt_history: &mut prompt_history,
            history_idx: &mut history_idx,
            slash_menu_index: &mut slash_menu_index,
            palette_open: &mut palette_open,
            palette_items: &palette_items,
            palette_selected: &mut palette_selected,
            search_mode: &mut search_mode,
            search_query: &mut search_query,
            search_line_cursor: &mut search_line_cursor,
            search_input_cursor: &mut search_input_cursor,
            transcript: &mut transcript,
            streaming_assistant: &mut streaming,
            transcript_scroll: &mut transcript_scroll,
            follow_output: &mut follow_output,
            ui_state: &mut ui_state,
            visible_tool_count: 0,
            show_tools: &mut show_tools,
            show_approvals: &mut show_approvals,
            show_logs: &mut show_logs,
            compact_tools: &mut compact_tools,
            tools_selected: &mut tools_selected,
            tools_focus: &mut tools_focus,
            approvals_selected: &mut approvals_selected,
            paths: &paths,
            logs: &mut logs,
            learn_overlay_cursor: &mut learn_overlay_cursor,
        });

        let ov = overlay.expect("overlay still open");
        assert_eq!(ov.summary, "q");
    }
}




