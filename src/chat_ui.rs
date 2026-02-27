use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::tui::state::{ToolRow, UiState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LearnOverlayTab {
    Capture,
    Review,
    Promote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LearnOverlayWriteState {
    Preview,
    Armed,
}

#[derive(Debug, Clone)]
pub(crate) struct LearnOverlayRenderModel {
    pub(crate) tab: LearnOverlayTab,
    pub(crate) selected_category_idx: usize,
    pub(crate) summary: String,
    pub(crate) review_id: String,
    pub(crate) promote_id: String,
    pub(crate) promote_target_idx: usize,
    pub(crate) promote_slug: String,
    pub(crate) promote_pack_id: String,
    pub(crate) promote_force: bool,
    pub(crate) promote_check_run: bool,
    pub(crate) promote_replay_verify: bool,
    pub(crate) promote_replay_verify_strict: bool,
    pub(crate) promote_replay_verify_run_id: String,
    pub(crate) input_focus: String,
    pub(crate) inline_message: Option<String>,
    pub(crate) review_rows: Vec<String>,
    pub(crate) review_selected_idx: usize,
    pub(crate) assist_on: bool,
    pub(crate) write_state: LearnOverlayWriteState,
    pub(crate) equivalent_cli: String,
    pub(crate) will_write: bool,
    pub(crate) writes_to: Vec<String>,
    pub(crate) target_path: String,
    pub(crate) sensitivity_paths: bool,
    pub(crate) sensitivity_secrets: bool,
    pub(crate) sensitivity_userdata: bool,
    pub(crate) overlay_logs: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn draw_chat_frame(
    f: &mut ratatui::Frame<'_>,
    mode_label: &str,
    provider_name: &str,
    provider_connected: bool,
    model: &str,
    status: &str,
    status_detail: &str,
    transcript: &[(String, String)],
    streaming_assistant: &str,
    ui_state: &UiState,
    tools_selected: usize,
    tools_focus: bool,
    show_tool_details: bool,
    approvals_selected: usize,
    cwd_label: &str,
    input: &str,
    logs: &[String],
    think_tick: u64,
    tui_refresh_ms: u64,
    show_tools: bool,
    show_approvals: bool,
    show_logs: bool,
    transcript_scroll: usize,
    compact_tools: bool,
    show_banner: bool,
    ui_tick: u64,
    overlay_hint: Option<String>,
    learn_overlay: Option<&LearnOverlayRenderModel>,
) {
    let input_display = format!("> {input}");
    let input_width = f.area().width.saturating_sub(2).max(1) as usize;
    let input_total_lines = crate::chat_view_utils::wrapped_line_count(&input_display, input_width);
    let max_input_lines = usize::from(f.area().height.saturating_sub(12)).clamp(1, 8);
    let input_visible_lines = input_total_lines.min(max_input_lines).max(1);
    let input_scroll = input_total_lines.saturating_sub(input_visible_lines);
    let input_section_height = (input_visible_lines as u16).saturating_add(2);

    let bottom_overlay_height = if overlay_hint.is_some() {
        9
    } else if show_logs {
        5
    } else {
        0
    };
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(1),
            Constraint::Length(input_section_height),
            Constraint::Length(1),
            Constraint::Length(bottom_overlay_height),
        ])
        .split(f.area());

    let left_header = format!("{mode_label}  ·  {provider_name}  ·  {model}");
    let right_header = "?";
    let header_pad = outer[0]
        .width
        .saturating_sub((left_header.chars().count() + right_header.chars().count()) as u16)
        as usize;
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(mode_label, Style::default().fg(Color::Yellow)),
            Span::raw("  ·  "),
            Span::styled(
                provider_name,
                Style::default().fg(if provider_connected {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
            Span::raw("  ·  "),
            Span::styled(model, Style::default().fg(Color::Yellow)),
            Span::raw(" ".repeat(header_pad)),
            Span::raw(right_header),
        ])),
        outer[0],
    );
    f.render_widget(
        Paragraph::new(crate::chat_view_utils::horizontal_rule(outer[1].width))
            .style(Style::default().fg(Color::DarkGray)),
        outer[1],
    );

    let has_side = show_tools || show_approvals;
    let (chat_area, separator_area, side_area) = if has_side {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(71),
                Constraint::Length(1),
                Constraint::Percentage(28),
            ])
            .split(outer[2]);
        (cols[0], Some(cols[1]), Some(cols[2]))
    } else {
        (outer[2], None, None)
    };

    let show_hero_banner = show_banner && transcript.is_empty() && streaming_assistant.is_empty();
    let mut chat_text = String::new();
    if show_hero_banner {
        chat_text.push_str(&crate::chat_view_utils::centered_multiline(
            &crate::chat_view_utils::localagent_banner(ui_tick),
            chat_area.width,
            0,
        ));
        chat_text.push_str("\n\n");
        chat_text.push_str(&crate::chat_view_utils::centered_left_block(
            "+ Type your message and press enter\n+ /help for a list of commands\n+ /mode to switch between Safe, Coding, Web, and Custom modes",
            chat_area.width,
            0,
        ));
    }
    let transcript_text = transcript
        .iter()
        .map(|(role, text)| format!("{}: {}", role.to_uppercase(), text))
        .collect::<Vec<_>>()
        .join("\n\n");
    if !transcript_text.is_empty() {
        if !chat_text.is_empty() {
            chat_text.push_str("\n\n");
        }
        chat_text.push_str(&transcript_text);
    }
    if !streaming_assistant.is_empty() {
        if !chat_text.is_empty() {
            chat_text.push_str("\n\n");
        }
        chat_text.push_str(&format!("ASSISTANT: {}", streaming_assistant));
    }
    let chat_style = if show_hero_banner {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let (chat_render, chat_plain) =
        crate::chat_view_utils::styled_chat_text(&chat_text, chat_style);
    let chat_width = chat_area.width.max(1) as usize;
    let chat_visible_lines = chat_area.height.max(1) as usize;
    let chat_total_lines = crate::chat_view_utils::wrapped_line_count(&chat_plain, chat_width);
    let max_scroll = chat_total_lines.saturating_sub(chat_visible_lines);
    let scroll = if transcript_scroll == usize::MAX {
        max_scroll
    } else {
        transcript_scroll.min(max_scroll)
    };
    f.render_widget(
        Paragraph::new(chat_render)
            .wrap(Wrap { trim: false })
            .scroll((scroll.min(u16::MAX as usize) as u16, 0)),
        chat_area,
    );

    if let Some(sep) = separator_area {
        let sep_text = vec!["│"; sep.height as usize].join("\n");
        f.render_widget(
            Paragraph::new(sep_text).style(Style::default().fg(Color::Yellow)),
            sep,
        );
    }

    if let Some(side) = side_area {
        match (show_tools, show_approvals) {
            (true, true) => {
                let right = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(side);
                draw_tools_pane(
                    f,
                    right[0],
                    ui_state,
                    compact_tools,
                    tools_selected,
                    tools_focus,
                    show_tool_details,
                );
                draw_approvals_pane(f, right[1], ui_state, approvals_selected, !tools_focus);
            }
            (true, false) => draw_tools_pane(
                f,
                side,
                ui_state,
                compact_tools,
                tools_selected,
                true,
                show_tool_details,
            ),
            (false, true) => draw_approvals_pane(f, side, ui_state, approvals_selected, true),
            (false, false) => {}
        }
    }

    let tools_running = ui_state.tool_calls.iter().any(|t| t.status == "running");
    let wave = ["▁", "▂", "▃", "▄", "▅", "▄", "▃", "▂"];
    let phase = ((think_tick / 3) % wave.len() as u64) as usize;
    let glow_style = Style::default().fg(match phase {
        0 | 1 => Color::DarkGray,
        2 | 3 => Color::Blue,
        4 | 5 => Color::Cyan,
        _ => Color::White,
    });
    let thinking_words = [
        "Thinking",
        "Reasoning",
        "Deliberating",
        "Considering",
        "Reflecting",
        "Analyzing",
        "Evaluating",
        "Inferring",
        "Planning",
        "Synthesizing",
        "Pondering",
        "Thinkering",
        "Thought-brewing",
        "Mind-marinating",
        "Ruminating",
        "idea-bombing",
    ];
    let working_words = [
        "Working",
        "Executing",
        "Processing",
        "Applying tools",
        "Building result",
        "Finalizing",
    ];
    let (status_text, status_style) = if status == "running" {
        if tools_running {
            (
                crate::chat_view_utils::rotating_status_word(
                    &working_words,
                    think_tick,
                    tui_refresh_ms,
                    0xA5A5_A5A5,
                ),
                Style::default().fg(Color::Yellow),
            )
        } else {
            (
                crate::chat_view_utils::rotating_status_word(
                    &thinking_words,
                    think_tick,
                    tui_refresh_ms,
                    0x5A5A_5A5A,
                ),
                Style::default().fg(Color::Cyan),
            )
        }
    } else {
        ("Ready", Style::default().fg(Color::DarkGray))
    };
    let status_hint = crate::chat_view_utils::activity_status_hint(ui_state, status);
    let mut status_spans = vec![
        if status == "running" {
            Span::styled(wave[phase], glow_style)
        } else {
            Span::styled("●", Style::default().fg(Color::DarkGray))
        },
        Span::raw(" "),
        if status == "running" {
            Span::styled(format!("{status_text}..."), status_style)
        } else {
            Span::styled(status_text, status_style)
        },
    ];
    if let Some(hint) = status_hint {
        status_spans.push(Span::raw("  "));
        status_spans.push(Span::styled(hint, Style::default().fg(Color::DarkGray)));
    }
    if !status_detail.trim().is_empty() {
        status_spans.push(Span::raw("  "));
        status_spans.push(Span::styled(
            crate::chat_view_utils::compact_status_detail(status_detail, 140),
            Style::default().fg(Color::Red),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(status_spans)), outer[3]);

    let input_box = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(input_visible_lines as u16),
            Constraint::Length(1),
        ])
        .split(outer[4]);
    f.render_widget(
        Paragraph::new(crate::chat_view_utils::horizontal_rule(input_box[0].width))
            .style(Style::default().fg(Color::DarkGray)),
        input_box[0],
    );
    f.render_widget(
        Paragraph::new(input_display)
            .wrap(Wrap { trim: false })
            .scroll((input_scroll as u16, 0)),
        input_box[1],
    );
    f.render_widget(
        Paragraph::new(crate::chat_view_utils::horizontal_rule(input_box[2].width))
            .style(Style::default().fg(Color::DarkGray)),
        input_box[2],
    );

    let footer_left = format!("cwd: {cwd_label}");
    let footer_right = if provider_connected {
        "Status - Connected"
    } else {
        "Status - Disconnected"
    };
    let footer_pad = outer[5]
        .width
        .saturating_sub((footer_left.chars().count() + footer_right.chars().count()) as u16)
        as usize;
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("cwd:", Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(cwd_label, Style::default().fg(Color::Yellow)),
            Span::raw(" ".repeat(footer_pad)),
            Span::styled("Status - ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if provider_connected {
                    "Connected"
                } else {
                    "Disconnected"
                },
                Style::default().fg(if provider_connected {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ])),
        outer[5],
    );

    if bottom_overlay_height > 0 {
        let overlay = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .split(outer[6]);
        f.render_widget(
            Paragraph::new(crate::chat_view_utils::horizontal_rule(overlay[0].width))
                .style(Style::default().fg(Color::DarkGray)),
            overlay[0],
        );
        if overlay_hint.is_some() {
            f.render_widget(Paragraph::new(""), overlay[1]);
        } else {
            f.render_widget(
                Paragraph::new("Logs (F3 to hide):").style(Style::default().fg(Color::DarkGray)),
                overlay[1],
            );
        }
        let logs_text = if let Some(hint) = overlay_hint {
            hint
        } else {
            logs.join("\n")
        };
        f.render_widget(
            Paragraph::new(logs_text).wrap(Wrap { trim: false }),
            overlay[2],
        );
    }

    if let Some(overlay) = learn_overlay {
        draw_learn_overlay(f, overlay);
    }
}

fn draw_learn_overlay(f: &mut ratatui::Frame<'_>, overlay: &LearnOverlayRenderModel) {
    let area = centered_rect(92, 86, f.area());
    f.render_widget(Clear, area);
    f.render_widget(
        Block::default()
            .title(" LEARN OVERLAY ")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow)),
        area,
    );

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(12),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(area);

    let tabs = format!(
        "{}  {}  {}",
        tab_label(1, LearnOverlayTab::Capture, overlay.tab),
        tab_label(2, LearnOverlayTab::Review, overlay.tab),
        tab_label(3, LearnOverlayTab::Promote, overlay.tab)
    );
    let target = match overlay.tab {
        LearnOverlayTab::Capture => "Target: Capture",
        LearnOverlayTab::Review => "Target: Review",
        LearnOverlayTab::Promote => "Target: Promote",
    };
    let pad = outer[0]
        .width
        .saturating_sub((tabs.chars().count() + target.chars().count()) as u16)
        as usize;
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(tabs, Style::default().fg(Color::Yellow)),
            Span::raw(" ".repeat(pad)),
            Span::styled(target, Style::default().fg(Color::Gray)),
        ])),
        outer[0],
    );
    f.render_widget(
        Paragraph::new(crate::chat_view_utils::horizontal_rule(outer[1].width))
            .style(Style::default().fg(Color::DarkGray)),
        outer[1],
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(outer[2]);

    match overlay.tab {
        LearnOverlayTab::Capture => {
            draw_learn_capture_form(f, body[0], overlay);
            draw_learn_cli_review(f, body[1], overlay);
        }
        LearnOverlayTab::Review => {
            draw_learn_review_form(f, body[0], overlay);
            draw_learn_cli_review(f, body[1], overlay);
        }
        LearnOverlayTab::Promote => {
            draw_learn_promote_form(f, body[0], overlay);
            draw_learn_cli_review(f, body[1], overlay);
        }
    }

    let hints = match overlay.tab {
        LearnOverlayTab::Capture => format!(
            "Capture: Enter Preview/Run | Ctrl+W Arm | Ctrl+A Assist:{} | Tab Focus | Esc/Q Close | Ctrl+1/2/3 Tabs",
            if overlay.assist_on { "ON" } else { "OFF" },
        ),
        LearnOverlayTab::Review => {
            "Review: Enter Preview | Up/Down Select | Tab Focus | Esc/Q Close | Ctrl+1/2/3 Tabs"
                .to_string()
        }
        LearnOverlayTab::Promote => {
            "Promote: Left/Right Target | Ctrl+W Arm | Enter Run | Ctrl+F/K/R/S Flags | Tab Focus | Esc/Q Close | Ctrl+1/2/3 Tabs".to_string()
        }
    };
    f.render_widget(
        Paragraph::new(hints)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Gray)),
        outer[3],
    );

    let logs = if overlay.overlay_logs.is_empty() {
        "LOGS: learn".to_string()
    } else {
        format!("LOGS: learn  {}", overlay.overlay_logs.join("  "))
    };
    f.render_widget(
        Paragraph::new(logs)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(Color::Yellow)),
        outer[4],
    );
}

fn draw_learn_capture_form(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    overlay: &LearnOverlayRenderModel,
) {
    let block = Block::default()
        .title(" - CAPTURE FORM ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(4),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);
    f.render_widget(Paragraph::new("Category:"), rows[0]);
    let categories = ["workflow_hint", "prompt_guidance", "check_candidate"];
    let cat_text = categories
        .iter()
        .enumerate()
        .map(|(idx, c)| {
            if idx == overlay.selected_category_idx {
                format!("> {c}")
            } else {
                format!("  {c}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    f.render_widget(
        Paragraph::new(cat_text).style(Style::default().fg(Color::Yellow)),
        rows[1],
    );
    let category_help = match overlay.selected_category_idx {
        0 => "workflow_hint: reusable process/pattern to follow next time",
        1 => "prompt_guidance: prompting instruction that improves tool/model behavior",
        _ => "check_candidate: candidate check to promote into .localagent/checks/",
    };
    f.render_widget(
        Paragraph::new(category_help)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Gray)),
        rows[2],
    );
    let summary_label = if overlay.input_focus == "capture.summary" {
        "Summary: <required>  [active]"
    } else {
        "Summary: <required>"
    };
    f.render_widget(
        Paragraph::new(summary_label).style(Style::default().fg(Color::Gray)),
        rows[3],
    );
    let summary = if overlay.summary.trim().is_empty() {
        "< Enter concise summary here... >".to_string()
    } else {
        overlay.summary.clone()
    };
    f.render_widget(
        Paragraph::new(summary)
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::DarkGray)),
            ),
        rows[4],
    );
    let requirement = if overlay.summary.trim().is_empty() {
        "summary: <required>"
    } else {
        "summary: ok"
    };
    f.render_widget(
        Paragraph::new(requirement).style(Style::default().fg(Color::Gray)),
        rows[5],
    );
    let focus_line = format!("field focus: {}", overlay.input_focus);
    f.render_widget(
        Paragraph::new(focus_line).style(Style::default().fg(Color::Gray)),
        rows[6],
    );
    if let Some(msg) = overlay.inline_message.as_deref() {
        f.render_widget(
            Paragraph::new(msg).style(Style::default().fg(Color::Red)),
            rows[6],
        );
    }
    f.render_widget(Paragraph::new("▸ Advanced Parameters"), rows[7]);
    f.render_widget(Paragraph::new("▸ Proposed Memory"), rows[8]);
    f.render_widget(Paragraph::new("▸ Evidence Rows"), rows[9]);
}

fn draw_learn_cli_review(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    overlay: &LearnOverlayRenderModel,
) {
    let tab_name = match overlay.tab {
        LearnOverlayTab::Capture => "capture",
        LearnOverlayTab::Review => "review",
        LearnOverlayTab::Promote => "promote",
    };
    let block = Block::default()
        .title(format!(" - CLI REVIEW ({tab_name}) "))
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let write_state = match overlay.write_state {
        LearnOverlayWriteState::Preview => "PREVIEW",
        LearnOverlayWriteState::Armed => "ARMED",
    };
    let writes_to = if overlay.writes_to.is_empty() {
        "none".to_string()
    } else {
        overlay
            .writes_to
            .iter()
            .map(|p| format!("• {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let text = format!(
        "Equivalent CLI:\n{}\n\nWrite State: {write_state}\nWill write: {}\nWrites to:\n{}\n\nTarget path: {}\n\nSensitivity flags:\n• Paths: {}\n• Secrets: {}\n• Userdata: {}",
        overlay.equivalent_cli,
        if overlay.will_write { "YES" } else { "NO" },
        writes_to,
        overlay.target_path,
        yes_no(overlay.sensitivity_paths),
        yes_no(overlay.sensitivity_secrets),
        yes_no(overlay.sensitivity_userdata)
    );
    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
}

fn draw_learn_review_form(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    overlay: &LearnOverlayRenderModel,
) {
    let block = Block::default()
        .title(" - REVIEW FORM ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let selected = if overlay.review_id.trim().is_empty() {
        "<empty>".to_string()
    } else {
        overlay.review_id.clone()
    };
    let rows = if overlay.review_rows.is_empty() {
        "• (no rows loaded) press Enter to load list".to_string()
    } else {
        overlay
            .review_rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                if i == overlay.review_selected_idx {
                    format!("> {r}")
                } else {
                    format!("  {r}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let id_label = if overlay.input_focus == "review.id" {
        "Selected ID [active]"
    } else {
        "Selected ID"
    };
    let mut text = format!(
        "Mode: list/show\n\n{id_label}: {selected}\nField focus: {}\n\nRows:\n{rows}\n\nEnter runs read-only list/show.",
        overlay.input_focus
    );
    if let Some(msg) = overlay.inline_message.as_deref() {
        text.push_str(&format!("\n\n{msg}"));
    }
    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
}

fn draw_learn_promote_form(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    overlay: &LearnOverlayRenderModel,
) {
    let block = Block::default()
        .title(" - PROMOTE FORM ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let targets = ["check", "pack", "agents"];
    let target = targets[overlay.promote_target_idx.min(2)];
    let id_label = if overlay.input_focus == "promote.id" {
        "ID (required) [active]"
    } else {
        "ID (required)"
    };
    let slug_label = if overlay.input_focus == "promote.slug" {
        "slug [active]"
    } else {
        "slug"
    };
    let pack_label = if overlay.input_focus == "promote.pack_id" {
        "pack_id [active]"
    } else {
        "pack_id"
    };
    let replay_id_label = if overlay.input_focus == "promote.replay_run_id" {
        "replay_verify_run_id [active]"
    } else {
        "replay_verify_run_id"
    };
    let mut text = format!(
        "{id_label}: {}\nTarget: {target}\n{slug_label}: {}\n{pack_label}: {}\n\nforce:{}  check_run:{}  replay_verify:{}  replay_verify_strict:{}\n{replay_id_label}: {}",
        if overlay.promote_id.trim().is_empty() {
            "<required>"
        } else {
            overlay.promote_id.as_str()
        },
        if overlay.promote_slug.trim().is_empty() {
            "<empty>"
        } else {
            overlay.promote_slug.as_str()
        },
        if overlay.promote_pack_id.trim().is_empty() {
            "<empty>"
        } else {
            overlay.promote_pack_id.as_str()
        },
        if overlay.promote_force { "ON" } else { "off" },
        if overlay.promote_check_run { "ON" } else { "off" },
        if overlay.promote_replay_verify { "ON" } else { "off" },
        if overlay.promote_replay_verify_strict { "ON" } else { "off" },
        if overlay.promote_replay_verify_run_id.trim().is_empty() {
            "<empty>"
        } else {
            overlay.promote_replay_verify_run_id.as_str()
        }
    );
    text.push_str(&format!(
        "\n\nField focus: {}\nTarget switch: [Left/Right]\nField focus cycle: [Tab]/[Shift+Tab]",
        overlay.input_focus
    ));
    if let Some(msg) = overlay.inline_message.as_deref() {
        text.push_str(&format!("\n\n{msg}"));
    }
    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
}

fn tab_label(num: u8, tab: LearnOverlayTab, active: LearnOverlayTab) -> String {
    let label = match tab {
        LearnOverlayTab::Capture => "Capture",
        LearnOverlayTab::Review => "Review",
        LearnOverlayTab::Promote => "Promote",
    };
    if tab == active {
        format!("[{num}] {label}")
    } else {
        format!("[{num}] {label}")
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "YES"
    } else {
        "NO"
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn draw_tools_pane(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    ui_state: &UiState,
    compact_tools: bool,
    tools_selected: usize,
    focused: bool,
    show_details: bool,
) {
    let row_count = if compact_tools { 20 } else { 12 };
    let rows: Vec<&ToolRow> = ui_state.tool_calls.iter().rev().take(row_count).collect();
    let selected = rows.get(tools_selected).copied();
    let summary = format!(
        "Tools {}  rows:{}  selected:{}/{}",
        if focused { "[focused]" } else { "" },
        rows.len(),
        if rows.is_empty() {
            0
        } else {
            tools_selected + 1
        },
        rows.len()
    );

    let layout = if show_details && selected.is_some() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(3),
                Constraint::Length(4),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(3),
                Constraint::Length(0),
            ])
            .split(area)
    };

    f.render_widget(
        Paragraph::new(summary).style(Style::default().fg(Color::DarkGray)),
        layout[0],
    );

    let total_w = layout[1].width.max(12);
    let tool_w = ((total_w as usize * 44) / 100).max(10) as u16;
    let status_w = ((total_w as usize * 17) / 100).max(8) as u16;
    let decision_w = ((total_w as usize * 27) / 100).max(9) as u16;
    let fixed = tool_w.saturating_add(status_w).saturating_add(decision_w);
    let ok_w = total_w.saturating_sub(fixed).max(4);

    let tool_rows = rows.iter().enumerate().map(|(idx, t)| {
        let is_selected = idx == tools_selected;
        let style = if is_selected {
            if focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            }
        } else {
            Style::default()
        };
        let tool_label = if is_protocol_badge_row(t) {
            format!("[PROTO] {}", t.tool_name)
        } else {
            t.tool_name.clone()
        };
        Row::new(vec![
            Cell::from(truncate_cell(
                &tool_label,
                tool_w.saturating_sub(1) as usize,
            )),
            Cell::from(truncate_cell(
                &t.status,
                status_w.saturating_sub(1) as usize,
            )),
            Cell::from(truncate_cell(
                t.decision.as_deref().unwrap_or("-"),
                decision_w.saturating_sub(1) as usize,
            )),
            Cell::from(
                t.ok.map(|v| if v { "ok" } else { "fail" })
                    .unwrap_or("-")
                    .to_string(),
            ),
        ])
        .style(style)
    });
    f.render_widget(
        Table::new(
            tool_rows,
            [
                Constraint::Length(tool_w),
                Constraint::Length(status_w),
                Constraint::Length(decision_w),
                Constraint::Length(ok_w),
            ],
        )
        .header(Row::new(vec!["Tool", "Status", "Decision", "OK"])),
        layout[1],
    );

    if show_details {
        if let Some(t) = selected {
            let detail = format!(
                "id: {}\nside_effects: {}\nreason: {}\nresult: {}",
                truncate_cell(&t.tool_call_id, 72),
                truncate_cell(&t.side_effects, 72),
                truncate_cell(t.decision_reason.as_deref().unwrap_or("-"), 72),
                truncate_cell(&t.short_result, 72),
            );
            f.render_widget(
                Paragraph::new(detail)
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(Color::DarkGray)),
                layout[2],
            );
        }
    }
}

fn draw_approvals_pane(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    ui_state: &UiState,
    approvals_selected: usize,
    focused: bool,
) {
    let summary = format!(
        "Approvals {}  pending:{}",
        if focused { "[focused]" } else { "" },
        ui_state.pending_approvals.len()
    );
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);
    f.render_widget(
        Paragraph::new(summary).style(Style::default().fg(Color::DarkGray)),
        layout[0],
    );

    let total_w = layout[1].width.max(12);
    let id_w = ((total_w as usize * 36) / 100).max(10) as u16;
    let status_w = ((total_w as usize * 19) / 100).max(8) as u16;
    let tool_w = total_w.saturating_sub(id_w).saturating_sub(status_w).max(8);

    let approval_rows = ui_state.pending_approvals.iter().enumerate().map(|(i, a)| {
        let style = if i == approvals_selected {
            if focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            }
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(truncate_cell(&a.id, id_w.saturating_sub(1) as usize)),
            Cell::from(truncate_cell(
                &a.status,
                status_w.saturating_sub(1) as usize,
            )),
            Cell::from(truncate_cell(&a.tool, tool_w.saturating_sub(1) as usize)),
        ])
        .style(style)
    });
    f.render_widget(
        Table::new(
            approval_rows,
            [
                Constraint::Length(id_w),
                Constraint::Length(status_w),
                Constraint::Length(tool_w),
            ],
        )
        .header(Row::new(vec!["Approval", "Status", "Tool"])),
        layout[1],
    );
}

fn truncate_cell(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut out = String::new();
    for (count, ch) in s.chars().enumerate() {
        if count >= max_chars {
            break;
        }
        out.push(ch);
    }
    if s.chars().count() > max_chars {
        if max_chars >= 3 {
            out.truncate(max_chars.saturating_sub(3));
            out.push_str("...");
        } else {
            out.truncate(max_chars);
        }
    }
    out
}

fn is_protocol_badge_row(t: &ToolRow) -> bool {
    if t.reason_token == "protocol" || t.status.to_ascii_lowercase().contains("protocol") {
        return true;
    }
    let sr = t.short_result.to_ascii_lowercase();
    sr.contains("model_tool_protocol_violation")
        || sr.contains("repeated malformed tool calls")
        || sr.contains("repeated invalid patch format")
        || sr.contains("tool-only phase")
}
