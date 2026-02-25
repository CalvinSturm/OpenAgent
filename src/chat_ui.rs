use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use crate::tui::state::{ToolRow, UiState};

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
) {
    let input_display = format!("> {input}");
    let input_width = f.area().width.saturating_sub(2).max(1) as usize;
    let input_total_lines = crate::wrapped_line_count(&input_display, input_width);
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
        Paragraph::new(crate::horizontal_rule(outer[1].width))
            .style(Style::default().fg(Color::DarkGray)),
        outer[1],
    );

    let has_side = show_tools || show_approvals;
    let mid = if has_side {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
            .split(outer[2])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(100), Constraint::Percentage(0)])
            .split(outer[2])
    };

    let show_hero_banner = show_banner && transcript.is_empty() && streaming_assistant.is_empty();
    let mut chat_text = String::new();
    if show_hero_banner {
        chat_text.push_str(&crate::centered_multiline(
            &crate::localagent_banner(ui_tick),
            mid[0].width,
            0,
        ));
        chat_text.push_str("\n\n");
        chat_text.push_str(&crate::centered_left_block(
            "+ Type your message and press enter\n+ /help for a list of commands\n+ /mode to switch between Safe, Coding, Web, and Custom modes",
            mid[0].width,
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
    let (chat_render, chat_plain) = crate::styled_chat_text(&chat_text, chat_style);
    let chat_width = mid[0].width.max(1) as usize;
    let chat_visible_lines = mid[0].height.max(1) as usize;
    let chat_total_lines = crate::wrapped_line_count(&chat_plain, chat_width);
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
        mid[0],
    );

    if has_side {
        match (show_tools, show_approvals) {
            (true, true) => {
                let right = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(mid[1]);
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
                mid[1],
                ui_state,
                compact_tools,
                tools_selected,
                true,
                show_tool_details,
            ),
            (false, true) => draw_approvals_pane(f, mid[1], ui_state, approvals_selected, true),
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
                crate::rotating_status_word(
                    &working_words,
                    think_tick,
                    tui_refresh_ms,
                    0xA5A5_A5A5,
                ),
                Style::default().fg(Color::Yellow),
            )
        } else {
            (
                crate::rotating_status_word(
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
    let status_hint = crate::activity_status_hint(ui_state, status);
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
            crate::compact_status_detail(status_detail, 140),
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
        Paragraph::new(crate::horizontal_rule(input_box[0].width))
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
        Paragraph::new(crate::horizontal_rule(input_box[2].width))
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
            Paragraph::new(crate::horizontal_rule(overlay[0].width))
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
