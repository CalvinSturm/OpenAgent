use std::time::Duration;

use anyhow::anyhow;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;

use crate::mcp::registry::doctor_server as mcp_doctor_server;
use crate::store;
use crate::{
    chat_view_utils, provider_cli_name, provider_runtime, resolved_mcp_config_path, run_chat_tui,
    startup_detect, ChatArgs, RunArgs,
};

#[derive(Debug, Clone)]
enum StartupWebStatus {
    NotRequired,
    Ready { tool_count: usize },
    Error(String),
}

#[derive(Debug, Clone)]
enum StartupPreset {
    Safe,
    Coding,
    Web,
    Custom,
}

#[derive(Debug, Clone)]
struct StartupSelections {
    preset: StartupPreset,
    enable_write_tools: bool,
    allow_write: bool,
    allow_shell: bool,
    enable_web: bool,
    plain_tui: bool,
}

impl Default for StartupSelections {
    fn default() -> Self {
        Self {
            preset: StartupPreset::Safe,
            enable_write_tools: false,
            allow_write: false,
            allow_shell: false,
            enable_web: false,
            plain_tui: false,
        }
    }
}

pub(crate) async fn run_startup_bootstrap(
    base_run: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    let mut detection =
        startup_detect::detect_startup_provider(provider_runtime::http_config_from_run_args(
            base_run,
        ))
        .await;
    let mut selections = StartupSelections::default();
    let mut web_status = refresh_startup_web_status(base_run, paths, &selections).await;
    let mut selected_idx = 0usize;
    let mut custom_menu_open = false;
    let mut provider_details_open = false;
    let mut tick = 0u64;
    let mut error_line: Option<String> = None;

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let run_result: anyhow::Result<Option<(ChatArgs, RunArgs)>> = async {
        loop {
            terminal.draw(|f| {
                draw_startup_bootstrap_frame(
                    f,
                    &detection,
                    &selections,
                    &web_status,
                    selected_idx,
                    custom_menu_open,
                    provider_details_open,
                    tick,
                    error_line.as_deref(),
                );
            })?;

            if event::poll(Duration::from_millis(16))? {
                match event::read()? {
                    CEvent::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Esc => return Ok(None),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(None);
                        }
                        KeyCode::Up => selected_idx = selected_idx.saturating_sub(1),
                        KeyCode::Down => {
                            let max_idx = if custom_menu_open { 5 } else { 3 };
                            selected_idx = (selected_idx + 1).min(max_idx);
                        }
                        KeyCode::Char(' ') => {
                            let was_custom_menu_open = custom_menu_open;
                            let prev_enable_web = selections.enable_web;
                            if let Some(err) = toggle_startup_selection(
                                &mut selections,
                                selected_idx,
                                &mut custom_menu_open,
                            ) {
                                error_line = Some(err);
                            } else {
                                if !was_custom_menu_open && custom_menu_open {
                                    selected_idx = 1;
                                } else if was_custom_menu_open && !custom_menu_open {
                                    selected_idx = 3;
                                } else if custom_menu_open {
                                    selected_idx = selected_idx.min(5);
                                } else {
                                    selected_idx = selected_idx.min(3);
                                }
                                if selections.enable_web != prev_enable_web {
                                    if selections.enable_web {
                                        web_status = refresh_startup_web_status(
                                            base_run,
                                            paths,
                                            &selections,
                                        )
                                        .await;
                                    } else {
                                        web_status = StartupWebStatus::NotRequired;
                                    }
                                }
                                error_line = None;
                            }
                        }
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            detection = startup_detect::detect_startup_provider(
                                provider_runtime::http_config_from_run_args(base_run),
                            )
                            .await;
                            web_status =
                                refresh_startup_web_status(base_run, paths, &selections).await;
                            error_line = None;
                        }
                        KeyCode::Char('d') | KeyCode::Char('D') => {
                            provider_details_open = !provider_details_open;
                        }
                        KeyCode::Char('p') | KeyCode::Char('P') => {
                            let prev_enable_web = selections.enable_web;
                            selections.preset = StartupPreset::Custom;
                            selections.enable_write_tools = true;
                            selections.allow_write = true;
                            selections.allow_shell = true;
                            selections.enable_web = true;
                            selections.plain_tui = false;
                            custom_menu_open = true;
                            selected_idx = 1;
                            if selections.enable_web != prev_enable_web {
                                web_status =
                                    refresh_startup_web_status(base_run, paths, &selections).await;
                            }
                            error_line = None;
                        }
                        KeyCode::Enter => {
                            if !custom_menu_open {
                                let prev_enable_web = selections.enable_web;
                                match selected_idx {
                                    0 => {
                                        apply_startup_preset(&mut selections, StartupPreset::Safe)
                                    }
                                    1 => {
                                        apply_startup_preset(&mut selections, StartupPreset::Coding)
                                    }
                                    2 => apply_startup_preset(&mut selections, StartupPreset::Web),
                                    3 => {
                                        apply_startup_preset(
                                            &mut selections,
                                            StartupPreset::Custom,
                                        );
                                        custom_menu_open = true;
                                        selected_idx = 1;
                                        error_line = None;
                                        continue;
                                    }
                                    _ => {}
                                }
                                if selections.enable_web != prev_enable_web {
                                    if selections.enable_web {
                                        web_status = refresh_startup_web_status(
                                            base_run,
                                            paths,
                                            &selections,
                                        )
                                        .await;
                                    } else {
                                        web_status = StartupWebStatus::NotRequired;
                                    }
                                }
                            }
                            if selections.enable_web {
                                if let StartupWebStatus::Error(e) = &web_status {
                                    error_line = Some(format!(
                                        "Web preset is enabled but Playwright MCP is not ready: {e}"
                                    ));
                                    continue;
                                }
                            }
                            let Some(provider) = detection.provider else {
                                error_line = Some(
                                    "No local provider detected yet. Start LM Studio/Ollama/llama.cpp, then press R."
                                        .to_string(),
                                );
                                continue;
                            };
                            let Some(model) = detection.model.clone() else {
                                error_line = Some(
                                    "Provider detected but no model found. Load a model locally, then press R."
                                        .to_string(),
                                );
                                continue;
                            };
                            let mut auto_run = base_run.clone();
                            auto_run.provider = Some(provider);
                            auto_run.model = Some(model);
                            auto_run.base_url = detection.base_url.clone();
                            auto_run.tui = true;
                            auto_run.stream = false;
                            auto_run.enable_write_tools = selections.enable_write_tools;
                            auto_run.allow_write = selections.allow_write;
                            auto_run.allow_shell = selections.allow_shell;
                            if selections.enable_web
                                && !auto_run.mcp.iter().any(|m| m == "playwright")
                            {
                                auto_run.mcp.push("playwright".to_string());
                            }
                            let chat = ChatArgs {
                                tui: true,
                                plain_tui: selections.plain_tui,
                                no_banner: false,
                            };
                            return Ok(Some((chat, auto_run)));
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            tick = tick.saturating_add(1);
        }
    }
    .await;

    let mut cleanup_err: Option<anyhow::Error> = None;
    if let Err(e) = disable_raw_mode() {
        cleanup_err = Some(anyhow!(e));
    }
    if let Err(e) = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    ) {
        if cleanup_err.is_none() {
            cleanup_err = Some(anyhow!(e));
        }
    }
    if let Err(e) = terminal.show_cursor() {
        if cleanup_err.is_none() {
            cleanup_err = Some(anyhow!(e));
        }
    }

    let next = run_result?;
    if let Some(e) = cleanup_err {
        return Err(e);
    }
    if let Some((chat, run)) = next {
        run_chat_tui(&chat, &run, paths).await?;
    }
    Ok(())
}

async fn refresh_startup_web_status(
    base_run: &RunArgs,
    paths: &store::StatePaths,
    selections: &StartupSelections,
) -> StartupWebStatus {
    if !selections.enable_web {
        return StartupWebStatus::NotRequired;
    }
    let mut probe_args = base_run.clone();
    if !probe_args.mcp.iter().any(|m| m == "playwright") {
        probe_args.mcp.push("playwright".to_string());
    }
    let mcp_config_path = resolved_mcp_config_path(&probe_args, &paths.state_dir);
    match mcp_doctor_server(&mcp_config_path, "playwright").await {
        Ok(tool_count) => StartupWebStatus::Ready { tool_count },
        Err(e) => StartupWebStatus::Error(e.to_string()),
    }
}

fn apply_startup_preset(selections: &mut StartupSelections, preset: StartupPreset) {
    selections.preset = preset.clone();
    match preset {
        StartupPreset::Safe => {
            selections.enable_write_tools = false;
            selections.allow_write = false;
            selections.allow_shell = false;
            selections.enable_web = false;
            selections.plain_tui = false;
        }
        StartupPreset::Coding => {
            selections.enable_write_tools = true;
            selections.allow_write = true;
            selections.allow_shell = true;
            selections.enable_web = false;
            selections.plain_tui = false;
        }
        StartupPreset::Web => {
            selections.enable_write_tools = false;
            selections.allow_write = false;
            selections.allow_shell = false;
            selections.enable_web = true;
            selections.plain_tui = false;
        }
        StartupPreset::Custom => {}
    }
}

fn toggle_startup_selection(
    selections: &mut StartupSelections,
    idx: usize,
    custom_menu_open: &mut bool,
) -> Option<String> {
    if *custom_menu_open {
        match idx {
            0 => *custom_menu_open = false,
            1 => selections.enable_write_tools = !selections.enable_write_tools,
            2 => selections.allow_write = !selections.allow_write,
            3 => selections.allow_shell = !selections.allow_shell,
            4 => selections.enable_web = !selections.enable_web,
            5 => selections.plain_tui = !selections.plain_tui,
            _ => {}
        }
        return None;
    }

    match idx {
        0 => apply_startup_preset(selections, StartupPreset::Safe),
        1 => apply_startup_preset(selections, StartupPreset::Coding),
        2 => apply_startup_preset(selections, StartupPreset::Web),
        3 => {
            apply_startup_preset(selections, StartupPreset::Custom);
            *custom_menu_open = true;
        }
        _ => {}
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn draw_startup_bootstrap_frame(
    f: &mut ratatui::Frame<'_>,
    detection: &startup_detect::StartupDetection,
    selections: &StartupSelections,
    web_status: &StartupWebStatus,
    selected_idx: usize,
    custom_menu_open: bool,
    provider_details_open: bool,
    tick: u64,
    error_line: Option<&str>,
) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(16),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .split(f.area());

    let provider_name = detection
        .provider
        .map(provider_cli_name)
        .unwrap_or("not detected");
    let model_name = detection.model.as_deref().unwrap_or("not detected");
    f.render_widget(
        Paragraph::new(chat_view_utils::horizontal_rule(outer[0].width))
            .style(Style::default().fg(Color::DarkGray)),
        outer[0],
    );

    let base_url = detection.base_url.as_deref().unwrap_or("-");
    let mut detected_text = format!(
        "Provider: {}\nModel: {}\nBase URL: {}\n{}",
        provider_name, model_name, base_url, detection.status_line
    );
    match web_status {
        StartupWebStatus::NotRequired => {
            detected_text.push_str("\nWeb/MCP: not enabled");
        }
        StartupWebStatus::Ready { tool_count } => {
            detected_text.push_str(&format!(
                "\nWeb/MCP: playwright ready (tool_count={tool_count})"
            ));
        }
        StartupWebStatus::Error(e) => {
            detected_text.push_str(&format!("\nWeb/MCP: not ready ({e})"));
        }
    }
    if let Some(err) = error_line {
        detected_text.push_str(&format!("\nError: {err}"));
    }

    let preset_rows = [
        ("Safe", "Chat only - tools disabled"),
        ("Coding", "Tools enabled"),
        ("Web", "Browsing + tools"),
        ("Custom", "Choose multiple options manually"),
    ];

    let provider_ready = detection.provider.is_some() && detection.model.is_some();
    let web_ready = match web_status {
        StartupWebStatus::NotRequired | StartupWebStatus::Ready { .. } => true,
        StartupWebStatus::Error(_) => false,
    };
    let all_systems_ready = provider_ready && web_ready && error_line.is_none();
    let status_color = if all_systems_ready {
        Color::Green
    } else if provider_ready {
        Color::Yellow
    } else {
        Color::Red
    };
    let status_summary = if all_systems_ready {
        "Ready"
    } else if provider_ready && !web_ready {
        "Web MCP Not Ready"
    } else if provider_ready {
        "Provider Connected"
    } else {
        "Not Connected"
    };
    let provider_summary = if provider_ready {
        "connected"
    } else {
        "not connected"
    };
    let provider_color = if provider_ready {
        Color::Green
    } else {
        Color::Yellow
    };

    f.render_widget(
        Paragraph::new(chat_view_utils::horizontal_rule(outer[0].width))
            .style(Style::default().fg(Color::White)),
        outer[0],
    );
    f.render_widget(
        Paragraph::new(chat_view_utils::horizontal_rule(outer[2].width))
            .style(Style::default().fg(Color::White)),
        outer[2],
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("LOCALAGENT", Style::default().fg(Color::Yellow)),
            Span::raw("  "),
            Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Provider: ", Style::default().fg(Color::White)),
            Span::styled(provider_summary, Style::default().fg(provider_color)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Status: ", Style::default().fg(Color::White)),
            Span::styled(status_summary, Style::default().fg(status_color)),
        ])),
        outer[1],
    );

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(outer[3]);

    let setup_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .title(Line::from(vec![Span::styled(
            " Mode ",
            Style::default().fg(Color::White),
        )]));
    let setup_inner = setup_block.inner(mid[0]);
    f.render_widget(setup_block, mid[0]);
    let mut setup_lines: Vec<Line> = Vec::new();
    if custom_menu_open {
        let back_style = if selected_idx == 0 {
            Style::default().fg(Color::Black).bg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };
        setup_lines.push(Line::from(vec![
            Span::styled(if selected_idx == 0 { "▸ " } else { "  " }, back_style),
            Span::styled("< Back", back_style),
        ]));
        setup_lines.push(Line::from(""));

        let custom_rows = [
            ("write tools", selections.enable_write_tools),
            ("allow write", selections.allow_write),
            ("allow shell", selections.allow_shell),
            ("web (playwright)", selections.enable_web),
            ("plain tui", selections.plain_tui),
        ];
        for (offset, (label, enabled)) in custom_rows.iter().enumerate() {
            let idx = offset + 1;
            let sel = idx == selected_idx;
            let style = if sel {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            setup_lines.push(Line::from(vec![
                Span::styled(if sel { "▸ " } else { "  " }, style),
                Span::styled(if *enabled { "[x] " } else { "[ ] " }, style),
                Span::styled(*label, style),
            ]));
        }
    } else {
        for (idx, (label, desc)) in preset_rows.iter().enumerate() {
            let is_selected = idx == selected_idx;
            let active = matches!(
                (&selections.preset, idx),
                (StartupPreset::Safe, 0)
                    | (StartupPreset::Coding, 1)
                    | (StartupPreset::Web, 2)
                    | (StartupPreset::Custom, 3)
            );
            let row_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            setup_lines.push(Line::from(vec![
                Span::styled(if is_selected { "▸ " } else { "  " }, row_style),
                Span::styled(if active { "◉ " } else { "○ " }, row_style),
                Span::styled(*label, row_style),
            ]));
            setup_lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(
                    *desc,
                    Style::default().fg(if is_selected {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    }),
                ),
            ]));
            if idx < preset_rows.len() - 1 {
                setup_lines.push(Line::from(""));
            }
        }
    }
    f.render_widget(
        Paragraph::new(setup_lines).wrap(Wrap { trim: false }),
        setup_inner,
    );

    let conn_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .title(Line::from(vec![Span::styled(
            " Provider ",
            Style::default().fg(Color::White),
        )]));
    let conn_inner = conn_block.inner(mid[1]);
    f.render_widget(conn_block, mid[1]);
    let mut conn_lines: Vec<Line> = Vec::new();
    if !provider_ready && !provider_details_open {
        let spinner = match tick % 4 {
            0 => "◴",
            1 => "◷",
            2 => "◶",
            _ => "◵",
        };
        conn_lines.push(Line::from(vec![
            Span::styled(spinner, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(
                "Detecting local providers...",
                Style::default().fg(Color::Yellow),
            ),
        ]));
        conn_lines.push(Line::from(""));
        conn_lines.push(Line::from(vec![Span::styled(
            "Start LM Studio, Ollama, or llama.cpp.",
            Style::default().fg(Color::Green),
        )]));
        conn_lines.push(Line::from(vec![Span::styled(
            "I'll connect automatically.",
            Style::default().fg(Color::Green),
        )]));
        conn_lines.push(Line::from(""));
        conn_lines.push(Line::from(vec![
            Span::styled("R:", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Refresh", Style::default().fg(Color::Yellow)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("D:", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Details", Style::default().fg(Color::White)),
        ]));
    } else {
        conn_lines.push(Line::from(vec![
            Span::styled("Provider: ", Style::default().fg(Color::White)),
            Span::styled(provider_name, Style::default().fg(Color::Cyan)),
        ]));
        conn_lines.push(Line::from(vec![
            Span::styled("Model: ", Style::default().fg(Color::White)),
            Span::styled(model_name, Style::default().fg(Color::Cyan)),
        ]));
        conn_lines.push(Line::from(vec![
            Span::styled("Base URL: ", Style::default().fg(Color::White)),
            Span::styled(base_url, Style::default().fg(Color::Cyan)),
        ]));
        conn_lines.push(Line::from(vec![
            Span::styled("Web/MCP: ", Style::default().fg(Color::White)),
            Span::styled(
                match web_status {
                    StartupWebStatus::NotRequired => "Disabled",
                    StartupWebStatus::Ready { .. } => "Ready",
                    StartupWebStatus::Error(_) => "Error",
                },
                Style::default().fg(match web_status {
                    StartupWebStatus::Ready { .. } => Color::Green,
                    StartupWebStatus::Error(_) => Color::Red,
                    StartupWebStatus::NotRequired => Color::DarkGray,
                }),
            ),
        ]));
        conn_lines.push(Line::from(""));
        if let Some(err) = error_line {
            conn_lines.push(Line::from(vec![Span::styled(
                format!("Error: {err}"),
                Style::default().fg(Color::Red),
            )]));
        } else {
            conn_lines.push(Line::from(vec![Span::styled(
                detection.status_line.clone(),
                Style::default().fg(Color::Yellow),
            )]));
        }
        if selections.enable_web {
            match web_status {
                StartupWebStatus::Ready { tool_count } => {
                    conn_lines.push(Line::from(vec![Span::styled(
                        format!("Playwright MCP ready ({tool_count} tools)"),
                        Style::default().fg(Color::Green),
                    )]))
                }
                StartupWebStatus::Error(_) => conn_lines.push(Line::from(vec![Span::styled(
                    "Run `localagent mcp doctor playwright`, then press R",
                    Style::default().fg(Color::Yellow),
                )])),
                StartupWebStatus::NotRequired => {}
            }
        }
        conn_lines.push(Line::from(""));
        conn_lines.push(Line::from(vec![
            Span::styled("R:", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Refresh", Style::default().fg(Color::Yellow)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("D:", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Hide details", Style::default().fg(Color::White)),
        ]));
    }
    f.render_widget(
        Paragraph::new(conn_lines).wrap(Wrap { trim: false }),
        conn_inner,
    );

    let enter_hint = if custom_menu_open {
        if provider_ready {
            "Start chat"
        } else {
            "Start disabled: no provider detected"
        }
    } else if provider_ready {
        "Select mode + start chat"
    } else {
        "Select mode (start disabled: no provider detected)"
    };
    let mut footer_line: Vec<Span<'static>> = vec![
        Span::styled("[↑/↓]", Style::default().fg(Color::White)),
        Span::raw(" "),
        Span::styled("Navigate", Style::default().fg(Color::White)),
        Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
    ];
    if custom_menu_open {
        footer_line.extend([
            Span::styled("[Space]", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Toggle option", Style::default().fg(Color::White)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
        ]);
    }
    footer_line.extend([
        Span::styled("[Enter]", Style::default().fg(Color::White)),
        Span::raw(" "),
        Span::styled(enter_hint, Style::default().fg(Color::White)),
    ]);
    let footer_outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(outer[5]);
    f.render_widget(
        Paragraph::new(Line::from(footer_line)).alignment(ratatui::layout::Alignment::Center),
        footer_outer[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("[R]", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Refresh", Style::default().fg(Color::White)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[D]", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Details", Style::default().fg(Color::White)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc]", Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled("Quit", Style::default().fg(Color::White)),
        ]))
        .alignment(ratatui::layout::Alignment::Center),
        footer_outer[1],
    );
}
