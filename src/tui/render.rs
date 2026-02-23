use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::tui::state::UiState;

pub fn draw(frame: &mut Frame<'_>, state: &UiState, approvals_selected: usize) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(5),
        ])
        .split(frame.area());

    let top = Line::from(format!(
        "run={} step={} provider={} model={} caps={} policy={} plan={} schema_repair={} tools={} r={} w={} sh={} net={} br={} exit={}",
        state.run_id,
        state.step,
        state.provider,
        state.model,
        if state.caps_source.is_empty() {
            "-"
        } else {
            &state.caps_source
        },
        if state.policy_hash.is_empty() {
            "-"
        } else {
            &state.policy_hash
        },
        state.enforce_plan_tools_effective.as_str(),
        if state.schema_repair_seen { "on" } else { "off" },
        state.total_tool_execs,
        state.filesystem_read_execs,
        state.filesystem_write_execs,
        state.shell_execs,
        state.network_execs,
        state.browser_execs,
        state.exit_reason.as_deref().unwrap_or("-")
    ));
    frame.render_widget(Paragraph::new(top), outer[0]);

    let sticky = Line::from(format!(
        "step={} goal=\"{}\" allow={} next={} view={} (v=toggle)",
        state.current_step_id,
        state.current_step_goal,
        state.step_allowed_tools_compact(),
        state.next_hint,
        if state.show_details {
            "expanded"
        } else {
            "compact"
        }
    ));
    frame.render_widget(Paragraph::new(sticky), outer[1]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[2]);
    frame.render_widget(
        Paragraph::new(state.assistant_text.clone())
            .block(Block::default().title("Assistant").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        mid[0],
    );
    let right = if state.show_details {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),
                Constraint::Percentage(48),
                Constraint::Percentage(52),
            ])
            .split(mid[1])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(mid[1])
    };

    if state.show_details {
        let diag = format!(
            "effective_plan_enf={}\nschema_repair={}\nlast_tool={}\nstep_allowed={}",
            state.enforce_plan_tools_effective,
            if state.schema_repair_seen {
                "on"
            } else {
                "off"
            },
            state.last_tool_summary(),
            state.step_allowed_tools_compact()
        );
        frame.render_widget(
            Paragraph::new(diag)
                .block(Block::default().title("Diagnostics").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            right[0],
        );
    }

    let rows = state.tool_calls.iter().map(|t| {
        Row::new(vec![
            Cell::from(t.tool_name.clone()),
            Cell::from(t.status.clone()),
            Cell::from(t.decision.clone().unwrap_or_default()),
            Cell::from(
                t.ok.map(|v| if v { "ok" } else { "fail" })
                    .unwrap_or("-")
                    .to_string(),
            ),
            Cell::from(t.side_effects.clone()),
            Cell::from(t.decision_reason.clone().unwrap_or_default()),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(18),
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Length(6),
                Constraint::Length(14),
                Constraint::Min(20),
            ],
        )
        .header(Row::new(vec![
            "Tool", "Status", "Decision", "OK", "Effects", "Reason",
        ]))
        .block(Block::default().title("Tools").borders(Borders::ALL)),
        if state.show_details {
            right[1]
        } else {
            right[0]
        },
    );

    let approv_rows = state.pending_approvals.iter().enumerate().map(|(i, a)| {
        let style = if i == approvals_selected {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(a.id.clone()),
            Cell::from(a.status.clone()),
            Cell::from(a.tool.clone()),
            Cell::from(a.created_at.clone()),
        ])
        .style(style)
    });
    frame.render_widget(
        Table::new(
            approv_rows,
            [
                Constraint::Length(36),
                Constraint::Length(10),
                Constraint::Length(20),
                Constraint::Length(24),
            ],
        )
        .header(Row::new(vec!["Approval ID", "Status", "Tool", "Created"]))
        .block(
            Block::default()
                .title("Approvals (a=approve d=deny r=refresh v=details q=quit)")
                .borders(Borders::ALL),
        ),
        if state.show_details {
            right[2]
        } else {
            right[1]
        },
    );

    let logs = state.logs.join("\n");
    frame.render_widget(
        Paragraph::new(logs)
            .block(Block::default().title("Logs").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        outer[3],
    );
}
