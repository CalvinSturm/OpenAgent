const SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/help", "show shortcuts and slash commands"),
    ("/mode", "show current mode"),
    ("/mode safe", "switch mode to safe"),
    ("/mode coding", "switch mode to coding"),
    ("/mode web", "switch mode to web"),
    ("/mode custom", "switch mode to custom"),
    ("/timeout", "show timeout settings and enter a new value"),
    ("/timeout 60", "set timeout to 60 seconds"),
    ("/timeout +30", "increase timeout by 30 seconds"),
    ("/timeout -10", "decrease timeout by 10 seconds"),
    ("/timeout off", "disable request and stream-idle timeout"),
    (
        "/params",
        "show current tuning params and enter a new key/value",
    ),
    ("/params max_steps 30", "set max agent loop steps"),
    (
        "/project guidance",
        "show resolved AGENTS.md guidance snapshot",
    ),
    (
        "/params compaction_mode summary",
        "enable summary compaction mode",
    ),
    ("/dismiss", "dismiss timeout notification"),
    ("/tool docs", "show usage for tool docs"),
    (
        "/tool docs mcp.stub.echo",
        "show MCP tool docs from local registry snapshot",
    ),
    ("/interrupt", "queue Interrupt for active run"),
    (
        "/interrupt fix course after tool finishes",
        "queue Interrupt message (applies after current tool finishes)",
    ),
    ("/next", "queue Next message for active run"),
    (
        "/next continue after this turn",
        "queue Next message (applies after this turn completes)",
    ),
    ("/queue", "show queue support/status"),
    ("/learn help", "show /learn command usage"),
    ("/learn list", "list learning entries"),
    ("/learn show <id>", "show one learning entry"),
    ("/learn archive <id>", "archive one learning entry"),
    ("/clear", "clear transcript (and session if enabled)"),
    ("/exit", "exit chat"),
    ("/hide tools", "hide tools pane"),
    ("/hide approvals", "hide approvals pane"),
    ("/hide logs", "hide logs pane"),
    ("/show tools", "show tools pane"),
    ("/show approvals", "show approvals pane"),
    ("/show logs", "show logs pane"),
    ("/show all", "show all panes"),
];

fn slash_command_matches(input: &str) -> Vec<(&'static str, &'static str)> {
    SLASH_COMMANDS
        .iter()
        .copied()
        .filter(|(cmd, _)| cmd.starts_with(input))
        .collect()
}

pub(crate) fn slash_match_count(input: &str) -> usize {
    slash_command_matches(input).len()
}

pub(crate) fn resolve_slash_command(input: &str) -> Option<&'static str> {
    let matches = slash_command_matches(input);
    if matches.len() == 1 {
        matches.first().map(|(cmd, _)| *cmd)
    } else {
        None
    }
}

pub(crate) fn selected_slash_command(input: &str, index: usize) -> Option<&'static str> {
    let matches = slash_command_matches(input);
    if matches.is_empty() {
        return None;
    }
    Some(matches[index % matches.len()].0)
}

pub(crate) fn slash_overlay_text(input: &str, selected: usize) -> Option<String> {
    let matches = slash_command_matches(input);
    if matches.is_empty() {
        return Some("no matching / commands".to_string());
    }
    let selected_idx = selected % matches.len();
    let window = 6usize;
    let start = if selected_idx >= window {
        selected_idx + 1 - window
    } else {
        0
    };
    let end = (start + window).min(matches.len());
    let mut lines = vec!["/ commands".to_string()];
    for (idx, (cmd, _desc)) in matches[start..end].iter().enumerate() {
        let absolute_idx = start + idx;
        lines.push(format!(
            "{} {}",
            if absolute_idx == selected_idx {
                "›"
            } else {
                " "
            },
            cmd
        ));
    }
    let (_cmd, desc) = matches[selected_idx];
    lines.push(format!("desc: {desc}"));
    Some(lines.join("\n"))
}

pub(crate) fn keybinds_overlay_text() -> Option<String> {
    let mut lines = vec!["keybinds".to_string()];
    let rows = [
        ("Esc", "quit chat"),
        (
            "Ctrl+T / Ctrl+Y / Ctrl+G",
            "toggle tools / approvals / logs",
        ),
        (
            "Ctrl+1 / Ctrl+2 / Ctrl+3",
            "same toggles (terminal-dependent)",
        ),
        ("PgUp / PgDn", "scroll transcript"),
        ("Ctrl+U / Ctrl+D", "scroll transcript"),
        ("Mouse wheel", "scroll transcript"),
        ("Ctrl+J / Ctrl+K", "approvals selection"),
        ("Ctrl+A / Ctrl+X", "approve / deny selected approval"),
        ("Ctrl+R", "refresh approvals"),
        ("Tab", "switch tools/approvals focus"),
        ("Ctrl+P", "command palette"),
        ("Ctrl+F", "search transcript"),
        ("Enter (empty input)", "toggle selected tool details"),
        ("/mode <...>", "switch chat mode (safe/coding/web/custom)"),
        (
            "/timeout <...>",
            "adjust request/stream idle timeout (or off)",
        ),
        ("/params <key> <value>", "adjust live agent tuning settings"),
        (
            "/project guidance",
            "show resolved AGENTS.md guidance snapshot",
        ),
        ("/dismiss", "dismiss timeout notification"),
        (
            "/tool docs <name>",
            "show tool docs from local registry snapshot",
        ),
        ("/interrupt <msg>", "queue Interrupt (active run only)"),
        ("/next <msg>", "queue Next (active run only)"),
        ("/queue", "show queue support/status"),
        ("/learn help", "show /learn usage and examples"),
        ("/learn list", "list learning entries in logs"),
        ("/learn show <id>", "show one learning entry in logs"),
        ("/learn archive <id>", "archive one learning entry"),
        ("/...", "slash commands dropdown"),
        ("?", "show this keybinds panel"),
    ];
    for (lhs, rhs) in rows {
        lines.push(format!("  {:<26} {}", lhs, rhs));
    }
    Some(lines.join("\n"))
}
