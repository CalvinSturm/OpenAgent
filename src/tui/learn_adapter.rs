use std::path::Path;

use anyhow::anyhow;

use crate::learning;

pub fn parse_and_dispatch_learn_slash(line: &str, state_dir: &Path) -> anyhow::Result<String> {
    let tokens = tokenize_learn_slash(line)?;
    if tokens.is_empty() || tokens[0] == "help" {
        return Ok(render_tui_learn_help());
    }
    match tokens[0].as_str() {
        "list" => dispatch_list(&tokens[1..], state_dir),
        "show" => dispatch_show(&tokens[1..], state_dir),
        "archive" => dispatch_archive(&tokens[1..], state_dir),
        _ => Err(anyhow!(
            "PR6A supports /learn help|list|show|archive; capture/promote are PR6B"
        )),
    }
}

fn dispatch_list(args: &[String], state_dir: &Path) -> anyhow::Result<String> {
    let mut statuses = Vec::<learning::LearningStatusV1>::new();
    let mut categories = Vec::<learning::LearningCategoryV1>::new();
    let mut limit = 50usize;
    let mut show_archived = false;
    let mut format = "table".to_string();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--status" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("learn parse error: --status requires value"))?;
                statuses.push(parse_status(v)?);
                i += 2;
            }
            "--category" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("learn parse error: --category requires value"))?;
                categories.push(parse_category(v)?);
                i += 2;
            }
            "--limit" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("learn parse error: --limit requires value"))?;
                limit = v
                    .parse::<usize>()
                    .map_err(|_| anyhow!("learn parse error: invalid --limit '{}'", v))?;
                i += 2;
            }
            "--show-archived" => {
                show_archived = true;
                i += 1;
            }
            "--format" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("learn parse error: --format requires value"))?;
                format = v.to_string();
                i += 2;
            }
            other => return Err(anyhow!("learn parse error: unknown list arg '{other}'")),
        }
    }
    let mut entries = learning::list_learning_entries(state_dir)?;
    if !statuses.is_empty() {
        entries.retain(|e| statuses.contains(&e.status));
    }
    if !categories.is_empty() {
        entries.retain(|e| categories.contains(&e.category));
    } else if !show_archived {
        entries.retain(|e| e.status != learning::LearningStatusV1::Archived);
    }
    if entries.len() > limit {
        entries.truncate(limit);
    }
    match format.as_str() {
        "table" => Ok(learning::render_learning_list_table(&entries)),
        "json" => learning::render_learning_list_json_preview(&entries),
        other => Err(anyhow!(
            "unsupported learn list format '{other}' (expected table|json)"
        )),
    }
}

fn dispatch_show(args: &[String], state_dir: &Path) -> anyhow::Result<String> {
    let id = args
        .first()
        .ok_or_else(|| anyhow!("learn parse error: /learn show <id>"))?;
    let mut format = "text".to_string();
    let mut show_evidence = true;
    let mut show_proposed = true;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow!("learn parse error: --format requires value"))?;
                format = v.to_string();
                i += 2;
            }
            "--show-evidence" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    anyhow!("learn parse error: --show-evidence requires true|false")
                })?;
                show_evidence = parse_bool_flag(v, "--show-evidence")?;
                i += 2;
            }
            "--show-proposed" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    anyhow!("learn parse error: --show-proposed requires true|false")
                })?;
                show_proposed = parse_bool_flag(v, "--show-proposed")?;
                i += 2;
            }
            other => return Err(anyhow!("learn parse error: unknown show arg '{other}'")),
        }
    }
    let entry = learning::load_learning_entry(state_dir, id)?;
    match format.as_str() {
        "text" => Ok(learning::render_learning_show_text(
            &entry,
            show_evidence,
            show_proposed,
        )),
        "json" => learning::render_learning_show_json_preview(&entry, show_evidence, show_proposed),
        other => Err(anyhow!(
            "unsupported learn show format '{other}' (expected text|json)"
        )),
    }
}

fn dispatch_archive(args: &[String], state_dir: &Path) -> anyhow::Result<String> {
    let id = args
        .first()
        .ok_or_else(|| anyhow!("learn parse error: /learn archive <id>"))?;
    let out = learning::archive_learning_entry(state_dir, id)?;
    Ok(learning::render_archive_confirmation(&out))
}

fn render_tui_learn_help() -> String {
    [
        "/learn help",
        "/learn list [--status <captured|promoted|archived>] [--category <workflow-hint|prompt-guidance|check-candidate>] [--limit N] [--show-archived] [--format table|json]",
        "/learn show <id> [--format text|json] [--show-evidence true|false] [--show-proposed true|false]",
        "/learn archive <id>",
        "note: /learn capture and /learn promote are planned for PR6B",
    ]
    .join("\n")
}

fn tokenize_learn_slash(line: &str) -> anyhow::Result<Vec<String>> {
    let rest = line
        .strip_prefix("/learn")
        .ok_or_else(|| anyhow!("internal parse error: expected /learn prefix"))?;
    split_shell_like(rest.trim())
}

fn split_shell_like(input: &str) -> anyhow::Result<Vec<String>> {
    #[derive(Clone, Copy)]
    enum Mode {
        Normal,
        Single,
        Double,
    }
    let mut mode = Mode::Normal;
    let mut out = Vec::<String>::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match mode {
            Mode::Normal => match ch {
                '\'' => mode = Mode::Single,
                '"' => mode = Mode::Double,
                '\\' => {
                    let next = chars
                        .next()
                        .ok_or_else(|| anyhow!("learn parse error: trailing escape"))?;
                    cur.push(next);
                }
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(ch),
            },
            Mode::Single => {
                if ch == '\'' {
                    mode = Mode::Normal;
                } else {
                    cur.push(ch);
                }
            }
            Mode::Double => match ch {
                '"' => mode = Mode::Normal,
                '\\' => {
                    let next = chars
                        .next()
                        .ok_or_else(|| anyhow!("learn parse error: trailing escape in quotes"))?;
                    cur.push(next);
                }
                _ => cur.push(ch),
            },
        }
    }
    match mode {
        Mode::Normal => {
            if !cur.is_empty() {
                out.push(cur);
            }
            Ok(out)
        }
        Mode::Single | Mode::Double => Err(anyhow!("learn parse error: unterminated quote")),
    }
}

fn parse_status(raw: &str) -> anyhow::Result<learning::LearningStatusV1> {
    match raw {
        "captured" => Ok(learning::LearningStatusV1::Captured),
        "promoted" => Ok(learning::LearningStatusV1::Promoted),
        "archived" => Ok(learning::LearningStatusV1::Archived),
        _ => Err(anyhow!("learn parse error: invalid --status '{}'", raw)),
    }
}

fn parse_category(raw: &str) -> anyhow::Result<learning::LearningCategoryV1> {
    match raw {
        "workflow-hint" => Ok(learning::LearningCategoryV1::WorkflowHint),
        "prompt-guidance" => Ok(learning::LearningCategoryV1::PromptGuidance),
        "check-candidate" => Ok(learning::LearningCategoryV1::CheckCandidate),
        _ => Err(anyhow!("learn parse error: invalid --category '{}'", raw)),
    }
}

fn parse_bool_flag(raw: &str, flag: &str) -> anyhow::Result<bool> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(anyhow!(
            "learn parse error: {} expects true|false, got '{}'",
            flag,
            raw
        )),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{parse_and_dispatch_learn_slash, split_shell_like};
    use crate::learning;

    #[test]
    fn split_shell_like_handles_quotes_and_escapes() {
        let t = split_shell_like(r#"show "id with spaces" --format \"json\""#).expect("tokens");
        assert_eq!(
            t,
            vec![
                "show".to_string(),
                "id with spaces".to_string(),
                "--format".to_string(),
                "\"json\"".to_string()
            ]
        );
    }

    #[test]
    fn split_shell_like_rejects_unterminated_quote() {
        let err = split_shell_like(r#"show "unterminated"#).expect_err("must fail");
        assert!(err.to_string().contains("unterminated quote"));
    }

    #[test]
    fn parse_and_dispatch_help_and_phase_b_guardrail() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let help = parse_and_dispatch_learn_slash("/learn help", &state_dir).expect("help");
        assert!(help.contains("/learn list"));
        let err =
            parse_and_dispatch_learn_slash("/learn promote 01JX --to check --slug x", &state_dir)
                .expect_err("phase b blocked");
        assert!(err
            .to_string()
            .contains("PR6A supports /learn help|list|show|archive"));
    }

    #[test]
    fn parse_and_dispatch_archive_updates_status() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let out = learning::capture_learning_entry(
            &state_dir,
            learning::CaptureLearningInput {
                category: learning::LearningCategoryV1::PromptGuidance,
                summary: "summary".to_string(),
                ..learning::CaptureLearningInput::default()
            },
        )
        .expect("capture");
        let msg =
            parse_and_dispatch_learn_slash(&format!("/learn archive {}", out.entry.id), &state_dir)
                .expect("archive");
        assert!(msg.contains("Archived learning"));
        let updated = learning::load_learning_entry(&state_dir, &out.entry.id).expect("load");
        assert_eq!(updated.status, learning::LearningStatusV1::Archived);
    }

    #[test]
    fn parse_and_dispatch_list_and_show_work() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let out = learning::capture_learning_entry(
            &state_dir,
            learning::CaptureLearningInput {
                category: learning::LearningCategoryV1::PromptGuidance,
                summary: "hello world".to_string(),
                ..learning::CaptureLearningInput::default()
            },
        )
        .expect("capture");
        let list = parse_and_dispatch_learn_slash("/learn list", &state_dir).expect("list");
        assert!(list.contains("ID  STATUS  CATEGORY"));
        let show =
            parse_and_dispatch_learn_slash(&format!("/learn show {}", out.entry.id), &state_dir)
                .expect("show");
        assert!(show.contains(&format!("id: {}", out.entry.id)));
    }
}
