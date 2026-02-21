use std::path::Path;

use crate::agent::AgentOutcome;
use crate::types::Role;

#[derive(Debug, Clone)]
pub enum Assertion {
    FileExists { path: String },
    FileContains { path: String, substring: String },
    ToolUsed { name: String },
    OutputContains { substring: String },
    McpResultContains { substring: String },
}

pub fn evaluate_assertions(
    assertions: &[Assertion],
    workdir: &Path,
    outcome: &AgentOutcome,
) -> Vec<String> {
    let mut failures = Vec::new();
    for assertion in assertions {
        match assertion {
            Assertion::FileExists { path } => {
                let full = workdir.join(path);
                if !full.exists() {
                    failures.push(format!("assertion failed: file_exists({path})"));
                }
            }
            Assertion::FileContains { path, substring } => {
                let full = workdir.join(path);
                match std::fs::read_to_string(&full) {
                    Ok(content) => {
                        if !content.contains(substring) {
                            failures.push(format!(
                                "assertion failed: file_contains({path}, {:?})",
                                substring
                            ));
                        }
                    }
                    Err(_) => {
                        failures.push(format!("assertion failed: file_contains({path}, ..)"));
                    }
                }
            }
            Assertion::ToolUsed { name } => {
                let used = outcome.tool_calls.iter().any(|tc| tc.name == *name);
                if !used {
                    failures.push(format!("assertion failed: tool_used({name})"));
                }
            }
            Assertion::OutputContains { substring } => {
                if !outcome.final_output.contains(substring) {
                    failures.push(format!(
                        "assertion failed: output_contains({:?})",
                        substring
                    ));
                }
            }
            Assertion::McpResultContains { substring } => {
                let found = outcome.messages.iter().any(|m| {
                    matches!(m.role, Role::Tool)
                        && m.tool_name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("mcp."))
                        && m.content
                            .as_deref()
                            .is_some_and(|content| content.contains(substring))
                });
                if !found {
                    failures.push(format!(
                        "assertion failed: mcp_result_contains({:?})",
                        substring
                    ));
                }
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{evaluate_assertions, Assertion};
    use crate::agent::{AgentExitReason, AgentOutcome};
    use crate::types::Message;

    #[test]
    fn file_assertions_work() {
        let tmp = tempdir().expect("tempdir");
        let file = tmp.path().join("a.txt");
        std::fs::write(&file, "hello world").expect("write");

        let outcome = AgentOutcome {
            run_id: "r".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:01Z".to_string(),
            exit_reason: AgentExitReason::Ok,
            final_output: String::new(),
            error: None,
            messages: Vec::<Message>::new(),
            tool_calls: Vec::new(),
        };
        let failures = evaluate_assertions(
            &[
                Assertion::FileExists {
                    path: "a.txt".to_string(),
                },
                Assertion::FileContains {
                    path: "a.txt".to_string(),
                    substring: "hello".to_string(),
                },
            ],
            tmp.path(),
            &outcome,
        );
        assert!(failures.is_empty());
    }
}
