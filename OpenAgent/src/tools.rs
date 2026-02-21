use std::path::{Path, PathBuf};

use serde_json::json;
use tokio::process::Command;

use crate::types::{Message, Role, ToolCall, ToolDef};

#[derive(Debug, Clone)]
pub struct ToolRuntime {
    pub workdir: PathBuf,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub max_tool_output_bytes: usize,
    pub max_read_bytes: usize,
}

pub fn builtin_tools_enabled(enable_write_tools: bool) -> Vec<ToolDef> {
    let mut tools = vec![
        ToolDef {
            name: "list_dir".to_string(),
            description: "List entries in a directory.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "read_file".to_string(),
            description: "Read a UTF-8 text file (lossy decode allowed).".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "shell".to_string(),
            description: "Run a shell command with optional args and cwd.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "cmd": { "type": "string" },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "cwd": { "type": "string" }
                },
                "required": ["cmd"]
            }),
        },
    ];

    if enable_write_tools {
        tools.push(ToolDef {
            name: "write_file".to_string(),
            description: "Write UTF-8 text content to a file.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "create_parents": { "type": "boolean" }
                },
                "required": ["path", "content"]
            }),
        });
        tools.push(ToolDef {
            name: "apply_patch".to_string(),
            description: "Apply a unified diff patch to a file.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "patch": { "type": "string" }
                },
                "required": ["path", "patch"]
            }),
        });
    }

    tools
}

pub fn resolve_path(workdir: &Path, input: &str) -> PathBuf {
    let p = PathBuf::from(input);
    if p.is_absolute() {
        p
    } else {
        workdir.join(p)
    }
}

pub async fn execute_tool(rt: &ToolRuntime, tc: &ToolCall) -> Message {
    let content = match tc.name.as_str() {
        "list_dir" => run_list_dir(rt, &tc.arguments).await,
        "read_file" => run_read_file(rt, &tc.arguments).await,
        "shell" => run_shell(rt, &tc.arguments).await,
        "write_file" => run_write_file(rt, &tc.arguments).await,
        "apply_patch" => run_apply_patch(rt, &tc.arguments).await,
        _ => json!({ "error": format!("unknown tool: {}", tc.name) }),
    };

    Message {
        role: Role::Tool,
        content: Some(content.to_string()),
        tool_call_id: Some(tc.id.clone()),
        tool_name: Some(tc.name.clone()),
        tool_calls: None,
    }
}

async fn run_list_dir(rt: &ToolRuntime, args: &serde_json::Value) -> serde_json::Value {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or(".")
        .to_string();
    let full_path = resolve_path(&rt.workdir, &path);
    let mut entries_out = Vec::new();

    match tokio::fs::read_dir(&full_path).await {
        Ok(mut rd) => loop {
            match rd.next_entry().await {
                Ok(Some(entry)) => {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    match entry.metadata().await {
                        Ok(meta) => entries_out.push(json!({
                            "name": file_name,
                            "is_dir": meta.is_dir(),
                            "len": meta.len()
                        })),
                        Err(e) => entries_out.push(json!({
                            "name": file_name,
                            "error": e.to_string()
                        })),
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    return json!({
                        "path": full_path.display().to_string(),
                        "error": e.to_string()
                    });
                }
            }
        },
        Err(e) => {
            return json!({
                "path": full_path.display().to_string(),
                "error": e.to_string()
            });
        }
    }

    json!({
        "path": full_path.display().to_string(),
        "entries": entries_out
    })
}

async fn run_read_file(rt: &ToolRuntime, args: &serde_json::Value) -> serde_json::Value {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let full_path = resolve_path(&rt.workdir, path);
    match tokio::fs::read(&full_path).await {
        Ok(bytes) => {
            let content = String::from_utf8_lossy(&bytes).to_string();
            let (content, truncated) = truncate_utf8_to_bytes(&content, rt.max_read_bytes);
            json!({
                "path": full_path.display().to_string(),
                "content": content,
                "truncated": truncated,
                "max_read_bytes": rt.max_read_bytes,
                "read_bytes": bytes.len()
            })
        }
        Err(e) => json!({
            "path": full_path.display().to_string(),
            "error": e.to_string()
        }),
    }
}

async fn run_shell(rt: &ToolRuntime, args: &serde_json::Value) -> serde_json::Value {
    if !rt.allow_shell {
        return json!({
            "error": "shell tool is disabled. Re-run with --allow-shell"
        });
    }

    let cmd = match args.get("cmd").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => {
            return json!({
                "error": "missing required argument: cmd"
            });
        }
    };

    let mut command = Command::new(cmd);
    if let Some(raw_args) = args.get("args").and_then(|v| v.as_array()) {
        for arg in raw_args {
            if let Some(s) = arg.as_str() {
                command.arg(s);
            }
        }
    }

    if let Some(cwd) = args.get("cwd").and_then(|v| v.as_str()) {
        command.current_dir(resolve_path(&rt.workdir, cwd));
    } else {
        command.current_dir(&rt.workdir);
    }

    match command.output().await {
        Ok(output) => {
            let stdout_raw = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr_raw = String::from_utf8_lossy(&output.stderr).to_string();
            let (stdout, stdout_truncated) =
                truncate_utf8_to_bytes(&stdout_raw, rt.max_tool_output_bytes);
            let (stderr, stderr_truncated) =
                truncate_utf8_to_bytes(&stderr_raw, rt.max_tool_output_bytes);
            json!({
                "status": output.status.code(),
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "max_tool_output_bytes": rt.max_tool_output_bytes
            })
        }
        Err(e) => json!({
            "error": e.to_string()
        }),
    }
}

async fn run_write_file(rt: &ToolRuntime, args: &serde_json::Value) -> serde_json::Value {
    if !rt.allow_write {
        return json!({ "error": "writes require --allow-write" });
    }

    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return json!({"error":"missing required argument: path"}),
    };
    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return json!({"error":"missing required argument: content"}),
    };
    let create_parents = args
        .get("create_parents")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let full_path = resolve_path(&rt.workdir, path);
    if create_parents {
        if let Some(parent) = full_path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return json!({
                    "path": full_path.display().to_string(),
                    "error": e.to_string()
                });
            }
        }
    }

    match tokio::fs::write(&full_path, content.as_bytes()).await {
        Ok(()) => json!({
            "path": full_path.display().to_string(),
            "bytes_written": content.len()
        }),
        Err(e) => json!({
            "path": full_path.display().to_string(),
            "error": e.to_string()
        }),
    }
}

async fn run_apply_patch(rt: &ToolRuntime, args: &serde_json::Value) -> serde_json::Value {
    if !rt.allow_write {
        return json!({ "error": "writes require --allow-write" });
    }

    let path = match args.get("path").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return json!({"error":"missing required argument: path"}),
    };
    let patch_text = match args.get("patch").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return json!({"error":"missing required argument: patch"}),
    };

    let full_path = resolve_path(&rt.workdir, path);
    let original_bytes = match tokio::fs::read(&full_path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return json!({
                "path": full_path.display().to_string(),
                "error": e.to_string()
            })
        }
    };
    let original_text = String::from_utf8_lossy(&original_bytes).to_string();
    let patch = match diffy::Patch::from_str(patch_text) {
        Ok(p) => p,
        Err(e) => {
            return json!({
                "path": full_path.display().to_string(),
                "error": format!("invalid patch: {e}")
            })
        }
    };
    let patched = match diffy::apply(&original_text, &patch) {
        Ok(p) => p,
        Err(e) => {
            return json!({
                "path": full_path.display().to_string(),
                "error": format!("failed to apply patch: {e}")
            })
        }
    };

    if let Some(parent) = full_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return json!({
                "path": full_path.display().to_string(),
                "error": e.to_string()
            });
        }
    }

    match tokio::fs::write(&full_path, patched.as_bytes()).await {
        Ok(()) => json!({
            "path": full_path.display().to_string(),
            "changed": patched != original_text,
            "bytes_written": patched.len()
        }),
        Err(e) => json!({
            "path": full_path.display().to_string(),
            "error": e.to_string()
        }),
    }
}

fn truncate_utf8_to_bytes(input: &str, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    (input[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;
    use tempfile::tempdir;

    use super::{builtin_tools_enabled, execute_tool, resolve_path, ToolRuntime};
    use crate::types::ToolCall;

    #[test]
    fn resolves_relative_path_from_workdir() {
        let base = PathBuf::from("some_workdir");
        let out = resolve_path(&base, "nested/file.txt");
        assert_eq!(out, base.join("nested/file.txt"));
    }

    #[test]
    fn write_tools_not_exposed_by_default() {
        let tools = builtin_tools_enabled(false);
        let names = tools.into_iter().map(|t| t.name).collect::<Vec<_>>();
        assert!(!names.iter().any(|n| n == "write_file"));
        assert!(!names.iter().any(|n| n == "apply_patch"));
    }

    #[tokio::test]
    async fn shell_tool_disabled_returns_error() {
        let rt = ToolRuntime {
            workdir: PathBuf::from("."),
            allow_shell: false,
            allow_write: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
        };
        let tc = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd": "echo", "args": ["hello"]}),
        };

        let msg = execute_tool(&rt, &tc).await;
        let content = msg.content.unwrap_or_default();
        assert!(content.contains("shell tool is disabled"));
    }

    #[tokio::test]
    async fn write_file_denied_when_allow_write_false() {
        let rt = ToolRuntime {
            workdir: PathBuf::from("."),
            allow_shell: false,
            allow_write: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
        };
        let tc = ToolCall {
            id: "tc_w".to_string(),
            name: "write_file".to_string(),
            arguments: json!({"path":"foo.txt", "content":"hello"}),
        };
        let msg = execute_tool(&rt, &tc).await;
        let content = msg.content.unwrap_or_default();
        assert!(content.contains("writes require --allow-write"));
    }

    #[tokio::test]
    async fn apply_patch_updates_file() {
        let tmp = tempdir().expect("tempdir");
        let file = tmp.path().join("a.txt");
        tokio::fs::write(&file, "hello\n")
            .await
            .expect("write file");
        let rt = ToolRuntime {
            workdir: tmp.path().to_path_buf(),
            allow_shell: false,
            allow_write: true,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
        };
        let tc = ToolCall {
            id: "tc_p".to_string(),
            name: "apply_patch".to_string(),
            arguments: json!({
                "path":"a.txt",
                "patch":"@@ -1 +1 @@\n-hello\n+world\n"
            }),
        };
        let msg = execute_tool(&rt, &tc).await;
        let content = msg.content.unwrap_or_default();
        assert!(content.contains("\"changed\":true"));
        let updated = tokio::fs::read_to_string(&file)
            .await
            .expect("read patched");
        assert_eq!(updated, "world\n");
    }
}
