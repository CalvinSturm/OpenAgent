use clap::ValueEnum;

use crate::eval::assert::Assertion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvalPack {
    Coding,
    Browser,
    All,
}

#[derive(Debug, Clone)]
pub enum Fixture {
    WriteFile { path: String, content: String },
    CreateDir { path: String },
}

#[derive(Debug, Clone)]
pub struct EvalTask {
    pub id: String,
    pub prompt: String,
    pub required_tools: Vec<String>,
    pub assertions: Vec<Assertion>,
    pub fixtures: Vec<Fixture>,
    pub needs_write: bool,
    pub needs_playwright: bool,
    pub optional: bool,
}

pub fn tasks_for_pack(pack: EvalPack) -> Vec<EvalTask> {
    let mut all = Vec::new();
    all.extend(coding_tasks());
    all.extend(browser_tasks());
    all.into_iter()
        .filter(|t| match pack {
            EvalPack::Coding => t.id.starts_with("C"),
            EvalPack::Browser => t.id.starts_with("B"),
            EvalPack::All => true,
        })
        .collect()
}

fn coding_tasks() -> Vec<EvalTask> {
    vec![
        EvalTask {
            id: "C1".to_string(),
            prompt: "Create a new file at src/hello.txt containing exactly hello followed by a newline. Use the write_file tool. Then respond with a brief confirmation.".to_string(),
            required_tools: vec!["write_file".to_string()],
            assertions: vec![
                Assertion::FileExists {
                    path: "src/hello.txt".to_string(),
                },
                Assertion::FileContains {
                    path: "src/hello.txt".to_string(),
                    substring: "hello\n".to_string(),
                },
                Assertion::ToolUsed {
                    name: "write_file".to_string(),
                },
            ],
            fixtures: vec![Fixture::CreateDir {
                path: "src".to_string(),
            }],
            needs_write: true,
            needs_playwright: false,
            optional: false,
        },
        EvalTask {
            id: "C2".to_string(),
            prompt: "Edit main.rs by using apply_patch so that fn answer() returns 2 instead of 1. Do not rewrite the whole file with write_file. Then confirm done.".to_string(),
            required_tools: vec!["apply_patch".to_string()],
            assertions: vec![
                Assertion::FileContains {
                    path: "main.rs".to_string(),
                    substring: "return 2;".to_string(),
                },
                Assertion::ToolUsed {
                    name: "apply_patch".to_string(),
                },
            ],
            fixtures: vec![Fixture::WriteFile {
                path: "main.rs".to_string(),
                content: "fn answer() -> i32 {\n    return 1;\n}\n".to_string(),
            }],
            needs_write: true,
            needs_playwright: false,
            optional: false,
        },
        EvalTask {
            id: "C3".to_string(),
            prompt: "This task is optional in MVP eval. No action needed.".to_string(),
            required_tools: vec![],
            assertions: vec![],
            fixtures: vec![],
            needs_write: false,
            needs_playwright: false,
            optional: true,
        },
    ]
}

fn browser_tasks() -> Vec<EvalTask> {
    vec![
        EvalTask {
            id: "B1".to_string(),
            prompt: "Using Playwright MCP tools, navigate to https://example.com and return the exact page title.".to_string(),
            required_tools: vec!["mcp.playwright.*".to_string()],
            assertions: vec![
                Assertion::OutputContains {
                    substring: "Example Domain".to_string(),
                },
                Assertion::McpResultContains {
                    substring: "Example Domain".to_string(),
                },
            ],
            fixtures: vec![],
            needs_write: false,
            needs_playwright: true,
            optional: false,
        },
        EvalTask {
            id: "B2".to_string(),
            prompt: "Using Playwright MCP tools on https://example.com, report the first heading text.".to_string(),
            required_tools: vec!["mcp.playwright.*".to_string()],
            assertions: vec![
                Assertion::OutputContains {
                    substring: "Example Domain".to_string(),
                },
                Assertion::McpResultContains {
                    substring: "Example Domain".to_string(),
                },
            ],
            fixtures: vec![],
            needs_write: false,
            needs_playwright: true,
            optional: true,
        },
    ]
}
