use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize, Clone)]
pub struct AuditResult {
    pub ok: bool,
    pub content: String,
    pub input_digest: Option<String>,
    pub output_digest: Option<String>,
    pub input_len: Option<usize>,
    pub output_len: Option<usize>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuditEvent {
    pub ts: String,
    pub run_id: String,
    pub step: u32,
    pub tool_call_id: String,
    pub tool: String,
    pub arguments: Value,
    pub decision: String,
    pub decision_reason: Option<String>,
    pub decision_source: Option<String>,
    pub approval_id: Option<String>,
    pub approval_key: Option<String>,
    pub approval_mode: Option<String>,
    pub auto_approve_scope: Option<String>,
    pub approval_key_version: Option<String>,
    pub tool_schema_hash_hex: Option<String>,
    pub hooks_config_hash_hex: Option<String>,
    pub planner_hash_hex: Option<String>,
    pub exec_target: Option<String>,
    pub result: AuditResult,
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn append(&self, event: &AuditEvent) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(event)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}
