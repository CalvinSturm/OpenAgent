use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DIAGNOSTIC_SCHEMA_VERSION: &str = "openagent.diagnostic.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub schema_version: String,
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub path: Option<PathBuf>,
    pub line: Option<u32>,
    pub col: Option<u32>,
    pub hint: Option<String>,
    // Keep details small and structured; intended for bounded machine-readable context.
    pub details: Option<Value>,
}

impl Diagnostic {
    pub fn sort_key(&self) -> (u8, &str, String, u32, u32, &str) {
        (
            self.severity.rank(),
            self.code.as_str(),
            self.path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            self.line.unwrap_or(0),
            self.col.unwrap_or(0),
            self.message.as_str(),
        )
    }
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warning => 1,
            Self::Info => 2,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

pub fn sort_diagnostics(diags: &mut [Diagnostic]) {
    diags.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
}

pub fn render_text(diags: &[Diagnostic]) -> String {
    let mut sorted = diags.to_vec();
    sort_diagnostics(&mut sorted);

    let mut out = String::new();
    for (idx, d) in sorted.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }

        out.push('[');
        out.push_str(d.severity.as_str());
        out.push(']');
        out.push(' ');
        out.push_str(&d.code);
        out.push_str(": ");
        out.push_str(&d.message);

        if d.path.is_some() || d.line.is_some() || d.col.is_some() {
            out.push('\n');
            out.push_str("  at ");
            if let Some(path) = &d.path {
                out.push_str(&path.to_string_lossy());
            }
            if let Some(line) = d.line {
                out.push(':');
                out.push_str(&line.to_string());
                if let Some(col) = d.col {
                    out.push(':');
                    out.push_str(&col.to_string());
                }
            } else if let Some(col) = d.col {
                out.push_str(":0:");
                out.push_str(&col.to_string());
            }
        }

        if let Some(hint) = &d.hint {
            out.push('\n');
            out.push_str("  hint: ");
            out.push_str(hint);
        }

        if let Some(details) = &d.details {
            out.push('\n');
            out.push_str("  details: ");
            match serde_json::to_string(details) {
                Ok(json) => out.push_str(&json),
                Err(_) => out.push_str("null"),
            }
        }
    }

    out
}

pub fn render_json(diags: &[Diagnostic]) -> Value {
    let mut sorted = diags.to_vec();
    sort_diagnostics(&mut sorted);
    serde_json::to_value(sorted).expect("Diagnostic is serializable")
}
