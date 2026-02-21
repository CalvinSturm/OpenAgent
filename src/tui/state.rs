use std::path::Path;

use crate::events::{Event, EventKind};
use crate::trust::approvals::{ApprovalsStore, StoredStatus};

#[derive(Debug, Clone, Default)]
pub struct ToolRow {
    pub tool_call_id: String,
    pub tool_name: String,
    pub side_effects: String,
    pub decision: Option<String>,
    pub decision_reason: Option<String>,
    pub status: String,
    pub ok: Option<bool>,
    pub short_result: String,
}

#[derive(Debug, Clone, Default)]
pub struct ApprovalRow {
    pub id: String,
    pub tool: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct UiState {
    pub run_id: String,
    pub step: u32,
    pub provider: String,
    pub model: String,
    pub caps_source: String,
    pub policy_hash: String,
    pub assistant_text: String,
    pub tool_calls: Vec<ToolRow>,
    pub pending_approvals: Vec<ApprovalRow>,
    pub logs: Vec<String>,
    pub exit_reason: Option<String>,
    max_log_lines: usize,
}

impl UiState {
    pub fn new(max_log_lines: usize) -> Self {
        Self {
            run_id: String::new(),
            step: 0,
            provider: String::new(),
            model: String::new(),
            caps_source: String::new(),
            policy_hash: String::new(),
            assistant_text: String::new(),
            tool_calls: Vec::new(),
            pending_approvals: Vec::new(),
            logs: Vec::new(),
            exit_reason: None,
            max_log_lines,
        }
    }

    pub fn apply_event(&mut self, ev: &Event) {
        self.step = ev.step;
        if self.run_id.is_empty() {
            self.run_id = ev.run_id.clone();
        }
        match ev.kind {
            EventKind::RunStart => {
                self.model = ev
                    .data
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
            }
            EventKind::RunEnd => {
                self.exit_reason = ev
                    .data
                    .get("exit_reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            EventKind::ModelDelta => {
                if let Some(delta) = ev.data.get("delta").and_then(|v| v.as_str()) {
                    self.assistant_text.push_str(delta);
                }
            }
            EventKind::ModelResponseEnd => {
                if self.assistant_text.is_empty() {
                    if let Some(content) = ev.data.get("content").and_then(|v| v.as_str()) {
                        self.assistant_text.push_str(content);
                    }
                }
            }
            EventKind::ToolCallDetected => {
                let id = ev
                    .data
                    .get("tool_call_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = ev
                    .data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let side = ev
                    .data
                    .get("side_effects")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                self.upsert_tool(id, name, side, "detected");
            }
            EventKind::ToolDecision => {
                let id = ev
                    .data
                    .get("tool_call_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = ev
                    .data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let side = ev
                    .data
                    .get("side_effects")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let decision = ev
                    .data
                    .get("decision")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let reason = ev
                    .data
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let row = self.upsert_tool(id, name, side, "decided");
                row.decision = Some(decision);
                row.decision_reason = reason;
            }
            EventKind::ToolExecStart => {
                let id = ev
                    .data
                    .get("tool_call_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = ev
                    .data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let side = ev
                    .data
                    .get("side_effects")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let _ = self.upsert_tool(id, name, side, "running");
            }
            EventKind::ToolExecEnd => {
                let id = ev
                    .data
                    .get("tool_call_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let name = ev
                    .data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let ok = ev.data.get("ok").and_then(|v| v.as_bool());
                let result = ev
                    .data
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let row = self.upsert_tool(id, name, String::new(), "done");
                row.ok = ok;
                row.short_result = truncate_chars(result, 200);
            }
            EventKind::PolicyLoaded => {
                if let Some(hash) = ev.data.get("policy_hash_hex").and_then(|v| v.as_str()) {
                    self.policy_hash = hash.to_string();
                }
            }
            EventKind::ProviderError => {
                let msg = ev
                    .data
                    .get("message_short")
                    .and_then(|v| v.as_str())
                    .unwrap_or("provider error");
                self.push_log(format!("provider_error: {msg}"));
            }
            EventKind::ProviderRetry => {
                let attempt = ev.data.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0);
                let max_attempts = ev
                    .data
                    .get("max_attempts")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let kind = ev
                    .data
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("other");
                let backoff_ms = ev
                    .data
                    .get("backoff_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                self.push_log(format!(
                    "provider_retry: attempt {attempt}/{max_attempts} kind={kind} backoff_ms={backoff_ms}"
                ));
            }
            EventKind::Error => {
                let msg = ev
                    .data
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                self.push_log(format!("error: {msg}"));
            }
            _ => {
                if matches!(ev.kind, EventKind::CompactionPerformed) {
                    self.push_log("compaction performed".to_string());
                }
            }
        }
    }

    pub fn refresh_approvals(&mut self, path: &Path) -> anyhow::Result<()> {
        let store = ApprovalsStore::new(path.to_path_buf());
        let data = store.list()?;
        let mut rows = data
            .requests
            .into_iter()
            .map(|(id, req)| ApprovalRow {
                id,
                tool: req.tool,
                status: match req.status {
                    StoredStatus::Pending => "pending",
                    StoredStatus::Approved => "approved",
                    StoredStatus::Denied => "denied",
                }
                .to_string(),
                created_at: req.created_at,
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        self.pending_approvals = rows;
        Ok(())
    }

    pub fn push_log(&mut self, line: String) {
        self.logs.push(line);
        if self.logs.len() > self.max_log_lines {
            let drain = self.logs.len() - self.max_log_lines;
            self.logs.drain(0..drain);
        }
    }

    fn upsert_tool(
        &mut self,
        tool_call_id: String,
        tool_name: String,
        side_effects: String,
        status: &str,
    ) -> &mut ToolRow {
        if let Some(idx) = self
            .tool_calls
            .iter()
            .position(|t| t.tool_call_id == tool_call_id)
        {
            let row = &mut self.tool_calls[idx];
            row.status = status.to_string();
            if !tool_name.is_empty() {
                row.tool_name = tool_name;
            }
            if !side_effects.is_empty() {
                row.side_effects = side_effects;
            }
            return row;
        }
        self.tool_calls.push(ToolRow {
            tool_call_id,
            tool_name,
            side_effects,
            decision: None,
            decision_reason: None,
            status: status.to_string(),
            ok: None,
            short_result: String::new(),
        });
        self.tool_calls.last_mut().expect("tool row")
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::events::{Event, EventKind};
    use crate::trust::approvals::ApprovalsStore;

    use super::UiState;

    #[test]
    fn apply_event_model_delta_appends() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ModelDelta,
            serde_json::json!({"delta":"hello"}),
        ));
        assert_eq!(s.assistant_text, "hello");
    }

    #[test]
    fn apply_event_tool_lifecycle() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolCallDetected,
            serde_json::json!({"tool_call_id":"tc1","name":"read_file","side_effects":"filesystem_read"}),
        ));
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolDecision,
            serde_json::json!({"tool_call_id":"tc1","name":"read_file","decision":"allow","reason":"ok"}),
        ));
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecEnd,
            serde_json::json!({"tool_call_id":"tc1","name":"read_file","ok":true,"content":"abc"}),
        ));
        assert_eq!(s.tool_calls.len(), 1);
        assert_eq!(s.tool_calls[0].decision.as_deref(), Some("allow"));
        assert_eq!(s.tool_calls[0].ok, Some(true));
        assert_eq!(s.tool_calls[0].short_result, "abc");
    }

    #[test]
    fn logs_are_capped() {
        let mut s = UiState::new(2);
        s.push_log("a".to_string());
        s.push_log("b".to_string());
        s.push_log("c".to_string());
        assert_eq!(s.logs, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn approvals_refresh_and_transition() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("approvals.json");
        let store = ApprovalsStore::new(path.clone());
        let id = store
            .create_pending("shell", &serde_json::json!({"cmd":"echo"}), None)
            .expect("pending");
        let mut s = UiState::new(10);
        s.refresh_approvals(&path).expect("refresh");
        assert_eq!(s.pending_approvals.len(), 1);
        assert_eq!(s.pending_approvals[0].status, "pending");
        store.approve(&id, None, None).expect("approve");
        s.refresh_approvals(&path).expect("refresh2");
        assert_eq!(s.pending_approvals[0].status, "approved");
    }
}
