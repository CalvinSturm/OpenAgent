use std::path::Path;

use crate::events::{Event, EventKind};
use crate::trust::approvals::{ApprovalsStore, StoredStatus};

#[derive(Debug, Clone, Default)]
pub struct ToolRow {
    pub tool_call_id: String,
    pub tool_name: String,
    pub side_effects: String,
    pub decision: Option<String>,
    pub decision_source: Option<String>,
    pub reason_token: String,
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
    pub mode_label: String,
    pub authority_label: String,
    pub caps_source: String,
    pub policy_hash: String,
    pub mcp_catalog_hash: String,
    pub net_status: String,
    pub assistant_text: String,
    pub tool_calls: Vec<ToolRow>,
    pub pending_approvals: Vec<ApprovalRow>,
    pub logs: Vec<String>,
    pub exit_reason: Option<String>,
    pub show_details: bool,
    pub current_step_id: String,
    pub current_step_goal: String,
    pub current_step_allowed_tools: Vec<String>,
    pub next_hint: String,
    pub enforce_plan_tools_effective: String,
    pub schema_repair_seen: bool,
    pub last_failure_class: String,
    pub last_tool_retry_count: u64,
    pub total_tool_execs: u64,
    pub filesystem_read_execs: u64,
    pub filesystem_write_execs: u64,
    pub shell_execs: u64,
    pub network_execs: u64,
    pub browser_execs: u64,
    max_log_lines: usize,
}

impl UiState {
    pub fn new(max_log_lines: usize) -> Self {
        Self {
            run_id: String::new(),
            step: 0,
            provider: String::new(),
            model: String::new(),
            mode_label: "SAFE".to_string(),
            authority_label: "VETO".to_string(),
            caps_source: String::new(),
            policy_hash: String::new(),
            mcp_catalog_hash: String::new(),
            net_status: "OK".to_string(),
            assistant_text: String::new(),
            tool_calls: Vec::new(),
            pending_approvals: Vec::new(),
            logs: Vec::new(),
            exit_reason: None,
            show_details: false,
            current_step_id: "-".to_string(),
            current_step_goal: "-".to_string(),
            current_step_allowed_tools: Vec::new(),
            next_hint: "-".to_string(),
            enforce_plan_tools_effective: "-".to_string(),
            schema_repair_seen: false,
            last_failure_class: "-".to_string(),
            last_tool_retry_count: 0,
            total_tool_execs: 0,
            filesystem_read_execs: 0,
            filesystem_write_execs: 0,
            shell_execs: 0,
            network_execs: 0,
            browser_execs: 0,
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
                if let Some(mode) = ev
                    .data
                    .get("enforce_plan_tools_effective")
                    .and_then(|v| v.as_str())
                {
                    self.enforce_plan_tools_effective = mode.to_string();
                }
                self.net_status = "OK".to_string();
            }
            EventKind::RunEnd => {
                self.exit_reason = ev
                    .data
                    .get("exit_reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                self.next_hint = "done".to_string();
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
                let source = ev
                    .data
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let is_deny = decision == "deny";
                let is_pending = decision == "require_approval";
                {
                    let row = self.upsert_tool(id, name, side, "decided");
                    row.decision = Some(decision);
                    row.decision_source = Some(source.clone());
                    row.reason_token = reason_token(&source, reason.as_deref()).to_string();
                    row.decision_reason = reason;
                    if is_deny {
                        row.status = format!("DENY:{}", row.reason_token);
                    } else if is_pending {
                        row.status = "PEND:approval".to_string();
                    }
                }
                if let Some(step_id) = ev.data.get("plan_step_id").and_then(|v| v.as_str()) {
                    self.current_step_id = step_id.to_string();
                }
                if let Some(allowed) = ev.data.get("plan_allowed_tools").and_then(|v| v.as_array())
                {
                    self.current_step_allowed_tools = allowed
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                }
                if is_deny {
                    self.next_hint = format!("blocked({})", reason_token(&source, None));
                } else if is_pending {
                    self.next_hint = "pending_approval".to_string();
                }
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
                let failure_class = ev
                    .data
                    .get("failure_class")
                    .and_then(|v| v.as_str())
                    .unwrap_or("E_OTHER");
                let side_effects = {
                    let row = self.upsert_tool(id, name, String::new(), "done");
                    row.ok = ok;
                    row.short_result = truncate_chars(result, 200);
                    if matches!(ok, Some(false)) {
                        row.status = format!("FAIL:{}", class_to_reason_token(failure_class));
                        row.reason_token = class_to_reason_token(failure_class).to_string();
                    }
                    row.side_effects.clone()
                };
                if matches!(ok, Some(true)) {
                    self.bump_usage(&side_effects);
                    self.next_hint = "continue".to_string();
                }
                self.last_tool_retry_count = ev
                    .data
                    .get("retry_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                self.last_failure_class = ev
                    .data
                    .get("failure_class")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("-")
                    .to_string();
            }
            EventKind::PolicyLoaded => {
                if let Some(hash) = ev.data.get("policy_hash_hex").and_then(|v| v.as_str()) {
                    self.policy_hash = hash.to_string();
                }
            }
            EventKind::PlannerStart | EventKind::WorkerStart => {
                if let Some(mode) = ev
                    .data
                    .get("enforce_plan_tools_effective")
                    .and_then(|v| v.as_str())
                {
                    self.enforce_plan_tools_effective = mode.to_string();
                }
                if let Some(step_id) = ev.data.get("plan_step_id").and_then(|v| v.as_str()) {
                    self.current_step_id = step_id.to_string();
                }
            }
            EventKind::ProviderError => {
                let msg = ev
                    .data
                    .get("message_short")
                    .and_then(|v| v.as_str())
                    .unwrap_or("provider error");
                self.push_log(format!("provider_error: {msg}"));
                self.net_status = "DISC".to_string();
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
                self.net_status = "SLOW".to_string();
            }
            EventKind::ToolRetry => {
                let tool = ev
                    .data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tool");
                let attempt = ev.data.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0);
                let max_retries = ev
                    .data
                    .get("max_retries")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let class = ev
                    .data
                    .get("failure_class")
                    .and_then(|v| v.as_str())
                    .unwrap_or("E_OTHER");
                let action = ev
                    .data
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stop");
                if class == "E_SCHEMA" && action == "repair" {
                    self.schema_repair_seen = true;
                }
                self.last_failure_class = class.to_string();
                self.last_tool_retry_count = attempt;
                self.push_log(format!(
                    "tool_retry: {tool} class={class} attempt={attempt}/{max_retries} action={action}"
                ));
            }
            EventKind::Error => {
                let msg = ev
                    .data
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                self.push_log(format!("error: {msg}"));
                if ev
                    .data
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    == "plan_halt_guard"
                {
                    self.next_hint = "blocked(plan)".to_string();
                }
            }
            _ => {
                if matches!(ev.kind, EventKind::CompactionPerformed) {
                    self.push_log("compaction performed".to_string());
                }
            }
        }
    }

    fn bump_usage(&mut self, side_effects: &str) {
        self.total_tool_execs = self.total_tool_execs.saturating_add(1);
        match side_effects {
            "filesystem_read" => {
                self.filesystem_read_execs = self.filesystem_read_execs.saturating_add(1)
            }
            "filesystem_write" => {
                self.filesystem_write_execs = self.filesystem_write_execs.saturating_add(1)
            }
            "shell_exec" => self.shell_execs = self.shell_execs.saturating_add(1),
            "network" => self.network_execs = self.network_execs.saturating_add(1),
            "browser" => self.browser_execs = self.browser_execs.saturating_add(1),
            _ => {}
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
            decision_source: None,
            reason_token: "-".to_string(),
            decision_reason: None,
            status: status.to_string(),
            ok: None,
            short_result: String::new(),
        });
        self.tool_calls.last_mut().expect("tool row")
    }

    pub fn step_allowed_tools_compact(&self) -> String {
        if self.current_step_allowed_tools.is_empty() {
            "-".to_string()
        } else {
            self.current_step_allowed_tools.join(",")
        }
    }

    pub fn last_tool_summary(&self) -> String {
        if let Some(last) = self.tool_calls.last() {
            let outcome = last.decision.clone().unwrap_or_else(|| last.status.clone());
            let reason = last.decision_reason.clone().unwrap_or_default();
            if reason.is_empty() {
                format!("{} {}", last.tool_name, outcome)
            } else {
                format!(
                    "{} {} {}",
                    last.tool_name,
                    outcome,
                    truncate_chars(&reason, 60)
                )
            }
        } else {
            "-".to_string()
        }
    }
}

fn reason_token(source: &str, reason: Option<&str>) -> &'static str {
    match source {
        "plan_step_constraint" => "plan",
        "runtime_budget" => "budget",
        "policy" => "policy",
        "approval_store" => "approval",
        _ => {
            let lower = reason.unwrap_or_default().to_ascii_lowercase();
            if lower.contains("invalid tool arguments")
                || lower.contains("missing required field")
                || lower.contains("schema")
            {
                "schema"
            } else if lower.contains("timeout")
                || lower.contains("timed out")
                || lower.contains("connection refused")
                || lower.contains("network")
            {
                "net"
            } else if lower.contains("user denied")
                || lower.contains("cancelled")
                || lower.contains("canceled")
            {
                "user"
            } else if lower.is_empty() {
                "other"
            } else {
                "tool"
            }
        }
    }
}

fn class_to_reason_token(class: &str) -> &'static str {
    match class {
        "E_SCHEMA" => "schema",
        "E_POLICY" => "policy",
        "E_TIMEOUT_TRANSIENT" | "E_NETWORK_TRANSIENT" => "net",
        "E_SELECTOR_AMBIGUOUS" | "E_NON_IDEMPOTENT" | "E_OTHER" => "tool",
        _ => "other",
    }
}

fn short_hash(s: &str) -> String {
    if s.is_empty() {
        "-".to_string()
    } else {
        s.chars().take(8).collect()
    }
}

impl UiState {
    pub fn policy_hash_short(&self) -> String {
        short_hash(&self.policy_hash)
    }

    pub fn mcp_hash_short(&self) -> String {
        short_hash(&self.mcp_catalog_hash)
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
        assert_eq!(s.total_tool_execs, 1);
        assert_eq!(s.filesystem_read_execs, 1);
    }

    #[test]
    fn schema_repair_flag_turns_on_from_retry_event() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolRetry,
            serde_json::json!({"name":"read_file","attempt":1,"max_retries":1,"failure_class":"E_SCHEMA","action":"repair"}),
        ));
        assert!(s.schema_repair_seen);
        assert_eq!(s.last_failure_class, "E_SCHEMA");
        assert_eq!(s.last_tool_retry_count, 1);
    }

    #[test]
    fn failure_class_and_retry_count_are_captured_on_tool_exec_end() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecEnd,
            serde_json::json!({
                "tool_call_id":"tc1",
                "name":"read_file",
                "ok":false,
                "content":"error",
                "retry_count":1,
                "failure_class":"E_TIMEOUT_TRANSIENT"
            }),
        ));
        assert_eq!(s.last_failure_class, "E_TIMEOUT_TRANSIENT");
        assert_eq!(s.last_tool_retry_count, 1);
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
            .create_pending("shell", &serde_json::json!({"cmd":"echo"}), None, None)
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
