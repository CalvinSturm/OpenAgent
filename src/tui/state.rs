use std::path::Path;
use std::time::{Duration, Instant};

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
    pub running_since: Option<Instant>,
    pub running_for_ms: u64,
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
    pub mcp_pin_enforcement: String,
    pub caps_source: String,
    pub policy_hash: String,
    pub mcp_catalog_hash: String,
    pub mcp_pin_state: String,
    pub mcp_lifecycle: String,
    pub mcp_running_for_ms: u64,
    pub mcp_stalled: bool,
    mcp_stall_notice_emitted: bool,
    pub cancel_lifecycle: String,
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
            mcp_pin_enforcement: "HARD".to_string(),
            caps_source: String::new(),
            policy_hash: String::new(),
            mcp_catalog_hash: String::new(),
            mcp_pin_state: "-".to_string(),
            mcp_lifecycle: "IDLE".to_string(),
            mcp_running_for_ms: 0,
            mcp_stalled: false,
            mcp_stall_notice_emitted: false,
            cancel_lifecycle: "NONE".to_string(),
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
                self.mcp_lifecycle = "IDLE".to_string();
                self.mcp_pin_state = "-".to_string();
                self.mcp_running_for_ms = 0;
                self.mcp_stalled = false;
                self.mcp_stall_notice_emitted = false;
                self.cancel_lifecycle = "NONE".to_string();
            }
            EventKind::RunEnd => {
                let exit_reason = ev
                    .data
                    .get("exit_reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                self.exit_reason = exit_reason.clone();
                if self.cancel_lifecycle == "REQUESTED"
                    || exit_reason.as_deref() == Some("cancelled")
                {
                    self.cancel_lifecycle = "COMPLETE".to_string();
                }
                if exit_reason.as_deref() == Some("cancelled") {
                    if self.tool_calls.iter().any(|t| {
                        is_mcp_tool(&t.tool_name) && (t.status == "running" || t.status == "STALL")
                    }) {
                        self.mcp_lifecycle = "CANCELLED".to_string();
                    }
                    for row in &mut self.tool_calls {
                        if is_mcp_tool(&row.tool_name)
                            && (row.status == "running" || row.status == "STALL")
                        {
                            row.status = "CANCEL:user".to_string();
                            row.reason_token = "user".to_string();
                            row.running_since = None;
                            row.running_for_ms = 0;
                            row.ok = Some(false);
                        }
                    }
                    self.mcp_running_for_ms = 0;
                    self.mcp_stalled = false;
                    self.mcp_stall_notice_emitted = false;
                }
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
                self.apply_tool_call_detected_event(ev);
            }
            EventKind::ToolDecision => {
                self.apply_tool_decision_event(ev);
            }
            EventKind::ToolExecStart => {
                self.apply_tool_exec_start_event(ev);
            }
            EventKind::ToolExecEnd => {
                self.apply_tool_exec_end_event(ev);
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
                if is_mcp_tool(tool) {
                    if action == "retry" {
                        self.mcp_lifecycle = "WAIT:RETRY".to_string();
                    } else if action == "stop" {
                        self.mcp_lifecycle = "FAIL".to_string();
                    }
                }
                self.last_failure_class = class.to_string();
                self.last_tool_retry_count = attempt;
                self.push_log(format!(
                    "tool_retry: {tool} class={class} attempt={attempt}/{max_retries} action={action}"
                ));
            }
            EventKind::McpDrift => {
                let expected = ev
                    .data
                    .get("catalog_hash_expected")
                    .or_else(|| ev.data.get("expected_hash_hex"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let actual = ev
                    .data
                    .get("catalog_hash_live")
                    .or_else(|| ev.data.get("actual_hash_hex"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let docs_expected = ev
                    .data
                    .get("docs_hash_expected")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let docs_actual = ev
                    .data
                    .get("docs_hash_live")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let catalog_drift = ev
                    .data
                    .get("catalog_drift")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(actual != expected && actual != "-");
                let docs_drift = ev
                    .data
                    .get("docs_drift")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let primary_code = ev
                    .data
                    .get("primary_code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("MCP_DRIFT");
                self.mcp_lifecycle = "DRIFT".to_string();
                self.mcp_pin_state = "DRIFT".to_string();
                self.mcp_stalled = false;
                self.mcp_running_for_ms = 0;
                let tool = ev
                    .data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("mcp.tool");
                let summary = match (catalog_drift, docs_drift) {
                    (true, true) => format!(
                        "mcp_drift[{primary_code}]: catalog {}->{} docs {}->{} tool={tool}",
                        truncate_chars(expected, 12),
                        truncate_chars(actual, 12),
                        truncate_chars(docs_expected, 12),
                        truncate_chars(docs_actual, 12),
                    ),
                    (true, false) => format!(
                        "mcp_drift[{primary_code}]: catalog {}->{} tool={tool}",
                        truncate_chars(expected, 12),
                        truncate_chars(actual, 12),
                    ),
                    (false, true) => format!(
                        "mcp_drift[{primary_code}]: docs {}->{} tool={tool}",
                        truncate_chars(docs_expected, 12),
                        truncate_chars(docs_actual, 12),
                    ),
                    (false, false) => format!("mcp_drift[{primary_code}]: tool={tool}"),
                };
                self.push_log(summary);
            }
            EventKind::McpProgress => {
                let ticks = ev
                    .data
                    .get("progress_ticks")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let elapsed_ms = ev
                    .data
                    .get("elapsed_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                self.mcp_lifecycle = "WAIT:TASK".to_string();
                self.mcp_running_for_ms = elapsed_ms;
                self.mcp_stalled = false;
                self.mcp_stall_notice_emitted = false;
                self.push_log(format!(
                    "mcp_progress: tool={} ticks={} elapsed_ms={}",
                    ev.data
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("mcp.tool"),
                    ticks,
                    elapsed_ms
                ));
            }
            EventKind::McpCancelled => {
                let reason = ev
                    .data
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("cancelled");
                self.mcp_lifecycle = "CANCELLED".to_string();
                self.mcp_running_for_ms = 0;
                self.mcp_stalled = false;
                self.mcp_stall_notice_emitted = false;
                self.next_hint = "cancelled".to_string();
                self.push_log(format!(
                    "mcp_cancelled: tool={} reason={}",
                    ev.data
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("mcp.tool"),
                    reason
                ));
            }
            EventKind::McpPinned => {
                if let Some(enforcement) = ev.data.get("enforcement").and_then(|v| v.as_str()) {
                    self.mcp_pin_enforcement = enforcement.to_ascii_uppercase();
                }
                let pinned = ev
                    .data
                    .get("pinned")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.mcp_pin_state = if pinned { "PINNED" } else { "UNPINNED" }.to_string();
                self.push_log(format!(
                    "mcp_pinned: configured={} startup_live={} pinned={}",
                    ev.data
                        .get("configured_hash_hex")
                        .and_then(|v| v.as_str())
                        .map(|s| truncate_chars(s, 12))
                        .unwrap_or_else(|| "-".to_string()),
                    ev.data
                        .get("startup_live_hash_hex")
                        .and_then(|v| v.as_str())
                        .map(|s| truncate_chars(s, 12))
                        .unwrap_or_else(|| "-".to_string()),
                    pinned
                ));
            }
            EventKind::PackActivated => {
                let pack_id = ev
                    .data
                    .get("pack_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("pack");
                let truncated = ev
                    .data
                    .get("truncated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let bytes_kept = ev
                    .data
                    .get("bytes_kept")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                self.push_log(format!(
                    "pack_activated: id={} truncated={} bytes_kept={}",
                    pack_id, truncated, bytes_kept
                ));
            }
            EventKind::QueueSubmitted => {
                let queue_id = ev
                    .data
                    .get("queue_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("q?");
                let kind = ev
                    .data
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let truncated = ev
                    .data
                    .get("truncated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let bytes_kept = ev
                    .data
                    .get("bytes_kept")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let boundary_phrase = ev
                    .data
                    .get("next_delivery")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                self.push_log(format!(
                    "queue_submitted: id={} kind={} truncated={} bytes_kept={} next={}",
                    queue_id, kind, truncated, bytes_kept, boundary_phrase
                ));
            }
            EventKind::QueueDelivered => {
                let queue_id = ev
                    .data
                    .get("queue_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("q?");
                let kind = ev
                    .data
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let boundary = ev
                    .data
                    .get("delivery_boundary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                self.push_log(format!(
                    "queue_delivered: id={} kind={} boundary={}",
                    queue_id, kind, boundary
                ));
            }
            EventKind::QueueInterrupt => {
                let queue_id = ev
                    .data
                    .get("queue_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("q?");
                let reason = ev
                    .data
                    .get("cancelled_reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("operator_steer");
                let cancelled_remaining_work = ev
                    .data
                    .get("cancelled_remaining_work")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.push_log(format!(
                    "queue_interrupt: id={} cancelled_remaining_work={} reason={}",
                    queue_id, cancelled_remaining_work, reason
                ));
                if cancelled_remaining_work {
                    self.next_hint = "interrupt_applied".to_string();
                }
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

    fn apply_tool_call_detected_event(&mut self, ev: &Event) {
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

    fn apply_tool_decision_event(&mut self, ev: &Event) {
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
        let is_mcp = is_mcp_tool(&name);
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
        if let Some(allowed) = ev.data.get("plan_allowed_tools").and_then(|v| v.as_array()) {
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
        if is_mcp {
            if is_pending {
                self.mcp_lifecycle = "WAIT:APPROVAL".to_string();
            } else if is_deny {
                self.mcp_lifecycle = "DENY".to_string();
            }
        }
    }

    fn apply_tool_exec_start_event(&mut self, ev: &Event) {
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
        if is_mcp_tool(
            ev.data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        ) {
            self.mcp_lifecycle = "RUNNING".to_string();
            self.mcp_running_for_ms = 0;
            self.mcp_stalled = false;
            self.mcp_stall_notice_emitted = false;
        }
    }

    fn apply_tool_exec_end_event(&mut self, ev: &Event) {
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
            row.running_since = None;
            row.running_for_ms = 0;
            if matches!(ok, Some(false)) {
                let mut token = class_to_reason_token(failure_class).to_string();
                if is_protocol_violation_text(result) {
                    token = "protocol".to_string();
                }
                row.status = format!("FAIL:{token}");
                row.reason_token = token;
            }
            row.side_effects.clone()
        };
        if matches!(ok, Some(true)) {
            self.bump_usage(&side_effects);
            self.next_hint = "continue".to_string();
            if is_mcp_tool(
                ev.data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            ) {
                self.mcp_lifecycle = "DONE".to_string();
                self.mcp_running_for_ms = 0;
                self.mcp_stalled = false;
                self.mcp_stall_notice_emitted = false;
            }
        } else if is_mcp_tool(
            ev.data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        ) {
            self.mcp_lifecycle = "FAIL".to_string();
            self.mcp_running_for_ms = 0;
            self.mcp_stalled = false;
            self.mcp_stall_notice_emitted = false;
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
            if status == "running" && row.running_since.is_none() {
                row.running_since = Some(Instant::now());
                row.running_for_ms = 0;
            }
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
            running_since: if status == "running" {
                Some(Instant::now())
            } else {
                None
            },
            running_for_ms: 0,
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
        "E_PROTOCOL" => "protocol",
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

    pub fn mcp_status_compact(&self) -> String {
        if self.mcp_catalog_hash.is_empty() {
            "-".to_string()
        } else if self.mcp_running_for_ms > 0 {
            format!(
                "{}:{}:{}s",
                self.mcp_hash_short(),
                self.mcp_lifecycle,
                self.mcp_running_for_ms / 1000
            )
        } else {
            format!("{}:{}", self.mcp_hash_short(), self.mcp_lifecycle)
        }
    }

    pub fn mark_cancel_requested(&mut self) {
        self.cancel_lifecycle = "REQUESTED".to_string();
        self.next_hint = "cancel_requested".to_string();
        self.push_log(
            "cancel requested; waiting for run to terminate (press q again to force quit)"
                .to_string(),
        );
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel_lifecycle == "REQUESTED"
    }

    pub fn on_tick(&mut self, now: Instant) {
        const MCP_STALL_THRESHOLD: Duration = Duration::from_secs(10);
        let mut has_mcp_running = false;
        let mut max_mcp_elapsed_ms = 0u64;
        let mut stall_notice: Option<String> = None;
        for row in &mut self.tool_calls {
            if row.status != "running" && row.status != "STALL" {
                continue;
            }
            let Some(since) = row.running_since else {
                continue;
            };
            let elapsed = now.duration_since(since);
            row.running_for_ms = elapsed.as_millis() as u64;
            if is_mcp_tool(&row.tool_name) {
                has_mcp_running = true;
                max_mcp_elapsed_ms = max_mcp_elapsed_ms.max(row.running_for_ms);
                if elapsed >= MCP_STALL_THRESHOLD {
                    row.status = "STALL".to_string();
                    row.reason_token = "net".to_string();
                    if !self.mcp_stall_notice_emitted {
                        stall_notice = Some(format!(
                            "mcp_stall: tool={} running_for={}s",
                            row.tool_name,
                            row.running_for_ms / 1000
                        ));
                        self.mcp_stall_notice_emitted = true;
                    }
                }
            }
        }
        if let Some(line) = stall_notice {
            self.push_log(line);
        }
        if has_mcp_running {
            self.mcp_running_for_ms = max_mcp_elapsed_ms;
            if max_mcp_elapsed_ms >= MCP_STALL_THRESHOLD.as_millis() as u64 {
                self.mcp_lifecycle = "STALL".to_string();
                self.mcp_stalled = true;
            } else {
                self.mcp_lifecycle = "RUNNING".to_string();
                self.mcp_stalled = false;
            }
        }
    }
}

fn is_mcp_tool(name: &str) -> bool {
    name.starts_with("mcp.")
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn is_protocol_violation_text(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("model_tool_protocol_violation")
        || t.contains("repeated malformed tool calls")
        || t.contains("repeated invalid patch format")
        || t.contains("tool-only phase")
        || t.contains("no tool call returned by probe")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

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
    fn tool_decision_reflects_deny_and_approval_in_tui_state() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolCallDetected,
            serde_json::json!({"tool_call_id":"tc_mcp","name":"mcp.stub.echo","side_effects":"network"}),
        ));
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolDecision,
            serde_json::json!({
                "tool_call_id":"tc_mcp",
                "name":"mcp.stub.echo",
                "side_effects":"network",
                "decision":"require_approval",
                "reason":"shell requires approval",
                "source":"policy"
            }),
        ));
        assert_eq!(s.tool_calls.len(), 1);
        assert_eq!(
            s.tool_calls[0].decision.as_deref(),
            Some("require_approval")
        );
        assert_eq!(s.tool_calls[0].status, "PEND:approval");
        assert_eq!(s.next_hint, "pending_approval");
        assert_eq!(s.mcp_lifecycle, "WAIT:APPROVAL");

        s.apply_event(&Event::new(
            "r1".to_string(),
            2,
            EventKind::ToolCallDetected,
            serde_json::json!({"tool_call_id":"tc2","name":"write_file","side_effects":"filesystem_write"}),
        ));
        s.apply_event(&Event::new(
            "r1".to_string(),
            2,
            EventKind::ToolDecision,
            serde_json::json!({
                "tool_call_id":"tc2",
                "name":"write_file",
                "side_effects":"filesystem_write",
                "decision":"deny",
                "reason":"writes denied",
                "source":"policy"
            }),
        ));
        assert_eq!(s.tool_calls.len(), 2);
        assert_eq!(s.tool_calls[1].decision.as_deref(), Some("deny"));
        assert!(s.tool_calls[1].status.starts_with("DENY:"));
        assert_eq!(s.next_hint, "blocked(policy)");
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
    fn tool_exec_end_protocol_violation_sets_protocol_reason_token() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecEnd,
            serde_json::json!({
                "tool_call_id":"tc1",
                "name":"apply_patch",
                "ok":false,
                "content":"MODEL_TOOL_PROTOCOL_VIOLATION: repeated invalid patch format for apply_patch",
                "retry_count":1,
                "failure_class":"E_OTHER"
            }),
        ));
        assert_eq!(s.tool_calls.len(), 1);
        assert_eq!(s.tool_calls[0].reason_token, "protocol");
        assert_eq!(s.tool_calls[0].status, "FAIL:protocol");
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

    #[test]
    fn approvals_queue_multiple_entries_preserve_independent_statuses() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("approvals.json");
        let store = ApprovalsStore::new(path.clone());
        let id1 = store
            .create_pending("shell", &serde_json::json!({"cmd":"echo one"}), None, None)
            .expect("pending1");
        let id2 = store
            .create_pending(
                "write_file",
                &serde_json::json!({"path":"x","content":"y"}),
                None,
                None,
            )
            .expect("pending2");

        let mut s = UiState::new(10);
        s.refresh_approvals(&path).expect("refresh");
        assert_eq!(s.pending_approvals.len(), 2);
        let rows = s
            .pending_approvals
            .iter()
            .map(|r| (r.id.clone(), r.status.clone(), r.tool.clone()))
            .collect::<Vec<_>>();
        let rows = rows
            .into_iter()
            .map(|(id, status, tool)| (id, (status, tool)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            rows.get(&id1),
            Some(&("pending".to_string(), "shell".to_string()))
        );
        assert_eq!(
            rows.get(&id2),
            Some(&("pending".to_string(), "write_file".to_string()))
        );

        store.deny(&id1).expect("deny1");
        s.refresh_approvals(&path).expect("refresh2");
        let rows2 = s
            .pending_approvals
            .iter()
            .map(|r| (r.id.clone(), r.status.clone(), r.tool.clone()))
            .collect::<Vec<_>>();
        let rows2 = rows2
            .into_iter()
            .map(|(id, status, tool)| (id, (status, tool)))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            rows2.get(&id1),
            Some(&("denied".to_string(), "shell".to_string()))
        );
        assert_eq!(
            rows2.get(&id2),
            Some(&("pending".to_string(), "write_file".to_string()))
        );
    }

    #[test]
    fn mcp_lifecycle_running_retry_done() {
        let mut s = UiState::new(10);
        s.mcp_catalog_hash = "abcdef123456".to_string();
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecStart,
            serde_json::json!({"tool_call_id":"tc1","name":"mcp.playwright.browser_snapshot","side_effects":"browser"}),
        ));
        assert_eq!(s.mcp_lifecycle, "RUNNING");
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolRetry,
            serde_json::json!({"name":"mcp.playwright.browser_snapshot","attempt":1,"max_retries":1,"failure_class":"E_TIMEOUT_TRANSIENT","action":"retry"}),
        ));
        assert_eq!(s.mcp_lifecycle, "WAIT:RETRY");
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecEnd,
            serde_json::json!({"tool_call_id":"tc1","name":"mcp.playwright.browser_snapshot","ok":true,"content":"ok","retry_count":1,"failure_class":null}),
        ));
        assert_eq!(s.mcp_lifecycle, "DONE");
        assert!(s.mcp_status_compact().contains("DONE"));
    }

    #[test]
    fn mcp_running_tool_marked_cancelled_on_run_cancel() {
        let mut s = UiState::new(10);
        s.mark_cancel_requested();
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecStart,
            serde_json::json!({"tool_call_id":"tc1","name":"mcp.playwright.browser_snapshot","side_effects":"browser"}),
        ));
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::RunEnd,
            serde_json::json!({"exit_reason":"cancelled"}),
        ));
        assert_eq!(s.mcp_lifecycle, "CANCELLED");
        assert_eq!(s.cancel_lifecycle, "COMPLETE");
        assert_eq!(s.tool_calls[0].status, "CANCEL:user");
        assert_eq!(s.tool_calls[0].reason_token, "user");
    }

    #[test]
    fn cancel_request_transitions_to_complete_on_run_end() {
        let mut s = UiState::new(10);
        s.mark_cancel_requested();
        assert!(s.cancel_requested());
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::RunEnd,
            serde_json::json!({"exit_reason":"ok"}),
        ));
        assert_eq!(s.cancel_lifecycle, "COMPLETE");
    }

    #[test]
    fn on_tick_marks_long_running_mcp_as_stalled() {
        let mut s = UiState::new(10);
        s.mcp_catalog_hash = "abcdef123456".to_string();
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::ToolExecStart,
            serde_json::json!({"tool_call_id":"tc1","name":"mcp.playwright.browser_snapshot","side_effects":"browser"}),
        ));
        s.tool_calls[0].running_since = Some(Instant::now() - Duration::from_secs(12));
        s.on_tick(Instant::now());
        assert_eq!(s.mcp_lifecycle, "STALL");
        assert!(s.mcp_stalled);
        assert!(s.mcp_running_for_ms >= 12_000);
        assert_eq!(s.tool_calls[0].status, "STALL");
    }

    #[test]
    fn mcp_drift_event_sets_drift_lifecycle() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::McpDrift,
            serde_json::json!({
                "name":"mcp.playwright.browser_snapshot",
                "expected_hash_hex":"abc",
                "actual_hash_hex":"def"
            }),
        ));
        assert_eq!(s.mcp_lifecycle, "DRIFT");
    }

    #[test]
    fn mcp_docs_drift_event_logs_docs_specific_summary() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::McpDrift,
            serde_json::json!({
                "name":"mcp.stub.echo",
                "catalog_hash_expected":"aaa",
                "catalog_hash_live":"aaa",
                "catalog_drift":false,
                "docs_hash_expected":"bbb",
                "docs_hash_live":"ccc",
                "docs_drift":true,
                "primary_code":"MCP_DOCS_DRIFT"
            }),
        ));
        assert_eq!(s.mcp_lifecycle, "DRIFT");
        let last = s.logs.last().cloned().unwrap_or_default();
        assert!(last.contains("MCP_DOCS_DRIFT"));
        assert!(last.contains("docs"));
        assert!(last.contains("mcp.stub.echo"));
    }

    #[test]
    fn mcp_pinned_event_sets_pin_state() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r".to_string(),
            1,
            EventKind::McpPinned,
            serde_json::json!({
                "enforcement":"warn",
                "configured_hash_hex":"abc",
                "startup_live_hash_hex":"abc",
                "pinned":true
            }),
        ));
        assert_eq!(s.mcp_pin_state, "PINNED");
        assert_eq!(s.mcp_pin_enforcement, "WARN");
    }

    #[test]
    fn mcp_progress_event_updates_lifecycle() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::McpProgress,
            serde_json::json!({
                "name":"mcp.playwright.browser_snapshot",
                "progress_ticks":2,
                "elapsed_ms":1500
            }),
        ));
        assert_eq!(s.mcp_lifecycle, "WAIT:TASK");
        assert_eq!(s.mcp_running_for_ms, 1500);
    }

    #[test]
    fn mcp_cancelled_event_sets_cancelled_lifecycle() {
        let mut s = UiState::new(10);
        s.apply_event(&Event::new(
            "r1".to_string(),
            1,
            EventKind::McpCancelled,
            serde_json::json!({
                "name":"mcp.playwright.browser_snapshot",
                "reason":"timeout"
            }),
        ));
        assert_eq!(s.mcp_lifecycle, "CANCELLED");
        assert_eq!(s.next_hint, "cancelled");
    }

    #[test]
    fn queue_events_log_stable_summaries() {
        let mut s = UiState::new(50);
        s.apply_event(&Event::new(
            "r".to_string(),
            1,
            EventKind::QueueSubmitted,
            serde_json::json!({
                "queue_id":"q7",
                "kind":"steer",
                "truncated": false,
                "bytes_kept": 12,
                "next_delivery":"after current tool finishes"
            }),
        ));
        s.apply_event(&Event::new(
            "r".to_string(),
            1,
            EventKind::QueueDelivered,
            serde_json::json!({
                "queue_id":"q7",
                "kind":"steer",
                "delivery_boundary":"post_tool"
            }),
        ));
        s.apply_event(&Event::new(
            "r".to_string(),
            1,
            EventKind::QueueInterrupt,
            serde_json::json!({
                "queue_id":"q7",
                "cancelled_remaining_work": true,
                "cancelled_reason":"operator_steer"
            }),
        ));
        let joined = s.logs.join("\n");
        assert!(joined.contains("queue_submitted: id=q7 kind=steer"));
        assert!(joined.contains("queue_delivered: id=q7 kind=steer boundary=post_tool"));
        assert!(joined.contains("queue_interrupt: id=q7 cancelled_remaining_work=true"));
        assert_eq!(s.next_hint, "interrupt_applied");
    }
}
