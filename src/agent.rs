use uuid::Uuid;

use crate::compaction::{context_size_chars, maybe_compact, CompactionReport, CompactionSettings};
use crate::events::{Event, EventKind, EventSink};
use crate::gate::{ApprovalMode, AutoApproveScope, GateContext, GateDecision, GateEvent, ToolGate};
use crate::hooks::protocol::{
    HookInvocationReport, PreModelCompactionPayload, PreModelPayload, ToolResultPayload,
};
use crate::hooks::runner::{make_pre_model_input, make_tool_result_input, HookManager};
use crate::mcp::registry::McpRegistry;
use crate::providers::http::{message_short, ProviderError};
use crate::providers::{ModelProvider, StreamDelta};
use crate::taint::{digest_prefix_hex, TaintMode, TaintSpan, TaintState, TaintToggle};
use crate::tools::{
    envelope_to_message, execute_tool, to_tool_result_envelope, tool_side_effects,
    validate_builtin_tool_args, ToolResultMeta, ToolRuntime,
};
use crate::trust::policy::{McpAllowSummary, Policy};
use crate::types::{GenerateRequest, Message, Role, SideEffects, TokenUsage, ToolCall, ToolDef};

pub fn sanitize_user_visible_output(raw: &str) -> String {
    let without_think = strip_tag_block(raw, "think");
    let trimmed = without_think.trim();
    let upper = trimmed.to_uppercase();
    if let Some(thought_idx) = upper.find("THOUGHT:") {
        if let Some(response_rel) = upper[thought_idx..].find("RESPONSE:") {
            let start = thought_idx + response_rel + "RESPONSE:".len();
            return trimmed[start..].trim().to_string();
        }
    }
    trimmed.to_string()
}

fn strip_tag_block(input: &str, tag: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut i = 0usize;
    while i < input.len() {
        let rest = &input[i..];
        if rest.starts_with(&open) {
            if let Some(end_rel) = rest.find(&close) {
                i += end_rel + close.len();
                continue;
            }
            break;
        }
        if let Some(ch) = rest.chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
pub enum AgentExitReason {
    Ok,
    ProviderError,
    PlannerError,
    Denied,
    ApprovalRequired,
    HookAborted,
    MaxSteps,
    BudgetExceeded,
    Cancelled,
}

impl AgentExitReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentExitReason::Ok => "ok",
            AgentExitReason::ProviderError => "provider_error",
            AgentExitReason::PlannerError => "planner_error",
            AgentExitReason::Denied => "denied",
            AgentExitReason::ApprovalRequired => "approval_required",
            AgentExitReason::HookAborted => "hook_aborted",
            AgentExitReason::MaxSteps => "max_steps",
            AgentExitReason::BudgetExceeded => "budget_exceeded",
            AgentExitReason::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ToolCallBudget {
    pub max_wall_time_ms: u64,
    pub max_total_tool_calls: usize,
    pub max_mcp_calls: usize,
    pub max_filesystem_read_calls: usize,
    pub max_filesystem_write_calls: usize,
    pub max_shell_calls: usize,
    pub max_network_calls: usize,
    pub max_browser_calls: usize,
}

#[derive(Debug, Clone)]
pub struct AgentOutcome {
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub exit_reason: AgentExitReason,
    pub final_output: String,
    pub error: Option<String>,
    pub messages: Vec<Message>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_decisions: Vec<ToolDecisionRecord>,
    pub compaction_settings: CompactionSettings,
    pub final_prompt_size_chars: usize,
    pub compaction_report: Option<CompactionReport>,
    pub hook_invocations: Vec<HookInvocationReport>,
    pub provider_retry_count: u32,
    pub provider_error_count: u32,
    pub token_usage: Option<TokenUsage>,
    pub taint: Option<AgentTaintRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentTaintRecord {
    pub enabled: bool,
    pub mode: String,
    pub digest_bytes: usize,
    pub overall: String,
    #[serde(default)]
    pub spans_by_tool_call_id: std::collections::BTreeMap<String, Vec<TaintSpan>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolDecisionRecord {
    pub step: u32,
    pub tool_call_id: String,
    pub tool: String,
    pub decision: String,
    pub reason: Option<String>,
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_overall: Option<String>,
    #[serde(default)]
    pub taint_enforced: bool,
    #[serde(default)]
    pub escalated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpRuntimeTraceEntry {
    pub step: u32,
    pub lifecycle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_ticks: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyLoadedInfo {
    pub version: u32,
    pub rules_count: usize,
    pub includes_count: usize,
    pub includes_resolved: Vec<String>,
    pub mcp_allowlist: Option<McpAllowSummary>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum PlanToolEnforcementMode {
    Off,
    Soft,
    Hard,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum McpPinEnforcementMode {
    Off,
    Warn,
    Hard,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlanStepConstraint {
    pub step_id: String,
    pub intended_tools: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkerStepStatus {
    step_id: String,
    status: String,
    next_step_id: Option<String>,
    user_output: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolFailureClass {
    Schema,
    Policy,
    TimeoutTransient,
    SelectorAmbiguous,
    NetworkTransient,
    NonIdempotent,
    Other,
}

impl ToolFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "E_SCHEMA",
            Self::Policy => "E_POLICY",
            Self::TimeoutTransient => "E_TIMEOUT_TRANSIENT",
            Self::SelectorAmbiguous => "E_SELECTOR_AMBIGUOUS",
            Self::NetworkTransient => "E_NETWORK_TRANSIENT",
            Self::NonIdempotent => "E_NON_IDEMPOTENT",
            Self::Other => "E_OTHER",
        }
    }

    fn retry_limit_for(self, side_effects: SideEffects) -> u32 {
        if matches!(
            side_effects,
            SideEffects::FilesystemWrite
                | SideEffects::ShellExec
                | SideEffects::Network
                | SideEffects::Browser
        ) {
            return 0;
        }
        match self {
            Self::Schema => 1,
            Self::TimeoutTransient => 1,
            Self::SelectorAmbiguous => 1,
            Self::NetworkTransient => 1,
            Self::Policy | Self::NonIdempotent | Self::Other => 0,
        }
    }
}

pub struct Agent<P: ModelProvider> {
    pub provider: P,
    pub model: String,
    pub tools: Vec<ToolDef>,
    pub max_steps: usize,
    pub tool_rt: ToolRuntime,
    pub gate: Box<dyn ToolGate>,
    pub gate_ctx: GateContext,
    pub mcp_registry: Option<std::sync::Arc<McpRegistry>>,
    pub stream: bool,
    pub event_sink: Option<Box<dyn EventSink>>,
    pub compaction_settings: CompactionSettings,
    pub hooks: HookManager,
    pub policy_loaded: Option<PolicyLoadedInfo>,
    pub policy_for_taint: Option<Policy>,
    pub taint_toggle: TaintToggle,
    pub taint_mode: TaintMode,
    pub taint_digest_bytes: usize,
    pub run_id_override: Option<String>,
    pub omit_tools_field_when_empty: bool,
    pub plan_tool_enforcement: PlanToolEnforcementMode,
    pub mcp_pin_enforcement: McpPinEnforcementMode,
    pub plan_step_constraints: Vec<PlanStepConstraint>,
    pub tool_call_budget: ToolCallBudget,
    pub mcp_runtime_trace: Vec<McpRuntimeTraceEntry>,
}

#[derive(Debug, Default, Clone, Copy)]
struct ToolCallBudgetUsage {
    total_tool_calls: usize,
    mcp_calls: usize,
    filesystem_read_calls: usize,
    filesystem_write_calls: usize,
    shell_calls: usize,
    network_calls: usize,
    browser_calls: usize,
}

fn side_effect_limit_label(side_effects: SideEffects) -> &'static str {
    match side_effects {
        SideEffects::FilesystemRead => "filesystem_read",
        SideEffects::FilesystemWrite => "filesystem_write",
        SideEffects::ShellExec => "shell",
        SideEffects::Network => "network",
        SideEffects::Browser => "browser",
        SideEffects::None => "none",
    }
}

fn budget_limit_for_side_effects(budget: &ToolCallBudget, side_effects: SideEffects) -> usize {
    match side_effects {
        SideEffects::FilesystemRead => budget.max_filesystem_read_calls,
        SideEffects::FilesystemWrite => budget.max_filesystem_write_calls,
        SideEffects::ShellExec => budget.max_shell_calls,
        SideEffects::Network => budget.max_network_calls,
        SideEffects::Browser => budget.max_browser_calls,
        SideEffects::None => 0,
    }
}

fn budget_usage_for_side_effects(usage: &ToolCallBudgetUsage, side_effects: SideEffects) -> usize {
    match side_effects {
        SideEffects::FilesystemRead => usage.filesystem_read_calls,
        SideEffects::FilesystemWrite => usage.filesystem_write_calls,
        SideEffects::ShellExec => usage.shell_calls,
        SideEffects::Network => usage.network_calls,
        SideEffects::Browser => usage.browser_calls,
        SideEffects::None => 0,
    }
}

fn increment_budget_usage(usage: &mut ToolCallBudgetUsage, side_effects: SideEffects) {
    usage.total_tool_calls = usage.total_tool_calls.saturating_add(1);
    match side_effects {
        SideEffects::FilesystemRead => {
            usage.filesystem_read_calls = usage.filesystem_read_calls.saturating_add(1)
        }
        SideEffects::FilesystemWrite => {
            usage.filesystem_write_calls = usage.filesystem_write_calls.saturating_add(1)
        }
        SideEffects::ShellExec => usage.shell_calls = usage.shell_calls.saturating_add(1),
        SideEffects::Network => usage.network_calls = usage.network_calls.saturating_add(1),
        SideEffects::Browser => usage.browser_calls = usage.browser_calls.saturating_add(1),
        SideEffects::None => {}
    }
}

fn check_and_consume_tool_budget(
    budget: &ToolCallBudget,
    usage: &mut ToolCallBudgetUsage,
    side_effects: SideEffects,
) -> Option<String> {
    let next_total = usage.total_tool_calls.saturating_add(1);
    if budget.max_total_tool_calls > 0 && next_total > budget.max_total_tool_calls {
        return Some(format!(
            "runtime budget exceeded: total tool calls {} > limit {}",
            next_total, budget.max_total_tool_calls
        ));
    }

    let side_effect_limit = budget_limit_for_side_effects(budget, side_effects);
    if side_effect_limit > 0 {
        let next_side_effect_count =
            budget_usage_for_side_effects(usage, side_effects).saturating_add(1);
        if next_side_effect_count > side_effect_limit {
            return Some(format!(
                "runtime budget exceeded: {} tool calls {} > limit {}",
                side_effect_limit_label(side_effects),
                next_side_effect_count,
                side_effect_limit
            ));
        }
    }

    increment_budget_usage(usage, side_effects);
    None
}

fn check_and_consume_mcp_budget(
    budget: &ToolCallBudget,
    usage: &mut ToolCallBudgetUsage,
    is_mcp_tool: bool,
) -> Option<String> {
    if !is_mcp_tool {
        return None;
    }
    let next_mcp = usage.mcp_calls.saturating_add(1);
    if budget.max_mcp_calls > 0 && next_mcp > budget.max_mcp_calls {
        return Some(format!(
            "runtime budget exceeded: mcp tool calls {} > limit {}",
            next_mcp, budget.max_mcp_calls
        ));
    }
    usage.mcp_calls = next_mcp;
    None
}

impl<P: ModelProvider> Agent<P> {
    fn emit_event(&mut self, run_id: &str, step: u32, kind: EventKind, data: serde_json::Value) {
        self.capture_mcp_runtime_trace(step, &kind, &data);
        if let Some(sink) = &mut self.event_sink {
            if let Err(e) = sink.emit(Event::new(run_id.to_string(), step, kind, data)) {
                eprintln!("WARN: failed to emit event: {e}");
            }
        }
    }

    fn capture_mcp_runtime_trace(&mut self, step: u32, kind: &EventKind, data: &serde_json::Value) {
        let mut push = |lifecycle: &str| {
            self.mcp_runtime_trace.push(McpRuntimeTraceEntry {
                step,
                lifecycle: lifecycle.to_string(),
                tool_call_id: data
                    .get("tool_call_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                tool_name: data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                reason: data
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                progress_ticks: data
                    .get("progress_ticks")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32),
                elapsed_ms: data.get("elapsed_ms").and_then(|v| v.as_u64()),
            });
        };
        match kind {
            EventKind::ToolExecStart => {
                if data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .starts_with("mcp.")
                {
                    push("running");
                }
            }
            EventKind::ToolExecEnd => {
                if data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .starts_with("mcp.")
                {
                    let ok = data.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if ok {
                        push("done");
                    } else {
                        push("fail");
                    }
                }
            }
            EventKind::ToolRetry => {
                if data
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .starts_with("mcp.")
                {
                    let action = data
                        .get("action")
                        .and_then(|v| v.as_str())
                        .unwrap_or("stop");
                    if action == "retry" {
                        push("wait_retry");
                    } else {
                        push("fail");
                    }
                }
            }
            EventKind::McpProgress => push("wait_task"),
            EventKind::McpCancelled => push("cancelled"),
            EventKind::McpPinned => push("pinned"),
            EventKind::McpDrift => push("drift"),
            _ => {}
        }
    }

    pub async fn run(
        &mut self,
        user_prompt: &str,
        session_messages: Vec<Message>,
        injected_messages: Vec<Message>,
    ) -> AgentOutcome {
        let run_id = self
            .run_id_override
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.gate_ctx.run_id = Some(run_id.clone());
        let started_at = crate::trust::now_rfc3339();
        self.emit_event(
            &run_id,
            0,
            EventKind::RunStart,
            serde_json::json!({"model": self.model}),
        );
        if let Some(policy) = &self.policy_loaded {
            self.emit_event(
                &run_id,
                0,
                EventKind::PolicyLoaded,
                serde_json::json!({
                    "version": policy.version,
                    "rules_count": policy.rules_count,
                    "includes_count": policy.includes_count,
                    "mcp_allowlist": policy.mcp_allowlist
                }),
            );
        }
        let mut messages = vec![Message {
            role: Role::System,
            content: Some(
                "You are an agent that may call tools to gather information. Use tools when \
                 needed, then provide a final direct answer when done. If no tools are \
                 needed, answer immediately."
                    .to_string(),
            ),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }];
        messages.extend(session_messages);
        for msg in injected_messages {
            messages.push(msg);
        }
        messages.push(Message {
            role: Role::User,
            content: Some(user_prompt.to_string()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        });

        let mut observed_tool_calls = Vec::new();
        let mut observed_tool_decisions: Vec<ToolDecisionRecord> = Vec::new();
        let mut last_compaction_report: Option<CompactionReport> = None;
        let mut hook_invocations: Vec<HookInvocationReport> = Vec::new();
        let mut provider_retry_count: u32 = 0;
        let mut provider_error_count: u32 = 0;
        let mut total_token_usage = TokenUsage::default();
        let mut saw_token_usage = false;
        let mut taint_state = TaintState::new();
        let mut active_plan_step_idx: usize = 0;
        let mut blocked_halt_count: u32 = 0;
        let mut blocked_control_envelope_count: u32 = 0;
        let mut last_user_output: Option<String> = None;
        let mut step_retry_counts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        let mut schema_repair_attempts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        let mut tool_budget_usage = ToolCallBudgetUsage::default();
        let run_started = std::time::Instant::now();
        let mut announced_plan_step_id: Option<String> = None;
        let expected_mcp_catalog_hash_hex = self
            .mcp_registry
            .as_ref()
            .and_then(|m| m.configured_tool_catalog_hash_hex().ok());
        'agent_steps: for step in 0..self.max_steps {
            if self.tool_call_budget.max_wall_time_ms > 0 {
                let elapsed_ms = run_started.elapsed().as_millis() as u64;
                if elapsed_ms > self.tool_call_budget.max_wall_time_ms {
                    let reason = format!(
                        "runtime budget exceeded: wall time {}ms > limit {}ms",
                        elapsed_ms, self.tool_call_budget.max_wall_time_ms
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::Error,
                        serde_json::json!({
                            "error": reason,
                            "source": "runtime_budget",
                            "elapsed_ms": elapsed_ms,
                            "max_wall_time_ms": self.tool_call_budget.max_wall_time_ms
                        }),
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::RunEnd,
                        serde_json::json!({"exit_reason":"budget_exceeded"}),
                    );
                    let final_prompt_size_chars = context_size_chars(&messages);
                    return AgentOutcome {
                        run_id,
                        started_at,
                        finished_at: crate::trust::now_rfc3339(),
                        exit_reason: AgentExitReason::BudgetExceeded,
                        final_output: reason.clone(),
                        error: Some(reason),
                        messages,
                        tool_calls: observed_tool_calls,
                        tool_decisions: observed_tool_decisions,
                        compaction_settings: self.compaction_settings.clone(),
                        final_prompt_size_chars,
                        compaction_report: last_compaction_report,
                        hook_invocations,
                        provider_retry_count,
                        provider_error_count,
                        token_usage: if saw_token_usage {
                            Some(total_token_usage.clone())
                        } else {
                            None
                        },
                        taint: taint_record_from_state(
                            self.taint_toggle,
                            self.taint_mode,
                            self.taint_digest_bytes,
                            &taint_state,
                        ),
                    };
                }
            }
            if !matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
                && !self.plan_step_constraints.is_empty()
                && active_plan_step_idx < self.plan_step_constraints.len()
            {
                let step_constraint = self.plan_step_constraints[active_plan_step_idx].clone();
                if announced_plan_step_id.as_deref() != Some(step_constraint.step_id.as_str()) {
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::StepStarted,
                        serde_json::json!({
                            "step_id": step_constraint.step_id,
                            "step_index": active_plan_step_idx,
                            "allowed_tools": step_constraint.intended_tools,
                            "enforcement_mode": format!("{:?}", self.plan_tool_enforcement).to_lowercase()
                        }),
                    );
                    announced_plan_step_id = Some(step_constraint.step_id.clone());
                }
            }
            let compacted = match maybe_compact(&messages, &self.compaction_settings) {
                Ok(c) => c,
                Err(e) => {
                    if let Some(pe) = e.downcast_ref::<ProviderError>() {
                        for r in &pe.retries {
                            provider_retry_count = provider_retry_count.saturating_add(1);
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ProviderRetry,
                                serde_json::json!({
                                    "attempt": r.attempt,
                                    "max_attempts": r.max_attempts,
                                    "kind": r.kind,
                                    "status": r.status,
                                    "backoff_ms": r.backoff_ms
                                }),
                            );
                        }
                        provider_error_count = provider_error_count.saturating_add(1);
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ProviderError,
                            serde_json::json!({
                                "kind": pe.kind,
                                "status": pe.http_status,
                                "retryable": pe.retryable,
                                "attempt": pe.attempt,
                                "max_attempts": pe.max_attempts,
                                "message_short": message_short(&pe.message)
                            }),
                        );
                    }
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::Error,
                        serde_json::json!({"error": format!("compaction failed: {e}")}),
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::RunEnd,
                        serde_json::json!({"exit_reason":"provider_error"}),
                    );
                    return AgentOutcome {
                        run_id,
                        started_at,
                        finished_at: crate::trust::now_rfc3339(),
                        exit_reason: AgentExitReason::ProviderError,
                        final_output: String::new(),
                        error: Some(format!("compaction failed: {e}")),
                        messages,
                        tool_calls: observed_tool_calls,
                        tool_decisions: observed_tool_decisions,
                        compaction_settings: self.compaction_settings.clone(),
                        final_prompt_size_chars: 0,
                        compaction_report: last_compaction_report,
                        hook_invocations,
                        provider_retry_count,
                        provider_error_count,
                        token_usage: if saw_token_usage {
                            Some(total_token_usage.clone())
                        } else {
                            None
                        },
                        taint: taint_record_from_state(
                            self.taint_toggle,
                            self.taint_mode,
                            self.taint_digest_bytes,
                            &taint_state,
                        ),
                    };
                }
            };
            if let Some(report) = compacted.report.clone() {
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::CompactionPerformed,
                    serde_json::json!({
                        "before_chars": report.before_chars,
                        "after_chars": report.after_chars,
                        "before_messages": report.before_messages,
                        "after_messages": report.after_messages,
                        "compacted_messages": report.compacted_messages,
                        "summary_digest_sha256": report.summary_digest_sha256
                    }),
                );
                last_compaction_report = Some(report);
            }
            messages = compacted.messages;

            let mut tools_sorted = self.tools.clone();
            tools_sorted.sort_by(|a, b| a.name.cmp(&b.name));

            if self.hooks.enabled() {
                let pre_payload = PreModelPayload {
                    messages: messages.clone(),
                    tools: tools_sorted.clone(),
                    stream: self.stream,
                    compaction: PreModelCompactionPayload::from(&self.compaction_settings),
                };
                let hook_input = make_pre_model_input(
                    &run_id,
                    step as u32,
                    provider_name(self.gate_ctx.provider),
                    &self.model,
                    &self.gate_ctx.workdir,
                    match serde_json::to_value(pre_payload) {
                        Ok(v) => v,
                        Err(e) => {
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::ProviderError,
                                final_output: String::new(),
                                error: Some(format!(
                                    "failed to encode pre_model hook payload: {e}"
                                )),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: 0,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                    },
                );
                match self.hooks.run_pre_model_hooks(hook_input).await {
                    Ok(result) => {
                        for inv in &result.invocations {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::HookStart,
                                serde_json::json!({
                                    "hook_name": inv.hook_name,
                                    "stage": inv.stage
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::HookEnd,
                                serde_json::json!({
                                    "hook_name": inv.hook_name,
                                    "stage": inv.stage,
                                    "action": inv.action,
                                    "modified": inv.modified,
                                    "duration_ms": inv.duration_ms
                                }),
                            );
                        }
                        hook_invocations.extend(result.invocations);
                        if let Some(reason) = result.abort_reason {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"hook_aborted"}),
                            );
                            let prompt_chars = context_size_chars(&messages);
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::HookAborted,
                                final_output: reason.clone(),
                                error: Some(reason),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: prompt_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                        if !result.append_messages.is_empty() {
                            messages.extend(result.append_messages);
                            if self.compaction_settings.max_context_chars > 0 {
                                let compacted_again =
                                    maybe_compact(&messages, &self.compaction_settings)
                                        .map_err(|e| format!("compaction failed after hooks: {e}"));
                                match compacted_again {
                                    Ok(out) => {
                                        if let Some(report) = out.report.clone() {
                                            self.emit_event(
                                                &run_id,
                                                step as u32,
                                                EventKind::CompactionPerformed,
                                                serde_json::json!({
                                                    "before_chars": report.before_chars,
                                                    "after_chars": report.after_chars,
                                                    "before_messages": report.before_messages,
                                                    "after_messages": report.after_messages,
                                                    "compacted_messages": report.compacted_messages,
                                                    "summary_digest_sha256": report.summary_digest_sha256,
                                                    "phase": "post_pre_model_hooks"
                                                }),
                                            );
                                            last_compaction_report = Some(report);
                                        }
                                        messages = out.messages;
                                        if self.compaction_settings.max_context_chars > 0
                                            && context_size_chars(&messages)
                                                > self.compaction_settings.max_context_chars
                                        {
                                            let prompt_chars = context_size_chars(&messages);
                                            return AgentOutcome {
                                                run_id,
                                                started_at,
                                                finished_at: crate::trust::now_rfc3339(),
                                                exit_reason: AgentExitReason::ProviderError,
                                                final_output: String::new(),
                                                error: Some(
                                                    "hooks caused prompt to exceed budget"
                                                        .to_string(),
                                                ),
                                                messages,
                                                tool_calls: observed_tool_calls,
                                                tool_decisions: observed_tool_decisions,
                                                compaction_settings: self
                                                    .compaction_settings
                                                    .clone(),
                                                final_prompt_size_chars: prompt_chars,
                                                compaction_report: last_compaction_report,
                                                hook_invocations,
                                                provider_retry_count,
                                                provider_error_count,
                                                token_usage: if saw_token_usage {
                                                    Some(total_token_usage.clone())
                                                } else {
                                                    None
                                                },
                                                taint: taint_record_from_state(
                                                    self.taint_toggle,
                                                    self.taint_mode,
                                                    self.taint_digest_bytes,
                                                    &taint_state,
                                                ),
                                            };
                                        }
                                    }
                                    Err(e) => {
                                        let prompt_chars = context_size_chars(&messages);
                                        return AgentOutcome {
                                            run_id,
                                            started_at,
                                            finished_at: crate::trust::now_rfc3339(),
                                            exit_reason: AgentExitReason::ProviderError,
                                            final_output: String::new(),
                                            error: Some(e),
                                            messages,
                                            tool_calls: observed_tool_calls,
                                            tool_decisions: observed_tool_decisions,
                                            compaction_settings: self.compaction_settings.clone(),
                                            final_prompt_size_chars: prompt_chars,
                                            compaction_report: last_compaction_report,
                                            hook_invocations,
                                            provider_retry_count,
                                            provider_error_count,
                                            token_usage: if saw_token_usage {
                                                Some(total_token_usage.clone())
                                            } else {
                                                None
                                            },
                                            taint: taint_record_from_state(
                                                self.taint_toggle,
                                                self.taint_mode,
                                                self.taint_digest_bytes,
                                                &taint_state,
                                            ),
                                        };
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::HookError,
                            serde_json::json!({"stage":"pre_model","error": e.message}),
                        );
                        let prompt_chars = context_size_chars(&messages);
                        return AgentOutcome {
                            run_id,
                            started_at,
                            finished_at: crate::trust::now_rfc3339(),
                            exit_reason: AgentExitReason::HookAborted,
                            final_output: String::new(),
                            error: Some(e.message),
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            compaction_settings: self.compaction_settings.clone(),
                            final_prompt_size_chars: prompt_chars,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                            token_usage: if saw_token_usage {
                                Some(total_token_usage.clone())
                            } else {
                                None
                            },
                            taint: taint_record_from_state(
                                self.taint_toggle,
                                self.taint_mode,
                                self.taint_digest_bytes,
                                &taint_state,
                            ),
                        };
                    }
                }
            }

            let req = GenerateRequest {
                model: self.model.clone(),
                messages: messages.clone(),
                tools: if self.omit_tools_field_when_empty && tools_sorted.is_empty() {
                    None
                } else {
                    Some(tools_sorted)
                },
            };
            let request_context_chars = context_size_chars(&req.messages);

            self.emit_event(
                &run_id,
                step as u32,
                EventKind::ModelRequestStart,
                serde_json::json!({
                    "message_count": req.messages.len(),
                    "tool_count": req.tools.as_ref().map(|t| t.len()).unwrap_or(0)
                }),
            );
            let resp_result = if self.stream {
                if self.provider.supports_streaming() {
                    let mut collected = Vec::<StreamDelta>::new();
                    let mut callback = |delta| collected.push(delta);
                    let out = self
                        .provider
                        .generate_streaming(req.clone(), &mut callback)
                        .await;
                    for delta in collected {
                        match delta {
                            StreamDelta::Content(text) => {
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::ModelDelta,
                                    serde_json::json!({"delta": text}),
                                );
                            }
                            StreamDelta::ToolCallFragment(fragment) => {
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::ModelDelta,
                                    serde_json::json!({
                                        "tool_call_fragment": {
                                            "index": fragment.index,
                                            "id": fragment.id,
                                            "name": fragment.name,
                                            "arguments_fragment": fragment.arguments_fragment,
                                            "complete": fragment.complete
                                        }
                                    }),
                                );
                            }
                        }
                    }
                    out
                } else {
                    eprintln!(
                        "WARN: provider does not support streaming; falling back to non-streaming"
                    );
                    self.provider.generate(req).await
                }
            } else {
                self.provider.generate(req).await
            };

            let resp = match resp_result {
                Ok(r) => r,
                Err(e) => {
                    if let Some(pe) = e.downcast_ref::<ProviderError>() {
                        for r in &pe.retries {
                            provider_retry_count = provider_retry_count.saturating_add(1);
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ProviderRetry,
                                serde_json::json!({
                                    "attempt": r.attempt,
                                    "max_attempts": r.max_attempts,
                                    "kind": r.kind,
                                    "status": r.status,
                                    "backoff_ms": r.backoff_ms
                                }),
                            );
                        }
                        provider_error_count = provider_error_count.saturating_add(1);
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ProviderError,
                            serde_json::json!({
                                "kind": pe.kind,
                                "status": pe.http_status,
                                "retryable": pe.retryable,
                                "attempt": pe.attempt,
                                "max_attempts": pe.max_attempts,
                                "message_short": message_short(&pe.message)
                            }),
                        );
                    }
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::Error,
                        serde_json::json!({"error": e.to_string()}),
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::RunEnd,
                        serde_json::json!({"exit_reason":"provider_error"}),
                    );
                    return AgentOutcome {
                        run_id,
                        started_at,
                        finished_at: crate::trust::now_rfc3339(),
                        exit_reason: AgentExitReason::ProviderError,
                        final_output: String::new(),
                        error: Some(e.to_string()),
                        messages,
                        tool_calls: observed_tool_calls,
                        tool_decisions: observed_tool_decisions,
                        compaction_settings: self.compaction_settings.clone(),
                        final_prompt_size_chars: request_context_chars,
                        compaction_report: last_compaction_report,
                        hook_invocations,
                        provider_retry_count,
                        provider_error_count,
                        token_usage: if saw_token_usage {
                            Some(total_token_usage.clone())
                        } else {
                            None
                        },
                        taint: taint_record_from_state(
                            self.taint_toggle,
                            self.taint_mode,
                            self.taint_digest_bytes,
                            &taint_state,
                        ),
                    };
                }
            };
            if let Some(usage) = &resp.usage {
                saw_token_usage = true;
                total_token_usage.prompt_tokens =
                    add_opt_u32(total_token_usage.prompt_tokens, usage.prompt_tokens);
                total_token_usage.completion_tokens =
                    add_opt_u32(total_token_usage.completion_tokens, usage.completion_tokens);
                total_token_usage.total_tokens =
                    add_opt_u32(total_token_usage.total_tokens, usage.total_tokens);
            }
            self.emit_event(
                &run_id,
                step as u32,
                EventKind::ModelResponseEnd,
                serde_json::json!({"tool_calls": resp.tool_calls.len()}),
            );
            let mut assistant = resp.assistant.clone();
            if let Some(c) = assistant.content.as_deref() {
                assistant.content = Some(sanitize_user_visible_output(c));
            }
            messages.push(assistant.clone());
            let worker_step_status =
                if !matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
                    && !self.plan_step_constraints.is_empty()
                {
                    parse_worker_step_status(
                        assistant.content.as_deref().unwrap_or_default(),
                        &self.plan_step_constraints,
                    )
                } else {
                    None
                };
            if !matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
                && !self.plan_step_constraints.is_empty()
                && worker_step_status.is_none()
                && resp.tool_calls.is_empty()
            {
                blocked_control_envelope_count = blocked_control_envelope_count.saturating_add(1);
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::StepBlocked,
                    serde_json::json!({
                        "reason": "invalid_control_envelope",
                        "required_schema_version": crate::planner::STEP_RESULT_SCHEMA_VERSION,
                        "blocked_count": blocked_control_envelope_count
                    }),
                );
                if blocked_control_envelope_count >= 2 {
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::RunEnd,
                        serde_json::json!({"exit_reason":"planner_error"}),
                    );
                    return AgentOutcome {
                        run_id,
                        started_at,
                        finished_at: crate::trust::now_rfc3339(),
                        exit_reason: AgentExitReason::PlannerError,
                        final_output: String::new(),
                        error: Some(
                            "worker response missing control envelope for planner-enforced mode"
                                .to_string(),
                        ),
                        messages,
                        tool_calls: observed_tool_calls,
                        tool_decisions: observed_tool_decisions,
                        compaction_settings: self.compaction_settings.clone(),
                        final_prompt_size_chars: request_context_chars,
                        compaction_report: last_compaction_report,
                        hook_invocations,
                        provider_retry_count,
                        provider_error_count,
                        token_usage: if saw_token_usage {
                            Some(total_token_usage.clone())
                        } else {
                            None
                        },
                        taint: taint_record_from_state(
                            self.taint_toggle,
                            self.taint_mode,
                            self.taint_digest_bytes,
                            &taint_state,
                        ),
                    };
                }
                messages.push(Message {
                    role: Role::Developer,
                    content: Some(format!(
                        "Return control JSON only using schema_version '{}'. Include step_id, status, and optional user_output for final response.",
                        crate::planner::STEP_RESULT_SCHEMA_VERSION
                    )),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                });
                continue;
            }
            if let Some(step_status) = worker_step_status.as_ref() {
                blocked_control_envelope_count = 0;
                if let Some(user_output) = step_status.user_output.as_ref() {
                    if !user_output.trim().is_empty() {
                        last_user_output = Some(user_output.trim().to_string());
                    }
                }
                let current_step_id = self
                    .plan_step_constraints
                    .get(active_plan_step_idx)
                    .map(|s| s.step_id.clone())
                    .unwrap_or_default();
                match step_status.status.as_str() {
                    "done" => {
                        if step_status.step_id != current_step_id {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::StepBlocked,
                                serde_json::json!({
                                    "step_id": step_status.step_id,
                                    "expected_step_id": current_step_id,
                                    "reason": "invalid_done_transition"
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"planner_error"}),
                            );
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::PlannerError,
                                final_output: String::new(),
                                error: Some(format!(
                                    "invalid step completion transition: got done for {}, expected {}",
                                    step_status.step_id, current_step_id
                                )),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: request_context_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::StepVerified,
                            serde_json::json!({
                                "step_id": step_status.step_id,
                                "next_step_id": step_status.next_step_id,
                                "status": step_status.status
                            }),
                        );
                        blocked_halt_count = 0;
                        step_retry_counts.remove(&current_step_id);
                        if let Some(next) = &step_status.next_step_id {
                            if next == "final" {
                                active_plan_step_idx = self.plan_step_constraints.len();
                            } else if let Some(next_idx) = self
                                .plan_step_constraints
                                .iter()
                                .position(|s| s.step_id == *next)
                            {
                                active_plan_step_idx = next_idx;
                            } else {
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::StepBlocked,
                                    serde_json::json!({
                                        "step_id": step_status.step_id,
                                        "next_step_id": next,
                                        "reason": "invalid_next_step_id"
                                    }),
                                );
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::RunEnd,
                                    serde_json::json!({"exit_reason":"planner_error"}),
                                );
                                return AgentOutcome {
                                    run_id,
                                    started_at,
                                    finished_at: crate::trust::now_rfc3339(),
                                    exit_reason: AgentExitReason::PlannerError,
                                    final_output: String::new(),
                                    error: Some(format!(
                                        "invalid next_step_id in worker status: {}",
                                        next
                                    )),
                                    messages,
                                    tool_calls: observed_tool_calls,
                                    tool_decisions: observed_tool_decisions,
                                    compaction_settings: self.compaction_settings.clone(),
                                    final_prompt_size_chars: request_context_chars,
                                    compaction_report: last_compaction_report,
                                    hook_invocations,
                                    provider_retry_count,
                                    provider_error_count,
                                    token_usage: if saw_token_usage {
                                        Some(total_token_usage.clone())
                                    } else {
                                        None
                                    },
                                    taint: taint_record_from_state(
                                        self.taint_toggle,
                                        self.taint_mode,
                                        self.taint_digest_bytes,
                                        &taint_state,
                                    ),
                                };
                            }
                        } else if active_plan_step_idx < self.plan_step_constraints.len() {
                            active_plan_step_idx = active_plan_step_idx.saturating_add(1);
                        }
                    }
                    "retry" => {
                        if step_status.step_id != current_step_id {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::StepBlocked,
                                serde_json::json!({
                                    "step_id": step_status.step_id,
                                    "expected_step_id": current_step_id,
                                    "reason": "invalid_retry_transition"
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"planner_error"}),
                            );
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::PlannerError,
                                final_output: String::new(),
                                error: Some(format!(
                                    "invalid retry transition: got retry for {}, expected {}",
                                    step_status.step_id, current_step_id
                                )),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: request_context_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                        let entry = step_retry_counts
                            .entry(step_status.step_id.clone())
                            .or_insert(0);
                        *entry = entry.saturating_add(1);
                        if *entry > 2 {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::StepBlocked,
                                serde_json::json!({
                                    "step_id": step_status.step_id,
                                    "reason": "retry_limit_exceeded",
                                    "retry_count": *entry
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"planner_error"}),
                            );
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::PlannerError,
                                final_output: String::new(),
                                error: Some(format!(
                                    "step {} exceeded retry transition limit",
                                    step_status.step_id
                                )),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: request_context_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                    }
                    "replan" => {
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::StepReplanned,
                            serde_json::json!({
                                "step_id": step_status.step_id,
                                "status": step_status.status
                            }),
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::RunEnd,
                            serde_json::json!({"exit_reason":"planner_error"}),
                        );
                        return AgentOutcome {
                            run_id,
                            started_at,
                            finished_at: crate::trust::now_rfc3339(),
                            exit_reason: AgentExitReason::PlannerError,
                            final_output: String::new(),
                            error: Some(format!(
                                "worker requested {} transition for step {}",
                                step_status.status, step_status.step_id
                            )),
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            compaction_settings: self.compaction_settings.clone(),
                            final_prompt_size_chars: request_context_chars,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                            token_usage: if saw_token_usage {
                                Some(total_token_usage.clone())
                            } else {
                                None
                            },
                            taint: taint_record_from_state(
                                self.taint_toggle,
                                self.taint_mode,
                                self.taint_digest_bytes,
                                &taint_state,
                            ),
                        };
                    }
                    "fail" => {
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::StepBlocked,
                            serde_json::json!({
                                "step_id": step_status.step_id,
                                "reason": "worker_fail_transition"
                            }),
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::RunEnd,
                            serde_json::json!({"exit_reason":"planner_error"}),
                        );
                        return AgentOutcome {
                            run_id,
                            started_at,
                            finished_at: crate::trust::now_rfc3339(),
                            exit_reason: AgentExitReason::PlannerError,
                            final_output: String::new(),
                            error: Some(format!(
                                "worker requested {} transition for step {}",
                                step_status.status, step_status.step_id
                            )),
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            compaction_settings: self.compaction_settings.clone(),
                            final_prompt_size_chars: request_context_chars,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                            token_usage: if saw_token_usage {
                                Some(total_token_usage.clone())
                            } else {
                                None
                            },
                            taint: taint_record_from_state(
                                self.taint_toggle,
                                self.taint_mode,
                                self.taint_digest_bytes,
                                &taint_state,
                            ),
                        };
                    }
                    _ => {}
                }
            }
            if matches!(self.taint_toggle, TaintToggle::On) {
                let idx = messages.len().saturating_sub(1);
                taint_state.mark_assistant_context_tainted(idx);
            }

            if resp.tool_calls.is_empty() {
                if !matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
                    && active_plan_step_idx < self.plan_step_constraints.len()
                {
                    let step_constraint = self.plan_step_constraints[active_plan_step_idx].clone();
                    blocked_halt_count = blocked_halt_count.saturating_add(1);
                    let reason = format!(
                            "premature finalization blocked: plan step {} still pending (allowed tools: {})",
                            step_constraint.step_id,
                        if step_constraint.intended_tools.is_empty() {
                            "none".to_string()
                        } else {
                            step_constraint.intended_tools.join(", ")
                        }
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::Error,
                        serde_json::json!({
                            "error": reason,
                            "source": "plan_halt_guard",
                            "blocked_halt_count": blocked_halt_count
                        }),
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::StepBlocked,
                        serde_json::json!({
                            "step_id": step_constraint.step_id,
                            "reason": "premature_finalization_blocked",
                            "blocked_halt_count": blocked_halt_count
                        }),
                    );
                    if blocked_halt_count >= 2 {
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::RunEnd,
                            serde_json::json!({"exit_reason":"planner_error"}),
                        );
                        return AgentOutcome {
                            run_id,
                            started_at,
                            finished_at: crate::trust::now_rfc3339(),
                            exit_reason: AgentExitReason::PlannerError,
                            final_output: String::new(),
                            error: Some("model repeatedly attempted to halt before completing required planner steps".to_string()),
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            compaction_settings: self.compaction_settings.clone(),
                            final_prompt_size_chars: request_context_chars,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                            token_usage: if saw_token_usage {
                                Some(total_token_usage.clone())
                            } else {
                                None
                            },
                            taint: taint_record_from_state(
                                self.taint_toggle,
                                self.taint_mode,
                                self.taint_digest_bytes,
                                &taint_state,
                            ),
                        };
                    }
                    messages.push(Message {
                        role: Role::Developer,
                        content: Some(format!(
                            "Continue execution. Do not finalize yet. Complete pending step {} using only intended tools ({}), then return the next tool call.",
                            step_constraint.step_id,
                            if step_constraint.intended_tools.is_empty() {
                                "none".to_string()
                            } else {
                                step_constraint.intended_tools.join(", ")
                            }
                        )),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    });
                    continue;
                }
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::RunEnd,
                    serde_json::json!({"exit_reason":"ok"}),
                );
                return AgentOutcome {
                    run_id,
                    started_at,
                    finished_at: crate::trust::now_rfc3339(),
                    exit_reason: AgentExitReason::Ok,
                    final_output: if !matches!(
                        self.plan_tool_enforcement,
                        PlanToolEnforcementMode::Off
                    ) && !self.plan_step_constraints.is_empty()
                    {
                        last_user_output.unwrap_or_default()
                    } else {
                        assistant.content.unwrap_or_default()
                    },
                    error: None,
                    messages,
                    tool_calls: observed_tool_calls,
                    tool_decisions: observed_tool_decisions,
                    compaction_settings: self.compaction_settings.clone(),
                    final_prompt_size_chars: request_context_chars,
                    compaction_report: last_compaction_report,
                    hook_invocations,
                    provider_retry_count,
                    provider_error_count,
                    token_usage: if saw_token_usage {
                        Some(total_token_usage.clone())
                    } else {
                        None
                    },
                    taint: taint_record_from_state(
                        self.taint_toggle,
                        self.taint_mode,
                        self.taint_digest_bytes,
                        &taint_state,
                    ),
                };
            }

            for tc in &resp.tool_calls {
                observed_tool_calls.push(tc.clone());
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::ToolCallDetected,
                    serde_json::json!({
                        "tool_call_id": tc.id,
                        "name": tc.name,
                        "arguments": tc.arguments,
                        "side_effects": tool_side_effects(&tc.name),
                        "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                    }),
                );
                if tc.name.starts_with("mcp.") {
                    if matches!(self.mcp_pin_enforcement, McpPinEnforcementMode::Off) {
                        // Drift probing disabled by configuration.
                    } else if let (Some(registry), Some(expected_hash)) = (
                        self.mcp_registry.as_ref(),
                        expected_mcp_catalog_hash_hex.as_ref(),
                    ) {
                        match registry.live_tool_catalog_hash_hex().await {
                            Ok(actual_hash) if actual_hash != *expected_hash => {
                                let reason = format!(
                                    "MCP_DRIFT detected: tool catalog hash changed during run (expected {}, got {})",
                                    expected_hash, actual_hash
                                );
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::McpDrift,
                                    serde_json::json!({
                                        "tool_call_id": tc.id,
                                        "name": tc.name,
                                        "expected_hash_hex": expected_hash,
                                        "actual_hash_hex": actual_hash
                                    }),
                                );
                                if matches!(self.mcp_pin_enforcement, McpPinEnforcementMode::Hard) {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::StepBlocked,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "reason": "mcp_drift"
                                        }),
                                    );
                                    observed_tool_decisions.push(ToolDecisionRecord {
                                        step: step as u32,
                                        tool_call_id: tc.id.clone(),
                                        tool: tc.name.clone(),
                                        decision: "deny".to_string(),
                                        reason: Some(reason.clone()),
                                        source: Some("mcp_drift".to_string()),
                                        taint_overall: Some(taint_state.overall_str().to_string()),
                                        taint_enforced: false,
                                        escalated: false,
                                        escalation_reason: None,
                                    });
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::ToolDecision,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "decision": "deny",
                                            "reason": reason,
                                            "source": "mcp_drift",
                                            "side_effects": tool_side_effects(&tc.name)
                                        }),
                                    );
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::RunEnd,
                                        serde_json::json!({"exit_reason":"denied"}),
                                    );
                                    return AgentOutcome {
                                        run_id,
                                        started_at,
                                        finished_at: crate::trust::now_rfc3339(),
                                        exit_reason: AgentExitReason::Denied,
                                        final_output: reason.clone(),
                                        error: Some(reason),
                                        messages,
                                        tool_calls: observed_tool_calls,
                                        tool_decisions: observed_tool_decisions,
                                        compaction_settings: self.compaction_settings.clone(),
                                        final_prompt_size_chars: request_context_chars,
                                        compaction_report: last_compaction_report,
                                        hook_invocations,
                                        provider_retry_count,
                                        provider_error_count,
                                        token_usage: if saw_token_usage {
                                            Some(total_token_usage.clone())
                                        } else {
                                            None
                                        },
                                        taint: taint_record_from_state(
                                            self.taint_toggle,
                                            self.taint_mode,
                                            self.taint_digest_bytes,
                                            &taint_state,
                                        ),
                                    };
                                }
                                observed_tool_decisions.push(ToolDecisionRecord {
                                    step: step as u32,
                                    tool_call_id: tc.id.clone(),
                                    tool: tc.name.clone(),
                                    decision: "allow".to_string(),
                                    reason: Some(reason.clone()),
                                    source: Some("mcp_drift_warn".to_string()),
                                    taint_overall: Some(taint_state.overall_str().to_string()),
                                    taint_enforced: false,
                                    escalated: false,
                                    escalation_reason: None,
                                });
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::ToolDecision,
                                    serde_json::json!({
                                        "tool_call_id": tc.id,
                                        "name": tc.name,
                                        "decision": "allow",
                                        "reason": reason,
                                        "source": "mcp_drift_warn",
                                        "side_effects": tool_side_effects(&tc.name)
                                    }),
                                );
                            }
                            Ok(_) => {}
                            Err(e) => {
                                let reason = format!(
                                    "MCP_DRIFT verification failed: unable to probe live tool catalog ({e})"
                                );
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::McpDrift,
                                    serde_json::json!({
                                        "tool_call_id": tc.id,
                                        "name": tc.name,
                                        "expected_hash_hex": expected_hash,
                                        "error": e.to_string()
                                    }),
                                );
                                if matches!(self.mcp_pin_enforcement, McpPinEnforcementMode::Hard) {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::StepBlocked,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "reason": "mcp_drift_probe_failed"
                                        }),
                                    );
                                    observed_tool_decisions.push(ToolDecisionRecord {
                                        step: step as u32,
                                        tool_call_id: tc.id.clone(),
                                        tool: tc.name.clone(),
                                        decision: "deny".to_string(),
                                        reason: Some(reason.clone()),
                                        source: Some("mcp_drift".to_string()),
                                        taint_overall: Some(taint_state.overall_str().to_string()),
                                        taint_enforced: false,
                                        escalated: false,
                                        escalation_reason: None,
                                    });
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::ToolDecision,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "decision": "deny",
                                            "reason": reason,
                                            "source": "mcp_drift",
                                            "side_effects": tool_side_effects(&tc.name)
                                        }),
                                    );
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::RunEnd,
                                        serde_json::json!({"exit_reason":"denied"}),
                                    );
                                    return AgentOutcome {
                                        run_id,
                                        started_at,
                                        finished_at: crate::trust::now_rfc3339(),
                                        exit_reason: AgentExitReason::Denied,
                                        final_output: reason.clone(),
                                        error: Some(reason),
                                        messages,
                                        tool_calls: observed_tool_calls,
                                        tool_decisions: observed_tool_decisions,
                                        compaction_settings: self.compaction_settings.clone(),
                                        final_prompt_size_chars: request_context_chars,
                                        compaction_report: last_compaction_report,
                                        hook_invocations,
                                        provider_retry_count,
                                        provider_error_count,
                                        token_usage: if saw_token_usage {
                                            Some(total_token_usage.clone())
                                        } else {
                                            None
                                        },
                                        taint: taint_record_from_state(
                                            self.taint_toggle,
                                            self.taint_mode,
                                            self.taint_digest_bytes,
                                            &taint_state,
                                        ),
                                    };
                                }
                                observed_tool_decisions.push(ToolDecisionRecord {
                                    step: step as u32,
                                    tool_call_id: tc.id.clone(),
                                    tool: tc.name.clone(),
                                    decision: "allow".to_string(),
                                    reason: Some(reason.clone()),
                                    source: Some("mcp_drift_warn".to_string()),
                                    taint_overall: Some(taint_state.overall_str().to_string()),
                                    taint_enforced: false,
                                    escalated: false,
                                    escalation_reason: None,
                                });
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::ToolDecision,
                                    serde_json::json!({
                                        "tool_call_id": tc.id,
                                        "name": tc.name,
                                        "decision": "allow",
                                        "reason": reason,
                                        "source": "mcp_drift_warn",
                                        "side_effects": tool_side_effects(&tc.name)
                                    }),
                                );
                            }
                        }
                    }
                }
                let plan_constraint = self
                    .plan_step_constraints
                    .get(active_plan_step_idx)
                    .cloned();
                let plan_allowed_tools = plan_constraint
                    .as_ref()
                    .map(|c| c.intended_tools.clone())
                    .unwrap_or_default();
                let plan_tool_allowed =
                    matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
                        || plan_allowed_tools.is_empty()
                        || plan_allowed_tools.iter().any(|t| t == &tc.name);
                let invalid_args_error = if tc.name.starts_with("mcp.") {
                    self.mcp_registry.as_ref().and_then(|reg| {
                        reg.validate_namespaced_tool_args(tc, self.tool_rt.tool_args_strict)
                            .err()
                    })
                } else {
                    validate_builtin_tool_args(
                        &tc.name,
                        &tc.arguments,
                        self.tool_rt.tool_args_strict,
                    )
                    .err()
                };
                if let Some(err) = &invalid_args_error {
                    let repair_key = format!("{}|{}", tc.name, err);
                    let attempts = schema_repair_attempts
                        .entry(repair_key)
                        .and_modify(|n| *n = n.saturating_add(1))
                        .or_insert(1);
                    if *attempts <= 1 && plan_tool_allowed {
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolRetry,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "attempt": *attempts,
                                "max_retries": 1,
                                "failure_class": "E_SCHEMA",
                                "action": "repair"
                            }),
                        );
                        let tool_msg =
                            make_invalid_args_tool_message(tc, err, self.tool_rt.exec_target_kind);
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecEnd,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "ok": false,
                                "truncated": false,
                                "retry_count": 0,
                                "failure_class": "E_SCHEMA",
                                "source": "schema_repair"
                            }),
                        );
                        messages.push(tool_msg);
                        messages.push(schema_repair_instruction_message(tc, err));
                        continue 'agent_steps;
                    }
                }
                let approval_mode_meta =
                    if matches!(self.gate_ctx.approval_mode, ApprovalMode::Auto) {
                        Some("auto".to_string())
                    } else {
                        None
                    };
                let auto_scope_meta = if matches!(self.gate_ctx.approval_mode, ApprovalMode::Auto) {
                    Some(
                        match self.gate_ctx.auto_approve_scope {
                            AutoApproveScope::Run => "run",
                            AutoApproveScope::Session => "session",
                        }
                        .to_string(),
                    )
                } else {
                    None
                };
                let approval_key_version_meta =
                    Some(self.gate_ctx.approval_key_version.as_str().to_string());
                let tool_schema_hash_hex = self.gate_ctx.tool_schema_hashes.get(&tc.name).cloned();
                let hooks_config_hash_hex = self.gate_ctx.hooks_config_hash_hex.clone();
                let planner_hash_hex = self.gate_ctx.planner_hash_hex.clone();
                self.gate_ctx.taint_enabled = matches!(self.taint_toggle, TaintToggle::On);
                self.gate_ctx.taint_mode = self.taint_mode;
                self.gate_ctx.taint_overall = taint_state.overall;
                self.gate_ctx.taint_sources = taint_state.last_sources.clone();
                let decision_exec_target = Some(
                    match self.gate_ctx.exec_target {
                        crate::target::ExecTargetKind::Host => "host",
                        crate::target::ExecTargetKind::Docker => "docker",
                    }
                    .to_string(),
                );
                if !plan_tool_allowed {
                    let step_id = plan_constraint
                        .as_ref()
                        .map(|c| c.step_id.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    let reason = format!(
                        "tool '{}' is not allowed for plan step {} (allowed: {})",
                        tc.name,
                        step_id,
                        if plan_allowed_tools.is_empty() {
                            "none".to_string()
                        } else {
                            plan_allowed_tools.join(", ")
                        }
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::StepBlocked,
                        serde_json::json!({
                            "step_id": step_id.clone(),
                            "tool": tc.name,
                            "reason": "tool_not_allowed_by_plan",
                            "allowed_tools": plan_allowed_tools.clone()
                        }),
                    );
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::ToolDecision,
                        serde_json::json!({
                            "tool_call_id": tc.id,
                            "name": tc.name,
                            "decision": "deny",
                            "reason": reason,
                            "source": "plan_step_constraint",
                            "planner_hash_hex": planner_hash_hex.clone(),
                            "plan_step_id": step_id,
                            "plan_step_index": active_plan_step_idx,
                            "plan_allowed_tools": plan_allowed_tools,
                            "enforcement_mode": format!("{:?}", self.plan_tool_enforcement).to_lowercase()
                        }),
                    );
                    self.gate.record(GateEvent {
                        run_id: run_id.clone(),
                        step: step as u32,
                        tool_call_id: tc.id.clone(),
                        tool: tc.name.clone(),
                        arguments: tc.arguments.clone(),
                        decision: "deny".to_string(),
                        decision_reason: Some(reason.clone()),
                        decision_source: Some("plan_step_constraint".to_string()),
                        approval_id: None,
                        approval_key: None,
                        approval_mode: approval_mode_meta.clone(),
                        auto_approve_scope: auto_scope_meta.clone(),
                        approval_key_version: approval_key_version_meta.clone(),
                        tool_schema_hash_hex: tool_schema_hash_hex.clone(),
                        hooks_config_hash_hex: hooks_config_hash_hex.clone(),
                        planner_hash_hex: planner_hash_hex.clone(),
                        exec_target: decision_exec_target.clone(),
                        taint_overall: Some(taint_state.overall_str().to_string()),
                        taint_enforced: false,
                        escalated: false,
                        escalation_reason: None,
                        result_ok: false,
                        result_content: reason.clone(),
                        result_input_digest: None,
                        result_output_digest: None,
                        result_input_len: None,
                        result_output_len: None,
                    });
                    observed_tool_decisions.push(ToolDecisionRecord {
                        step: step as u32,
                        tool_call_id: tc.id.clone(),
                        tool: tc.name.clone(),
                        decision: "deny".to_string(),
                        reason: Some(reason.clone()),
                        source: Some("plan_step_constraint".to_string()),
                        taint_overall: Some(taint_state.overall_str().to_string()),
                        taint_enforced: false,
                        escalated: false,
                        escalation_reason: None,
                    });

                    match self.plan_tool_enforcement {
                        PlanToolEnforcementMode::Off => {}
                        PlanToolEnforcementMode::Soft => {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolExecEnd,
                                serde_json::json!({
                                    "tool_call_id": tc.id,
                                    "name": tc.name,
                                    "ok": false,
                                    "truncated": false,
                                    "source": "plan_step_constraint"
                                }),
                            );
                            messages.push(envelope_to_message(to_tool_result_envelope(
                                tc,
                                "runtime",
                                false,
                                reason,
                                false,
                                ToolResultMeta {
                                    side_effects: tool_side_effects(&tc.name),
                                    bytes: None,
                                    exit_code: None,
                                    stderr_truncated: None,
                                    stdout_truncated: None,
                                    source: "runtime".to_string(),
                                    execution_target: "host".to_string(),
                                    docker: None,
                                },
                            )));
                            continue;
                        }
                        PlanToolEnforcementMode::Hard => {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"denied"}),
                            );
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::Denied,
                                final_output: reason,
                                error: None,
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: request_context_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                    }
                }
                match self.gate.decide(&self.gate_ctx, tc) {
                    GateDecision::Allow {
                        approval_id,
                        approval_key,
                        reason,
                        source,
                        taint_enforced,
                        escalated,
                        escalation_reason,
                    } => {
                        let side_effects = tool_side_effects(&tc.name);
                        if let Some(reason) = check_and_consume_tool_budget(
                            &self.tool_call_budget,
                            &mut tool_budget_usage,
                            side_effects,
                        ) {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolDecision,
                                serde_json::json!({
                                    "tool_call_id": tc.id,
                                    "name": tc.name,
                                    "decision": "deny",
                                    "reason": reason.clone(),
                                    "source": "runtime_budget",
                                    "side_effects": side_effects,
                                    "budget": {
                                        "max_total_tool_calls": self.tool_call_budget.max_total_tool_calls,
                                        "max_mcp_calls": self.tool_call_budget.max_mcp_calls,
                                        "max_filesystem_read_calls": self.tool_call_budget.max_filesystem_read_calls,
                                        "max_filesystem_write_calls": self.tool_call_budget.max_filesystem_write_calls,
                                        "max_shell_calls": self.tool_call_budget.max_shell_calls,
                                        "max_network_calls": self.tool_call_budget.max_network_calls,
                                        "max_browser_calls": self.tool_call_budget.max_browser_calls
                                    }
                                }),
                            );
                            self.gate.record(GateEvent {
                                run_id: run_id.clone(),
                                step: step as u32,
                                tool_call_id: tc.id.clone(),
                                tool: tc.name.clone(),
                                arguments: tc.arguments.clone(),
                                decision: "deny".to_string(),
                                decision_reason: Some(reason.clone()),
                                decision_source: Some("runtime_budget".to_string()),
                                approval_id: None,
                                approval_key: None,
                                approval_mode: approval_mode_meta.clone(),
                                auto_approve_scope: auto_scope_meta.clone(),
                                approval_key_version: approval_key_version_meta.clone(),
                                tool_schema_hash_hex: tool_schema_hash_hex.clone(),
                                hooks_config_hash_hex: hooks_config_hash_hex.clone(),
                                planner_hash_hex: planner_hash_hex.clone(),
                                exec_target: decision_exec_target.clone(),
                                taint_overall: Some(taint_state.overall_str().to_string()),
                                taint_enforced: false,
                                escalated: false,
                                escalation_reason: None,
                                result_ok: false,
                                result_content: reason.clone(),
                                result_input_digest: None,
                                result_output_digest: None,
                                result_input_len: None,
                                result_output_len: None,
                            });
                            observed_tool_decisions.push(ToolDecisionRecord {
                                step: step as u32,
                                tool_call_id: tc.id.clone(),
                                tool: tc.name.clone(),
                                decision: "deny".to_string(),
                                reason: Some(reason.clone()),
                                source: Some("runtime_budget".to_string()),
                                taint_overall: Some(taint_state.overall_str().to_string()),
                                taint_enforced: false,
                                escalated: false,
                                escalation_reason: None,
                            });
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::Error,
                                serde_json::json!({"error": reason.clone()}),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"budget_exceeded"}),
                            );
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::BudgetExceeded,
                                final_output: reason.clone(),
                                error: Some(reason),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: request_context_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                        if let Some(reason) = check_and_consume_mcp_budget(
                            &self.tool_call_budget,
                            &mut tool_budget_usage,
                            tc.name.starts_with("mcp."),
                        ) {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolDecision,
                                serde_json::json!({
                                    "tool_call_id": tc.id,
                                    "name": tc.name,
                                    "decision": "deny",
                                    "reason": reason.clone(),
                                    "source": "runtime_budget",
                                    "side_effects": side_effects,
                                    "budget": {
                                        "max_total_tool_calls": self.tool_call_budget.max_total_tool_calls,
                                        "max_mcp_calls": self.tool_call_budget.max_mcp_calls
                                    }
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::RunEnd,
                                serde_json::json!({"exit_reason":"budget_exceeded"}),
                            );
                            return AgentOutcome {
                                run_id,
                                started_at,
                                finished_at: crate::trust::now_rfc3339(),
                                exit_reason: AgentExitReason::BudgetExceeded,
                                final_output: reason.clone(),
                                error: Some(reason),
                                messages,
                                tool_calls: observed_tool_calls,
                                tool_decisions: observed_tool_decisions,
                                compaction_settings: self.compaction_settings.clone(),
                                final_prompt_size_chars: request_context_chars,
                                compaction_report: last_compaction_report,
                                hook_invocations,
                                provider_retry_count,
                                provider_error_count,
                                token_usage: if saw_token_usage {
                                    Some(total_token_usage.clone())
                                } else {
                                    None
                                },
                                taint: taint_record_from_state(
                                    self.taint_toggle,
                                    self.taint_mode,
                                    self.taint_digest_bytes,
                                    &taint_state,
                                ),
                            };
                        }
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolDecision,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "decision": "allow",
                                "approval_id": approval_id.clone(),
                                "approval_key": approval_key.clone(),
                                "reason": reason.clone(),
                                "source": source.clone(),
                                "approval_key_version": approval_key_version_meta.clone(),
                                "tool_schema_hash_hex": tool_schema_hash_hex.clone(),
                                "hooks_config_hash_hex": hooks_config_hash_hex.clone(),
                                "planner_hash_hex": planner_hash_hex.clone(),
                                "exec_target": decision_exec_target.clone(),
                                "taint_overall": taint_state.overall_str(),
                                "taint_enforced": taint_enforced,
                                "escalated": escalated,
                                "escalation_reason": escalation_reason.clone(),
                                "side_effects": tool_side_effects(&tc.name),
                                "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                            }),
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecTarget,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "exec_target": if tc.name.starts_with("mcp.") { "host" } else {
                                    match self.tool_rt.exec_target_kind {
                                        crate::target::ExecTargetKind::Host => "host",
                                        crate::target::ExecTargetKind::Docker => "docker",
                                    }
                                }
                            }),
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecStart,
                            serde_json::json!({"tool_call_id": tc.id, "name": tc.name, "side_effects": tool_side_effects(&tc.name)}),
                        );
                        let mut tool_msg = if let Some(err) = &invalid_args_error {
                            make_invalid_args_tool_message(tc, err, self.tool_rt.exec_target_kind)
                        } else {
                            let outcome =
                                run_tool_once(&self.tool_rt, tc, self.mcp_registry.as_ref()).await;
                            if let Some(meta) = outcome.mcp_meta {
                                if meta.progress_ticks > 0 {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::McpProgress,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "progress_ticks": meta.progress_ticks,
                                            "elapsed_ms": meta.elapsed_ms,
                                            "phase": "await_result"
                                        }),
                                    );
                                }
                                if meta.cancelled {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::McpCancelled,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "reason": "timeout",
                                            "elapsed_ms": meta.elapsed_ms
                                        }),
                                    );
                                }
                            }
                            outcome.message
                        };
                        let mut tool_retry_count = 0u32;
                        if invalid_args_error.is_none() {
                            loop {
                                let current_content = tool_msg.content.clone().unwrap_or_default();
                                if !tool_result_has_error(&current_content) {
                                    break;
                                }
                                let class = classify_tool_failure(tc, &current_content, false);
                                let max_retries = class.retry_limit_for(side_effects);
                                if tool_retry_count >= max_retries {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::ToolRetry,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "attempt": tool_retry_count,
                                            "max_retries": max_retries,
                                            "failure_class": class.as_str(),
                                            "action": "stop"
                                        }),
                                    );
                                    break;
                                }
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::ToolRetry,
                                    serde_json::json!({
                                        "tool_call_id": tc.id,
                                        "name": tc.name,
                                        "attempt": tool_retry_count + 1,
                                        "max_retries": max_retries,
                                        "failure_class": class.as_str(),
                                        "action": "retry"
                                    }),
                                );
                                tool_retry_count = tool_retry_count.saturating_add(1);
                                if let Some(reason) = check_and_consume_tool_budget(
                                    &self.tool_call_budget,
                                    &mut tool_budget_usage,
                                    side_effects,
                                ) {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::ToolDecision,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "decision": "deny",
                                            "reason": reason.clone(),
                                            "source": "runtime_budget",
                                            "side_effects": side_effects
                                        }),
                                    );
                                    self.gate.record(GateEvent {
                                        run_id: run_id.clone(),
                                        step: step as u32,
                                        tool_call_id: tc.id.clone(),
                                        tool: tc.name.clone(),
                                        arguments: tc.arguments.clone(),
                                        decision: "deny".to_string(),
                                        decision_reason: Some(reason.clone()),
                                        decision_source: Some("runtime_budget".to_string()),
                                        approval_id: None,
                                        approval_key: None,
                                        approval_mode: approval_mode_meta.clone(),
                                        auto_approve_scope: auto_scope_meta.clone(),
                                        approval_key_version: approval_key_version_meta.clone(),
                                        tool_schema_hash_hex: tool_schema_hash_hex.clone(),
                                        hooks_config_hash_hex: hooks_config_hash_hex.clone(),
                                        planner_hash_hex: planner_hash_hex.clone(),
                                        exec_target: decision_exec_target.clone(),
                                        taint_overall: Some(taint_state.overall_str().to_string()),
                                        taint_enforced: false,
                                        escalated: false,
                                        escalation_reason: None,
                                        result_ok: false,
                                        result_content: reason.clone(),
                                        result_input_digest: None,
                                        result_output_digest: None,
                                        result_input_len: None,
                                        result_output_len: None,
                                    });
                                    observed_tool_decisions.push(ToolDecisionRecord {
                                        step: step as u32,
                                        tool_call_id: tc.id.clone(),
                                        tool: tc.name.clone(),
                                        decision: "deny".to_string(),
                                        reason: Some(reason.clone()),
                                        source: Some("runtime_budget".to_string()),
                                        taint_overall: Some(taint_state.overall_str().to_string()),
                                        taint_enforced: false,
                                        escalated: false,
                                        escalation_reason: None,
                                    });
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::Error,
                                        serde_json::json!({"error": reason.clone()}),
                                    );
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::RunEnd,
                                        serde_json::json!({"exit_reason":"budget_exceeded"}),
                                    );
                                    return AgentOutcome {
                                        run_id,
                                        started_at,
                                        finished_at: crate::trust::now_rfc3339(),
                                        exit_reason: AgentExitReason::BudgetExceeded,
                                        final_output: reason.clone(),
                                        error: Some(reason),
                                        messages,
                                        tool_calls: observed_tool_calls,
                                        tool_decisions: observed_tool_decisions,
                                        compaction_settings: self.compaction_settings.clone(),
                                        final_prompt_size_chars: request_context_chars,
                                        compaction_report: last_compaction_report,
                                        hook_invocations,
                                        provider_retry_count,
                                        provider_error_count,
                                        token_usage: if saw_token_usage {
                                            Some(total_token_usage.clone())
                                        } else {
                                            None
                                        },
                                        taint: taint_record_from_state(
                                            self.taint_toggle,
                                            self.taint_mode,
                                            self.taint_digest_bytes,
                                            &taint_state,
                                        ),
                                    };
                                }
                                if let Some(reason) = check_and_consume_mcp_budget(
                                    &self.tool_call_budget,
                                    &mut tool_budget_usage,
                                    tc.name.starts_with("mcp."),
                                ) {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::Error,
                                        serde_json::json!({
                                            "error": reason.clone(),
                                            "source": "runtime_budget",
                                            "budget": {
                                                "max_mcp_calls": self.tool_call_budget.max_mcp_calls
                                            }
                                        }),
                                    );
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::RunEnd,
                                        serde_json::json!({"exit_reason":"budget_exceeded"}),
                                    );
                                    return AgentOutcome {
                                        run_id,
                                        started_at,
                                        finished_at: crate::trust::now_rfc3339(),
                                        exit_reason: AgentExitReason::BudgetExceeded,
                                        final_output: reason.clone(),
                                        error: Some(reason),
                                        messages,
                                        tool_calls: observed_tool_calls,
                                        tool_decisions: observed_tool_decisions,
                                        compaction_settings: self.compaction_settings.clone(),
                                        final_prompt_size_chars: request_context_chars,
                                        compaction_report: last_compaction_report,
                                        hook_invocations,
                                        provider_retry_count,
                                        provider_error_count,
                                        token_usage: if saw_token_usage {
                                            Some(total_token_usage.clone())
                                        } else {
                                            None
                                        },
                                        taint: taint_record_from_state(
                                            self.taint_toggle,
                                            self.taint_mode,
                                            self.taint_digest_bytes,
                                            &taint_state,
                                        ),
                                    };
                                }
                                let outcome =
                                    run_tool_once(&self.tool_rt, tc, self.mcp_registry.as_ref())
                                        .await;
                                if let Some(meta) = outcome.mcp_meta {
                                    if meta.progress_ticks > 0 {
                                        self.emit_event(
                                            &run_id,
                                            step as u32,
                                            EventKind::McpProgress,
                                            serde_json::json!({
                                                "tool_call_id": tc.id,
                                                "name": tc.name,
                                                "progress_ticks": meta.progress_ticks,
                                                "elapsed_ms": meta.elapsed_ms,
                                                "phase": "retry_await_result"
                                            }),
                                        );
                                    }
                                    if meta.cancelled {
                                        self.emit_event(
                                            &run_id,
                                            step as u32,
                                            EventKind::McpCancelled,
                                            serde_json::json!({
                                                "tool_call_id": tc.id,
                                                "name": tc.name,
                                                "reason": "timeout",
                                                "elapsed_ms": meta.elapsed_ms
                                            }),
                                        );
                                    }
                                }
                                tool_msg = outcome.message;
                            }
                        }
                        let original_content = tool_msg.content.clone().unwrap_or_default();
                        let mut input_digest = sha256_hex(original_content.as_bytes());
                        let mut output_digest = input_digest.clone();
                        let mut input_len = original_content.chars().count();
                        let mut output_len = input_len;
                        let mut final_truncated = infer_truncated_flag(&original_content);

                        if self.hooks.enabled() {
                            let payload = ToolResultPayload {
                                tool_call_id: tc.id.clone(),
                                tool_name: tc.name.clone(),
                                ok: !tool_result_has_error(&original_content),
                                content: original_content.clone(),
                                truncated: final_truncated,
                            };
                            let hook_input = make_tool_result_input(
                                &run_id,
                                step as u32,
                                provider_name(self.gate_ctx.provider),
                                &self.model,
                                &self.gate_ctx.workdir,
                                match serde_json::to_value(payload) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        self.emit_event(
                                            &run_id,
                                            step as u32,
                                            EventKind::HookError,
                                            serde_json::json!({"stage":"tool_result","error": e.to_string()}),
                                        );
                                        return AgentOutcome {
                                            run_id,
                                            started_at,
                                            finished_at: crate::trust::now_rfc3339(),
                                            exit_reason: AgentExitReason::HookAborted,
                                            final_output: String::new(),
                                            error: Some(format!(
                                                "failed to encode tool_result hook payload: {e}"
                                            )),
                                            messages,
                                            tool_calls: observed_tool_calls,
                                            tool_decisions: observed_tool_decisions,
                                            compaction_settings: self.compaction_settings.clone(),
                                            final_prompt_size_chars: request_context_chars,
                                            compaction_report: last_compaction_report,
                                            hook_invocations,
                                            provider_retry_count,
                                            provider_error_count,
                                            token_usage: if saw_token_usage {
                                                Some(total_token_usage.clone())
                                            } else {
                                                None
                                            },
                                            taint: taint_record_from_state(
                                                self.taint_toggle,
                                                self.taint_mode,
                                                self.taint_digest_bytes,
                                                &taint_state,
                                            ),
                                        };
                                    }
                                },
                            );
                            match self
                                .hooks
                                .run_tool_result_hooks(
                                    hook_input,
                                    &tc.name,
                                    &original_content,
                                    final_truncated,
                                )
                                .await
                            {
                                Ok(hook_out) => {
                                    for inv in &hook_out.invocations {
                                        self.emit_event(
                                            &run_id,
                                            step as u32,
                                            EventKind::HookStart,
                                            serde_json::json!({
                                                "hook_name": inv.hook_name,
                                                "stage": inv.stage
                                            }),
                                        );
                                        self.emit_event(
                                            &run_id,
                                            step as u32,
                                            EventKind::HookEnd,
                                            serde_json::json!({
                                                "hook_name": inv.hook_name,
                                                "stage": inv.stage,
                                                "action": inv.action,
                                                "modified": inv.modified,
                                                "duration_ms": inv.duration_ms,
                                                "input_digest": inv.input_digest,
                                                "output_digest": inv.output_digest
                                            }),
                                        );
                                    }
                                    hook_invocations.extend(hook_out.invocations);
                                    if let Some(reason) = hook_out.abort_reason {
                                        return AgentOutcome {
                                            run_id,
                                            started_at,
                                            finished_at: crate::trust::now_rfc3339(),
                                            exit_reason: AgentExitReason::HookAborted,
                                            final_output: String::new(),
                                            error: Some(reason),
                                            messages,
                                            tool_calls: observed_tool_calls,
                                            tool_decisions: observed_tool_decisions,
                                            compaction_settings: self.compaction_settings.clone(),
                                            final_prompt_size_chars: request_context_chars,
                                            compaction_report: last_compaction_report,
                                            hook_invocations,
                                            provider_retry_count,
                                            provider_error_count,
                                            token_usage: if saw_token_usage {
                                                Some(total_token_usage.clone())
                                            } else {
                                                None
                                            },
                                            taint: taint_record_from_state(
                                                self.taint_toggle,
                                                self.taint_mode,
                                                self.taint_digest_bytes,
                                                &taint_state,
                                            ),
                                        };
                                    }
                                    tool_msg.content = Some(hook_out.content.clone());
                                    final_truncated = hook_out.truncated;
                                    input_digest = hook_out.input_digest;
                                    output_digest = hook_out.output_digest;
                                    input_len = hook_out.input_len;
                                    output_len = hook_out.output_len;
                                }
                                Err(e) => {
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::HookError,
                                        serde_json::json!({"stage":"tool_result","error": e.message}),
                                    );
                                    return AgentOutcome {
                                        run_id,
                                        started_at,
                                        finished_at: crate::trust::now_rfc3339(),
                                        exit_reason: AgentExitReason::HookAborted,
                                        final_output: String::new(),
                                        error: Some(e.message),
                                        messages,
                                        tool_calls: observed_tool_calls,
                                        tool_decisions: observed_tool_decisions,
                                        compaction_settings: self.compaction_settings.clone(),
                                        final_prompt_size_chars: request_context_chars,
                                        compaction_report: last_compaction_report,
                                        hook_invocations,
                                        provider_retry_count,
                                        provider_error_count,
                                        token_usage: if saw_token_usage {
                                            Some(total_token_usage.clone())
                                        } else {
                                            None
                                        },
                                        taint: taint_record_from_state(
                                            self.taint_toggle,
                                            self.taint_mode,
                                            self.taint_digest_bytes,
                                            &taint_state,
                                        ),
                                    };
                                }
                            }
                        }

                        let content = tool_msg.content.clone().unwrap_or_default();
                        let final_failure_class = if tool_result_has_error(&content) {
                            Some(classify_tool_failure(
                                tc,
                                &content,
                                invalid_args_error.is_some(),
                            ))
                        } else {
                            None
                        };
                        if matches!(self.taint_toggle, TaintToggle::On) {
                            let spans = compute_taint_spans_for_tool(
                                tc,
                                &content,
                                self.policy_for_taint.as_ref(),
                                self.taint_digest_bytes,
                            );
                            if !spans.is_empty() {
                                let tool_message_index = messages.len();
                                taint_state.add_tool_spans(
                                    &tc.id,
                                    tool_message_index,
                                    spans.clone(),
                                );
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::TaintUpdated,
                                    serde_json::json!({
                                        "overall": taint_state.overall_str(),
                                        "new_spans": spans.len(),
                                        "sources": taint_state.sources_count_for_last_update()
                                    }),
                                );
                            }
                        }
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "allow".to_string(),
                            decision_reason: reason.clone(),
                            decision_source: source.clone(),
                            approval_id,
                            approval_key,
                            approval_mode: approval_mode_meta.clone(),
                            auto_approve_scope: auto_scope_meta.clone(),
                            approval_key_version: approval_key_version_meta.clone(),
                            tool_schema_hash_hex: tool_schema_hash_hex.clone(),
                            hooks_config_hash_hex: hooks_config_hash_hex.clone(),
                            planner_hash_hex: planner_hash_hex.clone(),
                            exec_target: decision_exec_target.clone(),
                            taint_overall: Some(taint_state.overall_str().to_string()),
                            taint_enforced,
                            escalated,
                            escalation_reason: escalation_reason.clone(),
                            result_ok: !tool_result_has_error(&content),
                            result_content: content,
                            result_input_digest: Some(input_digest),
                            result_output_digest: Some(output_digest),
                            result_input_len: Some(input_len),
                            result_output_len: Some(output_len),
                        });
                        observed_tool_decisions.push(ToolDecisionRecord {
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            decision: "allow".to_string(),
                            reason: reason.clone(),
                            source: source.clone(),
                            taint_overall: Some(taint_state.overall_str().to_string()),
                            taint_enforced,
                            escalated,
                            escalation_reason: escalation_reason.clone(),
                        });
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecEnd,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "ok": !tool_result_has_error(&tool_msg.content.clone().unwrap_or_default()),
                                "truncated": final_truncated,
                                "retry_count": tool_retry_count,
                                "failure_class": final_failure_class.map(|c| c.as_str())
                            }),
                        );
                        messages.push(tool_msg);
                    }
                    GateDecision::Deny {
                        reason,
                        approval_key,
                        source,
                        taint_enforced,
                        escalated,
                        escalation_reason,
                    } => {
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolDecision,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "decision": "deny",
                                "reason": reason.clone(),
                                "approval_key": approval_key.clone(),
                                "source": source.clone(),
                                "approval_key_version": approval_key_version_meta.clone(),
                                "tool_schema_hash_hex": tool_schema_hash_hex.clone(),
                                "hooks_config_hash_hex": hooks_config_hash_hex.clone(),
                                "planner_hash_hex": planner_hash_hex.clone(),
                                "exec_target": decision_exec_target.clone(),
                                "taint_overall": taint_state.overall_str(),
                                "taint_enforced": taint_enforced,
                                "escalated": escalated,
                                "escalation_reason": escalation_reason.clone(),
                                "side_effects": tool_side_effects(&tc.name),
                                "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                            }),
                        );
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "deny".to_string(),
                            decision_reason: Some(reason.clone()),
                            decision_source: source.clone(),
                            approval_id: None,
                            approval_key,
                            approval_mode: approval_mode_meta.clone(),
                            auto_approve_scope: auto_scope_meta.clone(),
                            approval_key_version: approval_key_version_meta.clone(),
                            tool_schema_hash_hex: tool_schema_hash_hex.clone(),
                            hooks_config_hash_hex: hooks_config_hash_hex.clone(),
                            planner_hash_hex: planner_hash_hex.clone(),
                            exec_target: decision_exec_target.clone(),
                            taint_overall: Some(taint_state.overall_str().to_string()),
                            taint_enforced,
                            escalated,
                            escalation_reason: escalation_reason.clone(),
                            result_ok: false,
                            result_content: reason.clone(),
                            result_input_digest: None,
                            result_output_digest: None,
                            result_input_len: None,
                            result_output_len: None,
                        });
                        observed_tool_decisions.push(ToolDecisionRecord {
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            decision: "deny".to_string(),
                            reason: Some(reason.clone()),
                            source: source.clone(),
                            taint_overall: Some(taint_state.overall_str().to_string()),
                            taint_enforced,
                            escalated,
                            escalation_reason: escalation_reason.clone(),
                        });
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::RunEnd,
                            serde_json::json!({"exit_reason":"denied"}),
                        );
                        return AgentOutcome {
                            run_id,
                            started_at,
                            finished_at: crate::trust::now_rfc3339(),
                            exit_reason: AgentExitReason::Denied,
                            final_output: format!(
                                "Tool call '{}' denied: {}",
                                tc.name,
                                if let Some(src) = &source {
                                    format!("{} (source: {})", reason, src)
                                } else {
                                    reason.clone()
                                }
                            ),
                            error: None,
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            compaction_settings: self.compaction_settings.clone(),
                            final_prompt_size_chars: request_context_chars,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                            token_usage: if saw_token_usage {
                                Some(total_token_usage.clone())
                            } else {
                                None
                            },
                            taint: taint_record_from_state(
                                self.taint_toggle,
                                self.taint_mode,
                                self.taint_digest_bytes,
                                &taint_state,
                            ),
                        };
                    }
                    GateDecision::RequireApproval {
                        reason,
                        approval_id,
                        approval_key,
                        source,
                        taint_enforced,
                        escalated,
                        escalation_reason,
                    } => {
                        if let Some(err) = &invalid_args_error {
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolDecision,
                                serde_json::json!({
                                    "tool_call_id": tc.id,
                                    "name": tc.name,
                                    "decision": "allow",
                                "reason": format!("invalid args bypassed approval: {err}"),
                                "approval_key_version": approval_key_version_meta.clone(),
                                "tool_schema_hash_hex": tool_schema_hash_hex.clone(),
                                "hooks_config_hash_hex": hooks_config_hash_hex.clone(),
                                "planner_hash_hex": planner_hash_hex.clone(),
                                "exec_target": decision_exec_target.clone(),
                                "taint_overall": taint_state.overall_str(),
                                "taint_enforced": taint_enforced,
                                "escalated": escalated,
                                "escalation_reason": escalation_reason.clone(),
                                "side_effects": tool_side_effects(&tc.name),
                                "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                            }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolExecTarget,
                                serde_json::json!({
                                    "tool_call_id": tc.id,
                                    "name": tc.name,
                                    "exec_target": if tc.name.starts_with("mcp.") { "host" } else {
                                        match self.tool_rt.exec_target_kind {
                                            crate::target::ExecTargetKind::Host => "host",
                                            crate::target::ExecTargetKind::Docker => "docker",
                                        }
                                    }
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolExecStart,
                                serde_json::json!({"tool_call_id": tc.id, "name": tc.name, "side_effects": tool_side_effects(&tc.name)}),
                            );
                            let tool_msg = make_invalid_args_tool_message(
                                tc,
                                err,
                                self.tool_rt.exec_target_kind,
                            );
                            let content = tool_msg.content.clone().unwrap_or_default();
                            self.gate.record(GateEvent {
                                run_id: run_id.clone(),
                                step: step as u32,
                                tool_call_id: tc.id.clone(),
                                tool: tc.name.clone(),
                                arguments: tc.arguments.clone(),
                                decision: "allow".to_string(),
                                decision_reason: Some(format!(
                                    "invalid args bypassed approval: {err}"
                                )),
                                decision_source: source.clone(),
                                approval_id: None,
                                approval_key: None,
                                approval_mode: approval_mode_meta.clone(),
                                auto_approve_scope: auto_scope_meta.clone(),
                                approval_key_version: approval_key_version_meta.clone(),
                                tool_schema_hash_hex: tool_schema_hash_hex.clone(),
                                hooks_config_hash_hex: hooks_config_hash_hex.clone(),
                                planner_hash_hex: planner_hash_hex.clone(),
                                exec_target: decision_exec_target.clone(),
                                taint_overall: Some(taint_state.overall_str().to_string()),
                                taint_enforced,
                                escalated,
                                escalation_reason: escalation_reason.clone(),
                                result_ok: false,
                                result_content: content.clone(),
                                result_input_digest: None,
                                result_output_digest: None,
                                result_input_len: None,
                                result_output_len: None,
                            });
                            observed_tool_decisions.push(ToolDecisionRecord {
                                step: step as u32,
                                tool_call_id: tc.id.clone(),
                                tool: tc.name.clone(),
                                decision: "allow".to_string(),
                                reason: Some(format!("invalid args bypassed approval: {err}")),
                                source: source.clone(),
                                taint_overall: Some(taint_state.overall_str().to_string()),
                                taint_enforced,
                                escalated,
                                escalation_reason: escalation_reason.clone(),
                            });
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolExecEnd,
                                serde_json::json!({
                                    "tool_call_id": tc.id,
                                    "name": tc.name,
                                    "ok": false,
                                    "truncated": false
                                }),
                            );
                            messages.push(tool_msg);
                            continue;
                        }
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolDecision,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "decision": "require_approval",
                                "reason": reason.clone(),
                                "approval_id": approval_id.clone(),
                                "approval_key": approval_key.clone(),
                                "source": source.clone(),
                                "approval_key_version": approval_key_version_meta.clone(),
                                "tool_schema_hash_hex": tool_schema_hash_hex.clone(),
                                "hooks_config_hash_hex": hooks_config_hash_hex.clone(),
                                "planner_hash_hex": planner_hash_hex.clone(),
                                "exec_target": decision_exec_target.clone(),
                                "taint_overall": taint_state.overall_str(),
                                "taint_enforced": taint_enforced,
                                "escalated": escalated,
                                "escalation_reason": escalation_reason.clone(),
                                "side_effects": tool_side_effects(&tc.name),
                                "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                            }),
                        );
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "require_approval".to_string(),
                            decision_reason: Some(reason.clone()),
                            decision_source: source.clone(),
                            approval_id: Some(approval_id.clone()),
                            approval_key,
                            approval_mode: approval_mode_meta.clone(),
                            auto_approve_scope: auto_scope_meta.clone(),
                            approval_key_version: approval_key_version_meta.clone(),
                            tool_schema_hash_hex,
                            hooks_config_hash_hex,
                            planner_hash_hex,
                            exec_target: decision_exec_target,
                            taint_overall: Some(taint_state.overall_str().to_string()),
                            taint_enforced,
                            escalated,
                            escalation_reason: escalation_reason.clone(),
                            result_ok: false,
                            result_content: reason.clone(),
                            result_input_digest: None,
                            result_output_digest: None,
                            result_input_len: None,
                            result_output_len: None,
                        });
                        observed_tool_decisions.push(ToolDecisionRecord {
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            decision: "require_approval".to_string(),
                            reason: Some(reason.clone()),
                            source: source.clone(),
                            taint_overall: Some(taint_state.overall_str().to_string()),
                            taint_enforced,
                            escalated,
                            escalation_reason: escalation_reason.clone(),
                        });
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::RunEnd,
                            serde_json::json!({"exit_reason":"approval_required"}),
                        );
                        return AgentOutcome {
                            run_id,
                            started_at,
                            finished_at: crate::trust::now_rfc3339(),
                            exit_reason: AgentExitReason::ApprovalRequired,
                            final_output: if escalated {
                                let src = if taint_state.last_sources.is_empty() {
                                    "other".to_string()
                                } else {
                                    taint_state.last_sources.join("/")
                                };
                                format!(
                                    "Approval required due to tainted content (source: {}). Run: localagent approve {} (or deny) then re-run.",
                                    src, approval_id
                                )
                            } else {
                                format!(
                                    "Approval required: {} ({}){}. Run: localagent approve {} (or deny) then re-run.",
                                    approval_id,
                                    reason,
                                    source
                                        .as_ref()
                                        .map(|s| format!(" [source: {}]", s))
                                        .unwrap_or_default(),
                                    approval_id
                                )
                            },
                            error: None,
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            compaction_settings: self.compaction_settings.clone(),
                            final_prompt_size_chars: request_context_chars,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                            token_usage: if saw_token_usage {
                                Some(total_token_usage.clone())
                            } else {
                                None
                            },
                            taint: taint_record_from_state(
                                self.taint_toggle,
                                self.taint_mode,
                                self.taint_digest_bytes,
                                &taint_state,
                            ),
                        };
                    }
                }
            }
        }

        self.emit_event(
            &run_id,
            self.max_steps as u32,
            EventKind::RunEnd,
            serde_json::json!({"exit_reason":"max_steps"}),
        );
        let final_prompt_size_chars = context_size_chars(&messages);
        AgentOutcome {
            run_id,
            started_at,
            finished_at: crate::trust::now_rfc3339(),
            exit_reason: AgentExitReason::MaxSteps,
            final_output: "Max steps reached before the model produced a final answer.".to_string(),
            error: None,
            messages,
            tool_calls: observed_tool_calls,
            tool_decisions: observed_tool_decisions,
            compaction_settings: self.compaction_settings.clone(),
            final_prompt_size_chars,
            compaction_report: last_compaction_report,
            hook_invocations,
            provider_retry_count,
            provider_error_count,
            token_usage: if saw_token_usage {
                Some(total_token_usage.clone())
            } else {
                None
            },
            taint: taint_record_from_state(
                self.taint_toggle,
                self.taint_mode,
                self.taint_digest_bytes,
                &taint_state,
            ),
        }
    }
}

async fn run_tool_once(
    tool_rt: &ToolRuntime,
    tc: &ToolCall,
    mcp_registry: Option<&std::sync::Arc<McpRegistry>>,
) -> ToolRunOutcome {
    if tc.name.starts_with("mcp.") {
        match mcp_registry {
            Some(reg) => match reg.call_namespaced_tool(tc, tool_rt.tool_args_strict).await {
                Ok(outcome) => ToolRunOutcome {
                    message: outcome.message,
                    mcp_meta: Some(outcome.meta),
                },
                Err(e) => ToolRunOutcome {
                    message: envelope_to_message(to_tool_result_envelope(
                        tc,
                        "mcp",
                        false,
                        format!("mcp call failed: {e}"),
                        false,
                        ToolResultMeta {
                            side_effects: tool_side_effects(&tc.name),
                            bytes: None,
                            exit_code: None,
                            stderr_truncated: None,
                            stdout_truncated: None,
                            source: "mcp".to_string(),
                            execution_target: "host".to_string(),
                            docker: None,
                        },
                    )),
                    mcp_meta: None,
                },
            },
            None => ToolRunOutcome {
                message: envelope_to_message(to_tool_result_envelope(
                    tc,
                    "mcp",
                    false,
                    "mcp registry not available".to_string(),
                    false,
                    ToolResultMeta {
                        side_effects: tool_side_effects(&tc.name),
                        bytes: None,
                        exit_code: None,
                        stderr_truncated: None,
                        stdout_truncated: None,
                        source: "mcp".to_string(),
                        execution_target: "host".to_string(),
                        docker: None,
                    },
                )),
                mcp_meta: None,
            },
        }
    } else {
        ToolRunOutcome {
            message: execute_tool(tool_rt, tc).await,
            mcp_meta: None,
        }
    }
}

struct ToolRunOutcome {
    message: Message,
    mcp_meta: Option<crate::mcp::registry::McpCallMeta>,
}

fn parse_worker_step_status(
    raw: &str,
    constraints: &[PlanStepConstraint],
) -> Option<WorkerStepStatus> {
    let value = parse_jsonish(raw)?;
    let obj = value.as_object()?;
    let schema = obj.get("schema_version").and_then(|v| v.as_str())?;
    if schema != crate::planner::STEP_RESULT_SCHEMA_VERSION {
        return None;
    }
    let step_id = obj.get("step_id").and_then(|v| v.as_str())?.to_string();
    if step_id != "final" && !constraints.iter().any(|s| s.step_id == step_id) {
        return None;
    }
    let status = obj.get("status").and_then(|v| v.as_str())?.to_string();
    if !matches!(status.as_str(), "done" | "retry" | "replan" | "fail") {
        return None;
    }
    let next_step_id = obj
        .get("next_step_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let user_output = obj
        .get("user_output")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some(WorkerStepStatus {
        step_id,
        status,
        next_step_id,
        user_output,
    })
}

fn parse_jsonish(raw: &str) -> Option<serde_json::Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Some(v);
    }
    if let Some(candidate) = fenced_json_candidate(trimmed) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&candidate) {
            return Some(v);
        }
    }
    if let Some((start, end)) = find_json_bounds(trimmed) {
        let candidate = &trimmed[start..=end];
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(candidate) {
            return Some(v);
        }
    }
    None
}

fn fenced_json_candidate(s: &str) -> Option<String> {
    if !s.starts_with("```") {
        return None;
    }
    let lines = s.lines().collect::<Vec<_>>();
    if lines.len() < 3 {
        return None;
    }
    if !lines.first()?.starts_with("```") || !lines.last()?.starts_with("```") {
        return None;
    }
    Some(lines[1..lines.len() - 1].join("\n"))
}

fn find_json_bounds(s: &str) -> Option<(usize, usize)> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end <= start {
        return None;
    }
    Some((start, end))
}

fn classify_tool_failure(
    tc: &ToolCall,
    raw_content: &str,
    invalid_args_error: bool,
) -> ToolFailureClass {
    let text = tool_result_text(raw_content).to_ascii_lowercase();
    if invalid_args_error
        || text.contains("invalid tool arguments")
        || text.contains("missing required field")
        || text.contains("unknown field not allowed")
        || text.contains("must be a ")
        || text.contains("has invalid type")
    {
        return ToolFailureClass::Schema;
    }
    if text.contains("denied") || text.contains("not allowed") || text.contains("approval required")
    {
        return ToolFailureClass::Policy;
    }
    if text.contains("strict mode violation")
        || (text.contains("locator") && text.contains("multiple"))
        || (text.contains("selector") && text.contains("ambiguous"))
    {
        return ToolFailureClass::SelectorAmbiguous;
    }
    if text.contains("timed out") || text.contains("timeout") || text.contains("stream idle") {
        return ToolFailureClass::TimeoutTransient;
    }
    if text.contains("mcp call failed")
        || text.contains("connection refused")
        || text.contains("response channel closed")
        || text.contains("failed to spawn mcp")
        || text.contains("temporarily unavailable")
    {
        return ToolFailureClass::NetworkTransient;
    }
    let side_effects = tool_side_effects(&tc.name);
    if matches!(
        side_effects,
        crate::types::SideEffects::FilesystemWrite
            | crate::types::SideEffects::ShellExec
            | crate::types::SideEffects::Browser
            | crate::types::SideEffects::Network
    ) {
        return ToolFailureClass::NonIdempotent;
    }
    ToolFailureClass::Other
}

fn tool_result_text(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => v
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or(raw)
            .to_string(),
        Err(_) => raw.to_string(),
    }
}
fn tool_result_has_error(content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => {
            if let Some(ok) = v.get("ok").and_then(|x| x.as_bool()) {
                !ok
            } else {
                v.get("error").is_some()
            }
        }
        Err(_) => false,
    }
}

fn infer_truncated_flag(content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => v
            .get("truncated")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn make_invalid_args_tool_message(
    tc: &ToolCall,
    err: &str,
    exec_target_kind: crate::target::ExecTargetKind,
) -> Message {
    let source = if tc.name.starts_with("mcp.") {
        "mcp"
    } else {
        "builtin"
    };
    envelope_to_message(to_tool_result_envelope(
        tc,
        source,
        false,
        format!("invalid tool arguments: {err}"),
        false,
        ToolResultMeta {
            side_effects: tool_side_effects(&tc.name),
            bytes: None,
            exit_code: None,
            stderr_truncated: None,
            stdout_truncated: None,
            source: source.to_string(),
            execution_target: if source == "mcp" {
                "host".to_string()
            } else {
                match exec_target_kind {
                    crate::target::ExecTargetKind::Host => "host".to_string(),
                    crate::target::ExecTargetKind::Docker => "docker".to_string(),
                }
            },
            docker: None,
        },
    ))
}

fn schema_repair_instruction_message(tc: &ToolCall, err: &str) -> Message {
    Message {
        role: Role::Developer,
        content: Some(format!(
            "Schema repair required for tool '{}': {}. Re-emit exactly one corrected tool call for '{}' with valid arguments only.",
            tc.name, err, tc.name
        )),
        tool_call_id: None,
        tool_name: None,
        tool_calls: None,
    }
}

fn provider_name(provider: crate::gate::ProviderKind) -> &'static str {
    match provider {
        crate::gate::ProviderKind::Lmstudio => "lmstudio",
        crate::gate::ProviderKind::Llamacpp => "llamacpp",
        crate::gate::ProviderKind::Ollama => "ollama",
        crate::gate::ProviderKind::Mock => "mock",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn add_opt_u32(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.saturating_add(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

fn taint_record_from_state(
    toggle: TaintToggle,
    mode: TaintMode,
    digest_bytes: usize,
    state: &TaintState,
) -> Option<AgentTaintRecord> {
    if !matches!(toggle, TaintToggle::On) {
        return None;
    }
    Some(AgentTaintRecord {
        enabled: true,
        mode: match mode {
            TaintMode::Propagate => "propagate".to_string(),
            TaintMode::PropagateAndEnforce => "propagate_and_enforce".to_string(),
        },
        digest_bytes,
        overall: state.overall_str().to_string(),
        spans_by_tool_call_id: state.spans_by_tool_call_id.clone(),
    })
}

fn compute_taint_spans_for_tool(
    tc: &ToolCall,
    tool_message_content: &str,
    policy: Option<&Policy>,
    digest_bytes: usize,
) -> Vec<TaintSpan> {
    let mut spans = Vec::new();
    let side_effects = tool_side_effects(&tc.name);
    let content_for_digest = extract_tool_envelope_content(tool_message_content);
    let digest = digest_prefix_hex(&content_for_digest, digest_bytes);

    match side_effects {
        crate::types::SideEffects::Browser => spans.push(TaintSpan {
            source: "browser".to_string(),
            detail: tc.name.clone(),
            digest,
        }),
        crate::types::SideEffects::Network => spans.push(TaintSpan {
            source: "network".to_string(),
            detail: tc.name.clone(),
            digest,
        }),
        _ => {
            if tc.name == "read_file" {
                if let Some(path) = tc.arguments.get("path").and_then(|v| v.as_str()) {
                    if let Some(p) = policy.and_then(|p| p.taint_file_match(path)) {
                        spans.push(TaintSpan {
                            source: "file".to_string(),
                            detail: format!("matched taint glob: {p}"),
                            digest,
                        });
                    }
                }
            }
        }
    }
    spans
}

fn extract_tool_envelope_content(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => v
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or(raw)
            .to_string(),
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::json;

    use super::{
        sanitize_user_visible_output, Agent, AgentExitReason, McpPinEnforcementMode,
        PlanStepConstraint,
        PlanToolEnforcementMode, ToolCallBudget,
    };
    use crate::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
    use crate::gate::{ApprovalMode, AutoApproveScope, GateContext, NoGate, ProviderKind};
    use crate::hooks::config::HooksMode;
    use crate::hooks::runner::{HookManager, HookRuntimeConfig};
    use crate::providers::{ModelProvider, StreamDelta};
    use crate::target::{ExecTargetKind, HostTarget};
    use crate::tools::{ToolArgsStrict, ToolRuntime};
    use crate::types::{GenerateRequest, GenerateResponse, Message, Role};

    struct MockProvider {
        generate_calls: Arc<AtomicUsize>,
        stream_calls: Arc<AtomicUsize>,
        seen_messages: Arc<Mutex<Vec<Message>>>,
    }

    #[test]
    fn sanitize_hides_thought_and_think_sections() {
        let s = "<think>internal</think>\nTHOUGHT: hidden\nRESPONSE: visible";
        assert_eq!(sanitize_user_visible_output(s), "visible");
    }

    #[async_trait]
    impl ModelProvider for MockProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            *self.seen_messages.lock().expect("lock") = _req.messages.clone();
            self.generate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some("done".to_string()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: Vec::new(),
                usage: None,
            })
        }

        fn supports_streaming(&self) -> bool {
            true
        }

        async fn generate_streaming(
            &self,
            req: GenerateRequest,
            _on_delta: &mut (dyn FnMut(StreamDelta) + Send),
        ) -> anyhow::Result<GenerateResponse> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            self.generate(req).await
        }
    }

    #[tokio::test]
    async fn non_stream_mode_uses_non_stream_generate() {
        let generate_calls = Arc::new(AtomicUsize::new(0));
        let stream_calls = Arc::new(AtomicUsize::new(0));
        let provider = MockProvider {
            generate_calls: generate_calls.clone(),
            stream_calls: stream_calls.clone(),
            seen_messages: Arc::new(Mutex::new(Vec::new())),
        };
        let mut agent = Agent {
            provider,
            model: "m".to_string(),
            tools: Vec::new(),
            max_steps: 1,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: None,
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Off,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: Vec::new(),
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert_eq!(out.final_output, "done");
        assert_eq!(generate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(stream_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn task_memory_message_is_injected_into_transcript() {
        let seen_messages = Arc::new(Mutex::new(Vec::new()));
        let provider = MockProvider {
            generate_calls: Arc::new(AtomicUsize::new(0)),
            stream_calls: Arc::new(AtomicUsize::new(0)),
            seen_messages: seen_messages.clone(),
        };
        let mut agent = Agent {
            provider,
            model: "m".to_string(),
            tools: Vec::new(),
            max_steps: 1,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: None,
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Off,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: Vec::new(),
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let mem_msg = Message {
            role: Role::Developer,
            content: Some("TASK MEMORY (user-authored, authoritative)\n- [x] T: C".to_string()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        };
        let out = agent.run("hi", vec![], vec![mem_msg]).await;
        assert!(out.messages.iter().any(|m| m
            .content
            .as_deref()
            .unwrap_or_default()
            .contains("TASK MEMORY")));
        assert!(seen_messages.lock().expect("lock").iter().any(|m| m
            .content
            .as_deref()
            .unwrap_or_default()
            .contains("TASK MEMORY")));
    }

    #[test]
    fn tool_error_detection() {
        assert!(super::tool_result_has_error(
            &json!({"error":"x"}).to_string()
        ));
        assert!(!super::tool_result_has_error(
            &json!({"ok":true}).to_string()
        ));
    }

    #[test]
    fn tool_failure_classification_schema_and_network() {
        let tc_read = crate::types::ToolCall {
            id: "tc-schema".to_string(),
            name: "read_file".to_string(),
            arguments: serde_json::json!({"path":"a.txt"}),
        };
        let schema_msg = json!({
            "schema_version":"openagent.tool_result.v1",
            "ok":false,
            "content":"invalid tool arguments: missing required field: path"
        })
        .to_string();
        assert_eq!(
            super::classify_tool_failure(&tc_read, &schema_msg, false).as_str(),
            "E_SCHEMA"
        );

        let tc_mcp = crate::types::ToolCall {
            id: "tc-net".to_string(),
            name: "mcp.playwright.browser_snapshot".to_string(),
            arguments: serde_json::json!({}),
        };
        let net_msg = json!({
            "schema_version":"openagent.tool_result.v1",
            "ok":false,
            "content":"mcp call failed: connection refused"
        })
        .to_string();
        assert_eq!(
            super::classify_tool_failure(&tc_mcp, &net_msg, false).as_str(),
            "E_NETWORK_TRANSIENT"
        );
    }

    #[test]
    fn retry_policy_disables_blind_retries_for_side_effectful_tools() {
        assert_eq!(
            super::ToolFailureClass::TimeoutTransient
                .retry_limit_for(crate::types::SideEffects::FilesystemRead),
            1
        );
        assert_eq!(
            super::ToolFailureClass::TimeoutTransient
                .retry_limit_for(crate::types::SideEffects::ShellExec),
            0
        );
        assert_eq!(
            super::ToolFailureClass::NetworkTransient
                .retry_limit_for(crate::types::SideEffects::Browser),
            0
        );
    }

    struct EventCaptureSink {
        events: Arc<Mutex<Vec<crate::events::Event>>>,
    }

    impl crate::events::EventSink for EventCaptureSink {
        fn emit(&mut self, event: crate::events::Event) -> anyhow::Result<()> {
            self.events.lock().expect("lock").push(event);
            Ok(())
        }
    }

    struct ToolCallProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ModelProvider for ToolCallProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(GenerateResponse {
                    assistant: Message {
                        role: Role::Assistant,
                        content: Some(String::new()),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    },
                    tool_calls: vec![crate::types::ToolCall {
                        id: "tc1".to_string(),
                        name: "read_file".to_string(),
                        arguments: serde_json::json!({"path":"a.txt"}),
                    }],
                    usage: None,
                })
            } else {
                Ok(GenerateResponse {
                    assistant: Message {
                        role: Role::Assistant,
                        content: Some("done".to_string()),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    },
                    tool_calls: Vec::new(),
                    usage: None,
                })
            }
        }
    }

    struct NoToolProvider;

    #[async_trait]
    impl ModelProvider for NoToolProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some("done".to_string()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: Vec::new(),
                usage: None,
            })
        }
    }

    struct DualToolProvider;

    #[async_trait]
    impl ModelProvider for DualToolProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some(String::new()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: vec![
                    crate::types::ToolCall {
                        id: "tc1".to_string(),
                        name: "read_file".to_string(),
                        arguments: serde_json::json!({"path":"a.txt"}),
                    },
                    crate::types::ToolCall {
                        id: "tc2".to_string(),
                        name: "read_file".to_string(),
                        arguments: serde_json::json!({"path":"a.txt"}),
                    },
                ],
                usage: None,
            })
        }
    }

    struct StaticContentProvider {
        content: String,
    }

    #[async_trait]
    impl ModelProvider for StaticContentProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some(self.content.clone()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: Vec::new(),
                usage: None,
            })
        }
    }

    struct InvalidThenValidProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ModelProvider for InvalidThenValidProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => Ok(GenerateResponse {
                    assistant: Message {
                        role: Role::Assistant,
                        content: Some(String::new()),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    },
                    tool_calls: vec![crate::types::ToolCall {
                        id: "tc_bad".to_string(),
                        name: "read_file".to_string(),
                        arguments: serde_json::json!({}),
                    }],
                    usage: None,
                }),
                1 => Ok(GenerateResponse {
                    assistant: Message {
                        role: Role::Assistant,
                        content: Some(String::new()),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    },
                    tool_calls: vec![crate::types::ToolCall {
                        id: "tc_good".to_string(),
                        name: "read_file".to_string(),
                        arguments: serde_json::json!({"path":"a.txt"}),
                    }],
                    usage: None,
                }),
                _ => Ok(GenerateResponse {
                    assistant: Message {
                        role: Role::Assistant,
                        content: Some("done".to_string()),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    },
                    tool_calls: Vec::new(),
                    usage: None,
                }),
            }
        }
    }

    #[tokio::test]
    async fn emits_tool_exec_target_before_exec_start() {
        let tmp = tempfile::tempdir().expect("tmp");
        tokio::fs::write(tmp.path().join("a.txt"), "x")
            .await
            .expect("write");
        let events = Arc::new(Mutex::new(Vec::<crate::events::Event>::new()));
        let provider = ToolCallProvider {
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut agent = Agent {
            provider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({"type":"object"}),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 3,
            tool_rt: ToolRuntime {
                workdir: tmp.path().to_path_buf(),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: tmp.path().to_path_buf(),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: None,
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: Some(Box::new(EventCaptureSink {
                events: events.clone(),
            })),
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Off,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: Vec::new(),
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert_eq!(out.final_output, "done");
        let evs = events.lock().expect("lock");
        let target_idx = evs
            .iter()
            .position(|e| matches!(e.kind, crate::events::EventKind::ToolExecTarget))
            .expect("target event");
        let start_idx = evs
            .iter()
            .position(|e| matches!(e.kind, crate::events::EventKind::ToolExecStart))
            .expect("start event");
        assert!(target_idx < start_idx);
    }

    #[tokio::test]
    async fn plan_tool_enforcement_hard_denies_disallowed_tool() {
        let provider = ToolCallProvider {
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut agent = Agent {
            provider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({"type":"object"}),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 2,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: Some("plan123".to_string()),
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Hard,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: vec![PlanStepConstraint {
                step_id: "S1".to_string(),
                intended_tools: vec!["list_dir".to_string()],
            }],
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::Denied));
        assert!(out.final_output.contains("is not allowed for plan step S1"));
        assert!(out
            .tool_decisions
            .iter()
            .any(|d| d.source.as_deref() == Some("plan_step_constraint")));
    }

    #[tokio::test]
    async fn halting_is_blocked_when_plan_steps_are_pending() {
        let mut agent = Agent {
            provider: NoToolProvider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({"type":"object"}),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 3,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: Some("plan123".to_string()),
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Hard,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: vec![PlanStepConstraint {
                step_id: "S1".to_string(),
                intended_tools: vec!["read_file".to_string()],
            }],
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::PlannerError));
        let err = out.error.as_deref().unwrap_or_default();
        assert!(err.contains("halt") || err.contains("control envelope"));
    }

    #[tokio::test]
    async fn emits_step_lifecycle_events_for_pending_plan_halt() {
        let events = Arc::new(Mutex::new(Vec::<crate::events::Event>::new()));
        let mut agent = Agent {
            provider: NoToolProvider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({"type":"object"}),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 2,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: Some("plan123".to_string()),
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: Some(Box::new(EventCaptureSink {
                events: events.clone(),
            })),
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Hard,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: vec![PlanStepConstraint {
                step_id: "S1".to_string(),
                intended_tools: vec!["read_file".to_string()],
            }],
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::PlannerError));
        let evs = events.lock().expect("lock");
        assert!(evs
            .iter()
            .any(|e| matches!(e.kind, crate::events::EventKind::StepStarted)));
        assert!(evs
            .iter()
            .any(|e| matches!(e.kind, crate::events::EventKind::StepBlocked)));
    }

    #[tokio::test]
    async fn tool_budget_exceeded_returns_deterministic_exit() {
        let tmp = tempfile::tempdir().expect("tmp");
        tokio::fs::write(tmp.path().join("a.txt"), "x")
            .await
            .expect("write");
        let mut agent = Agent {
            provider: DualToolProvider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({"type":"object"}),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 1,
            tool_rt: ToolRuntime {
                workdir: tmp.path().to_path_buf(),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: tmp.path().to_path_buf(),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: None,
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Off,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: Vec::new(),
            tool_call_budget: ToolCallBudget {
                max_total_tool_calls: 1,
                ..ToolCallBudget::default()
            },
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::BudgetExceeded));
        assert!(out
            .tool_decisions
            .iter()
            .any(|d| d.source.as_deref() == Some("runtime_budget")));
    }

    #[tokio::test]
    async fn planner_enforced_final_output_uses_user_output_field() {
        let provider = StaticContentProvider {
            content: r#"{"schema_version":"openagent.step_result.v1","step_id":"S1","status":"done","next_step_id":"final","user_output":"all checks passed"}"#.to_string(),
        };
        let mut agent = Agent {
            provider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({"type":"object"}),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 2,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: Some("plan123".to_string()),
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Hard,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: vec![PlanStepConstraint {
                step_id: "S1".to_string(),
                intended_tools: vec!["read_file".to_string()],
            }],
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::Ok));
        assert_eq!(out.final_output, "all checks passed");
    }

    #[tokio::test]
    async fn schema_repair_retry_happens_before_execution() {
        let tmp = tempfile::tempdir().expect("tmp");
        tokio::fs::write(tmp.path().join("a.txt"), "x")
            .await
            .expect("write");
        let events = Arc::new(Mutex::new(Vec::<crate::events::Event>::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = InvalidThenValidProvider {
            calls: calls.clone(),
        };
        let mut agent = Agent {
            provider,
            model: "m".to_string(),
            tools: vec![crate::types::ToolDef {
                name: "read_file".to_string(),
                description: "d".to_string(),
                parameters: serde_json::json!({
                    "type":"object",
                    "properties":{"path":{"type":"string"}},
                    "required":["path"]
                }),
                side_effects: crate::types::SideEffects::FilesystemRead,
            }],
            max_steps: 4,
            tool_rt: ToolRuntime {
                workdir: tmp.path().to_path_buf(),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: tmp.path().to_path_buf(),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: None,
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: Some(Box::new(EventCaptureSink {
                events: events.clone(),
            })),
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Off,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: Vec::new(),
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::Ok));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let evs = events.lock().expect("lock");
        assert!(evs.iter().any(|e| {
            matches!(e.kind, crate::events::EventKind::ToolRetry)
                && e.data
                    .get("failure_class")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    == "E_SCHEMA"
                && e.data
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    == "repair"
        }));
    }

    #[tokio::test]
    async fn invalid_done_transition_fails_with_planner_error() {
        let content = serde_json::json!({
            "schema_version": crate::planner::STEP_RESULT_SCHEMA_VERSION,
            "step_id": "S2",
            "status": "done",
            "evidence": ["ok"]
        })
        .to_string();
        let mut agent = Agent {
            provider: StaticContentProvider { content },
            model: "m".to_string(),
            tools: Vec::new(),
            max_steps: 1,
            tool_rt: ToolRuntime {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_shell_in_workdir_only: false,
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
                exec_target_kind: ExecTargetKind::Host,
                exec_target: std::sync::Arc::new(HostTarget),
            },
            gate: Box::new(NoGate::new()),
            gate_ctx: GateContext {
                workdir: std::env::current_dir().expect("cwd"),
                allow_shell: false,
                allow_write: false,
                approval_mode: ApprovalMode::Interrupt,
                auto_approve_scope: AutoApproveScope::Run,
                unsafe_mode: false,
                unsafe_bypass_allow_flags: false,
                run_id: None,
                enable_write_tools: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                provider: ProviderKind::Ollama,
                model: "m".to_string(),
                exec_target: ExecTargetKind::Host,
                approval_key_version: crate::gate::ApprovalKeyVersion::V1,
                tool_schema_hashes: std::collections::BTreeMap::new(),
                hooks_config_hash_hex: None,
                planner_hash_hex: Some("plan123".to_string()),
                taint_enabled: false,
                taint_mode: crate::taint::TaintMode::Propagate,
                taint_overall: crate::taint::TaintLevel::Clean,
                taint_sources: Vec::new(),
            },
            mcp_registry: None,
            stream: false,
            event_sink: None,
            compaction_settings: CompactionSettings {
                max_context_chars: 0,
                mode: CompactionMode::Off,
                keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
            },
            hooks: HookManager::build(HookRuntimeConfig {
                mode: HooksMode::Off,
                config_path: std::env::temp_dir().join("unused_hooks.yaml"),
                strict: false,
                timeout_ms: 1000,
                max_stdout_bytes: 200_000,
            })
            .expect("hooks"),
            policy_loaded: None,
            policy_for_taint: None,
            taint_toggle: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            run_id_override: None,
            omit_tools_field_when_empty: false,
            plan_tool_enforcement: PlanToolEnforcementMode::Hard,
            mcp_pin_enforcement: McpPinEnforcementMode::Hard,
            plan_step_constraints: vec![
                PlanStepConstraint {
                    step_id: "S1".to_string(),
                    intended_tools: Vec::new(),
                },
                PlanStepConstraint {
                    step_id: "S2".to_string(),
                    intended_tools: Vec::new(),
                },
            ],
            tool_call_budget: ToolCallBudget::default(),
            mcp_runtime_trace: Vec::new(),
        };
        let out = agent.run("hi", vec![], Vec::new()).await;
        assert!(matches!(out.exit_reason, AgentExitReason::PlannerError));
        assert!(out
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("invalid step completion transition"));
    }

    #[test]
    fn taint_spans_browser_deterministic() {
        let tc = crate::types::ToolCall {
            id: "tc1".to_string(),
            name: "mcp.playwright.browser_snapshot".to_string(),
            arguments: serde_json::json!({}),
        };
        let content = serde_json::json!({
            "schema_version":"openagent.tool_result.v1",
            "content":"OPENAGENT_FIXTURE_OK"
        })
        .to_string();
        let a = super::compute_taint_spans_for_tool(&tc, &content, None, 8);
        let b = super::compute_taint_spans_for_tool(&tc, &content, None, 8);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].source, "browser");
        assert_eq!(a[0].digest, b[0].digest);
    }

    #[test]
    fn taint_file_glob_matches_read_file() {
        let policy = crate::trust::policy::Policy::from_yaml(
            r#"
version: 2
default: deny
taint:
  file_path_globs: ["**/.env"]
"#,
        )
        .expect("policy");
        let tc = crate::types::ToolCall {
            id: "tcf".to_string(),
            name: "read_file".to_string(),
            arguments: serde_json::json!({"path":"repo/.env"}),
        };
        let spans = super::compute_taint_spans_for_tool(&tc, "secret", Some(&policy), 16);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].source, "file");
        assert!(spans[0].detail.contains("matched taint glob"));
    }
}
