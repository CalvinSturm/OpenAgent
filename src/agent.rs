use crate::agent_budget::{
    check_and_consume_mcp_budget, check_and_consume_tool_budget, ToolCallBudgetUsage,
};
use uuid::Uuid;

use crate::agent_impl_guard::{implementation_integrity_violation, prompt_requires_tool_only};
use crate::agent_output_sanitize::sanitize_user_visible_output as sanitize_user_visible_output_impl;
use crate::agent_taint_helpers::{compute_taint_spans_for_tool, taint_record_from_state};
use crate::agent_tool_exec::{
    classify_tool_failure, contains_tool_wrapper_markers, extract_content_tool_calls,
    infer_truncated_flag, is_apply_patch_invalid_format_error, make_invalid_args_tool_message,
    run_tool_once, schema_repair_instruction_message, tool_result_has_error,
};
use crate::agent_utils::{add_opt_u32, provider_name, sha256_hex};
use crate::agent_worker_protocol::parse_worker_step_status;
use crate::compaction::{
    context_size_chars, maybe_compact, CompactionOutcome, CompactionReport, CompactionSettings,
};
use crate::events::{EventKind, EventSink};
use crate::gate::{ApprovalMode, AutoApproveScope, GateContext, GateDecision, GateEvent, ToolGate};
use crate::hooks::protocol::{
    HookInvocationReport, PreModelCompactionPayload, PreModelPayload, ToolResultPayload,
};
use crate::hooks::runner::{make_pre_model_input, make_tool_result_input, HookManager};
use crate::mcp::registry::McpRegistry;
use crate::operator_queue::{
    DeliveryBoundary, PendingMessageQueue, QueueLimits, QueueMessageKind, QueueSubmitRequest,
    QueuedOperatorMessage,
};
use crate::providers::http::{message_short, ProviderError};
use crate::providers::{ModelProvider, StreamDelta};
use crate::taint::{TaintMode, TaintSpan, TaintState, TaintToggle};
use crate::tools::{
    envelope_to_message, to_tool_result_envelope, tool_side_effects, validate_builtin_tool_args,
    ToolResultMeta, ToolRuntime,
};
use crate::trust::policy::{McpAllowSummary, Policy};
use crate::types::{GenerateRequest, Message, Role, TokenUsage, ToolCall, ToolDef};

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

pub fn sanitize_user_visible_output(raw: &str) -> String {
    sanitize_user_visible_output_impl(raw)
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

struct AgentOutcomeBuilderInput {
    run_id: String,
    started_at: String,
    exit_reason: AgentExitReason,
    final_output: String,
    error: Option<String>,
    messages: Vec<Message>,
    tool_calls: Vec<ToolCall>,
    tool_decisions: Vec<ToolDecisionRecord>,
    final_prompt_size_chars: usize,
    compaction_report: Option<CompactionReport>,
    hook_invocations: Vec<HookInvocationReport>,
    provider_retry_count: u32,
    provider_error_count: u32,
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
pub(crate) struct WorkerStepStatus {
    pub(crate) step_id: String,
    pub(crate) status: String,
    pub(crate) next_step_id: Option<String>,
    pub(crate) user_output: Option<String>,
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
    pub operator_queue: PendingMessageQueue,
    #[allow(dead_code)]
    pub operator_queue_limits: QueueLimits,
    pub operator_queue_rx: Option<std::sync::mpsc::Receiver<QueueSubmitRequest>>,
}

impl<P: ModelProvider> Agent<P> {
    fn emit_run_start_events(&mut self, run_id: &str) {
        self.emit_event(
            run_id,
            0,
            EventKind::RunStart,
            serde_json::json!({"model": self.model}),
        );
        if let Some(policy) = &self.policy_loaded {
            self.emit_event(
                run_id,
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
    }

    fn build_initial_messages(
        &self,
        user_prompt: &str,
        session_messages: Vec<Message>,
        injected_messages: Vec<Message>,
    ) -> Vec<Message> {
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
        messages
    }

    fn compute_run_preflight_caches(
        &self,
    ) -> (
        Option<String>,
        Option<String>,
        std::collections::BTreeSet<String>,
    ) {
        let expected_mcp_catalog_hash_hex = self
            .mcp_registry
            .as_ref()
            .and_then(|m| m.configured_tool_catalog_hash_hex().ok());
        let expected_mcp_docs_hash_hex = self
            .mcp_registry
            .as_ref()
            .and_then(|m| m.configured_tool_docs_hash_hex().ok());
        let allowed_tool_names: std::collections::BTreeSet<String> =
            self.tools.iter().map(|t| t.name.clone()).collect();
        (
            expected_mcp_catalog_hash_hex,
            expected_mcp_docs_hash_hex,
            allowed_tool_names,
        )
    }

    fn emit_plan_step_started_if_needed(
        &mut self,
        run_id: &str,
        step: u32,
        active_plan_step_idx: usize,
        announced_plan_step_id: &mut Option<String>,
    ) {
        if matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
            || self.plan_step_constraints.is_empty()
            || active_plan_step_idx >= self.plan_step_constraints.len()
        {
            return;
        }
        let step_constraint = self.plan_step_constraints[active_plan_step_idx].clone();
        if announced_plan_step_id.as_deref() == Some(step_constraint.step_id.as_str()) {
            return;
        }
        self.emit_event(
            run_id,
            step,
            EventKind::StepStarted,
            serde_json::json!({
                "step_id": step_constraint.step_id,
                "step_index": active_plan_step_idx,
                "allowed_tools": step_constraint.intended_tools,
                "enforcement_mode": format!("{:?}", self.plan_tool_enforcement).to_lowercase()
            }),
        );
        *announced_plan_step_id = Some(step_constraint.step_id.clone());
    }

    fn record_detected_tool_call(
        &mut self,
        run_id: &str,
        step: u32,
        tc: &ToolCall,
        observed_tool_calls: &mut Vec<ToolCall>,
    ) {
        observed_tool_calls.push(tc.clone());
        self.emit_event(
            run_id,
            step,
            EventKind::ToolCallDetected,
            serde_json::json!({
                "tool_call_id": tc.id,
                "name": tc.name,
                "arguments": tc.arguments,
                "side_effects": tool_side_effects(&tc.name),
                "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
            }),
        );
    }

    fn check_wall_time_budget_exceeded(
        &mut self,
        run_id: &str,
        step: u32,
        run_started: &std::time::Instant,
    ) -> Option<String> {
        if self.tool_call_budget.max_wall_time_ms == 0 {
            return None;
        }
        let elapsed_ms = run_started.elapsed().as_millis() as u64;
        if elapsed_ms <= self.tool_call_budget.max_wall_time_ms {
            return None;
        }
        let reason = format!(
            "runtime budget exceeded: wall time {}ms > limit {}ms",
            elapsed_ms, self.tool_call_budget.max_wall_time_ms
        );
        self.emit_event(
            run_id,
            step,
            EventKind::Error,
            serde_json::json!({
                "error": reason,
                "source": "runtime_budget",
                "elapsed_ms": elapsed_ms,
                "max_wall_time_ms": self.tool_call_budget.max_wall_time_ms
            }),
        );
        self.emit_event(
            run_id,
            step,
            EventKind::RunEnd,
            serde_json::json!({"exit_reason":"budget_exceeded"}),
        );
        Some(reason)
    }

    fn compact_messages_for_step(
        &mut self,
        run_id: &str,
        step: u32,
        messages: &[Message],
        provider_retry_count: &mut u32,
        provider_error_count: &mut u32,
    ) -> Result<CompactionOutcome, String> {
        match maybe_compact(messages, &self.compaction_settings) {
            Ok(c) => Ok(c),
            Err(e) => {
                if let Some(pe) = e.downcast_ref::<ProviderError>() {
                    for r in &pe.retries {
                        *provider_retry_count = provider_retry_count.saturating_add(1);
                        self.emit_event(
                            run_id,
                            step,
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
                    *provider_error_count = provider_error_count.saturating_add(1);
                    self.emit_event(
                        run_id,
                        step,
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
                let err_text = format!("compaction failed: {e}");
                self.emit_event(
                    run_id,
                    step,
                    EventKind::Error,
                    serde_json::json!({"error": err_text}),
                );
                self.emit_event(
                    run_id,
                    step,
                    EventKind::RunEnd,
                    serde_json::json!({"exit_reason":"provider_error"}),
                );
                Err(err_text)
            }
        }
    }

    #[allow(dead_code)]
    pub fn queue_operator_message(
        &mut self,
        kind: QueueMessageKind,
        content: &str,
    ) -> QueuedOperatorMessage {
        let submitted = self
            .operator_queue
            .submit(kind, content, &self.operator_queue_limits)
            .queued;
        if let Some(run_id) = self.gate_ctx.run_id.clone() {
            self.emit_event(
                &run_id,
                0,
                EventKind::QueueSubmitted,
                serde_json::json!({
                    "queue_id": submitted.queue_id,
                    "sequence_no": submitted.sequence_no,
                    "kind": submitted.kind,
                    "truncated": submitted.truncated,
                    "bytes_kept": submitted.bytes_kept,
                    "bytes_loaded": submitted.bytes_loaded,
                    "next_delivery": match submitted.kind {
                        QueueMessageKind::Steer => DeliveryBoundary::PostTool.user_phrase(),
                        QueueMessageKind::FollowUp => DeliveryBoundary::TurnIdle.user_phrase(),
                    }
                }),
            );
        }
        submitted
    }

    #[allow(dead_code)]
    pub fn pending_operator_messages(&self) -> &[QueuedOperatorMessage] {
        self.operator_queue.pending()
    }

    #[allow(dead_code)]
    pub fn clear_operator_queue(&mut self) {
        self.operator_queue.clear();
    }

    fn finalize_run_outcome(
        &self,
        input: AgentOutcomeBuilderInput,
        saw_token_usage: bool,
        total_token_usage: &TokenUsage,
        taint_state: &TaintState,
    ) -> AgentOutcome {
        AgentOutcome {
            run_id: input.run_id,
            started_at: input.started_at,
            finished_at: crate::trust::now_rfc3339(),
            exit_reason: input.exit_reason,
            final_output: input.final_output,
            error: input.error,
            messages: input.messages,
            tool_calls: input.tool_calls,
            tool_decisions: input.tool_decisions,
            compaction_settings: self.compaction_settings.clone(),
            final_prompt_size_chars: input.final_prompt_size_chars,
            compaction_report: input.compaction_report,
            hook_invocations: input.hook_invocations,
            provider_retry_count: input.provider_retry_count,
            provider_error_count: input.provider_error_count,
            token_usage: if saw_token_usage {
                Some(total_token_usage.clone())
            } else {
                None
            },
            taint: taint_record_from_state(
                self.taint_toggle,
                self.taint_mode,
                self.taint_digest_bytes,
                taint_state,
            ),
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
        self.emit_run_start_events(&run_id);
        let mut messages =
            self.build_initial_messages(user_prompt, session_messages, injected_messages);

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
        let mut blocked_tool_only_count: u32 = 0;
        let mut tool_only_phase_active = prompt_requires_tool_only(user_prompt);
        let mut last_user_output: Option<String> = None;
        let mut step_retry_counts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        let mut schema_repair_attempts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        let mut malformed_tool_call_attempts: u32 = 0;
        let mut invalid_patch_format_attempts: u32 = 0;
        let mut tool_budget_usage = ToolCallBudgetUsage::default();
        let run_started = std::time::Instant::now();
        let mut announced_plan_step_id: Option<String> = None;
        let (expected_mcp_catalog_hash_hex, expected_mcp_docs_hash_hex, allowed_tool_names) =
            self.compute_run_preflight_caches();
        'agent_steps: for step in 0..self.max_steps {
            self.drain_external_operator_queue(&run_id, step as u32);
            if let Some(reason) =
                self.check_wall_time_budget_exceeded(&run_id, step as u32, &run_started)
            {
                let final_prompt_size_chars = context_size_chars(&messages);
                return self.finalize_run_outcome(
                    AgentOutcomeBuilderInput {
                        run_id,
                        started_at,
                        exit_reason: AgentExitReason::BudgetExceeded,
                        final_output: reason.clone(),
                        error: Some(reason),
                        messages,
                        tool_calls: observed_tool_calls,
                        tool_decisions: observed_tool_decisions,
                        final_prompt_size_chars,
                        compaction_report: last_compaction_report,
                        hook_invocations,
                        provider_retry_count,
                        provider_error_count,
                    },
                    saw_token_usage,
                    &total_token_usage,
                    &taint_state,
                );
            }
            self.emit_plan_step_started_if_needed(
                &run_id,
                step as u32,
                active_plan_step_idx,
                &mut announced_plan_step_id,
            );
            let compacted = match self.compact_messages_for_step(
                &run_id,
                step as u32,
                &messages,
                &mut provider_retry_count,
                &mut provider_error_count,
            ) {
                Ok(c) => c,
                Err(err_text) => {
                    return self.finalize_run_outcome(
                        AgentOutcomeBuilderInput {
                            run_id,
                            started_at,
                            exit_reason: AgentExitReason::ProviderError,
                            final_output: String::new(),
                            error: Some(err_text),
                            messages,
                            tool_calls: observed_tool_calls,
                            tool_decisions: observed_tool_decisions,
                            final_prompt_size_chars: 0,
                            compaction_report: last_compaction_report,
                            hook_invocations,
                            provider_retry_count,
                            provider_error_count,
                        },
                        saw_token_usage,
                        &total_token_usage,
                        &taint_state,
                    );
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

            let mut resp = match resp_result {
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
            if resp.tool_calls.is_empty() {
                let assistant_content = resp.assistant.content.clone().unwrap_or_default();
                let normalized_calls = extract_content_tool_calls(
                    &assistant_content,
                    step as u32,
                    &allowed_tool_names,
                );
                if !normalized_calls.is_empty() {
                    resp.tool_calls = normalized_calls;
                    resp.assistant.content = None;
                } else if contains_tool_wrapper_markers(&assistant_content) {
                    malformed_tool_call_attempts = malformed_tool_call_attempts.saturating_add(1);
                    if malformed_tool_call_attempts >= 2 {
                        let reason = "MODEL_TOOL_PROTOCOL_VIOLATION: empty or malformed [TOOL_CALL] envelope".to_string();
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::Error,
                            serde_json::json!({
                                "error": reason,
                                "source": "tool_protocol_guard",
                                "failure_class": "E_PROTOCOL_TOOL_WRAPPER",
                                "attempt": malformed_tool_call_attempts
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
                }
            }
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
            if tool_only_phase_active
                && resp.tool_calls.is_empty()
                && !resp
                    .assistant
                    .content
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
            {
                blocked_tool_only_count = blocked_tool_only_count.saturating_add(1);
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::StepBlocked,
                    serde_json::json!({
                        "reason": "tool_only_violation",
                        "blocked_count": blocked_tool_only_count
                    }),
                );
                if blocked_tool_only_count >= 2 {
                    let reason = "MODEL_TOOL_PROTOCOL_VIOLATION: repeated prose output during tool-only phase".to_string();
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::Error,
                        serde_json::json!({
                            "error": reason,
                            "source": "tool_protocol_guard",
                            "failure_class": "E_PROTOCOL_TOOL_ONLY"
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
                messages.push(resp.assistant.clone());
                messages.push(Message {
                    role: Role::Developer,
                    content: Some(
                        "Tool-only phase active. Return exactly one valid tool call and no prose."
                            .to_string(),
                    ),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                });
                continue;
            }
            if !resp.tool_calls.is_empty() {
                tool_only_phase_active = false;
            }
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
                let (queue_delivered, queue_interrupted) = self.deliver_operator_queue_at_boundary(
                    &run_id,
                    step as u32,
                    DeliveryBoundary::TurnIdle,
                    &mut messages,
                );
                if queue_interrupted || queue_delivered {
                    continue 'agent_steps;
                }
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::RunEnd,
                    serde_json::json!({"exit_reason":"ok"}),
                );
                let final_output =
                    if !matches!(self.plan_tool_enforcement, PlanToolEnforcementMode::Off)
                        && !self.plan_step_constraints.is_empty()
                    {
                        last_user_output.unwrap_or_default()
                    } else {
                        assistant.content.unwrap_or_default()
                    };
                if let Some(reason) = implementation_integrity_violation(
                    user_prompt,
                    &final_output,
                    &observed_tool_calls,
                ) {
                    self.emit_event(
                        &run_id,
                        step as u32,
                        EventKind::Error,
                        serde_json::json!({
                            "error": reason,
                            "source": "implementation_integrity_guard"
                        }),
                    );
                    return AgentOutcome {
                        run_id,
                        started_at,
                        finished_at: crate::trust::now_rfc3339(),
                        exit_reason: AgentExitReason::PlannerError,
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
                return AgentOutcome {
                    run_id,
                    started_at,
                    finished_at: crate::trust::now_rfc3339(),
                    exit_reason: AgentExitReason::Ok,
                    final_output,
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
                self.record_detected_tool_call(&run_id, step as u32, tc, &mut observed_tool_calls);
                if tc.name.starts_with("mcp.") {
                    if matches!(self.mcp_pin_enforcement, McpPinEnforcementMode::Off) {
                        // Drift probing disabled by configuration.
                    } else if let (Some(registry), Some(expected_hash)) = (
                        self.mcp_registry.as_ref(),
                        expected_mcp_catalog_hash_hex.as_ref(),
                    ) {
                        let live_catalog = registry.live_tool_catalog_hash_hex().await;
                        let live_docs = if expected_mcp_docs_hash_hex.is_some() {
                            Some(registry.live_tool_docs_hash_hex().await)
                        } else {
                            None
                        };
                        match (live_catalog, live_docs) {
                            (Ok(actual_hash), Some(Ok(actual_docs_hash))) => {
                                let expected_docs_hash =
                                    expected_mcp_docs_hash_hex.as_deref().unwrap_or_default();
                                let catalog_drift = actual_hash != *expected_hash;
                                let docs_drift = actual_docs_hash != expected_docs_hash;
                                if !catalog_drift && !docs_drift {
                                    // No drift.
                                } else {
                                    let mut codes = Vec::new();
                                    if catalog_drift {
                                        codes.push("MCP_CATALOG_DRIFT");
                                    }
                                    if docs_drift {
                                        codes.push("MCP_DOCS_DRIFT");
                                    }
                                    let primary_code =
                                        codes.first().copied().unwrap_or("MCP_CATALOG_DRIFT");
                                    let reason = if catalog_drift && docs_drift {
                                        format!(
                                            "MCP drift detected: catalog hash changed (expected {}, got {}) and docs hash changed (expected {}, got {})",
                                            expected_hash, actual_hash, expected_docs_hash, actual_docs_hash
                                        )
                                    } else if catalog_drift {
                                        format!(
                                            "MCP_CATALOG_DRIFT detected: tool catalog hash changed during run (expected {}, got {})",
                                            expected_hash, actual_hash
                                        )
                                    } else {
                                        format!(
                                            "MCP_DOCS_DRIFT detected: tool docs hash changed during run (expected {}, got {})",
                                            expected_docs_hash, actual_docs_hash
                                        )
                                    };
                                    self.emit_event(
                                        &run_id,
                                        step as u32,
                                        EventKind::McpDrift,
                                        serde_json::json!({
                                            "tool_call_id": tc.id,
                                            "name": tc.name,
                                            "expected_hash_hex": expected_hash,
                                            "actual_hash_hex": actual_hash,
                                            "catalog_hash_expected": expected_hash,
                                            "catalog_hash_live": actual_hash,
                                            "catalog_drift": catalog_drift,
                                            "docs_hash_expected": expected_docs_hash,
                                            "docs_hash_live": actual_docs_hash,
                                            "docs_drift": docs_drift,
                                            "enforcement": format!("{:?}", self.mcp_pin_enforcement).to_lowercase(),
                                            "codes": codes,
                                            "primary_code": primary_code
                                        }),
                                    );
                                    if matches!(
                                        self.mcp_pin_enforcement,
                                        McpPinEnforcementMode::Hard
                                    ) {
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
                                            taint_overall: Some(
                                                taint_state.overall_str().to_string(),
                                            ),
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
                            (Ok(actual_hash), Some(Err(e))) => {
                                let reason = format!(
                                    "MCP_DRIFT verification failed: unable to probe live docs hash ({e})"
                                );
                                self.emit_event(
                                    &run_id,
                                    step as u32,
                                    EventKind::McpDrift,
                                    serde_json::json!({
                                        "tool_call_id": tc.id,
                                        "name": tc.name,
                                        "expected_hash_hex": expected_hash,
                                        "actual_hash_hex": actual_hash,
                                        "catalog_hash_expected": expected_hash,
                                        "catalog_hash_live": actual_hash,
                                        "catalog_drift": false,
                                        "docs_hash_expected": expected_mcp_docs_hash_hex,
                                        "docs_probe_error": e.to_string(),
                                        "docs_drift": false,
                                        "enforcement": format!("{:?}", self.mcp_pin_enforcement).to_lowercase(),
                                        "codes": ["MCP_DOCS_DRIFT_PROBE_FAILED"],
                                        "primary_code": "MCP_DOCS_DRIFT_PROBE_FAILED"
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
                            (Ok(actual_hash), None) => {
                                if actual_hash != *expected_hash {
                                    let reason = format!(
                                        "MCP_CATALOG_DRIFT detected: tool catalog hash changed during run (expected {}, got {})",
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
                                            "actual_hash_hex": actual_hash,
                                            "catalog_hash_expected": expected_hash,
                                            "catalog_hash_live": actual_hash,
                                            "catalog_drift": true,
                                            "docs_drift": false,
                                            "enforcement": format!("{:?}", self.mcp_pin_enforcement).to_lowercase(),
                                            "codes": ["MCP_CATALOG_DRIFT"],
                                            "primary_code": "MCP_CATALOG_DRIFT"
                                        }),
                                    );
                                    if matches!(
                                        self.mcp_pin_enforcement,
                                        McpPinEnforcementMode::Hard
                                    ) {
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
                                            taint_overall: Some(
                                                taint_state.overall_str().to_string(),
                                            ),
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
                            (Err(e), _) => {
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
                                        "catalog_hash_expected": expected_hash,
                                        "catalog_probe_error": e.to_string(),
                                        "enforcement": format!("{:?}", self.mcp_pin_enforcement).to_lowercase(),
                                        "codes": ["MCP_CATALOG_DRIFT_PROBE_FAILED"],
                                        "primary_code": "MCP_CATALOG_DRIFT_PROBE_FAILED",
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
                    malformed_tool_call_attempts = malformed_tool_call_attempts.saturating_add(1);
                    if malformed_tool_call_attempts >= 2 {
                        let reason = format!(
                            "MODEL_TOOL_PROTOCOL_VIOLATION: repeated malformed tool calls (tool='{}', error='{}')",
                            tc.name, err
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::Error,
                            serde_json::json!({
                                "error": reason,
                                "source": "tool_protocol_guard",
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "failure_class": "E_SCHEMA",
                                "attempt": malformed_tool_call_attempts
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
                        self.drain_external_operator_queue(&run_id, step as u32);
                        let (_, queue_interrupted) = self.deliver_operator_queue_at_boundary(
                            &run_id,
                            step as u32,
                            DeliveryBoundary::PostTool,
                            &mut messages,
                        );
                        if queue_interrupted {
                            continue 'agent_steps;
                        }
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
                            self.drain_external_operator_queue(&run_id, step as u32);
                            let (_, queue_interrupted) = self.deliver_operator_queue_at_boundary(
                                &run_id,
                                step as u32,
                                DeliveryBoundary::PostTool,
                                &mut messages,
                            );
                            if queue_interrupted {
                                continue 'agent_steps;
                            }
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
                                if is_apply_patch_invalid_format_error(tc, &current_content) {
                                    invalid_patch_format_attempts =
                                        invalid_patch_format_attempts.saturating_add(1);
                                    if invalid_patch_format_attempts >= 2 {
                                        let reason = "MODEL_TOOL_PROTOCOL_VIOLATION: repeated invalid patch format for apply_patch".to_string();
                                        self.emit_event(
                                            &run_id,
                                            step as u32,
                                            EventKind::Error,
                                            serde_json::json!({
                                                "error": reason,
                                                "source": "tool_protocol_guard",
                                                "tool_call_id": tc.id,
                                                "name": tc.name,
                                                "failure_class": "E_PROTOCOL_PATCH_FORMAT",
                                                "attempt": invalid_patch_format_attempts
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
                        self.drain_external_operator_queue(&run_id, step as u32);
                        let (_, queue_interrupted) = self.deliver_operator_queue_at_boundary(
                            &run_id,
                            step as u32,
                            DeliveryBoundary::PostTool,
                            &mut messages,
                        );
                        if queue_interrupted {
                            continue 'agent_steps;
                        }
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
                            self.drain_external_operator_queue(&run_id, step as u32);
                            let (_, queue_interrupted) = self.deliver_operator_queue_at_boundary(
                                &run_id,
                                step as u32,
                                DeliveryBoundary::PostTool,
                                &mut messages,
                            );
                            if queue_interrupted {
                                continue 'agent_steps;
                            }
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

#[cfg(test)]
#[path = "agent_tests.rs"]
mod agent_tests;
