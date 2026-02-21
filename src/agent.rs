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
use crate::tools::{
    envelope_to_message, execute_tool, to_tool_result_envelope, tool_side_effects,
    validate_builtin_tool_args, ToolResultMeta, ToolRuntime,
};
use crate::trust::policy::McpAllowSummary;
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
            AgentExitReason::Cancelled => "cancelled",
        }
    }
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
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolDecisionRecord {
    pub step: u32,
    pub tool_call_id: String,
    pub tool: String,
    pub decision: String,
    pub reason: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyLoadedInfo {
    pub version: u32,
    pub rules_count: usize,
    pub includes_count: usize,
    pub includes_resolved: Vec<String>,
    pub mcp_allowlist: Option<McpAllowSummary>,
}

pub struct Agent<P: ModelProvider> {
    pub provider: P,
    pub model: String,
    pub tools: Vec<ToolDef>,
    pub max_steps: usize,
    pub tool_rt: ToolRuntime,
    pub gate: Box<dyn ToolGate>,
    pub gate_ctx: GateContext,
    pub mcp_registry: Option<McpRegistry>,
    pub stream: bool,
    pub event_sink: Option<Box<dyn EventSink>>,
    pub compaction_settings: CompactionSettings,
    pub hooks: HookManager,
    pub policy_loaded: Option<PolicyLoadedInfo>,
    pub run_id_override: Option<String>,
    pub omit_tools_field_when_empty: bool,
}

impl<P: ModelProvider> Agent<P> {
    fn emit_event(&mut self, run_id: &str, step: u32, kind: EventKind, data: serde_json::Value) {
        if let Some(sink) = &mut self.event_sink {
            if let Err(e) = sink.emit(Event::new(run_id.to_string(), step, kind, data)) {
                eprintln!("WARN: failed to emit event: {e}");
            }
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
        for step in 0..self.max_steps {
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
            messages.push(resp.assistant.clone());

            if resp.tool_calls.is_empty() {
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
                    final_output: resp.assistant.content.unwrap_or_default(),
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
                match self.gate.decide(&self.gate_ctx, tc) {
                    GateDecision::Allow {
                        approval_id,
                        approval_key,
                        reason,
                        source,
                    } => {
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
                                "side_effects": tool_side_effects(&tc.name),
                                "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                            }),
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecStart,
                            serde_json::json!({"tool_call_id": tc.id, "name": tc.name, "side_effects": tool_side_effects(&tc.name)}),
                        );
                        let mut tool_msg = if let Some(err) = &invalid_args_error {
                            make_invalid_args_tool_message(tc, err)
                        } else if tc.name.starts_with("mcp.") {
                            match &self.mcp_registry {
                                Some(reg) => match reg
                                    .call_namespaced_tool(tc, self.tool_rt.tool_args_strict)
                                    .await
                                {
                                    Ok(msg) => msg,
                                    Err(e) => envelope_to_message(to_tool_result_envelope(
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
                                        },
                                    )),
                                },
                                None => envelope_to_message(to_tool_result_envelope(
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
                                    },
                                )),
                            }
                        } else {
                            execute_tool(&self.tool_rt, tc).await
                        };
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
                                    };
                                }
                            }
                        }

                        let content = tool_msg.content.clone().unwrap_or_default();
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
                        });
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecEnd,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "ok": !tool_result_has_error(&tool_msg.content.clone().unwrap_or_default()),
                                "truncated": final_truncated
                            }),
                        );
                        messages.push(tool_msg);
                    }
                    GateDecision::Deny {
                        reason,
                        approval_key,
                        source,
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
                        };
                    }
                    GateDecision::RequireApproval {
                        reason,
                        approval_id,
                        approval_key,
                        source,
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
                                    "side_effects": tool_side_effects(&tc.name),
                                    "tool_args_strict": if self.tool_rt.tool_args_strict.is_enabled() { "on" } else { "off" }
                                }),
                            );
                            self.emit_event(
                                &run_id,
                                step as u32,
                                EventKind::ToolExecStart,
                                serde_json::json!({"tool_call_id": tc.id, "name": tc.name, "side_effects": tool_side_effects(&tc.name)}),
                            );
                            let tool_msg = make_invalid_args_tool_message(tc, err);
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
                            final_output: format!(
                                "Approval required: {} ({}){}. Run: openagent approve {} (or deny) then re-run.",
                                approval_id,
                                reason,
                                source
                                    .as_ref()
                                    .map(|s| format!(" [source: {}]", s))
                                    .unwrap_or_default(),
                                approval_id
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
        }
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

fn make_invalid_args_tool_message(tc: &ToolCall, err: &str) -> Message {
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
        },
    ))
}

fn provider_name(provider: crate::gate::ProviderKind) -> &'static str {
    match provider {
        crate::gate::ProviderKind::Lmstudio => "lmstudio",
        crate::gate::ProviderKind::Llamacpp => "llamacpp",
        crate::gate::ProviderKind::Ollama => "ollama",
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::json;

    use super::Agent;
    use crate::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
    use crate::gate::{ApprovalMode, AutoApproveScope, GateContext, NoGate, ProviderKind};
    use crate::hooks::config::HooksMode;
    use crate::hooks::runner::{HookManager, HookRuntimeConfig};
    use crate::providers::{ModelProvider, StreamDelta};
    use crate::tools::{ToolArgsStrict, ToolRuntime};
    use crate::types::{GenerateRequest, GenerateResponse, Message, Role};

    struct MockProvider {
        generate_calls: Arc<AtomicUsize>,
        stream_calls: Arc<AtomicUsize>,
        seen_messages: Arc<Mutex<Vec<Message>>>,
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
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
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
            run_id_override: None,
            omit_tools_field_when_empty: false,
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
                allow_write: false,
                max_tool_output_bytes: 200_000,
                max_read_bytes: 200_000,
                unsafe_bypass_allow_flags: false,
                tool_args_strict: ToolArgsStrict::On,
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
            run_id_override: None,
            omit_tools_field_when_empty: false,
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
}
