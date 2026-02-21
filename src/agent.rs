use uuid::Uuid;

use crate::events::{Event, EventKind, EventSink};
use crate::gate::{ApprovalMode, AutoApproveScope, GateContext, GateDecision, GateEvent, ToolGate};
use crate::mcp::registry::McpRegistry;
use crate::providers::{ModelProvider, StreamDelta};
use crate::tools::{execute_tool, ToolRuntime};
use crate::types::{GenerateRequest, Message, Role, ToolCall, ToolDef};

#[derive(Debug, Clone, Copy)]
pub enum AgentExitReason {
    Ok,
    ProviderError,
    Denied,
    ApprovalRequired,
    MaxSteps,
    Cancelled,
}

impl AgentExitReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentExitReason::Ok => "ok",
            AgentExitReason::ProviderError => "provider_error",
            AgentExitReason::Denied => "denied",
            AgentExitReason::ApprovalRequired => "approval_required",
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
}

impl<P: ModelProvider> Agent<P> {
    fn emit_event(&mut self, run_id: &str, step: u32, kind: EventKind, data: serde_json::Value) {
        if let Some(sink) = &mut self.event_sink {
            if let Err(e) = sink.emit(Event::new(run_id.to_string(), step, kind, data)) {
                eprintln!("WARN: failed to emit event: {e}");
            }
        }
    }

    pub async fn run(&mut self, user_prompt: &str, session_messages: Vec<Message>) -> AgentOutcome {
        let run_id = Uuid::new_v4().to_string();
        self.gate_ctx.run_id = Some(run_id.clone());
        let started_at = crate::trust::now_rfc3339();
        self.emit_event(
            &run_id,
            0,
            EventKind::RunStart,
            serde_json::json!({"model": self.model}),
        );
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
        messages.push(Message {
            role: Role::User,
            content: Some(user_prompt.to_string()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        });

        let mut observed_tool_calls = Vec::new();
        for step in 0..self.max_steps {
            let mut tools_sorted = self.tools.clone();
            tools_sorted.sort_by(|a, b| a.name.cmp(&b.name));

            let req = GenerateRequest {
                model: self.model.clone(),
                messages: messages.clone(),
                tools: tools_sorted,
            };

            self.emit_event(
                &run_id,
                step as u32,
                EventKind::ModelRequestStart,
                serde_json::json!({"message_count": req.messages.len(), "tool_count": req.tools.len()}),
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
                    };
                }
            };
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
                };
            }

            for tc in &resp.tool_calls {
                observed_tool_calls.push(tc.clone());
                self.emit_event(
                    &run_id,
                    step as u32,
                    EventKind::ToolCallDetected,
                    serde_json::json!({"tool_call_id": tc.id, "name": tc.name, "arguments": tc.arguments}),
                );
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
                                "approval_key": approval_key.clone()
                            }),
                        );
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecStart,
                            serde_json::json!({"tool_call_id": tc.id, "name": tc.name}),
                        );
                        let tool_msg = if tc.name.starts_with("mcp.") {
                            match &self.mcp_registry {
                                Some(reg) => match reg.call_namespaced_tool(tc).await {
                                    Ok(msg) => msg,
                                    Err(e) => Message {
                                        role: Role::Tool,
                                        content: Some(
                                            serde_json::json!({"error": format!("mcp call failed: {}", e)})
                                                .to_string(),
                                        ),
                                        tool_call_id: Some(tc.id.clone()),
                                        tool_name: Some(tc.name.clone()),
                                        tool_calls: None,
                                    },
                                },
                                None => Message {
                                    role: Role::Tool,
                                    content: Some(
                                        serde_json::json!({"error":"mcp registry not available"}).to_string(),
                                    ),
                                    tool_call_id: Some(tc.id.clone()),
                                    tool_name: Some(tc.name.clone()),
                                    tool_calls: None,
                                },
                            }
                        } else {
                            execute_tool(&self.tool_rt, tc).await
                        };
                        let content = tool_msg.content.clone().unwrap_or_default();
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "allow".to_string(),
                            approval_id,
                            approval_key,
                            approval_mode: approval_mode_meta.clone(),
                            auto_approve_scope: auto_scope_meta.clone(),
                            result_ok: !tool_result_has_error(&content),
                            result_content: content,
                        });
                        self.emit_event(
                            &run_id,
                            step as u32,
                            EventKind::ToolExecEnd,
                            serde_json::json!({
                                "tool_call_id": tc.id,
                                "name": tc.name,
                                "ok": !tool_result_has_error(&tool_msg.content.clone().unwrap_or_default())
                            }),
                        );
                        messages.push(tool_msg);
                    }
                    GateDecision::Deny {
                        reason,
                        approval_key,
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
                                "approval_key": approval_key.clone()
                            }),
                        );
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "deny".to_string(),
                            approval_id: None,
                            approval_key,
                            approval_mode: approval_mode_meta.clone(),
                            auto_approve_scope: auto_scope_meta.clone(),
                            result_ok: false,
                            result_content: reason.clone(),
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
                            final_output: format!("Tool call '{}' denied: {}", tc.name, reason),
                            error: None,
                            messages,
                            tool_calls: observed_tool_calls,
                        };
                    }
                    GateDecision::RequireApproval {
                        reason,
                        approval_id,
                        approval_key,
                    } => {
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
                                "approval_key": approval_key.clone()
                            }),
                        );
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "require_approval".to_string(),
                            approval_id: Some(approval_id.clone()),
                            approval_key,
                            approval_mode: approval_mode_meta.clone(),
                            auto_approve_scope: auto_scope_meta.clone(),
                            result_ok: false,
                            result_content: reason,
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
                                "Approval required: {}. Run: openagent approve {} (or deny) then re-run.",
                                approval_id, approval_id
                            ),
                            error: None,
                            messages,
                            tool_calls: observed_tool_calls,
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
        AgentOutcome {
            run_id,
            started_at,
            finished_at: crate::trust::now_rfc3339(),
            exit_reason: AgentExitReason::MaxSteps,
            final_output: "Max steps reached before the model produced a final answer.".to_string(),
            error: None,
            messages,
            tool_calls: observed_tool_calls,
        }
    }
}
fn tool_result_has_error(content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => v.get("error").is_some(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;

    use super::Agent;
    use crate::gate::{ApprovalMode, AutoApproveScope, GateContext, NoGate, ProviderKind};
    use crate::providers::{ModelProvider, StreamDelta};
    use crate::tools::ToolRuntime;
    use crate::types::{GenerateRequest, GenerateResponse, Message, Role};

    struct MockProvider {
        generate_calls: Arc<AtomicUsize>,
        stream_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ModelProvider for MockProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
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
        };
        let out = agent.run("hi", vec![]).await;
        assert_eq!(out.final_output, "done");
        assert_eq!(generate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(stream_calls.load(Ordering::SeqCst), 0);
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
