use uuid::Uuid;

use crate::gate::{GateContext, GateDecision, GateEvent, ToolGate};
use crate::providers::ModelProvider;
use crate::tools::{execute_tool, ToolRuntime};
use crate::types::{GenerateRequest, Message, Role, ToolDef};

pub struct Agent<P: ModelProvider> {
    pub provider: P,
    pub model: String,
    pub tools: Vec<ToolDef>,
    pub max_steps: usize,
    pub tool_rt: ToolRuntime,
    pub gate: Box<dyn ToolGate>,
    pub gate_ctx: GateContext,
}

impl<P: ModelProvider> Agent<P> {
    pub async fn run(&mut self, user_prompt: &str) -> anyhow::Result<String> {
        let run_id = Uuid::new_v4().to_string();
        let mut messages = vec![
            Message {
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
            },
            Message {
                role: Role::User,
                content: Some(user_prompt.to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
        ];

        for step in 0..self.max_steps {
            let mut tools_sorted = self.tools.clone();
            tools_sorted.sort_by(|a, b| a.name.cmp(&b.name));

            let req = GenerateRequest {
                model: self.model.clone(),
                messages: messages.clone(),
                tools: tools_sorted,
            };

            let resp = self.provider.generate(req).await?;
            messages.push(resp.assistant.clone());

            if resp.tool_calls.is_empty() {
                return Ok(resp.assistant.content.unwrap_or_default());
            }

            for tc in &resp.tool_calls {
                match self.gate.decide(&self.gate_ctx, tc) {
                    GateDecision::Allow => {
                        let tool_msg = execute_tool(&self.tool_rt, tc).await;
                        let content = tool_msg.content.clone().unwrap_or_default();
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "allow".to_string(),
                            approval_id: None,
                            result_ok: !tool_result_has_error(&content),
                            result_content: content,
                        });
                        messages.push(tool_msg);
                    }
                    GateDecision::Deny { reason } => {
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "deny".to_string(),
                            approval_id: None,
                            result_ok: false,
                            result_content: reason.clone(),
                        });
                        return Ok(format!("Tool call '{}' denied: {}", tc.name, reason));
                    }
                    GateDecision::RequireApproval {
                        reason,
                        approval_id,
                    } => {
                        self.gate.record(GateEvent {
                            run_id: run_id.clone(),
                            step: step as u32,
                            tool_call_id: tc.id.clone(),
                            tool: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                            decision: "require_approval".to_string(),
                            approval_id: Some(approval_id.clone()),
                            result_ok: false,
                            result_content: reason,
                        });
                        return Ok(format!(
                            "Approval required: {}. Run: agentloop approve {} (or deny) then re-run.",
                            approval_id, approval_id
                        ));
                    }
                }
            }
        }

        Ok("Max steps reached before the model produced a final answer.".to_string())
    }
}

fn tool_result_has_error(content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => v.get("error").is_some(),
        Err(_) => false,
    }
}
