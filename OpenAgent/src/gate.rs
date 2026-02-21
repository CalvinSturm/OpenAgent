use std::path::PathBuf;

use clap::ValueEnum;
use serde_json::Value;

use crate::trust::approvals::{ApprovalStatus, ApprovalsStore};
use crate::trust::audit::{AuditEvent, AuditLog, AuditResult};
use crate::trust::policy::{Policy, PolicyDecision};
use crate::types::ToolCall;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProviderKind {
    Lmstudio,
    Llamacpp,
    Ollama,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TrustMode {
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone)]
pub enum GateDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String, approval_id: String },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GateContext {
    pub workdir: PathBuf,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub enable_write_tools: bool,
    pub max_tool_output_bytes: usize,
    pub max_read_bytes: usize,
    pub provider: ProviderKind,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct GateEvent {
    pub run_id: String,
    pub step: u32,
    pub tool_call_id: String,
    pub tool: String,
    pub arguments: Value,
    pub decision: String,
    pub approval_id: Option<String>,
    pub result_ok: bool,
    pub result_content: String,
}

pub trait ToolGate: Send {
    fn decide(&mut self, ctx: &GateContext, call: &ToolCall) -> GateDecision;
    fn record(&mut self, event: GateEvent);
}

#[derive(Debug, Clone)]
pub struct NoGate;

impl NoGate {
    pub fn new() -> Self {
        Self
    }
}

impl ToolGate for NoGate {
    fn decide(&mut self, _ctx: &GateContext, _call: &ToolCall) -> GateDecision {
        GateDecision::Allow
    }

    fn record(&mut self, _event: GateEvent) {}
}

#[derive(Debug, Clone)]
pub struct TrustGate {
    pub policy: Policy,
    pub approvals: ApprovalsStore,
    pub audit: AuditLog,
    #[allow(dead_code)]
    pub trust_mode: TrustMode,
}

impl TrustGate {
    pub fn new(
        policy: Policy,
        approvals: ApprovalsStore,
        audit: AuditLog,
        trust_mode: TrustMode,
    ) -> Self {
        Self {
            policy,
            approvals,
            audit,
            trust_mode,
        }
    }
}

impl ToolGate for TrustGate {
    fn decide(&mut self, ctx: &GateContext, call: &ToolCall) -> GateDecision {
        if call.name == "shell" && !ctx.allow_shell {
            return GateDecision::Deny {
                reason: "shell requires --allow-shell".to_string(),
            };
        }
        if (call.name == "write_file" || call.name == "apply_patch") && !ctx.allow_write {
            return GateDecision::Deny {
                reason: "writes require --allow-write".to_string(),
            };
        }

        match self.policy.evaluate(&call.name, &call.arguments) {
            PolicyDecision::Allow => GateDecision::Allow,
            PolicyDecision::Deny => GateDecision::Deny {
                reason: format!("policy denied tool '{}'", call.name),
            },
            PolicyDecision::RequireApproval => {
                match self
                    .approvals
                    .find_matching_status(&call.name, &call.arguments)
                {
                    Ok(Some((_id, ApprovalStatus::Approved))) => GateDecision::Allow,
                    Ok(Some((id, ApprovalStatus::Denied))) => GateDecision::Deny {
                        reason: format!("approval denied: {id}"),
                    },
                    Ok(Some((id, ApprovalStatus::Pending))) => GateDecision::RequireApproval {
                        reason: format!("approval pending: {id}"),
                        approval_id: id,
                    },
                    Ok(None) => match self.approvals.create_pending(&call.name, &call.arguments) {
                        Ok(id) => GateDecision::RequireApproval {
                            reason: format!("approval required: {id}"),
                            approval_id: id,
                        },
                        Err(e) => GateDecision::Deny {
                            reason: format!("failed to create approval request: {e}"),
                        },
                    },
                    Err(e) => GateDecision::Deny {
                        reason: format!("failed to read approvals store: {e}"),
                    },
                }
            }
        }
    }

    fn record(&mut self, event: GateEvent) {
        let audit = AuditEvent {
            ts: crate::trust::now_rfc3339(),
            run_id: event.run_id,
            step: event.step,
            tool_call_id: event.tool_call_id,
            tool: event.tool,
            arguments: event.arguments,
            decision: event.decision,
            approval_id: event.approval_id,
            result: AuditResult {
                ok: event.result_ok,
                content: event.result_content,
            },
        };
        if let Err(e) = self.audit.append(&audit) {
            eprintln!("WARN: failed to append audit log: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::{GateContext, GateDecision, NoGate, ProviderKind, ToolGate};
    use crate::types::ToolCall;

    #[test]
    fn nogate_always_allows() {
        let mut gate = NoGate::new();
        let ctx = GateContext {
            workdir: PathBuf::from("."),
            allow_shell: false,
            allow_write: false,
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "test-model".to_string(),
        };
        let call = ToolCall {
            id: "tc_0".to_string(),
            name: "read_file".to_string(),
            arguments: json!({"path":"Cargo.toml"}),
        };
        let decision = gate.decide(&ctx, &call);
        assert!(matches!(decision, GateDecision::Allow));
    }
}
