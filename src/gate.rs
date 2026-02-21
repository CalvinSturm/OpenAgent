use std::path::PathBuf;

use clap::ValueEnum;
use hex::encode as hex_encode;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::trust::approvals::{
    canonical_json, ApprovalDecisionMatch, ApprovalStatus, ApprovalsStore,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ApprovalMode {
    Interrupt,
    Auto,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AutoApproveScope {
    Run,
    Session,
}

#[derive(Debug, Clone)]
pub enum GateDecision {
    Allow {
        approval_id: Option<String>,
        approval_key: Option<String>,
    },
    Deny {
        reason: String,
        approval_key: Option<String>,
    },
    RequireApproval {
        reason: String,
        approval_id: String,
        approval_key: Option<String>,
    },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GateContext {
    pub workdir: PathBuf,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub approval_mode: ApprovalMode,
    pub auto_approve_scope: AutoApproveScope,
    pub unsafe_mode: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub run_id: Option<String>,
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
    pub approval_key: Option<String>,
    pub approval_mode: Option<String>,
    pub auto_approve_scope: Option<String>,
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

impl Default for NoGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolGate for NoGate {
    fn decide(&mut self, _ctx: &GateContext, _call: &ToolCall) -> GateDecision {
        GateDecision::Allow {
            approval_id: None,
            approval_key: None,
        }
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
    pub policy_hash_hex: String,
}

impl TrustGate {
    pub fn new(
        policy: Policy,
        approvals: ApprovalsStore,
        audit: AuditLog,
        trust_mode: TrustMode,
        policy_hash_hex: String,
    ) -> Self {
        Self {
            policy,
            approvals,
            audit,
            trust_mode,
            policy_hash_hex,
        }
    }
}

impl ToolGate for TrustGate {
    fn decide(&mut self, ctx: &GateContext, call: &ToolCall) -> GateDecision {
        let approval_key = compute_approval_key(
            &call.name,
            &call.arguments,
            &ctx.workdir,
            &self.policy_hash_hex,
        );

        if call.name == "shell" && !ctx.allow_shell && !ctx.unsafe_bypass_allow_flags {
            return GateDecision::Deny {
                reason: "shell requires --allow-shell".to_string(),
                approval_key: Some(approval_key),
            };
        }
        if (call.name == "write_file" || call.name == "apply_patch")
            && !ctx.allow_write
            && !ctx.unsafe_bypass_allow_flags
        {
            return GateDecision::Deny {
                reason: "writes require --allow-write".to_string(),
                approval_key: Some(approval_key),
            };
        }

        match self.policy.evaluate(&call.name, &call.arguments) {
            PolicyDecision::Allow => GateDecision::Allow {
                approval_id: None,
                approval_key: Some(approval_key),
            },
            PolicyDecision::Deny => GateDecision::Deny {
                reason: format!("policy denied tool '{}'", call.name),
                approval_key: Some(approval_key),
            },
            PolicyDecision::RequireApproval => {
                if matches!(ctx.approval_mode, ApprovalMode::Auto) {
                    return match ctx.auto_approve_scope {
                        AutoApproveScope::Run => GateDecision::Allow {
                            approval_id: Some(format!(
                                "auto:{}:{}",
                                ctx.run_id.clone().unwrap_or_else(|| "run".to_string()),
                                call.id
                            )),
                            approval_key: Some(approval_key),
                        },
                        AutoApproveScope::Session => {
                            match self.approvals.ensure_approved_for_key(
                                &call.name,
                                &call.arguments,
                                &approval_key,
                            ) {
                                Ok(id) => GateDecision::Allow {
                                    approval_id: Some(id),
                                    approval_key: Some(approval_key),
                                },
                                Err(e) => GateDecision::Deny {
                                    reason: format!("failed to auto-approve: {e}"),
                                    approval_key: Some(approval_key),
                                },
                            }
                        }
                    };
                }

                match self.approvals.consume_matching_approved(&approval_key) {
                    Ok(Some(usage)) => GateDecision::Allow {
                        approval_id: Some(usage.id),
                        approval_key: Some(usage.approval_key),
                    },
                    Ok(None) => match self.approvals.find_matching_decision(&approval_key) {
                        Ok(Some(ApprovalDecisionMatch {
                            id,
                            status: ApprovalStatus::Denied,
                        })) => GateDecision::Deny {
                            reason: format!("approval denied: {id}"),
                            approval_key: Some(approval_key),
                        },
                        Ok(Some(ApprovalDecisionMatch {
                            id,
                            status: ApprovalStatus::Pending,
                        })) => GateDecision::RequireApproval {
                            reason: format!("approval pending: {id}"),
                            approval_id: id,
                            approval_key: Some(approval_key),
                        },
                        Ok(None) => {
                            match self.approvals.create_pending(
                                &call.name,
                                &call.arguments,
                                Some(approval_key.clone()),
                            ) {
                                Ok(id) => GateDecision::RequireApproval {
                                    reason: if matches!(ctx.approval_mode, ApprovalMode::Fail) {
                                        format!("approval required (fail mode): {id}")
                                    } else {
                                        format!("approval required: {id}")
                                    },
                                    approval_id: id,
                                    approval_key: Some(approval_key),
                                },
                                Err(e) => GateDecision::Deny {
                                    reason: format!("failed to create approval request: {e}"),
                                    approval_key: Some(approval_key),
                                },
                            }
                        }
                        Err(e) => GateDecision::Deny {
                            reason: format!("failed to read approvals store: {e}"),
                            approval_key: Some(approval_key),
                        },
                    },
                    Err(e) => GateDecision::Deny {
                        reason: format!("failed to read approvals store: {e}"),
                        approval_key: Some(approval_key),
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
            approval_key: event.approval_key,
            approval_mode: event.approval_mode,
            auto_approve_scope: event.auto_approve_scope,
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

pub fn compute_policy_hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize())
}

pub fn compute_approval_key(
    tool_name: &str,
    arguments: &Value,
    workdir: &std::path::Path,
    policy_hash_hex: &str,
) -> String {
    let canonical_args = canonical_json(arguments).unwrap_or_else(|_| "null".to_string());
    let normalized_workdir = normalize_workdir(workdir);
    let payload = format!(
        "v1\n{}\n{}\n{}\n{}\n",
        tool_name, canonical_args, normalized_workdir, policy_hash_hex
    );
    compute_policy_hash_hex(payload.as_bytes())
}

fn normalize_workdir(path: &std::path::Path) -> String {
    match std::fs::canonicalize(path) {
        Ok(p) => p.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        compute_approval_key, compute_policy_hash_hex, ApprovalMode, AutoApproveScope, GateContext,
        GateDecision, NoGate, ProviderKind, ToolGate, TrustGate, TrustMode,
    };
    use crate::trust::approvals::ApprovalsStore;
    use crate::trust::audit::AuditLog;
    use crate::trust::policy::Policy;
    use crate::types::ToolCall;

    #[test]
    fn nogate_always_allows() {
        let mut gate = NoGate::new();
        let ctx = GateContext {
            workdir: PathBuf::from("."),
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
            provider: ProviderKind::Lmstudio,
            model: "test-model".to_string(),
        };
        let call = ToolCall {
            id: "tc_0".to_string(),
            name: "read_file".to_string(),
            arguments: json!({"path":"Cargo.toml"}),
        };
        let decision = gate.decide(&ctx, &call);
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[test]
    fn approval_key_matching_allows_when_approved() {
        let tmp = tempdir().expect("tempdir");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::safe_default();
        let policy_hash = compute_policy_hash_hex(b"default");
        let ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: true,
            allow_write: false,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r1".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key = compute_approval_key(&call.name, &call.arguments, &ctx.workdir, &policy_hash);
        let id = store
            .create_pending(&call.name, &call.arguments, Some(key.clone()))
            .expect("create pending");
        store.approve(&id, None, None).expect("approve");
        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        let decision = gate.decide(&ctx, &call);
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[test]
    fn approval_ttl_expired_requires_new() {
        let tmp = tempdir().expect("tempdir");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::safe_default();
        let policy_hash = compute_policy_hash_hex(b"default");
        let ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: true,
            allow_write: false,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r1".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key = compute_approval_key(&call.name, &call.arguments, &ctx.workdir, &policy_hash);
        let id = store
            .create_pending(&call.name, &call.arguments, Some(key))
            .expect("create pending");
        store.approve(&id, Some(0), None).expect("approve expired");
        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        let decision = gate.decide(&ctx, &call);
        assert!(matches!(decision, GateDecision::RequireApproval { .. }));
    }

    #[test]
    fn approval_max_uses_exhaustion() {
        let tmp = tempdir().expect("tempdir");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::safe_default();
        let policy_hash = compute_policy_hash_hex(b"default");
        let ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: true,
            allow_write: false,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r1".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key = compute_approval_key(&call.name, &call.arguments, &ctx.workdir, &policy_hash);
        let id = store
            .create_pending(&call.name, &call.arguments, Some(key))
            .expect("create pending");
        store.approve(&id, None, Some(1)).expect("approve");
        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::Allow { .. }
        ));
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::RequireApproval { .. }
        ));
    }

    #[test]
    fn approval_mode_fail_requires_approval() {
        let tmp = tempdir().expect("tempdir");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::safe_default();
        let policy_hash = compute_policy_hash_hex(b"default");
        let ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: true,
            allow_write: false,
            approval_mode: ApprovalMode::Fail,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r1".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::RequireApproval { .. }
        ));
    }

    #[test]
    fn approval_mode_auto_run_allows() {
        let tmp = tempdir().expect("tempdir");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::safe_default();
        let policy_hash = compute_policy_hash_hex(b"default");
        let ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: true,
            allow_write: false,
            approval_mode: ApprovalMode::Auto,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r99".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
        };
        let call = ToolCall {
            id: "tc_abc".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        match gate.decide(&ctx, &call) {
            GateDecision::Allow { approval_id, .. } => {
                let id = approval_id.unwrap_or_default();
                assert!(id.contains("auto:r99:tc_abc"));
            }
            _ => panic!("expected allow"),
        }
    }
}
