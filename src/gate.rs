use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::ValueEnum;
use hex::encode as hex_encode;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::target::ExecTargetKind;
use crate::trust::approvals::{
    canonical_json, ApprovalDecisionMatch, ApprovalProvenance, ApprovalStatus, ApprovalsStore,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ApprovalKeyVersion {
    V1,
    V2,
}

impl ApprovalKeyVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

#[derive(Debug, Clone)]
pub enum GateDecision {
    Allow {
        approval_id: Option<String>,
        approval_key: Option<String>,
        reason: Option<String>,
        source: Option<String>,
    },
    Deny {
        reason: String,
        approval_key: Option<String>,
        source: Option<String>,
    },
    RequireApproval {
        reason: String,
        approval_id: String,
        approval_key: Option<String>,
        source: Option<String>,
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
    pub exec_target: ExecTargetKind,
    pub approval_key_version: ApprovalKeyVersion,
    pub tool_schema_hashes: BTreeMap<String, String>,
    pub hooks_config_hash_hex: Option<String>,
    pub planner_hash_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GateEvent {
    pub run_id: String,
    pub step: u32,
    pub tool_call_id: String,
    pub tool: String,
    pub arguments: Value,
    pub decision: String,
    pub decision_reason: Option<String>,
    pub decision_source: Option<String>,
    pub approval_id: Option<String>,
    pub approval_key: Option<String>,
    pub approval_mode: Option<String>,
    pub auto_approve_scope: Option<String>,
    pub approval_key_version: Option<String>,
    pub tool_schema_hash_hex: Option<String>,
    pub hooks_config_hash_hex: Option<String>,
    pub planner_hash_hex: Option<String>,
    pub exec_target: Option<String>,
    pub result_ok: bool,
    pub result_content: String,
    pub result_input_digest: Option<String>,
    pub result_output_digest: Option<String>,
    pub result_input_len: Option<usize>,
    pub result_output_len: Option<usize>,
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
            reason: None,
            source: None,
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
        let tool_schema_hash_hex = ctx.tool_schema_hashes.get(&call.name).cloned();
        let approval_key = compute_approval_key_with_version(
            ctx.approval_key_version,
            &call.name,
            &call.arguments,
            &ctx.workdir,
            &self.policy_hash_hex,
            tool_schema_hash_hex.as_deref(),
            ctx.hooks_config_hash_hex.as_deref(),
            ctx.exec_target,
            ctx.planner_hash_hex.as_deref(),
        );
        let approval_provenance = ApprovalProvenance {
            approval_key_version: ctx.approval_key_version.as_str().to_string(),
            tool_schema_hash_hex,
            hooks_config_hash_hex: ctx.hooks_config_hash_hex.clone(),
            exec_target: Some(
                match ctx.exec_target {
                    ExecTargetKind::Host => "host",
                    ExecTargetKind::Docker => "docker",
                }
                .to_string(),
            ),
            planner_hash_hex: ctx.planner_hash_hex.clone(),
        };
        let args_with_target = with_exec_target_arg(&call.arguments, ctx.exec_target);

        if call.name == "shell" && !ctx.allow_shell && !ctx.unsafe_bypass_allow_flags {
            return GateDecision::Deny {
                reason: "shell requires --allow-shell".to_string(),
                approval_key: Some(approval_key),
                source: Some("hard_gate".to_string()),
            };
        }
        if (call.name == "write_file" || call.name == "apply_patch")
            && !ctx.allow_write
            && !ctx.unsafe_bypass_allow_flags
        {
            return GateDecision::Deny {
                reason: "writes require --allow-write".to_string(),
                approval_key: Some(approval_key),
                source: Some("hard_gate".to_string()),
            };
        }

        if let Err(reason) = self.policy.mcp_tool_allowed(&call.name) {
            return GateDecision::Deny {
                reason,
                approval_key: Some(approval_key),
                source: Some("mcp_allowlist".to_string()),
            };
        }

        let eval = self.policy.evaluate(&call.name, &args_with_target);
        match eval.decision {
            PolicyDecision::Allow => GateDecision::Allow {
                approval_id: None,
                approval_key: Some(approval_key),
                reason: eval.reason,
                source: eval.source,
            },
            PolicyDecision::Deny => GateDecision::Deny {
                reason: eval
                    .reason
                    .unwrap_or_else(|| format!("policy denied tool '{}'", call.name)),
                approval_key: Some(approval_key),
                source: eval.source,
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
                            reason: eval.reason.clone(),
                            source: eval.source.clone(),
                        },
                        AutoApproveScope::Session => {
                            match self.approvals.ensure_approved_for_key(
                                &call.name,
                                &call.arguments,
                                &approval_key,
                                Some(approval_provenance.clone()),
                            ) {
                                Ok(id) => GateDecision::Allow {
                                    approval_id: Some(id),
                                    approval_key: Some(approval_key),
                                    reason: eval.reason.clone(),
                                    source: eval.source.clone(),
                                },
                                Err(e) => GateDecision::Deny {
                                    reason: format!("failed to auto-approve: {e}"),
                                    approval_key: Some(approval_key),
                                    source: eval.source.clone(),
                                },
                            }
                        }
                    };
                }

                match self
                    .approvals
                    .consume_matching_approved(&approval_key, ctx.approval_key_version.as_str())
                {
                    Ok(Some(usage)) => GateDecision::Allow {
                        approval_id: Some(usage.id),
                        approval_key: Some(usage.approval_key),
                        reason: eval.reason.clone(),
                        source: eval.source.clone(),
                    },
                    Ok(None) => match self
                        .approvals
                        .find_matching_decision(&approval_key, ctx.approval_key_version.as_str())
                    {
                        Ok(Some(ApprovalDecisionMatch {
                            id,
                            status: ApprovalStatus::Denied,
                        })) => GateDecision::Deny {
                            reason: format!("approval denied: {id}"),
                            approval_key: Some(approval_key),
                            source: eval.source.clone(),
                        },
                        Ok(Some(ApprovalDecisionMatch {
                            id,
                            status: ApprovalStatus::Pending,
                        })) => GateDecision::RequireApproval {
                            reason: eval
                                .reason
                                .clone()
                                .unwrap_or_else(|| format!("approval pending: {id}")),
                            approval_id: id,
                            approval_key: Some(approval_key),
                            source: eval.source.clone(),
                        },
                        Ok(None) => {
                            match self.approvals.create_pending(
                                &call.name,
                                &call.arguments,
                                Some(approval_key.clone()),
                                Some(approval_provenance.clone()),
                            ) {
                                Ok(id) => GateDecision::RequireApproval {
                                    reason: eval.reason.clone().unwrap_or_else(|| {
                                        if matches!(ctx.approval_mode, ApprovalMode::Fail) {
                                            format!("approval required (fail mode): {id}")
                                        } else {
                                            format!("approval required: {id}")
                                        }
                                    }),
                                    approval_id: id,
                                    approval_key: Some(approval_key),
                                    source: eval.source.clone(),
                                },
                                Err(e) => GateDecision::Deny {
                                    reason: format!("failed to create approval request: {e}"),
                                    approval_key: Some(approval_key),
                                    source: eval.source.clone(),
                                },
                            }
                        }
                        Err(e) => GateDecision::Deny {
                            reason: format!("failed to read approvals store: {e}"),
                            approval_key: Some(approval_key),
                            source: eval.source.clone(),
                        },
                    },
                    Err(e) => GateDecision::Deny {
                        reason: format!("failed to read approvals store: {e}"),
                        approval_key: Some(approval_key),
                        source: eval.source,
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
            decision_reason: event.decision_reason,
            decision_source: event.decision_source,
            approval_id: event.approval_id,
            approval_key: event.approval_key,
            approval_mode: event.approval_mode,
            auto_approve_scope: event.auto_approve_scope,
            approval_key_version: event.approval_key_version,
            tool_schema_hash_hex: event.tool_schema_hash_hex,
            hooks_config_hash_hex: event.hooks_config_hash_hex,
            planner_hash_hex: event.planner_hash_hex,
            exec_target: event.exec_target,
            result: AuditResult {
                ok: event.result_ok,
                content: event.result_content,
                input_digest: event.result_input_digest,
                output_digest: event.result_output_digest,
                input_len: event.result_input_len,
                output_len: event.result_output_len,
            },
        };
        if let Err(e) = self.audit.append(&audit) {
            eprintln!("WARN: failed to append audit log: {e}");
        }
    }
}

fn with_exec_target_arg(args: &Value, exec_target: ExecTargetKind) -> Value {
    let mut out = match args {
        Value::Object(map) => Value::Object(map.clone()),
        _ => Value::Object(serde_json::Map::new()),
    };
    if let Value::Object(ref mut map) = out {
        map.insert(
            "__exec_target".to_string(),
            Value::String(
                match exec_target {
                    ExecTargetKind::Host => "host",
                    ExecTargetKind::Docker => "docker",
                }
                .to_string(),
            ),
        );
    }
    out
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

#[allow(clippy::too_many_arguments)]
pub fn compute_approval_key_with_version(
    version: ApprovalKeyVersion,
    tool_name: &str,
    arguments: &Value,
    workdir: &std::path::Path,
    policy_hash_hex: &str,
    tool_schema_hash_hex: Option<&str>,
    hooks_config_hash_hex: Option<&str>,
    exec_target: ExecTargetKind,
    planner_hash_hex: Option<&str>,
) -> String {
    match version {
        ApprovalKeyVersion::V1 => {
            compute_approval_key(tool_name, arguments, workdir, policy_hash_hex)
        }
        ApprovalKeyVersion::V2 => {
            let canonical_args = canonical_json(arguments).unwrap_or_else(|_| "null".to_string());
            let normalized_workdir = normalize_workdir(workdir);
            let payload = format!(
                "v2|tool={}|args={}|workdir={}|policy={}|schema={}|hooks={}|exec_target={}|planner={}",
                tool_name,
                canonical_args,
                normalized_workdir,
                policy_hash_hex,
                tool_schema_hash_hex.unwrap_or("none"),
                hooks_config_hash_hex.unwrap_or("none"),
                match exec_target {
                    ExecTargetKind::Host => "host",
                    ExecTargetKind::Docker => "docker",
                },
                planner_hash_hex.unwrap_or("none"),
            );
            compute_policy_hash_hex(payload.as_bytes())
        }
    }
}

fn normalize_workdir(path: &std::path::Path) -> String {
    match std::fs::canonicalize(path) {
        Ok(p) => p.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        compute_approval_key, compute_policy_hash_hex, ApprovalKeyVersion, ApprovalMode,
        AutoApproveScope, ExecTargetKind, GateContext, GateDecision, NoGate, ProviderKind,
        ToolGate, TrustGate, TrustMode,
    };
    use crate::trust::approvals::{ApprovalProvenance, ApprovalsStore};
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
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
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
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key = compute_approval_key(&call.name, &call.arguments, &ctx.workdir, &policy_hash);
        let id = store
            .create_pending(&call.name, &call.arguments, Some(key.clone()), None)
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
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key = compute_approval_key(&call.name, &call.arguments, &ctx.workdir, &policy_hash);
        let id = store
            .create_pending(&call.name, &call.arguments, Some(key), None)
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
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
        };
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key = compute_approval_key(&call.name, &call.arguments, &ctx.workdir, &policy_hash);
        let id = store
            .create_pending(&call.name, &call.arguments, Some(key), None)
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
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
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
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
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

    #[test]
    fn policy_can_match_exec_target_condition() {
        let tmp = tempdir().expect("tempdir");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::from_yaml(
            r#"
version: 2
default: allow
rules:
  - tool: "read_file"
    decision: deny
    when:
      - arg: "__exec_target"
        op: equals
        value: "docker"
"#,
        )
        .expect("policy");
        let policy_hash = compute_policy_hash_hex(b"custom");
        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        let call = ToolCall {
            id: "tc_x".to_string(),
            name: "read_file".to_string(),
            arguments: json!({"path":"a.txt"}),
        };

        let mut ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: false,
            allow_write: false,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
        };
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::Allow { .. }
        ));
        ctx.exec_target = ExecTargetKind::Docker;
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::Deny { .. }
        ));
    }

    #[test]
    fn approval_key_v2_deterministic_known_hash() {
        let got = super::compute_approval_key_with_version(
            ApprovalKeyVersion::V2,
            "read_file",
            &json!({"path":"a.txt"}),
            std::path::Path::new("/tmp/w"),
            "abc",
            Some("def"),
            None,
            ExecTargetKind::Host,
            None,
        );
        assert_eq!(
            got,
            "6cec1a4c99be252db98654e874d29f1aa0306692181b4ae494ef42bfbca5aba1"
        );
    }

    #[test]
    fn gate_key_version_matching_v1_vs_v2() {
        let tmp = tempdir().expect("tmp");
        let approvals = tmp.path().join("approvals.json");
        let audit = tmp.path().join("audit.jsonl");
        let store = ApprovalsStore::new(approvals);
        let policy = Policy::safe_default();
        let policy_hash = compute_policy_hash_hex(b"default");
        let call = ToolCall {
            id: "tc_1".to_string(),
            name: "shell".to_string(),
            arguments: json!({"cmd":"echo","args":["hi"]}),
        };
        let key_v2 = super::compute_approval_key_with_version(
            ApprovalKeyVersion::V2,
            &call.name,
            &call.arguments,
            tmp.path(),
            &policy_hash,
            None,
            None,
            ExecTargetKind::Host,
            None,
        );
        let id = store
            .create_pending(
                &call.name,
                &call.arguments,
                Some(key_v2),
                Some(ApprovalProvenance {
                    approval_key_version: "v2".to_string(),
                    tool_schema_hash_hex: None,
                    hooks_config_hash_hex: None,
                    exec_target: Some("host".to_string()),
                    planner_hash_hex: None,
                }),
            )
            .expect("pending");
        store.approve(&id, None, None).expect("approve");

        let mut gate = TrustGate::new(
            policy,
            store,
            AuditLog::new(audit),
            TrustMode::On,
            policy_hash,
        );
        let mut ctx = GateContext {
            workdir: tmp.path().to_path_buf(),
            allow_shell: true,
            allow_write: false,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some("r".to_string()),
            enable_write_tools: false,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: "m".to_string(),
            exec_target: ExecTargetKind::Host,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: None,
            planner_hash_hex: None,
        };
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::RequireApproval { .. }
        ));
        ctx.approval_key_version = ApprovalKeyVersion::V2;
        assert!(matches!(
            gate.decide(&ctx, &call),
            GateDecision::Allow { .. }
        ));
    }
}
