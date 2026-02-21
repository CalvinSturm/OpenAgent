use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::gate::{
    ApprovalKeyVersion, ApprovalMode, AutoApproveScope, GateContext, GateDecision, ProviderKind,
    ToolGate, TrustGate, TrustMode,
};
use crate::target::ExecTargetKind;
use crate::trust::approvals::ApprovalsStore;
use crate::trust::audit::AuditLog;
use crate::trust::policy::Policy;
use crate::types::ToolCall;

#[derive(Debug, Deserialize)]
pub struct PolicyTestFile {
    pub version: u32,
    pub cases: Vec<PolicyTestCase>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyTestCase {
    pub name: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
    pub context: PolicyTestContext,
    pub expect: PolicyTestExpect,
}

#[derive(Debug, Deserialize)]
pub struct PolicyTestContext {
    pub workdir: String,
    pub exec_target: String,
    pub mode: String,
    #[serde(default)]
    pub planner_hash_hex: Option<String>,
    #[serde(default)]
    pub hooks_hash_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyTestExpect {
    pub decision: String,
    #[serde(default)]
    pub reason_contains: Option<String>,
    #[serde(default)]
    pub source_contains: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicyTestReport {
    pub schema_version: String,
    pub policy_path: String,
    pub cases: Vec<PolicyTestResult>,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct PolicyTestResult {
    pub name: String,
    pub expected: String,
    pub got: String,
    pub reason: Option<String>,
    pub source: Option<String>,
    pub pass: bool,
    #[serde(default)]
    pub failures: Vec<String>,
}

pub fn run_policy_tests(policy_path: &Path, cases_path: &Path) -> anyhow::Result<PolicyTestReport> {
    let policy = Policy::from_path(policy_path)
        .with_context(|| format!("failed loading policy {}", policy_path.display()))?;
    let raw = std::fs::read_to_string(cases_path)
        .with_context(|| format!("failed reading cases file {}", cases_path.display()))?;
    let cases_file: PolicyTestFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed parsing cases YAML {}", cases_path.display()))?;
    if cases_file.version != 1 {
        anyhow::bail!(
            "unsupported policy test file version: {}",
            cases_file.version
        );
    }

    let tmp = std::env::temp_dir().join(format!("openagent_policy_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).context("failed to create tempdir for policy tests")?;
    let mut gate = TrustGate::new(
        policy,
        ApprovalsStore::new(tmp.join("approvals.json")),
        AuditLog::new(tmp.join("audit.jsonl")),
        TrustMode::On,
        "policy-test".to_string(),
    );

    let mut results = Vec::new();
    for (idx, case) in cases_file.cases.iter().enumerate() {
        let ctx = GateContext {
            workdir: normalize_path(&case.context.workdir),
            allow_shell: true,
            allow_write: true,
            approval_mode: ApprovalMode::Interrupt,
            auto_approve_scope: AutoApproveScope::Run,
            approval_key_version: ApprovalKeyVersion::V1,
            tool_schema_hashes: BTreeMap::new(),
            hooks_config_hash_hex: case.context.hooks_hash_hex.clone(),
            planner_hash_hex: case.context.planner_hash_hex.clone(),
            unsafe_mode: false,
            unsafe_bypass_allow_flags: false,
            run_id: Some(format!("policy_test_{idx}")),
            enable_write_tools: true,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            provider: ProviderKind::Lmstudio,
            model: case.context.mode.clone(),
            exec_target: if case.context.exec_target == "docker" {
                ExecTargetKind::Docker
            } else {
                ExecTargetKind::Host
            },
        };
        let call = ToolCall {
            id: format!("tc_{idx}"),
            name: case.tool.clone(),
            arguments: case.arguments.clone(),
        };
        let (got, reason, source) = match gate.decide(&ctx, &call) {
            GateDecision::Allow { reason, source, .. } => ("allow".to_string(), reason, source),
            GateDecision::Deny { reason, source, .. } => ("deny".to_string(), Some(reason), source),
            GateDecision::RequireApproval { reason, source, .. } => {
                ("require_approval".to_string(), Some(reason), source)
            }
        };
        let mut failures = Vec::new();
        if got != case.expect.decision {
            failures.push(format!(
                "decision mismatch: expected {}, got {}",
                case.expect.decision, got
            ));
        }
        if let Some(needle) = &case.expect.reason_contains {
            if !reason.as_deref().unwrap_or_default().contains(needle) {
                failures.push(format!("reason does not contain '{}'", needle));
            }
        }
        if let Some(needle) = &case.expect.source_contains {
            if !source.as_deref().unwrap_or_default().contains(needle) {
                failures.push(format!("source does not contain '{}'", needle));
            }
        }
        let pass = failures.is_empty();
        results.push(PolicyTestResult {
            name: case.name.clone(),
            expected: case.expect.decision.clone(),
            got,
            reason,
            source,
            pass,
            failures,
        });
    }

    let passed = results.iter().filter(|r| r.pass).count();
    let failed = results.len().saturating_sub(passed);
    Ok(PolicyTestReport {
        schema_version: "openagent.policy_test.v1".to_string(),
        policy_path: policy_path.display().to_string(),
        cases: results,
        passed,
        failed,
    })
}

fn normalize_path(input: &str) -> PathBuf {
    let p = PathBuf::from(input);
    match std::fs::canonicalize(&p) {
        Ok(c) => c,
        Err(_) => p,
    }
}

#[cfg(test)]
mod tests {
    use super::run_policy_tests;

    #[test]
    fn policy_test_runner_parses_and_evaluates() {
        let tmp = tempfile::tempdir().expect("tmp");
        let policy = tmp.path().join("policy.yaml");
        let cases = tmp.path().join("cases.yaml");
        std::fs::write(
            &policy,
            r#"
version: 2
default: deny
rules:
  - tool: "read_file"
    decision: allow
"#,
        )
        .expect("policy");
        std::fs::write(
            &cases,
            r#"
version: 1
cases:
  - name: "allow read"
    tool: "read_file"
    arguments: {"path":"a.txt"}
    context:
      workdir: "."
      exec_target: "host"
      mode: "single"
      planner_hash_hex: null
      hooks_hash_hex: null
    expect:
      decision: "allow"
      source_contains: "policy"
"#,
        )
        .expect("cases");
        let report = run_policy_tests(&policy, &cases).expect("run");
        assert_eq!(report.failed, 0);
        assert_eq!(report.passed, 1);
    }
}
