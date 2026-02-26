use std::collections::BTreeMap;
use std::ffi::OsString;

use anyhow::anyhow;
use serde::Serialize;

use crate::compaction::{CompactionMode, ToolResultPersist};
use crate::gate::{ApprovalMode, AutoApproveScope, TrustMode};
use crate::tools::ToolArgsStrict;
use crate::RunArgs;

pub const PROFILE_SCHEMA_ID: &str = "openagent.reliability_profile.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedReliabilityProfile {
    pub name: String,
    pub source: String,
    pub profile_hash_hex: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RunArgsPresence {
    pub max_context_chars: bool,
    pub compaction_mode: bool,
    pub compaction_keep_last: bool,
    pub tool_result_persist: bool,
    pub max_tool_output_bytes: bool,
    pub max_read_bytes: bool,
    pub max_steps: bool,
    pub max_total_tool_calls: bool,
    pub max_wall_time_ms: bool,
    pub tool_args_strict: bool,
    pub trust: bool,
    pub approval_mode: bool,
    pub auto_approve_scope: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ReliabilityProfileDef {
    pub name: &'static str,
    pub description: &'static str,
    pub values: ReliabilityProfileValues,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ReliabilityProfileValues {
    pub max_context_chars: usize,
    pub compaction_mode: &'static str,
    pub compaction_keep_last: usize,
    pub tool_result_persist: &'static str,
    pub max_tool_output_bytes: usize,
    pub max_read_bytes: usize,
    pub max_steps: usize,
    pub max_total_tool_calls: usize,
    pub max_wall_time_ms: u64,
    pub tool_args_strict: &'static str,
    pub trust: &'static str,
    pub approval_mode: &'static str,
    pub auto_approve_scope: &'static str,
}

const BUILTIN_PROFILES: &[ReliabilityProfileDef] = &[
    ReliabilityProfileDef {
        name: "coding_balanced",
        description: "Balanced local coding defaults with bounded context and compaction.",
        values: ReliabilityProfileValues {
            max_context_chars: 64_000,
            compaction_mode: "summary",
            compaction_keep_last: 24,
            tool_result_persist: "digest",
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            max_steps: 24,
            max_total_tool_calls: 0,
            max_wall_time_ms: 0,
            tool_args_strict: "on",
            trust: "off",
            approval_mode: "interrupt",
            auto_approve_scope: "run",
        },
    },
    ReliabilityProfileDef {
        name: "local_small_strict",
        description: "Smaller budgets and stricter compaction tuned for smaller local models.",
        values: ReliabilityProfileValues {
            max_context_chars: 24_000,
            compaction_mode: "summary",
            compaction_keep_last: 16,
            tool_result_persist: "digest",
            max_tool_output_bytes: 64_000,
            max_read_bytes: 64_000,
            max_steps: 14,
            max_total_tool_calls: 20,
            max_wall_time_ms: 0,
            tool_args_strict: "on",
            trust: "off",
            approval_mode: "fail",
            auto_approve_scope: "run",
        },
    },
    ReliabilityProfileDef {
        name: "web_cautious",
        description:
            "Conservative MCP/web-oriented defaults with tighter output and explicit approvals.",
        values: ReliabilityProfileValues {
            max_context_chars: 48_000,
            compaction_mode: "summary",
            compaction_keep_last: 20,
            tool_result_persist: "digest",
            max_tool_output_bytes: 96_000,
            max_read_bytes: 128_000,
            max_steps: 20,
            max_total_tool_calls: 30,
            max_wall_time_ms: 0,
            tool_args_strict: "on",
            trust: "off",
            approval_mode: "interrupt",
            auto_approve_scope: "run",
        },
    },
];

pub fn get_builtin_profile(name: &str) -> Option<&'static ReliabilityProfileDef> {
    BUILTIN_PROFILES.iter().find(|p| p.name == name)
}

pub fn list_builtin_profiles_sorted() -> Vec<&'static ReliabilityProfileDef> {
    let mut out = BUILTIN_PROFILES.iter().collect::<Vec<_>>();
    out.sort_by_key(|p| p.name);
    out
}

pub fn render_profile_show(name: &str) -> anyhow::Result<String> {
    let p = get_builtin_profile(name).ok_or_else(|| {
        anyhow!(
            "unknown reliability profile '{}'; available: {}",
            name,
            list_builtin_profiles_sorted()
                .into_iter()
                .map(|p| p.name)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let mut lines = Vec::new();
    lines.push(format!("name: {}", p.name));
    lines.push("source: builtin".to_string());
    lines.push(format!("schema: {}", PROFILE_SCHEMA_ID));
    lines.push(format!("description: {}", p.description));
    lines.push(format!("profile_hash_hex: {}", profile_hash_hex(p)));
    lines.push("values:".to_string());
    for (k, v) in profile_show_kvs(p) {
        lines.push(format!("  {}: {}", k, v));
    }
    lines.push("notes:".to_string());
    lines.push("  allow_shell: not set by profile (operator must pass explicit flags)".to_string());
    lines.push("  allow_write: not set by profile (operator must pass explicit flags)".to_string());
    lines.push(
        "  enable_write_tools: not set by profile (operator must pass explicit flags)".to_string(),
    );
    Ok(lines.join("\n"))
}

fn profile_show_kvs(p: &ReliabilityProfileDef) -> Vec<(String, String)> {
    let v = p.values;
    vec![
        ("approval_mode".to_string(), v.approval_mode.to_string()),
        (
            "auto_approve_scope".to_string(),
            v.auto_approve_scope.to_string(),
        ),
        (
            "compaction_keep_last".to_string(),
            v.compaction_keep_last.to_string(),
        ),
        ("compaction_mode".to_string(), v.compaction_mode.to_string()),
        (
            "max_context_chars".to_string(),
            v.max_context_chars.to_string(),
        ),
        ("max_read_bytes".to_string(), v.max_read_bytes.to_string()),
        ("max_steps".to_string(), v.max_steps.to_string()),
        (
            "max_tool_output_bytes".to_string(),
            v.max_tool_output_bytes.to_string(),
        ),
        (
            "max_total_tool_calls".to_string(),
            v.max_total_tool_calls.to_string(),
        ),
        (
            "max_wall_time_ms".to_string(),
            v.max_wall_time_ms.to_string(),
        ),
        (
            "tool_args_strict".to_string(),
            v.tool_args_strict.to_string(),
        ),
        (
            "tool_result_persist".to_string(),
            v.tool_result_persist.to_string(),
        ),
        ("trust".to_string(), v.trust.to_string()),
    ]
}

pub fn profile_hash_hex(profile: &ReliabilityProfileDef) -> String {
    let canonical = canonical_profile_json(profile);
    crate::store::sha256_hex(canonical.as_bytes())
}

fn canonical_profile_json(profile: &ReliabilityProfileDef) -> String {
    let mut values = BTreeMap::new();
    values.insert(
        "max_context_chars".to_string(),
        serde_json::Value::from(profile.values.max_context_chars as u64),
    );
    values.insert(
        "compaction_mode".to_string(),
        serde_json::Value::from(profile.values.compaction_mode),
    );
    values.insert(
        "compaction_keep_last".to_string(),
        serde_json::Value::from(profile.values.compaction_keep_last as u64),
    );
    values.insert(
        "tool_result_persist".to_string(),
        serde_json::Value::from(profile.values.tool_result_persist),
    );
    values.insert(
        "max_tool_output_bytes".to_string(),
        serde_json::Value::from(profile.values.max_tool_output_bytes as u64),
    );
    values.insert(
        "max_read_bytes".to_string(),
        serde_json::Value::from(profile.values.max_read_bytes as u64),
    );
    values.insert(
        "max_steps".to_string(),
        serde_json::Value::from(profile.values.max_steps as u64),
    );
    values.insert(
        "max_total_tool_calls".to_string(),
        serde_json::Value::from(profile.values.max_total_tool_calls as u64),
    );
    values.insert(
        "max_wall_time_ms".to_string(),
        serde_json::Value::from(profile.values.max_wall_time_ms),
    );
    values.insert(
        "tool_args_strict".to_string(),
        serde_json::Value::from(profile.values.tool_args_strict),
    );
    values.insert(
        "trust".to_string(),
        serde_json::Value::from(profile.values.trust),
    );
    values.insert(
        "approval_mode".to_string(),
        serde_json::Value::from(profile.values.approval_mode),
    );
    values.insert(
        "auto_approve_scope".to_string(),
        serde_json::Value::from(profile.values.auto_approve_scope),
    );
    serde_json::to_string(&serde_json::json!({
        "profile_schema": PROFILE_SCHEMA_ID,
        "name": profile.name,
        "source": "builtin",
        "values": values,
    }))
    .expect("canonical profile json")
}

pub fn apply_builtin_profile_to_run_args(
    run: &mut RunArgs,
    presence: &RunArgsPresence,
) -> anyhow::Result<Option<AppliedReliabilityProfile>> {
    let Some(name) = run.reliability_profile.clone() else {
        return Ok(None);
    };
    let profile = get_builtin_profile(&name).ok_or_else(|| {
        anyhow!(
            "unknown reliability profile '{}'; run `localagent profile list`",
            name
        )
    })?;
    apply_values_to_run_args(run, profile.values, presence)?;
    let applied = AppliedReliabilityProfile {
        name: profile.name.to_string(),
        source: "builtin".to_string(),
        profile_hash_hex: profile_hash_hex(profile),
    };
    run.resolved_reliability_profile_source = Some(applied.source.clone());
    run.resolved_reliability_profile_hash_hex = Some(applied.profile_hash_hex.clone());
    Ok(Some(applied))
}

fn apply_values_to_run_args(
    run: &mut RunArgs,
    values: ReliabilityProfileValues,
    presence: &RunArgsPresence,
) -> anyhow::Result<()> {
    if !presence.max_context_chars {
        run.max_context_chars = values.max_context_chars;
    }
    if !presence.compaction_mode {
        run.compaction_mode = parse_compaction_mode(values.compaction_mode)?;
    }
    if !presence.compaction_keep_last {
        run.compaction_keep_last = values.compaction_keep_last;
    }
    if !presence.tool_result_persist {
        run.tool_result_persist = parse_tool_result_persist(values.tool_result_persist)?;
    }
    if !presence.max_tool_output_bytes {
        run.max_tool_output_bytes = values.max_tool_output_bytes;
    }
    if !presence.max_read_bytes {
        run.max_read_bytes = values.max_read_bytes;
    }
    if !presence.max_steps {
        run.max_steps = values.max_steps;
    }
    if !presence.max_total_tool_calls {
        run.max_total_tool_calls = values.max_total_tool_calls;
    }
    if !presence.max_wall_time_ms {
        run.max_wall_time_ms = values.max_wall_time_ms;
    }
    if !presence.tool_args_strict {
        run.tool_args_strict = parse_tool_args_strict(values.tool_args_strict)?;
    }
    if !presence.trust {
        run.trust = parse_trust_mode(values.trust)?;
    }
    if !presence.approval_mode {
        run.approval_mode = parse_approval_mode(values.approval_mode)?;
    }
    if !presence.auto_approve_scope {
        run.auto_approve_scope = parse_auto_approve_scope(values.auto_approve_scope)?;
    }
    Ok(())
}

pub fn detect_run_args_presence_from_argv(argv: &[OsString]) -> RunArgsPresence {
    let mut p = RunArgsPresence::default();
    for arg in argv.iter().skip(1) {
        let Some(s) = arg.to_str() else {
            continue;
        };
        let mark = |flag: &str, value: &mut bool| {
            if s == flag || s.starts_with(&format!("{flag}=")) {
                *value = true;
            }
        };
        mark("--max-context-chars", &mut p.max_context_chars);
        mark("--compaction-mode", &mut p.compaction_mode);
        mark("--compaction-keep-last", &mut p.compaction_keep_last);
        mark("--tool-result-persist", &mut p.tool_result_persist);
        mark("--max-tool-output-bytes", &mut p.max_tool_output_bytes);
        mark("--max-read-bytes", &mut p.max_read_bytes);
        mark("--max-steps", &mut p.max_steps);
        mark("--max-total-tool-calls", &mut p.max_total_tool_calls);
        mark("--max-wall-time-ms", &mut p.max_wall_time_ms);
        mark("--tool-args-strict", &mut p.tool_args_strict);
        mark("--trust", &mut p.trust);
        mark("--approval-mode", &mut p.approval_mode);
        mark("--auto-approve-scope", &mut p.auto_approve_scope);
    }
    p
}

fn parse_compaction_mode(v: &str) -> anyhow::Result<CompactionMode> {
    match v {
        "off" => Ok(CompactionMode::Off),
        "summary" => Ok(CompactionMode::Summary),
        _ => Err(anyhow!(
            "unsupported compaction_mode in builtin profile: {v}"
        )),
    }
}

fn parse_tool_result_persist(v: &str) -> anyhow::Result<ToolResultPersist> {
    match v {
        "all" => Ok(ToolResultPersist::All),
        "digest" => Ok(ToolResultPersist::Digest),
        "none" => Ok(ToolResultPersist::None),
        _ => Err(anyhow!(
            "unsupported tool_result_persist in builtin profile: {v}"
        )),
    }
}

fn parse_tool_args_strict(v: &str) -> anyhow::Result<ToolArgsStrict> {
    match v {
        "on" => Ok(ToolArgsStrict::On),
        "off" => Ok(ToolArgsStrict::Off),
        _ => Err(anyhow!(
            "unsupported tool_args_strict in builtin profile: {v}"
        )),
    }
}

fn parse_trust_mode(v: &str) -> anyhow::Result<TrustMode> {
    match v {
        "auto" => Ok(TrustMode::Auto),
        "off" => Ok(TrustMode::Off),
        "on" => Ok(TrustMode::On),
        _ => Err(anyhow!("unsupported trust in builtin profile: {v}")),
    }
}

fn parse_approval_mode(v: &str) -> anyhow::Result<ApprovalMode> {
    match v {
        "interrupt" => Ok(ApprovalMode::Interrupt),
        "fail" => Ok(ApprovalMode::Fail),
        "auto" => Ok(ApprovalMode::Auto),
        _ => Err(anyhow!("unsupported approval_mode in builtin profile: {v}")),
    }
}

fn parse_auto_approve_scope(v: &str) -> anyhow::Result<AutoApproveScope> {
    match v {
        "run" => Ok(AutoApproveScope::Run),
        "session" => Ok(AutoApproveScope::Session),
        _ => Err(anyhow!(
            "unsupported auto_approve_scope in builtin profile: {v}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn builtin_profile_listing_sorted_and_contains_expected_names() {
        let names = list_builtin_profiles_sorted()
            .into_iter()
            .map(|p| p.name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["coding_balanced", "local_small_strict", "web_cautious"]
        );
    }

    #[test]
    fn profile_hash_is_deterministic() {
        let p = get_builtin_profile("coding_balanced").expect("profile");
        assert_eq!(profile_hash_hex(p), profile_hash_hex(p));
    }

    #[test]
    fn builtins_do_not_enable_side_effect_flags() {
        for p in BUILTIN_PROFILES {
            let show = render_profile_show(p.name).expect("show");
            assert!(show.contains("allow_shell: not set by profile"));
            assert!(show.contains("allow_write: not set by profile"));
            assert!(show.contains("enable_write_tools: not set by profile"));
        }
    }

    #[test]
    fn argv_presence_detects_explicit_flags() {
        let args = vec![
            OsString::from("localagent"),
            OsString::from("--reliability-profile"),
            OsString::from("coding_balanced"),
            OsString::from("--max-steps=9"),
            OsString::from("--approval-mode"),
            OsString::from("fail"),
        ];
        let p = detect_run_args_presence_from_argv(&args);
        assert!(p.max_steps);
        assert!(p.approval_mode);
        assert!(!p.max_context_chars);
    }

    #[test]
    fn explicit_cli_flags_override_profile_defaults() {
        let mut run = crate::RunArgs::parse_from([
            "localagent",
            "--reliability-profile",
            "local_small_strict",
            "--max-steps",
            "9",
            "--approval-mode",
            "interrupt",
        ]);
        let presence = detect_run_args_presence_from_argv(&[
            OsString::from("localagent"),
            OsString::from("--reliability-profile"),
            OsString::from("local_small_strict"),
            OsString::from("--max-steps"),
            OsString::from("9"),
            OsString::from("--approval-mode"),
            OsString::from("interrupt"),
        ]);
        let applied = apply_builtin_profile_to_run_args(&mut run, &presence)
            .expect("apply")
            .expect("applied");
        assert_eq!(applied.name, "local_small_strict");
        assert_eq!(run.max_steps, 9);
        assert_eq!(run.approval_mode, ApprovalMode::Interrupt);
        assert_eq!(run.max_context_chars, 24_000);
        assert_eq!(
            run.resolved_reliability_profile_hash_hex.as_deref(),
            Some(applied.profile_hash_hex.as_str())
        );
    }
}
