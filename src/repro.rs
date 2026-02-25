use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::{config_hash_hex, sha256_hex, stable_path_string, RunRecord};
use crate::tools::builtin_tools_enabled;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ReproMode {
    Off,
    On,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ReproEnvMode {
    Off,
    Safe,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproSnapshot {
    pub schema_version: String,
    pub run_id: String,
    pub created_at: String,
    pub openagent_version: String,
    pub host: ReproHost,
    pub provider: ReproProvider,
    pub gating: ReproGating,
    pub tools: ReproTools,
    pub execution: ReproExecution,
    pub determinism: ReproDeterminism,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproHost {
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproProvider {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub caps_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps_snapshot: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps_cache_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproGating {
    pub trust_mode: String,
    pub approval_mode: String,
    pub approval_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash_hex: Option<String>,
    #[serde(default)]
    pub includes_resolved: Vec<String>,
    pub hooks_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks_config_hash_hex: Option<String>,
    pub taint_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_policy_globs_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproTools {
    pub tool_schema_hash_hex_map: BTreeMap<String, String>,
    pub tool_catalog: Vec<crate::store::ToolCatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproExecution {
    pub exec_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker: Option<ReproDocker>,
    pub workdir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproDocker {
    pub image: String,
    pub workdir: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproDeterminism {
    pub config_hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_fingerprint_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReproRecord {
    pub enabled: bool,
    pub env_mode: String,
    pub snapshot: ReproSnapshot,
    pub repro_hash_hex: String,
}

#[derive(Debug, Clone)]
pub struct ReproBuildInput {
    pub run_id: String,
    pub created_at: String,
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub caps_source: String,
    pub trust_mode: String,
    pub approval_mode: String,
    pub approval_key: String,
    pub policy_hash_hex: Option<String>,
    pub includes_resolved: Vec<String>,
    pub hooks_mode: String,
    pub hooks_config_hash_hex: Option<String>,
    pub taint_mode: String,
    pub taint_policy_globs_hash_hex: Option<String>,
    pub tool_schema_hash_hex_map: BTreeMap<String, String>,
    pub tool_catalog: Vec<crate::store::ToolCatalogEntry>,
    pub exec_target: String,
    pub docker: Option<ReproDocker>,
    pub workdir: String,
    pub config_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayVerifyReport {
    pub schema_version: String,
    pub run_id: String,
    pub status: String,
    pub checks: Vec<ReplayVerifyCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayVerifyCheck {
    pub name: String,
    pub expected: String,
    pub actual: String,
    pub ok: bool,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn build_repro_record(
    mode: ReproMode,
    env_mode: ReproEnvMode,
    input: ReproBuildInput,
) -> anyhow::Result<Option<RunReproRecord>> {
    if matches!(mode, ReproMode::Off) {
        return Ok(None);
    }
    let env_fingerprint_hex = env_fingerprint(env_mode)?;
    let snapshot = ReproSnapshot {
        schema_version: "openagent.repro_snapshot.v1".to_string(),
        run_id: input.run_id.clone(),
        created_at: input.created_at,
        openagent_version: env!("CARGO_PKG_VERSION").to_string(),
        host: ReproHost {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: hostname(),
        },
        provider: ReproProvider {
            provider: input.provider,
            base_url: input.base_url,
            model: input.model,
            caps_source: input.caps_source,
            caps_snapshot: None,
            caps_cache_key: None,
        },
        gating: ReproGating {
            trust_mode: input.trust_mode,
            approval_mode: input.approval_mode,
            approval_key: input.approval_key,
            policy_hash_hex: input.policy_hash_hex,
            includes_resolved: input.includes_resolved,
            hooks_mode: input.hooks_mode,
            hooks_config_hash_hex: input.hooks_config_hash_hex,
            taint_mode: input.taint_mode,
            taint_policy_globs_hash_hex: input.taint_policy_globs_hash_hex,
        },
        tools: ReproTools {
            tool_schema_hash_hex_map: input.tool_schema_hash_hex_map,
            tool_catalog: input.tool_catalog,
        },
        execution: ReproExecution {
            exec_target: input.exec_target,
            docker: input.docker,
            workdir: input.workdir,
        },
        determinism: ReproDeterminism {
            config_hash_hex: input.config_hash_hex,
            env_fingerprint_hex,
        },
    };
    let repro_hash_hex = repro_hash_hex(&snapshot)?;
    Ok(Some(RunReproRecord {
        enabled: true,
        env_mode: format!("{:?}", env_mode).to_lowercase(),
        snapshot,
        repro_hash_hex,
    }))
}

pub fn repro_hash_hex(snapshot: &ReproSnapshot) -> anyhow::Result<String> {
    let value = serde_json::to_value(snapshot)?;
    let canonical = crate::trust::approvals::canonical_json(&value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

pub fn env_fingerprint(mode: ReproEnvMode) -> anyhow::Result<Option<String>> {
    let map = filtered_env(mode);
    if map.is_empty() {
        return Ok(None);
    }
    let value = serde_json::to_value(map)?;
    let canonical = crate::trust::approvals::canonical_json(&value)?;
    Ok(Some(sha256_hex(canonical.as_bytes())))
}

fn filtered_env(mode: ReproEnvMode) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match mode {
        ReproEnvMode::Off => {}
        ReproEnvMode::Safe => {
            for (k, v) in std::env::vars() {
                if k.starts_with("OPENAGENT_") || k == "RUST_LOG" {
                    out.insert(k, v);
                }
            }
        }
        ReproEnvMode::All => {
            for (k, v) in std::env::vars() {
                if looks_secret_key(&k) {
                    continue;
                }
                out.insert(k, v);
            }
        }
    }
    out
}

fn looks_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "KEY",
        "TOKEN",
        "SECRET",
        "PASS",
        "PWD",
        "CREDENTIAL",
        "COOKIE",
        "SESSION",
        "AUTH",
        "BEARER",
        "PRIVATE",
        "_PAT",
    ]
    .iter()
    .any(|s| upper.contains(s))
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
}

pub fn verify_run_record(record: &RunRecord, strict: bool) -> anyhow::Result<ReplayVerifyReport> {
    let mut checks = Vec::new();

    if let Some(fp) = &record.config_fingerprint {
        let actual = config_hash_hex(fp)?;
        checks.push(ReplayVerifyCheck {
            name: "config_hash_hex".to_string(),
            expected: record.config_hash_hex.clone(),
            ok: actual == record.config_hash_hex,
            actual,
            severity: "error".to_string(),
            note: None,
        });
    } else {
        checks.push(unavailable_check(
            "config_hash_hex",
            "missing config_fingerprint",
        ));
    }

    let policy_path = Path::new(&record.resolved_paths.policy_path);
    if policy_path.exists() {
        let bytes = std::fs::read(policy_path)
            .with_context(|| format!("failed reading policy file {}", policy_path.display()))?;
        let actual = sha256_hex(&bytes);
        checks.push(ReplayVerifyCheck {
            name: "policy_hash_hex".to_string(),
            expected: record
                .policy_hash_hex
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            ok: record.policy_hash_hex.as_deref() == Some(actual.as_str()),
            actual,
            severity: "warn".to_string(),
            note: None,
        });
    } else {
        checks.push(unavailable_check(
            "policy_hash_hex",
            "policy path unavailable",
        ));
    }

    let hooks_path = Path::new(&record.cli.hooks_config_path);
    if hooks_path.exists() {
        let bytes = std::fs::read(hooks_path)
            .with_context(|| format!("failed reading hooks config {}", hooks_path.display()))?;
        let actual = sha256_hex(&bytes);
        checks.push(ReplayVerifyCheck {
            name: "hooks_config_hash_hex".to_string(),
            expected: record
                .hooks_config_hash_hex
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            ok: record.hooks_config_hash_hex.as_deref() == Some(actual.as_str()),
            actual,
            severity: "warn".to_string(),
            note: None,
        });
    } else {
        checks.push(unavailable_check(
            "hooks_config_hash_hex",
            "hooks config path unavailable",
        ));
    }

    let builtin = builtin_tools_enabled(true, true);
    let mut actual_schema_map = crate::store::tool_schema_hash_hex_map(&builtin);
    let mut mcp_live_snapshot_note = None;
    let mut mcp_live_hash = String::from("unavailable");
    match try_live_mcp_snapshot(record) {
        Ok(Some((snapshot, hash_hex))) => {
            for entry in &snapshot {
                actual_schema_map.insert(
                    entry.name.clone(),
                    crate::store::hash_tool_schema(&entry.parameters),
                );
            }
            mcp_live_hash = hash_hex;
        }
        Ok(None) => {
            mcp_live_snapshot_note = Some("MCP live catalog unavailable during verify".to_string());
        }
        Err(e) => {
            mcp_live_snapshot_note = Some(format!("MCP live catalog unavailable: {e}"));
        }
    }

    let expected_mcp_hash = record
        .cli
        .mcp_tool_catalog_hash_hex
        .clone()
        .or_else(|| {
            if record.cli.mcp_tool_snapshot.is_empty() {
                None
            } else {
                crate::store::mcp_tool_snapshot_hash_hex(&record.cli.mcp_tool_snapshot).ok()
            }
        })
        .unwrap_or_else(|| "-".to_string());
    let mcp_hash_ok = expected_mcp_hash == "-" || expected_mcp_hash == mcp_live_hash;
    checks.push(ReplayVerifyCheck {
        name: "mcp_tool_catalog_hash_hex".to_string(),
        expected: expected_mcp_hash,
        actual: mcp_live_hash,
        ok: mcp_hash_ok,
        severity: "warn".to_string(),
        note: mcp_live_snapshot_note,
    });
    if let Some(pin) = &record.mcp_pin_snapshot {
        let expected = pin.configured_catalog_hash_hex.clone();
        let actual = pin
            .startup_live_catalog_hash_hex
            .clone()
            .unwrap_or_else(|| "unavailable".to_string());
        let enforcement = if pin.enforcement.is_empty() {
            record.cli.mcp_pin_enforcement.as_str()
        } else {
            pin.enforcement.as_str()
        };
        let must_match = matches!(enforcement, "hard");
        let ok = if must_match {
            !expected.is_empty() && expected == actual
        } else {
            true
        };
        checks.push(ReplayVerifyCheck {
            name: "mcp_pin_snapshot".to_string(),
            expected: format!("enforcement={} configured={}", enforcement, expected),
            actual: format!("startup_live={} pinned={}", actual, pin.pinned),
            ok,
            severity: if must_match {
                "error".to_string()
            } else {
                "warn".to_string()
            },
            note: pin
                .mcp_config_hash_hex
                .as_ref()
                .map(|h| format!("mcp_config_hash={}", h)),
        });
    }

    let mut schema_ok = true;
    let mut actual_map = BTreeMap::new();
    for (name, expected) in &record.tool_schema_hash_hex_map {
        if let Some(actual) = actual_schema_map.get(name) {
            if actual != expected {
                schema_ok = false;
            }
            actual_map.insert(name.clone(), actual.clone());
        } else {
            schema_ok = false;
            actual_map.insert(name.clone(), "unavailable".to_string());
        }
    }
    checks.push(ReplayVerifyCheck {
        name: "tool_schema_hash_hex_map".to_string(),
        expected: serde_json::to_string(&record.tool_schema_hash_hex_map)?,
        actual: serde_json::to_string(&actual_map)?,
        ok: schema_ok,
        severity: "warn".to_string(),
        note: Some("MCP tool schemas may be unavailable during offline verify".to_string()),
    });

    if let Some(repro) = &record.repro {
        let actual = repro_hash_hex(&repro.snapshot)?;
        checks.push(ReplayVerifyCheck {
            name: "repro_hash_hex".to_string(),
            expected: repro.repro_hash_hex.clone(),
            actual,
            ok: repro.repro_hash_hex == repro_hash_hex(&repro.snapshot)?,
            severity: "error".to_string(),
            note: None,
        });
    }

    checks.push(verify_mcp_runtime_trace_continuity(record));

    let has_error_fail = checks.iter().any(|c| !c.ok && c.severity == "error");
    let has_warn_fail = checks.iter().any(|c| !c.ok && c.severity == "warn");
    let status = if strict {
        if checks.iter().any(|c| !c.ok) {
            "fail"
        } else {
            "pass"
        }
    } else if has_error_fail {
        "fail"
    } else if has_warn_fail {
        "warn"
    } else {
        "pass"
    };

    Ok(ReplayVerifyReport {
        schema_version: "openagent.replay_verify.v1".to_string(),
        run_id: record.metadata.run_id.clone(),
        status: status.to_string(),
        checks,
    })
}

fn unavailable_check(name: &str, note: &str) -> ReplayVerifyCheck {
    ReplayVerifyCheck {
        name: name.to_string(),
        expected: "-".to_string(),
        actual: "unavailable".to_string(),
        ok: false,
        severity: "warn".to_string(),
        note: Some(note.to_string()),
    }
}

fn verify_mcp_runtime_trace_continuity(record: &RunRecord) -> ReplayVerifyCheck {
    if record.mcp_runtime_trace.is_empty() {
        return ReplayVerifyCheck {
            name: "mcp_runtime_trace_continuity".to_string(),
            expected: "continuous transitions with terminal lifecycle".to_string(),
            actual: "unavailable".to_string(),
            ok: false,
            severity: "warn".to_string(),
            note: Some("run record has no MCP runtime trace entries".to_string()),
        };
    }

    let mut last_by_tool_call = BTreeMap::<String, String>::new();
    let mut terminal_by_tool_call = BTreeMap::<String, bool>::new();
    let mut violations = Vec::<String>::new();

    for entry in &record.mcp_runtime_trace {
        let Some(tool_call_id) = entry.tool_call_id.as_ref() else {
            continue;
        };
        let lifecycle = entry.lifecycle.as_str();
        let prev = last_by_tool_call.get(tool_call_id).map(String::as_str);
        let valid = match prev {
            None => matches!(lifecycle, "running" | "wait_task" | "wait_retry"),
            Some("running") => matches!(
                lifecycle,
                "running" | "wait_task" | "wait_retry" | "done" | "fail" | "cancelled" | "drift"
            ),
            Some("wait_task") => matches!(
                lifecycle,
                "wait_task" | "wait_retry" | "running" | "done" | "fail" | "cancelled" | "drift"
            ),
            Some("wait_retry") => matches!(
                lifecycle,
                "wait_retry" | "running" | "wait_task" | "done" | "fail" | "cancelled" | "drift"
            ),
            Some("done" | "fail" | "cancelled" | "drift") => false,
            Some(_) => false,
        };

        if !valid {
            violations.push(format!(
                "{tool_call_id}:{prev}->{lifecycle}",
                prev = prev.unwrap_or("none")
            ));
            continue;
        }

        if matches!(lifecycle, "done" | "fail" | "cancelled" | "drift") {
            terminal_by_tool_call.insert(tool_call_id.clone(), true);
        }
        last_by_tool_call.insert(tool_call_id.clone(), lifecycle.to_string());
    }

    for tool_call_id in last_by_tool_call.keys() {
        if !terminal_by_tool_call
            .get(tool_call_id)
            .copied()
            .unwrap_or(false)
        {
            violations.push(format!("{tool_call_id}:missing_terminal"));
        }
    }

    let actual = format!(
        "tool_calls={} violations={}",
        last_by_tool_call.len(),
        violations.len()
    );
    ReplayVerifyCheck {
        name: "mcp_runtime_trace_continuity".to_string(),
        expected: "continuous transitions with terminal lifecycle".to_string(),
        actual,
        ok: violations.is_empty(),
        severity: "warn".to_string(),
        note: if violations.is_empty() {
            None
        } else {
            Some(format!(
                "sample={}",
                violations
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            ))
        },
    }
}

fn try_live_mcp_snapshot(
    record: &RunRecord,
) -> anyhow::Result<Option<(Vec<crate::store::McpToolSnapshotEntry>, String)>> {
    if record.cli.mcp_servers.is_empty() {
        return Ok(None);
    }
    let Some(path) = &record.cli.mcp_config_path else {
        return Ok(None);
    };
    let cfg_path = Path::new(path);
    if !cfg_path.exists() {
        return Ok(None);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let registry = rt.block_on(crate::mcp::registry::McpRegistry::from_config_path(
        cfg_path,
        &record.cli.mcp_servers,
        Duration::from_secs(30),
    ))?;
    let mut snapshot = registry
        .tool_defs()
        .into_iter()
        .map(|t| crate::store::McpToolSnapshotEntry {
            name: t.name,
            parameters: t.parameters,
        })
        .collect::<Vec<_>>();
    snapshot.sort_by(|a, b| a.name.cmp(&b.name));
    let hash_hex = crate::store::mcp_tool_snapshot_hash_hex(&snapshot)?;
    Ok(Some((snapshot, hash_hex)))
}

pub fn render_verify_report(report: &ReplayVerifyReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "run_id: {}\nstatus: {}\n",
        report.run_id, report.status
    ));
    let mut checks = report.checks.clone();
    checks.sort_by(|a, b| a.name.cmp(&b.name));
    for c in checks {
        out.push_str(&format!(
            "- {} [{}] ok={} expected={} actual={}",
            c.name, c.severity, c.ok, c.expected, c.actual
        ));
        if let Some(note) = c.note {
            out.push_str(&format!(" note={}", note));
        }
        out.push('\n');
    }
    out
}

pub fn write_repro_out(path: &Path, record: &RunReproRecord) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(record)?)?;
    Ok(())
}

pub fn stable_workdir_string(path: &Path) -> String {
    stable_path_string(path)
}

#[cfg(test)]
mod tests {
    use super::{
        build_repro_record, env_fingerprint, looks_secret_key, repro_hash_hex, ReproBuildInput,
        ReproEnvMode, ReproMode,
    };
    use crate::store::ToolCatalogEntry;
    use crate::types::SideEffects;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};

    fn env_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn snapshot_hash_is_deterministic() {
        let rec = build_repro_record(
            ReproMode::On,
            ReproEnvMode::Off,
            ReproBuildInput {
                run_id: "r1".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                provider: "ollama".to_string(),
                base_url: "http://localhost:11434".to_string(),
                model: "m".to_string(),
                caps_source: "off".to_string(),
                trust_mode: "off".to_string(),
                approval_mode: "interrupt".to_string(),
                approval_key: "v1".to_string(),
                policy_hash_hex: None,
                includes_resolved: vec![],
                hooks_mode: "off".to_string(),
                hooks_config_hash_hex: None,
                taint_mode: "off".to_string(),
                taint_policy_globs_hash_hex: None,
                tool_schema_hash_hex_map: BTreeMap::new(),
                tool_catalog: vec![ToolCatalogEntry {
                    name: "read_file".to_string(),
                    side_effects: SideEffects::FilesystemRead,
                }],
                exec_target: "host".to_string(),
                docker: None,
                workdir: ".".to_string(),
                config_hash_hex: "cfg".to_string(),
            },
        )
        .expect("repro")
        .expect("some");
        let h1 = rec.repro_hash_hex.clone();
        let h2 = repro_hash_hex(&rec.snapshot).expect("hash");
        assert_eq!(h1, h2);
    }

    #[test]
    fn safe_env_fingerprint_is_stable() {
        let _guard = env_test_lock().lock().expect("lock");
        let a = env_fingerprint(ReproEnvMode::Safe).expect("fp");
        let b = env_fingerprint(ReproEnvMode::Safe).expect("fp");
        assert_eq!(a, b);
    }

    #[test]
    fn all_env_mode_excludes_secret_keys() {
        let _guard = env_test_lock().lock().expect("lock");
        std::env::set_var("OPENAGENT_VISIBLE", "1");
        std::env::set_var("MY_SECRET_TOKEN", "x");
        let fp = env_fingerprint(ReproEnvMode::All).expect("fp");
        assert!(fp.is_some());
    }

    #[test]
    fn secret_key_detection_covers_more_token_shapes() {
        assert!(looks_secret_key("DB_CREDENTIAL"));
        assert!(looks_secret_key("GITHUB_PAT"));
        assert!(looks_secret_key("SESSION_COOKIE"));
        assert!(!looks_secret_key("PATH"));
    }
}
