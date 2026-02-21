use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent::{Agent, AgentExitReason, AgentOutcome, PolicyLoadedInfo};
use crate::compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
use crate::eval::assert::evaluate_assertions;
use crate::eval::tasks::{tasks_for_pack, EvalPack, EvalTask, Fixture};
use crate::gate::{
    compute_policy_hash_hex, ApprovalMode, AutoApproveScope, GateContext, NoGate, ProviderKind,
    ToolGate, TrustGate, TrustMode,
};
use crate::hooks::config::HooksMode;
use crate::hooks::runner::{HookManager, HookRuntimeConfig};
use crate::mcp::registry::{list_servers, McpRegistry};
use crate::providers::http::HttpConfig;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai_compat::OpenAiCompatProvider;
use crate::providers::ModelProvider;
use crate::store::{
    config_hash_hex, provider_to_string, resolve_state_paths, stable_path_string,
    ConfigFingerprintV1, RunCliConfig, StatePaths,
};
use crate::tools::{builtin_tools_enabled, ToolArgsStrict, ToolRuntime};
use crate::trust::approvals::ApprovalsStore;
use crate::trust::audit::AuditLog;
use crate::trust::policy::{McpAllowSummary, Policy};

#[derive(Debug, Clone)]
pub struct EvalConfig {
    pub provider: ProviderKind,
    pub base_url: String,
    pub api_key: Option<String>,
    pub models: Vec<String>,
    pub pack: EvalPack,
    pub out: Option<PathBuf>,
    pub runs_per_task: usize,
    pub max_steps: usize,
    pub timeout_seconds: u64,
    pub trust: TrustMode,
    pub approval_mode: ApprovalMode,
    pub auto_approve_scope: AutoApproveScope,
    pub enable_write_tools: bool,
    pub allow_write: bool,
    pub allow_shell: bool,
    pub unsafe_mode: bool,
    pub no_limits: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub mcp: Vec<String>,
    pub mcp_config: Option<PathBuf>,
    pub session: String,
    pub no_session: bool,
    pub max_session_messages: usize,
    pub max_context_chars: usize,
    pub compaction_mode: CompactionMode,
    pub compaction_keep_last: usize,
    pub tool_result_persist: ToolResultPersist,
    pub hooks_mode: HooksMode,
    pub hooks_config: Option<PathBuf>,
    pub hooks_strict: bool,
    pub hooks_timeout_ms: u64,
    pub hooks_max_stdout_bytes: usize,
    pub tool_args_strict: ToolArgsStrict,
    pub tui_enabled: bool,
    pub tui_refresh_ms: u64,
    pub tui_max_log_lines: usize,
    pub state_dir_override: Option<PathBuf>,
    pub policy_override: Option<PathBuf>,
    pub approvals_override: Option<PathBuf>,
    pub audit_override: Option<PathBuf>,
    pub workdir_override: Option<PathBuf>,
    pub keep_workdir: bool,
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResults {
    pub schema_version: String,
    pub created_at: String,
    pub config: EvalResultsConfig,
    pub summary: EvalSummary,
    pub by_model: BTreeMap<String, ModelSummary>,
    pub runs: Vec<EvalRunRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResultsConfig {
    pub provider: String,
    pub base_url: String,
    pub models: Vec<String>,
    pub pack: String,
    pub runs_per_task: usize,
    pub max_steps: usize,
    pub timeout_seconds: u64,
    pub trust_mode: String,
    pub approval_mode: String,
    pub auto_approve_scope: String,
    pub allow_shell: bool,
    pub allow_write: bool,
    pub enable_write_tools: bool,
    pub unsafe_mode: bool,
    pub no_limits: bool,
    pub unsafe_bypass_allow_flags: bool,
    pub mcp: Vec<String>,
    pub no_session: bool,
    pub session: String,
    pub max_context_chars: usize,
    pub compaction_mode: String,
    pub compaction_keep_last: usize,
    pub tool_result_persist: String,
    pub hooks_mode: String,
    pub hooks_config_path: String,
    pub hooks_strict: bool,
    pub hooks_timeout_ms: u64,
    pub hooks_max_stdout_bytes: usize,
    pub tool_args_strict: String,
    pub tui_enabled: bool,
    pub tui_refresh_ms: u64,
    pub tui_max_log_lines: usize,
    pub http_max_retries: u32,
    pub http_timeout_ms: u64,
    pub http_connect_timeout_ms: u64,
    pub http_stream_idle_timeout_ms: u64,
    pub http_max_response_bytes: usize,
    pub http_max_line_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalSummary {
    pub total_runs: usize,
    pub passed: usize,
    pub failed: usize,
    pub pass_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelSummary {
    pub passed: usize,
    pub failed: usize,
    pub tasks: BTreeMap<String, TaskSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskSummary {
    pub passed: usize,
    pub failed: usize,
    pub runs: Vec<EvalRunRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRunRow {
    pub model: String,
    pub task_id: String,
    pub run_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    pub run_id: String,
    pub exit_reason: String,
    pub passed: bool,
    pub failures: Vec<String>,
    pub stats: EvalRunStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRunStats {
    pub steps: usize,
    pub tool_calls: usize,
}

pub async fn run_eval(config: EvalConfig, cwd: &Path) -> anyhow::Result<PathBuf> {
    if config.models.is_empty() {
        return Err(anyhow!("--models is required and must not be empty"));
    }
    let base_workdir = if let Some(path) = &config.workdir_override {
        std::fs::canonicalize(path)
            .with_context(|| format!("failed to resolve --workdir {}", path.display()))?
    } else {
        std::fs::canonicalize(cwd)
            .with_context(|| "failed to resolve current workdir".to_string())?
    };

    let state_paths = resolve_state_paths(
        &base_workdir,
        config.state_dir_override.clone(),
        config.policy_override.clone(),
        config.approvals_override.clone(),
        config.audit_override.clone(),
    );
    if state_paths.using_legacy_dir {
        eprintln!(
            "WARN: using legacy state dir at {}",
            state_paths.state_dir.display()
        );
    }

    let mcp_config_path = config
        .mcp_config
        .clone()
        .unwrap_or_else(|| state_paths.state_dir.join("mcp_servers.json"));
    let mut enabled_mcp = config.mcp.clone();
    let tasks = tasks_for_pack(config.pack);
    let has_browser_tasks = tasks.iter().any(|t| t.needs_playwright && !t.optional);
    if has_browser_tasks
        && !enabled_mcp.iter().any(|m| m == "playwright")
        && list_servers(&mcp_config_path)
            .map(|names| names.iter().any(|n| n == "playwright"))
            .unwrap_or(false)
    {
        enabled_mcp.push("playwright".to_string());
    }

    let out_path = config.out.clone().unwrap_or_else(|| {
        let ts = crate::trust::now_rfc3339().replace(':', "-");
        state_paths
            .state_dir
            .join("eval")
            .join(format!("results_{ts}.json"))
    });

    let mut results = EvalResults {
        schema_version: "openagent.eval.v1".to_string(),
        created_at: crate::trust::now_rfc3339(),
        config: EvalResultsConfig {
            provider: provider_to_string(config.provider),
            base_url: config.base_url.clone(),
            models: config.models.clone(),
            pack: format!("{:?}", config.pack).to_lowercase(),
            runs_per_task: config.runs_per_task,
            max_steps: config.max_steps,
            timeout_seconds: config.timeout_seconds,
            trust_mode: format!("{:?}", config.trust).to_lowercase(),
            approval_mode: format!("{:?}", config.approval_mode).to_lowercase(),
            auto_approve_scope: format!("{:?}", config.auto_approve_scope).to_lowercase(),
            allow_shell: config.allow_shell,
            allow_write: config.allow_write,
            enable_write_tools: config.enable_write_tools,
            unsafe_mode: config.unsafe_mode,
            no_limits: config.no_limits,
            unsafe_bypass_allow_flags: config.unsafe_bypass_allow_flags,
            mcp: enabled_mcp.clone(),
            no_session: config.no_session,
            session: config.session.clone(),
            max_context_chars: config.max_context_chars,
            compaction_mode: format!("{:?}", config.compaction_mode).to_lowercase(),
            compaction_keep_last: config.compaction_keep_last,
            tool_result_persist: format!("{:?}", config.tool_result_persist).to_lowercase(),
            hooks_mode: format!("{:?}", config.hooks_mode).to_lowercase(),
            hooks_config_path: config
                .hooks_config
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| {
                    state_paths
                        .state_dir
                        .join("hooks.yaml")
                        .display()
                        .to_string()
                }),
            hooks_strict: config.hooks_strict,
            hooks_timeout_ms: config.hooks_timeout_ms,
            hooks_max_stdout_bytes: config.hooks_max_stdout_bytes,
            tool_args_strict: format!("{:?}", config.tool_args_strict).to_lowercase(),
            tui_enabled: config.tui_enabled,
            tui_refresh_ms: config.tui_refresh_ms,
            tui_max_log_lines: config.tui_max_log_lines,
            http_max_retries: config.http.http_max_retries,
            http_timeout_ms: config.http.request_timeout_ms,
            http_connect_timeout_ms: config.http.connect_timeout_ms,
            http_stream_idle_timeout_ms: config.http.stream_idle_timeout_ms,
            http_max_response_bytes: config.http.max_response_bytes,
            http_max_line_bytes: config.http.max_line_bytes,
        },
        summary: EvalSummary::default(),
        by_model: BTreeMap::new(),
        runs: Vec::new(),
    };

    for model in &config.models {
        for task in &tasks {
            if task.optional {
                continue;
            }
            if task.needs_write && !config.allow_write && !config.unsafe_bypass_allow_flags {
                let row = skipped_row(
                    model,
                    task,
                    0,
                    "skipped: coding pack requires --allow-write (or --unsafe-bypass-allow-flags)",
                );
                print_row(&row);
                push_row(&mut results, row);
                continue;
            }
            if task.needs_playwright && !enabled_mcp.iter().any(|m| m == "playwright") {
                let row = skipped_row(
                    model,
                    task,
                    0,
                    "skipped: browser pack requires MCP playwright",
                );
                print_row(&row);
                push_row(&mut results, row);
                continue;
            }
            if let Some(reason) =
                missing_required_tool_reason(task, config.enable_write_tools, &enabled_mcp)
            {
                let row = skipped_row(model, task, 0, &reason);
                print_row(&row);
                push_row(&mut results, row);
                continue;
            }

            for run_index in 0..config.runs_per_task {
                let run_dir = create_run_workdir(config.workdir_override.as_deref())?;
                apply_fixtures(&run_dir, &task.fixtures)?;

                let timeout = Duration::from_secs(config.timeout_seconds);
                let exec = run_single(&config, &state_paths, &run_dir, &enabled_mcp, model, task);
                let row = match tokio::time::timeout(timeout, exec).await {
                    Ok(Ok(mut row)) => {
                        row.run_index = run_index;
                        if config.keep_workdir || config.workdir_override.is_some() {
                            row.workdir = Some(run_dir.display().to_string());
                        }
                        row
                    }
                    Ok(Err(e)) => {
                        let run_id = Uuid::new_v4().to_string();
                        write_synthetic_error_artifact(
                            &config,
                            &state_paths,
                            model,
                            &run_id,
                            format!("run error: {e}"),
                        );
                        EvalRunRow {
                            model: model.clone(),
                            task_id: task.id.clone(),
                            run_index,
                            workdir: if config.keep_workdir || config.workdir_override.is_some() {
                                Some(run_dir.display().to_string())
                            } else {
                                None
                            },
                            run_id,
                            exit_reason: "provider_error".to_string(),
                            passed: false,
                            failures: vec![format!("run error: {e}")],
                            stats: EvalRunStats {
                                steps: 0,
                                tool_calls: 0,
                            },
                        }
                    }
                    Err(_) => {
                        let run_id = Uuid::new_v4().to_string();
                        write_synthetic_error_artifact(
                            &config,
                            &state_paths,
                            model,
                            &run_id,
                            "timeout".to_string(),
                        );
                        EvalRunRow {
                            model: model.clone(),
                            task_id: task.id.clone(),
                            run_index,
                            workdir: if config.keep_workdir || config.workdir_override.is_some() {
                                Some(run_dir.display().to_string())
                            } else {
                                None
                            },
                            run_id,
                            exit_reason: "timeout".to_string(),
                            passed: false,
                            failures: vec!["timeout".to_string()],
                            stats: EvalRunStats {
                                steps: 0,
                                tool_calls: 0,
                            },
                        }
                    }
                };
                if config.workdir_override.is_none() && !config.keep_workdir {
                    let _ = std::fs::remove_dir_all(&run_dir);
                }
                print_row(&row);
                push_row(&mut results, row);
            }
        }
    }

    finalize_summary(&mut results);
    write_results(&out_path, &results)?;
    println!("eval results written: {}", out_path.display());
    Ok(out_path)
}

fn write_synthetic_error_artifact(
    config: &EvalConfig,
    state_paths: &StatePaths,
    model: &str,
    run_id: &str,
    error: String,
) {
    let now = crate::trust::now_rfc3339();
    let outcome = AgentOutcome {
        run_id: run_id.to_string(),
        started_at: now.clone(),
        finished_at: now,
        exit_reason: AgentExitReason::ProviderError,
        final_output: String::new(),
        error: Some(error),
        messages: Vec::new(),
        tool_calls: Vec::new(),
        tool_decisions: Vec::new(),
        compaction_settings: CompactionSettings {
            max_context_chars: config.max_context_chars,
            mode: config.compaction_mode,
            keep_last: config.compaction_keep_last,
            tool_result_persist: config.tool_result_persist,
        },
        final_prompt_size_chars: 0,
        compaction_report: None,
        hook_invocations: Vec::new(),
    };
    let _ = write_run_artifact_for_eval(
        config,
        state_paths,
        model,
        &outcome,
        Vec::new(),
        EvalPolicyMeta {
            source: "none".to_string(),
            hash_hex: None,
            version: None,
            includes_resolved: Vec::new(),
            mcp_allowlist: None,
        },
    );
}

fn push_row(results: &mut EvalResults, row: EvalRunRow) {
    let model = row.model.clone();
    let task_id = row.task_id.clone();
    let model_entry = results.by_model.entry(model.clone()).or_default();
    let task_entry = model_entry.tasks.entry(task_id).or_default();
    if row.passed {
        model_entry.passed += 1;
        task_entry.passed += 1;
    } else {
        model_entry.failed += 1;
        task_entry.failed += 1;
    }
    task_entry.runs.push(row.clone());
    results.runs.push(row);
}

fn finalize_summary(results: &mut EvalResults) {
    results.summary.total_runs = results.runs.len();
    results.summary.passed = results.runs.iter().filter(|r| r.passed).count();
    results.summary.failed = results
        .summary
        .total_runs
        .saturating_sub(results.summary.passed);
    results.summary.pass_rate = if results.summary.total_runs == 0 {
        0.0
    } else {
        results.summary.passed as f64 / results.summary.total_runs as f64
    };
}

fn print_row(row: &EvalRunRow) {
    let status = if row.passed { "PASS" } else { "FAIL" };
    println!(
        "{} | {} | {} | {} | {}",
        row.model, row.task_id, status, row.run_id, row.exit_reason
    );
}

fn missing_required_tool_reason(
    task: &EvalTask,
    enable_write_tools: bool,
    enabled_mcp: &[String],
) -> Option<String> {
    for req in &task.required_tools {
        if (req == "write_file" || req == "apply_patch") && !enable_write_tools {
            return Some(format!("skipped: required tool '{}' not enabled", req));
        }
        if req.starts_with("mcp.playwright") && !enabled_mcp.iter().any(|m| m == "playwright") {
            return Some("skipped: required MCP server 'playwright' not enabled".to_string());
        }
    }
    None
}

fn skipped_row(model: &str, task: &EvalTask, run_index: usize, reason: &str) -> EvalRunRow {
    EvalRunRow {
        model: model.to_string(),
        task_id: task.id.clone(),
        run_index,
        workdir: None,
        run_id: format!("skipped-{}", Uuid::new_v4()),
        exit_reason: "skipped".to_string(),
        passed: false,
        failures: vec![reason.to_string()],
        stats: EvalRunStats {
            steps: 0,
            tool_calls: 0,
        },
    }
}

fn create_run_workdir(override_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = override_path {
        std::fs::create_dir_all(path)?;
        return Ok(path.to_path_buf());
    }
    let path = std::env::temp_dir().join(format!("openagent-eval-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn apply_fixtures(workdir: &Path, fixtures: &[Fixture]) -> anyhow::Result<()> {
    for fx in fixtures {
        match fx {
            Fixture::WriteFile { path, content } => {
                let full = workdir.join(path);
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(full, content)?;
            }
            Fixture::CreateDir { path } => {
                std::fs::create_dir_all(workdir.join(path))?;
            }
        }
    }
    Ok(())
}

async fn run_single(
    config: &EvalConfig,
    state_paths: &StatePaths,
    workdir: &Path,
    enabled_mcp: &[String],
    model: &str,
    task: &EvalTask,
) -> anyhow::Result<EvalRunRow> {
    let gate_ctx = GateContext {
        workdir: workdir.to_path_buf(),
        allow_shell: config.allow_shell,
        allow_write: config.allow_write,
        approval_mode: config.approval_mode,
        auto_approve_scope: config.auto_approve_scope,
        unsafe_mode: config.unsafe_mode,
        unsafe_bypass_allow_flags: config.unsafe_bypass_allow_flags,
        run_id: None,
        enable_write_tools: config.enable_write_tools,
        max_tool_output_bytes: if config.no_limits { 0 } else { 200_000 },
        max_read_bytes: if config.no_limits { 0 } else { 200_000 },
        provider: config.provider,
        model: model.to_string(),
    };
    let gate_build = build_gate(config.trust, state_paths)?;
    let policy_hash_hex = gate_build.policy_hash_hex.clone();
    let policy_source = gate_build.policy_source.to_string();
    let policy_version = gate_build.policy_version;
    let includes_resolved = gate_build.includes_resolved.clone();
    let mcp_allowlist = gate_build.mcp_allowlist.clone();
    let policy_loaded_info = policy_version.map(|version| PolicyLoadedInfo {
        version,
        rules_count: gate_build
            .policy_for_exposure
            .as_ref()
            .map(Policy::rules_len)
            .unwrap_or(0),
        includes_count: includes_resolved.len(),
        includes_resolved: includes_resolved.clone(),
        mcp_allowlist: mcp_allowlist.clone(),
    });

    let mcp_config_path = config
        .mcp_config
        .clone()
        .unwrap_or_else(|| state_paths.state_dir.join("mcp_servers.json"));
    let mcp_registry = if enabled_mcp.is_empty() {
        None
    } else {
        Some(
            McpRegistry::from_config_path(&mcp_config_path, enabled_mcp, Duration::from_secs(30))
                .await?,
        )
    };

    let mut tools = builtin_tools_enabled(config.enable_write_tools);
    if let Some(reg) = &mcp_registry {
        let mut mcp_defs = reg.tool_defs();
        if let Some(policy) = &gate_build.policy_for_exposure {
            mcp_defs.retain(|t| policy.mcp_tool_allowed(&t.name).is_ok());
        }
        tools.extend(mcp_defs);
    }

    let tool_catalog = tools
        .iter()
        .map(|t| crate::store::ToolCatalogEntry {
            name: t.name.clone(),
            side_effects: t.side_effects,
        })
        .collect::<Vec<_>>();

    let provider = make_provider(
        config.provider,
        &config.base_url,
        config.api_key.clone(),
        config.http,
    )?;
    let mut agent = Agent {
        provider,
        model: model.to_string(),
        tools,
        max_steps: config.max_steps,
        tool_rt: ToolRuntime {
            workdir: workdir.to_path_buf(),
            allow_shell: config.allow_shell,
            allow_write: config.allow_write,
            max_tool_output_bytes: if config.no_limits { 0 } else { 200_000 },
            max_read_bytes: if config.no_limits { 0 } else { 200_000 },
            unsafe_bypass_allow_flags: config.unsafe_bypass_allow_flags,
            tool_args_strict: config.tool_args_strict,
        },
        gate: gate_build.gate,
        gate_ctx,
        mcp_registry,
        stream: false,
        event_sink: None,
        compaction_settings: CompactionSettings {
            max_context_chars: config.max_context_chars,
            mode: config.compaction_mode,
            keep_last: config.compaction_keep_last,
            tool_result_persist: config.tool_result_persist,
        },
        hooks: HookManager::build(HookRuntimeConfig {
            mode: config.hooks_mode,
            config_path: config
                .hooks_config
                .clone()
                .unwrap_or_else(|| state_paths.state_dir.join("hooks.yaml")),
            strict: config.hooks_strict,
            timeout_ms: config.hooks_timeout_ms,
            max_stdout_bytes: config.hooks_max_stdout_bytes,
        })?,
        policy_loaded: policy_loaded_info,
    };
    let session_messages = Vec::new();
    let outcome = agent.run(&task.prompt, session_messages).await;
    let failures = evaluate_assertions(&task.assertions, workdir, &outcome);
    let passed = failures.is_empty() && matches!(outcome.exit_reason, AgentExitReason::Ok);

    write_run_artifact_for_eval(
        config,
        state_paths,
        model,
        &outcome,
        tool_catalog,
        EvalPolicyMeta {
            source: policy_source,
            hash_hex: policy_hash_hex,
            version: policy_version,
            includes_resolved,
            mcp_allowlist,
        },
    )?;

    Ok(EvalRunRow {
        model: model.to_string(),
        task_id: task.id.clone(),
        run_index: 0,
        workdir: None,
        run_id: outcome.run_id.clone(),
        exit_reason: outcome.exit_reason.as_str().to_string(),
        passed,
        failures,
        stats: EvalRunStats {
            steps: outcome
                .messages
                .iter()
                .filter(|m| matches!(m.role, crate::types::Role::Assistant))
                .count(),
            tool_calls: outcome.tool_calls.len(),
        },
    })
}

fn write_run_artifact_for_eval(
    config: &EvalConfig,
    state_paths: &StatePaths,
    model: &str,
    outcome: &AgentOutcome,
    tool_catalog: Vec<crate::store::ToolCatalogEntry>,
    policy: EvalPolicyMeta,
) -> anyhow::Result<()> {
    let cli_config = RunCliConfig {
        provider: provider_to_string(config.provider),
        base_url: config.base_url.clone(),
        model: model.to_string(),
        trust_mode: format!("{:?}", config.trust).to_lowercase(),
        allow_shell: config.allow_shell,
        allow_write: config.allow_write,
        enable_write_tools: config.enable_write_tools,
        max_tool_output_bytes: if config.no_limits { 0 } else { 200_000 },
        max_read_bytes: if config.no_limits { 0 } else { 200_000 },
        approval_mode: format!("{:?}", config.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", config.auto_approve_scope).to_lowercase(),
        unsafe_mode: config.unsafe_mode,
        no_limits: config.no_limits,
        unsafe_bypass_allow_flags: config.unsafe_bypass_allow_flags,
        stream: false,
        events_path: None,
        max_context_chars: config.max_context_chars,
        compaction_mode: format!("{:?}", config.compaction_mode).to_lowercase(),
        compaction_keep_last: config.compaction_keep_last,
        tool_result_persist: format!("{:?}", config.tool_result_persist).to_lowercase(),
        hooks_mode: format!("{:?}", config.hooks_mode).to_lowercase(),
        hooks_config_path: config
            .hooks_config
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| {
                state_paths
                    .state_dir
                    .join("hooks.yaml")
                    .display()
                    .to_string()
            }),
        hooks_strict: config.hooks_strict,
        hooks_timeout_ms: config.hooks_timeout_ms,
        hooks_max_stdout_bytes: config.hooks_max_stdout_bytes,
        tool_args_strict: format!("{:?}", config.tool_args_strict).to_lowercase(),
        tui_enabled: config.tui_enabled,
        tui_refresh_ms: config.tui_refresh_ms,
        tui_max_log_lines: config.tui_max_log_lines,
        http_max_retries: config.http.http_max_retries,
        http_timeout_ms: config.http.request_timeout_ms,
        http_connect_timeout_ms: config.http.connect_timeout_ms,
        http_stream_idle_timeout_ms: config.http.stream_idle_timeout_ms,
        http_max_response_bytes: config.http.max_response_bytes,
        http_max_line_bytes: config.http.max_line_bytes,
        tool_catalog,
        policy_version: policy.version,
        includes_resolved: policy.includes_resolved.clone(),
        mcp_allowlist: policy.mcp_allowlist.clone(),
    };
    let fingerprint = ConfigFingerprintV1 {
        schema_version: "openagent.confighash.v1".to_string(),
        provider: provider_to_string(config.provider),
        base_url: config.base_url.clone(),
        model: model.to_string(),
        trust_mode: format!("{:?}", config.trust).to_lowercase(),
        state_dir: stable_path_string(&state_paths.state_dir),
        policy_path: stable_path_string(&state_paths.policy_path),
        approvals_path: stable_path_string(&state_paths.approvals_path),
        audit_path: stable_path_string(&state_paths.audit_path),
        allow_shell: config.allow_shell,
        allow_write: config.allow_write,
        enable_write_tools: config.enable_write_tools,
        max_steps: config.max_steps,
        max_tool_output_bytes: if config.no_limits { 0 } else { 200_000 },
        max_read_bytes: if config.no_limits { 0 } else { 200_000 },
        session_name: if config.no_session {
            String::new()
        } else {
            config.session.clone()
        },
        no_session: config.no_session,
        max_session_messages: config.max_session_messages,
        approval_mode: format!("{:?}", config.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", config.auto_approve_scope).to_lowercase(),
        unsafe_mode: config.unsafe_mode,
        no_limits: config.no_limits,
        unsafe_bypass_allow_flags: config.unsafe_bypass_allow_flags,
        stream: false,
        events_path: String::new(),
        max_context_chars: config.max_context_chars,
        compaction_mode: format!("{:?}", config.compaction_mode).to_lowercase(),
        compaction_keep_last: config.compaction_keep_last,
        tool_result_persist: format!("{:?}", config.tool_result_persist).to_lowercase(),
        hooks_mode: format!("{:?}", config.hooks_mode).to_lowercase(),
        hooks_config_path: config
            .hooks_config
            .as_ref()
            .map(|p| stable_path_string(p))
            .unwrap_or_else(|| stable_path_string(&state_paths.state_dir.join("hooks.yaml"))),
        hooks_strict: config.hooks_strict,
        hooks_timeout_ms: config.hooks_timeout_ms,
        hooks_max_stdout_bytes: config.hooks_max_stdout_bytes,
        tool_args_strict: format!("{:?}", config.tool_args_strict).to_lowercase(),
        tui_enabled: config.tui_enabled,
        tui_refresh_ms: config.tui_refresh_ms,
        tui_max_log_lines: config.tui_max_log_lines,
        http_max_retries: config.http.http_max_retries,
        http_timeout_ms: config.http.request_timeout_ms,
        http_connect_timeout_ms: config.http.connect_timeout_ms,
        http_stream_idle_timeout_ms: config.http.stream_idle_timeout_ms,
        http_max_response_bytes: config.http.max_response_bytes,
        http_max_line_bytes: config.http.max_line_bytes,
        tool_catalog_names: cli_config
            .tool_catalog
            .iter()
            .map(|t| t.name.clone())
            .collect(),
        policy_version: policy.version,
        includes_resolved: policy.includes_resolved.clone(),
        mcp_allowlist: policy.mcp_allowlist.clone(),
    };
    let cfg_hash = config_hash_hex(&fingerprint)?;
    let _ = crate::store::write_run_record(
        state_paths,
        cli_config,
        crate::store::PolicyRecordInfo {
            source: policy.source,
            hash_hex: policy.hash_hex,
            version: policy.version,
            includes_resolved: policy.includes_resolved,
            mcp_allowlist: policy.mcp_allowlist,
        },
        cfg_hash,
        outcome,
    )?;
    Ok(())
}

struct GateBuild {
    gate: Box<dyn ToolGate>,
    policy_hash_hex: Option<String>,
    policy_source: &'static str,
    policy_for_exposure: Option<Policy>,
    policy_version: Option<u32>,
    includes_resolved: Vec<String>,
    mcp_allowlist: Option<McpAllowSummary>,
}

#[derive(Debug, Clone)]
struct EvalPolicyMeta {
    source: String,
    hash_hex: Option<String>,
    version: Option<u32>,
    includes_resolved: Vec<String>,
    mcp_allowlist: Option<McpAllowSummary>,
}

fn build_gate(trust: TrustMode, paths: &StatePaths) -> anyhow::Result<GateBuild> {
    match trust {
        TrustMode::Off => Ok(GateBuild {
            gate: Box::new(NoGate::new()),
            policy_hash_hex: None,
            policy_source: "none",
            policy_for_exposure: None,
            policy_version: None,
            includes_resolved: Vec::new(),
            mcp_allowlist: None,
        }),
        TrustMode::Auto => {
            if !paths.policy_path.exists() {
                return Ok(GateBuild {
                    gate: Box::new(NoGate::new()),
                    policy_hash_hex: None,
                    policy_source: "none",
                    policy_for_exposure: None,
                    policy_version: None,
                    includes_resolved: Vec::new(),
                    mcp_allowlist: None,
                });
            }
            let bytes = std::fs::read(&paths.policy_path)?;
            let policy = Policy::from_path(&paths.policy_path).with_context(|| {
                format!("failed parsing policy {}", paths.policy_path.display())
            })?;
            let hash = compute_policy_hash_hex(&bytes);
            let policy_version = policy.version();
            let includes_resolved = policy.includes_resolved().to_vec();
            let mcp_allowlist = policy.mcp_allowlist_summary();
            Ok(GateBuild {
                gate: Box::new(TrustGate::new(
                    policy.clone(),
                    ApprovalsStore::new(paths.approvals_path.clone()),
                    AuditLog::new(paths.audit_path.clone()),
                    TrustMode::Auto,
                    hash.clone(),
                )),
                policy_hash_hex: Some(hash),
                policy_source: "file",
                policy_for_exposure: Some(policy),
                policy_version: Some(policy_version),
                includes_resolved,
                mcp_allowlist,
            })
        }
        TrustMode::On => {
            let (policy, hash, src) = if paths.policy_path.exists() {
                let bytes = std::fs::read(&paths.policy_path)?;
                let policy = Policy::from_path(&paths.policy_path).with_context(|| {
                    format!("failed parsing policy {}", paths.policy_path.display())
                })?;
                (policy, compute_policy_hash_hex(&bytes), "file")
            } else {
                let repr = crate::trust::policy::safe_default_policy_repr();
                (
                    Policy::safe_default(),
                    compute_policy_hash_hex(repr.as_bytes()),
                    "default",
                )
            };
            let policy_version = policy.version();
            let includes_resolved = policy.includes_resolved().to_vec();
            let mcp_allowlist = policy.mcp_allowlist_summary();
            Ok(GateBuild {
                gate: Box::new(TrustGate::new(
                    policy.clone(),
                    ApprovalsStore::new(paths.approvals_path.clone()),
                    AuditLog::new(paths.audit_path.clone()),
                    TrustMode::On,
                    hash.clone(),
                )),
                policy_hash_hex: Some(hash),
                policy_source: src,
                policy_for_exposure: Some(policy),
                policy_version: Some(policy_version),
                includes_resolved,
                mcp_allowlist,
            })
        }
    }
}

enum EvalProvider {
    OpenAiCompat(OpenAiCompatProvider),
    Ollama(OllamaProvider),
}

#[async_trait::async_trait]
impl ModelProvider for EvalProvider {
    async fn generate(
        &self,
        req: crate::types::GenerateRequest,
    ) -> anyhow::Result<crate::types::GenerateResponse> {
        match self {
            EvalProvider::OpenAiCompat(p) => p.generate(req).await,
            EvalProvider::Ollama(p) => p.generate(req).await,
        }
    }
}

fn make_provider(
    provider: ProviderKind,
    base_url: &str,
    api_key: Option<String>,
    http: HttpConfig,
) -> anyhow::Result<EvalProvider> {
    match provider {
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => Ok(EvalProvider::OpenAiCompat(
            OpenAiCompatProvider::new(base_url.to_string(), api_key, http)?,
        )),
        ProviderKind::Ollama => Ok(EvalProvider::Ollama(OllamaProvider::new(
            base_url.to_string(),
            http,
        )?)),
    }
}

fn write_results(path: &Path, results: &EvalResults) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(results)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{finalize_summary, EvalResults, EvalResultsConfig, EvalRunRow, EvalRunStats};

    #[test]
    fn summary_aggregation_counts_pass_fail() {
        let mut results = EvalResults {
            schema_version: "openagent.eval.v1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            config: EvalResultsConfig {
                provider: "ollama".to_string(),
                base_url: "http://localhost:11434".to_string(),
                models: vec!["m".to_string()],
                pack: "coding".to_string(),
                runs_per_task: 1,
                max_steps: 30,
                timeout_seconds: 60,
                trust_mode: "on".to_string(),
                approval_mode: "auto".to_string(),
                auto_approve_scope: "run".to_string(),
                allow_shell: false,
                allow_write: false,
                enable_write_tools: true,
                unsafe_mode: false,
                no_limits: false,
                unsafe_bypass_allow_flags: false,
                mcp: vec![],
                no_session: true,
                session: "default".to_string(),
                max_context_chars: 0,
                compaction_mode: "off".to_string(),
                compaction_keep_last: 20,
                tool_result_persist: "digest".to_string(),
                hooks_mode: "off".to_string(),
                hooks_config_path: String::new(),
                hooks_strict: false,
                hooks_timeout_ms: 2000,
                hooks_max_stdout_bytes: 200_000,
                tool_args_strict: "on".to_string(),
                tui_enabled: false,
                tui_refresh_ms: 50,
                tui_max_log_lines: 200,
                http_max_retries: 2,
                http_timeout_ms: 60_000,
                http_connect_timeout_ms: 2_000,
                http_stream_idle_timeout_ms: 15_000,
                http_max_response_bytes: 10_000_000,
                http_max_line_bytes: 200_000,
            },
            summary: Default::default(),
            by_model: BTreeMap::new(),
            runs: vec![
                EvalRunRow {
                    model: "m".to_string(),
                    task_id: "C1".to_string(),
                    run_index: 0,
                    workdir: None,
                    run_id: "r1".to_string(),
                    exit_reason: "ok".to_string(),
                    passed: true,
                    failures: vec![],
                    stats: EvalRunStats {
                        steps: 1,
                        tool_calls: 1,
                    },
                },
                EvalRunRow {
                    model: "m".to_string(),
                    task_id: "C2".to_string(),
                    run_index: 0,
                    workdir: None,
                    run_id: "r2".to_string(),
                    exit_reason: "denied".to_string(),
                    passed: false,
                    failures: vec!["x".to_string()],
                    stats: EvalRunStats {
                        steps: 1,
                        tool_calls: 1,
                    },
                },
            ],
        };
        finalize_summary(&mut results);
        assert_eq!(results.summary.total_runs, 2);
        assert_eq!(results.summary.passed, 1);
        assert_eq!(results.summary.failed, 1);
        assert!(results.summary.pass_rate > 0.4 && results.summary.pass_rate < 0.6);
    }
}
