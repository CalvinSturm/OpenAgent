use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::watch;

use crate::agent::{
    self, Agent, AgentExitReason, PlanToolEnforcementMode, PolicyLoadedInfo, ToolCallBudget,
};
use crate::compaction::CompactionSettings;
use crate::events::{Event, EventKind};
use crate::gate::{ApprovalMode, GateContext, ProviderKind};
use crate::hooks::runner::{HookManager, HookRuntimeConfig};
use crate::mcp::registry::McpRegistry;
use crate::ops_helpers;
use crate::packs;
use crate::planner;
use crate::project_guidance;
use crate::providers::ModelProvider;
use crate::repo_map;
use crate::repro;
use crate::repro::ReproEnvMode;
use crate::run_prep;
use crate::runtime_events;
use crate::runtime_flags;
use crate::runtime_paths;
use crate::runtime_wiring;
use crate::session::{
    self, settings_from_run, task_memory_message, RunSettingInputs, SessionStore,
};
use crate::store::{self, PlannerRunRecord, WorkerRunRecord};
use crate::store::{config_hash_hex, extract_session_messages, provider_to_string};
use crate::taint;
use crate::taint::TaintToggle;
use crate::target::{DockerTarget, ExecTarget, ExecTargetKind, HostTarget};
use crate::tools::ToolRuntime;
use crate::trust;
use crate::trust::policy::Policy;
use crate::types::{Message, Role};
use crate::{instruction_runtime, planner_runtime, tui, DockerNetwork, RunArgs};
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_agent<P: ModelProvider>(
    provider: P,
    provider_kind: ProviderKind,
    base_url: &str,
    default_model: &str,
    prompt: &str,
    args: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<RunExecutionResult> {
    run_agent_with_ui(
        provider,
        provider_kind,
        base_url,
        default_model,
        prompt,
        args,
        paths,
        None,
        None,
        None,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_agent_with_ui<P: ModelProvider>(
    provider: P,
    provider_kind: ProviderKind,
    base_url: &str,
    default_model: &str,
    prompt: &str,
    args: &RunArgs,
    paths: &store::StatePaths,
    external_ui_tx: Option<Sender<Event>>,
    external_operator_queue_rx: Option<
        std::sync::mpsc::Receiver<crate::operator_queue::QueueSubmitRequest>,
    >,
    shared_mcp_registry: Option<std::sync::Arc<McpRegistry>>,
    suppress_stdout_stream: bool,
) -> anyhow::Result<RunExecutionResult> {
    let workdir = std::fs::canonicalize(&args.workdir)
        .with_context(|| format!("failed to resolve workdir: {}", args.workdir.display()))?;
    let exec_target: std::sync::Arc<dyn ExecTarget> = match args.exec_target {
        ExecTargetKind::Host => std::sync::Arc::new(HostTarget),
        ExecTargetKind::Docker => {
            DockerTarget::validate_available().with_context(|| {
                "docker execution target requested. Install/start Docker or re-run with --exec-target host"
            })?;
            std::sync::Arc::new(DockerTarget::new(
                args.docker_image.clone(),
                args.docker_workdir.clone(),
                match args.docker_network {
                    DockerNetwork::None => "none",
                    DockerNetwork::Bridge => "bridge",
                }
                .to_string(),
                args.docker_user.clone(),
            ))
        }
    };
    let resolved_target_kind = exec_target.kind();
    let _target_desc = exec_target.describe();
    let mut gate_ctx = GateContext {
        workdir: workdir.clone(),
        allow_shell: args.allow_shell || args.allow_shell_in_workdir,
        allow_write: args.allow_write,
        approval_mode: args.approval_mode,
        auto_approve_scope: args.auto_approve_scope,
        unsafe_mode: args.unsafe_mode,
        unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
        run_id: None,
        enable_write_tools: args.enable_write_tools,
        max_tool_output_bytes: if args.no_limits {
            0
        } else {
            args.max_tool_output_bytes
        },
        max_read_bytes: if args.no_limits {
            0
        } else {
            args.max_read_bytes
        },
        provider: provider_kind,
        model: default_model.to_string(),
        exec_target: resolved_target_kind,
        approval_key_version: args.approval_key,
        tool_schema_hashes: std::collections::BTreeMap::new(),
        hooks_config_hash_hex: None,
        planner_hash_hex: None,
        taint_enabled: matches!(args.taint, TaintToggle::On),
        taint_mode: args.taint_mode,
        taint_overall: taint::TaintLevel::Clean,
        taint_sources: Vec::new(),
    };
    let gate_build = runtime_wiring::build_gate(args, paths)?;
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
    let gate = gate_build.gate;

    let planner_strict_effective = if args.no_planner_strict {
        false
    } else {
        args.planner_strict
    };
    let planner_model = args
        .planner_model
        .clone()
        .unwrap_or_else(|| default_model.to_string());
    let worker_model = args
        .worker_model
        .clone()
        .unwrap_or_else(|| default_model.to_string());
    let plan_enforcement_explicit = runtime_flags::has_explicit_plan_tool_enforcement_flag();
    let effective_plan_tool_enforcement = runtime_flags::resolve_plan_tool_enforcement(
        args.mode,
        args.enforce_plan_tools,
        plan_enforcement_explicit,
    );
    gate_ctx.model = worker_model.clone();

    let session_path = paths.sessions_dir.join(format!("{}.json", args.session));
    let session_store = SessionStore::new(session_path.clone(), args.session.clone());
    if !args.no_session && args.reset_session {
        session_store.reset()?;
    }
    let mut session_data = if args.no_session {
        session::SessionData::empty(&args.session)
    } else {
        session_store.load()?
    };
    let explicit_flags = runtime_flags::parse_explicit_flags();
    let resolved_settings = session::resolve_run_settings(
        args.use_session_settings,
        !args.no_session,
        &session_data,
        &explicit_flags,
        RunSettingInputs {
            max_context_chars: args.max_context_chars,
            compaction_mode: args.compaction_mode,
            compaction_keep_last: args.compaction_keep_last,
            tool_result_persist: args.tool_result_persist,
            tool_args_strict: args.tool_args_strict,
            caps_mode: args.caps,
            hooks_mode: args.hooks,
        },
    );
    let session_messages = if args.no_session {
        Vec::new()
    } else {
        session_data.messages.clone()
    };
    let task_memory = if args.no_session {
        None
    } else {
        task_memory_message(&session_data.task_memory)
    };
    let instruction_resolution =
        instruction_runtime::resolve_instruction_messages(args, &paths.state_dir, &worker_model)?;
    let project_guidance_resolution = project_guidance::resolve_project_guidance(
        &args.workdir,
        project_guidance::ProjectGuidanceLimits::default(),
    )
    .ok()
    .filter(|g| !g.merged_text.is_empty());
    let repo_map_resolution = if args.use_repomap {
        repo_map::resolve_repo_map(
            &args.workdir,
            repo_map::RepoMapLimits {
                max_out_bytes: args.repomap_max_bytes,
                ..repo_map::RepoMapLimits::default()
            },
        )
        .ok()
        .filter(|m| !m.content.is_empty())
    } else {
        None
    };
    let activated_packs = if args.packs.is_empty() {
        Vec::new()
    } else {
        packs::activate_packs(&args.workdir, &args.packs, packs::PackLimits::default())?
    };

    let mcp_config_path = runtime_paths::resolved_mcp_config_path(args, &paths.state_dir);
    let mcp_registry = if let Some(reg) = shared_mcp_registry {
        Some(reg)
    } else if args.mcp.is_empty() {
        None
    } else {
        Some(std::sync::Arc::new(
            McpRegistry::from_config_path(&mcp_config_path, &args.mcp, Duration::from_secs(30))
                .await?,
        ))
    };

    let prep = run_prep::prepare_tools_and_qualification(run_prep::PrepareToolsInput {
        provider: &provider,
        provider_kind,
        base_url,
        worker_model: &worker_model,
        args,
        state_dir: &paths.state_dir,
        mcp_config_path: &mcp_config_path,
        mcp_registry: mcp_registry.as_ref(),
        policy_for_exposure: gate_build.policy_for_exposure.as_ref(),
    })
    .await?;
    let all_tools = prep.all_tools;
    let mcp_tool_snapshot = prep.mcp_tool_snapshot;
    let qualification_fallback_note = prep.qualification_fallback_note;
    if let Some(note) = &qualification_fallback_note {
        eprintln!("WARN: {note}");
    }
    let mcp_tool_catalog_hash_hex = prep.mcp_tool_catalog_hash_hex;
    let mcp_tool_docs_hash_hex = prep.mcp_tool_docs_hash_hex;
    let mcp_config_hash_hex = prep.mcp_config_hash_hex;
    let mcp_startup_live_catalog_hash_hex = prep.mcp_startup_live_catalog_hash_hex;
    let mcp_startup_live_docs_hash_hex = prep.mcp_startup_live_docs_hash_hex;
    let mcp_snapshot_pinned = prep.mcp_snapshot_pinned;
    let mcp_pin_enforcement = format!("{:?}", args.mcp_pin_enforcement).to_lowercase();
    let hooks_config_path = runtime_paths::resolved_hooks_config_path(args, &paths.state_dir);
    let tool_schema_hash_hex_map = store::tool_schema_hash_hex_map(&all_tools);
    gate_ctx.tool_schema_hashes = tool_schema_hash_hex_map.clone();
    let hooks_config_hash_hex = ops_helpers::compute_hooks_config_hash_hex(
        resolved_settings.hooks_mode,
        &hooks_config_path,
    );
    gate_ctx.hooks_config_hash_hex = hooks_config_hash_hex.clone();
    let hook_manager = HookManager::build(HookRuntimeConfig {
        mode: resolved_settings.hooks_mode,
        config_path: hooks_config_path.clone(),
        strict: args.hooks_strict,
        timeout_ms: args.hooks_timeout_ms,
        max_stdout_bytes: args.hooks_max_stdout_bytes,
    })?;

    let tool_catalog = all_tools
        .iter()
        .map(|t| store::ToolCatalogEntry {
            name: t.name.clone(),
            side_effects: t.side_effects,
        })
        .collect::<Vec<_>>();

    let (ui_tx, ui_rx) = if args.tui {
        let (tx, rx) = std::sync::mpsc::channel();
        (Some(tx), Some(rx))
    } else {
        (external_ui_tx, None)
    };
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let ui_join = if let Some(rx) = ui_rx {
        let approvals_path = paths.approvals_path.clone();
        let cfg = tui::TuiConfig {
            refresh_ms: args.tui_refresh_ms,
            max_log_lines: args.tui_max_log_lines,
            provider: provider_to_string(provider_kind),
            model: worker_model.clone(),
            mode_label: if !args.allow_shell && !args.allow_write && !args.enable_write_tools {
                "SAFE".to_string()
            } else {
                "CODE".to_string()
            },
            authority_label: if args.approval_mode == ApprovalMode::Auto {
                "EXEC".to_string()
            } else {
                "VETO".to_string()
            },
            mcp_pin_enforcement: mcp_pin_enforcement.to_ascii_uppercase(),
            caps_source: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
            policy_hash: policy_hash_hex.clone().unwrap_or_default(),
            mcp_catalog_hash: mcp_tool_catalog_hash_hex.clone().unwrap_or_default(),
        };
        Some(std::thread::spawn(move || {
            tui::run_live(rx, approvals_path, cfg, cancel_tx.clone())
        }))
    } else {
        None
    };
    let mut event_sink = runtime_wiring::build_event_sink(
        args.stream,
        args.events.as_deref(),
        args.tui,
        ui_tx,
        suppress_stdout_stream,
    )?;

    let run_id = uuid::Uuid::new_v4().to_string();
    let mut planner_record: Option<PlannerRunRecord> = None;
    let mut worker_record: Option<WorkerRunRecord> = None;
    let mut planner_injected_message: Option<Message> = None;
    let mut plan_step_constraints: Vec<agent::PlanStepConstraint> = Vec::new();
    let mcp_pin_snapshot = if mcp_tool_catalog_hash_hex.is_some()
        || mcp_startup_live_catalog_hash_hex.is_some()
        || mcp_tool_docs_hash_hex.is_some()
        || mcp_startup_live_docs_hash_hex.is_some()
    {
        Some(store::McpPinSnapshotRecord {
            enforcement: mcp_pin_enforcement.clone(),
            configured_catalog_hash_hex: mcp_tool_catalog_hash_hex.clone().unwrap_or_default(),
            startup_live_catalog_hash_hex: mcp_startup_live_catalog_hash_hex.clone(),
            configured_docs_hash_hex: mcp_tool_docs_hash_hex.clone(),
            startup_live_docs_hash_hex: mcp_startup_live_docs_hash_hex.clone(),
            mcp_config_hash_hex: mcp_config_hash_hex.clone(),
            pinned: mcp_snapshot_pinned,
        })
    } else {
        None
    };
    runtime_events::emit_event(
        &mut event_sink,
        &run_id,
        0,
        EventKind::McpPinned,
        serde_json::json!({
            "enforcement": mcp_pin_enforcement,
            "configured_hash_hex": mcp_tool_catalog_hash_hex,
            "startup_live_hash_hex": mcp_startup_live_catalog_hash_hex,
            "configured_docs_hash_hex": mcp_tool_docs_hash_hex,
            "startup_live_docs_hash_hex": mcp_startup_live_docs_hash_hex,
            "mcp_config_hash_hex": mcp_config_hash_hex,
            "pinned": mcp_snapshot_pinned
        }),
    );
    for p in &activated_packs {
        runtime_events::emit_event(
            &mut event_sink,
            &run_id,
            0,
            EventKind::PackActivated,
            serde_json::json!({
                "schema": "openagent.pack_activated.v1",
                "pack_id": p.pack_id,
                "pack_hash_hex": p.pack_hash_hex,
                "truncated": p.truncated,
                "bytes_kept": p.bytes_kept
            }),
        );
    }
    if let Some(note) = &qualification_fallback_note {
        runtime_events::emit_event(
            &mut event_sink,
            &run_id,
            0,
            EventKind::Error,
            serde_json::json!({
                "error": note,
                "source": "orchestrator_qualification_fallback"
            }),
        );
    }

    if matches!(args.mode, planner::RunMode::PlannerWorker) {
        runtime_events::emit_event(
            &mut event_sink,
            &run_id,
            0,
            EventKind::PlannerStart,
            serde_json::json!({
                "planner_model": planner_model,
                "planner_max_steps": args.planner_max_steps,
                "planner_output": format!("{:?}", args.planner_output).to_lowercase(),
                "planner_strict": planner_strict_effective,
                "enforce_plan_tools_effective": format!("{:?}", effective_plan_tool_enforcement).to_lowercase()
            }),
        );
        let planner_out = planner_runtime::run_planner_phase(
            &provider,
            &run_id,
            &planner_model,
            prompt,
            args.planner_max_steps,
            args.planner_output,
            planner_strict_effective,
            &mut event_sink,
        )
        .await;
        match planner_out {
            Ok(out) => {
                if planner_strict_effective && !out.ok {
                    runtime_events::emit_event(
                        &mut event_sink,
                        &run_id,
                        0,
                        EventKind::PlannerEnd,
                        serde_json::json!({
                            "ok": false,
                            "planner_hash_hex": out.plan_hash_hex,
                            "error_short": out.error.clone().unwrap_or_else(|| "planner validation failed".to_string())
                        }),
                    );
                    let outcome = agent::AgentOutcome {
                        run_id: run_id.clone(),
                        started_at: trust::now_rfc3339(),
                        finished_at: trust::now_rfc3339(),
                        exit_reason: AgentExitReason::PlannerError,
                        final_output: String::new(),
                        error: out.error.clone(),
                        messages: vec![Message {
                            role: Role::Assistant,
                            content: out.raw_output.clone(),
                            tool_call_id: None,
                            tool_name: None,
                            tool_calls: None,
                        }],
                        tool_calls: Vec::new(),
                        tool_decisions: Vec::new(),
                        compaction_settings: CompactionSettings {
                            max_context_chars: resolved_settings.max_context_chars,
                            mode: resolved_settings.compaction_mode,
                            keep_last: resolved_settings.compaction_keep_last,
                            tool_result_persist: resolved_settings.tool_result_persist,
                        },
                        final_prompt_size_chars: 0,
                        compaction_report: None,
                        hook_invocations: Vec::new(),
                        provider_retry_count: 0,
                        provider_error_count: 0,
                        token_usage: None,
                        taint: None,
                    };
                    planner_record = Some(PlannerRunRecord {
                        model: planner_model.clone(),
                        max_steps: args.planner_max_steps,
                        strict: planner_strict_effective,
                        output_format: format!("{:?}", args.planner_output).to_lowercase(),
                        plan_json: out.plan_json,
                        plan_hash_hex: out.plan_hash_hex,
                        ok: false,
                        raw_output: out.raw_output,
                        error: out.error,
                    });
                    worker_record = Some(WorkerRunRecord {
                        model: worker_model.clone(),
                        injected_planner_hash_hex: None,
                        step_result_valid: None,
                        step_result_json: None,
                        step_result_error: None,
                    });
                    let cli_config =
                        runtime_paths::build_run_cli_config(runtime_paths::RunCliConfigInput {
                            provider_kind,
                            base_url,
                            model: &worker_model,
                            args,
                            resolved_settings: &resolved_settings,
                            hooks_config_path: &hooks_config_path,
                            mcp_config_path: &mcp_config_path,
                            tool_catalog: tool_catalog.clone(),
                            mcp_tool_snapshot: mcp_tool_snapshot.clone(),
                            mcp_tool_catalog_hash_hex: mcp_tool_catalog_hash_hex.clone(),
                            policy_version,
                            includes_resolved: includes_resolved.clone(),
                            mcp_allowlist: mcp_allowlist.clone(),
                            mode: args.mode,
                            planner_model: Some(planner_model.clone()),
                            worker_model: Some(worker_model.clone()),
                            planner_max_steps: Some(args.planner_max_steps),
                            planner_output: Some(
                                format!("{:?}", args.planner_output).to_lowercase(),
                            ),
                            planner_strict: Some(planner_strict_effective),
                            enforce_plan_tools: Some(
                                format!("{:?}", effective_plan_tool_enforcement).to_lowercase(),
                            ),
                            instructions: &instruction_resolution,
                            project_guidance: project_guidance_resolution.as_ref(),
                            repo_map: repo_map_resolution.as_ref(),
                            activated_packs: &activated_packs,
                        });
                    let config_fingerprint = runtime_paths::build_config_fingerprint(
                        &cli_config,
                        args,
                        &worker_model,
                        paths,
                    );
                    let cfg_hash = config_hash_hex(&config_fingerprint)?;
                    let run_artifact_path = match store::write_run_record(
                        paths,
                        cli_config,
                        store::PolicyRecordInfo {
                            source: policy_source,
                            hash_hex: policy_hash_hex,
                            version: policy_version,
                            includes_resolved,
                            mcp_allowlist,
                        },
                        cfg_hash,
                        &outcome,
                        args.mode,
                        planner_record,
                        worker_record,
                        tool_schema_hash_hex_map.clone(),
                        hooks_config_hash_hex.clone(),
                        Some(config_fingerprint.clone()),
                        None,
                        Vec::new(),
                        mcp_pin_snapshot.clone(),
                    ) {
                        Ok(p) => Some(p),
                        Err(write_err) => {
                            eprintln!("WARN: failed to write run artifact: {write_err}");
                            None
                        }
                    };
                    if let Some(h) = ui_join {
                        let _ = h.join();
                    }
                    return Ok(RunExecutionResult {
                        outcome,
                        run_artifact_path,
                    });
                }
                runtime_events::emit_event(
                    &mut event_sink,
                    &run_id,
                    0,
                    EventKind::PlannerEnd,
                    serde_json::json!({
                        "ok": out.ok,
                        "planner_hash_hex": out.plan_hash_hex,
                        "error_short": out.error.clone().unwrap_or_default()
                    }),
                );
                let handoff = format!(
                    "{}\n\n{}",
                    planner::planner_handoff_content(&out.plan_json)?,
                    planner::planner_worker_contract_content(&out.plan_json)?
                );
                if matches!(
                    effective_plan_tool_enforcement,
                    PlanToolEnforcementMode::Soft | PlanToolEnforcementMode::Hard
                ) {
                    match planner::extract_plan_step_tools(&out.plan_json) {
                        Ok(steps) => {
                            plan_step_constraints = steps
                                .into_iter()
                                .map(|s| agent::PlanStepConstraint {
                                    step_id: s.step_id,
                                    intended_tools: s.intended_tools,
                                })
                                .collect();
                        }
                        Err(e) => {
                            eprintln!("WARN: failed to extract plan step constraints: {e}");
                        }
                    }
                }
                planner_injected_message = Some(Message {
                    role: Role::Developer,
                    content: Some(handoff),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                });
                gate_ctx.planner_hash_hex = Some(out.plan_hash_hex.clone());
                worker_record = Some(WorkerRunRecord {
                    model: worker_model.clone(),
                    injected_planner_hash_hex: Some(out.plan_hash_hex.clone()),
                    step_result_valid: None,
                    step_result_json: None,
                    step_result_error: None,
                });
                planner_record = Some(PlannerRunRecord {
                    model: planner_model.clone(),
                    max_steps: args.planner_max_steps,
                    strict: planner_strict_effective,
                    output_format: format!("{:?}", args.planner_output).to_lowercase(),
                    plan_json: out.plan_json,
                    plan_hash_hex: out.plan_hash_hex,
                    ok: out.ok,
                    raw_output: out.raw_output,
                    error: out.error,
                });
                runtime_events::emit_event(
                    &mut event_sink,
                    &run_id,
                    0,
                    EventKind::WorkerStart,
                    serde_json::json!({
                        "worker_model": worker_model,
                        "planner_hash_hex": planner_record.as_ref().map(|p| p.plan_hash_hex.clone()).unwrap_or_default(),
                        "enforce_plan_tools_effective": format!("{:?}", effective_plan_tool_enforcement).to_lowercase()
                    }),
                );
            }
            Err(e) => {
                let err_short = e.to_string();
                runtime_events::emit_event(
                    &mut event_sink,
                    &run_id,
                    0,
                    EventKind::PlannerEnd,
                    serde_json::json!({
                        "ok": false,
                        "planner_hash_hex": "",
                        "error_short": err_short
                    }),
                );
                let outcome = agent::AgentOutcome {
                    run_id: run_id.clone(),
                    started_at: trust::now_rfc3339(),
                    finished_at: trust::now_rfc3339(),
                    exit_reason: AgentExitReason::PlannerError,
                    final_output: String::new(),
                    error: Some(e.to_string()),
                    messages: vec![Message {
                        role: Role::User,
                        content: Some(prompt.to_string()),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    }],
                    tool_calls: Vec::new(),
                    tool_decisions: Vec::new(),
                    compaction_settings: CompactionSettings {
                        max_context_chars: resolved_settings.max_context_chars,
                        mode: resolved_settings.compaction_mode,
                        keep_last: resolved_settings.compaction_keep_last,
                        tool_result_persist: resolved_settings.tool_result_persist,
                    },
                    final_prompt_size_chars: 0,
                    compaction_report: None,
                    hook_invocations: Vec::new(),
                    provider_retry_count: 0,
                    provider_error_count: 0,
                    token_usage: None,
                    taint: None,
                };
                let cli_config =
                    runtime_paths::build_run_cli_config(runtime_paths::RunCliConfigInput {
                        provider_kind,
                        base_url,
                        model: &worker_model,
                        args,
                        resolved_settings: &resolved_settings,
                        hooks_config_path: &hooks_config_path,
                        mcp_config_path: &mcp_config_path,
                        tool_catalog: tool_catalog.clone(),
                        mcp_tool_snapshot: mcp_tool_snapshot.clone(),
                        mcp_tool_catalog_hash_hex: mcp_tool_catalog_hash_hex.clone(),
                        policy_version,
                        includes_resolved: includes_resolved.clone(),
                        mcp_allowlist: mcp_allowlist.clone(),
                        mode: args.mode,
                        planner_model: Some(planner_model.clone()),
                        worker_model: Some(worker_model.clone()),
                        planner_max_steps: Some(args.planner_max_steps),
                        planner_output: Some(format!("{:?}", args.planner_output).to_lowercase()),
                        planner_strict: Some(planner_strict_effective),
                        enforce_plan_tools: Some(
                            format!("{:?}", effective_plan_tool_enforcement).to_lowercase(),
                        ),
                        instructions: &instruction_resolution,
                        project_guidance: project_guidance_resolution.as_ref(),
                        repo_map: repo_map_resolution.as_ref(),
                        activated_packs: &activated_packs,
                    });
                let config_fingerprint = runtime_paths::build_config_fingerprint(
                    &cli_config,
                    args,
                    &worker_model,
                    paths,
                );
                let cfg_hash = config_hash_hex(&config_fingerprint)?;
                let run_artifact_path = match store::write_run_record(
                    paths,
                    cli_config,
                    store::PolicyRecordInfo {
                        source: policy_source,
                        hash_hex: policy_hash_hex,
                        version: policy_version,
                        includes_resolved,
                        mcp_allowlist,
                    },
                    cfg_hash,
                    &outcome,
                    args.mode,
                    planner_record,
                    worker_record,
                    tool_schema_hash_hex_map.clone(),
                    hooks_config_hash_hex.clone(),
                    Some(config_fingerprint.clone()),
                    None,
                    Vec::new(),
                    mcp_pin_snapshot.clone(),
                ) {
                    Ok(p) => Some(p),
                    Err(write_err) => {
                        eprintln!("WARN: failed to write run artifact: {write_err}");
                        None
                    }
                };
                if let Some(h) = ui_join {
                    let _ = h.join();
                }
                return Ok(RunExecutionResult {
                    outcome,
                    run_artifact_path,
                });
            }
        }
    }

    let mut agent = Agent {
        provider,
        model: worker_model.clone(),
        tools: all_tools,
        max_steps: args.max_steps,
        tool_rt: ToolRuntime {
            workdir,
            allow_shell: args.allow_shell,
            allow_shell_in_workdir_only: args.allow_shell_in_workdir,
            allow_write: args.allow_write,
            max_tool_output_bytes: if args.no_limits {
                0
            } else {
                args.max_tool_output_bytes
            },
            max_read_bytes: if args.no_limits {
                0
            } else {
                args.max_read_bytes
            },
            unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
            tool_args_strict: resolved_settings.tool_args_strict,
            exec_target_kind: resolved_target_kind,
            exec_target,
        },
        gate,
        gate_ctx,
        mcp_registry,
        stream: args.stream,
        event_sink,
        compaction_settings: CompactionSettings {
            max_context_chars: resolved_settings.max_context_chars,
            mode: resolved_settings.compaction_mode,
            keep_last: resolved_settings.compaction_keep_last,
            tool_result_persist: resolved_settings.tool_result_persist,
        },
        hooks: hook_manager,
        policy_loaded: policy_loaded_info,
        policy_for_taint: gate_build.policy_for_exposure.clone(),
        taint_toggle: args.taint,
        taint_mode: args.taint_mode,
        taint_digest_bytes: args.taint_digest_bytes,
        run_id_override: Some(run_id.clone()),
        omit_tools_field_when_empty: false,
        plan_tool_enforcement: effective_plan_tool_enforcement,
        mcp_pin_enforcement: args.mcp_pin_enforcement,
        plan_step_constraints,
        tool_call_budget: ToolCallBudget {
            max_wall_time_ms: if args.no_limits {
                0
            } else {
                args.max_wall_time_ms
            },
            max_total_tool_calls: args.max_total_tool_calls,
            max_mcp_calls: args.max_mcp_calls,
            max_filesystem_read_calls: args.max_filesystem_read_calls,
            max_filesystem_write_calls: args.max_filesystem_write_calls,
            max_shell_calls: args.max_shell_calls,
            max_network_calls: args.max_network_calls,
            max_browser_calls: args.max_browser_calls,
        },
        mcp_runtime_trace: Vec::new(),
        operator_queue: crate::operator_queue::PendingMessageQueue::default(),
        operator_queue_limits: crate::operator_queue::QueueLimits::default(),
        operator_queue_rx: external_operator_queue_rx,
    };

    let base_instruction_messages = instruction_resolution.messages.clone();
    let project_guidance_message = project_guidance_resolution
        .as_ref()
        .and_then(project_guidance::project_guidance_message);
    let repo_map_message = repo_map_resolution
        .as_ref()
        .and_then(repo_map::repo_map_message);
    let pack_guidance_message = packs::pack_guidance_message(&activated_packs);
    let base_task_memory = task_memory.clone();
    let initial_injected_messages = runtime_paths::merge_injected_messages(
        base_instruction_messages.clone(),
        project_guidance_message.clone(),
        repo_map_message.clone(),
        pack_guidance_message.clone(),
        base_task_memory.clone(),
        planner_injected_message.clone(),
    );

    let mut outcome = tokio::select! {
        out = agent.run(
            prompt,
            session_messages.clone(),
            initial_injected_messages,
        ) => out,
        _ = tokio::signal::ctrl_c() => {
            agent::AgentOutcome {
                run_id: uuid::Uuid::new_v4().to_string(),
                started_at: trust::now_rfc3339(),
                finished_at: trust::now_rfc3339(),
                exit_reason: AgentExitReason::Cancelled,
                final_output: String::new(),
                error: Some("cancelled".to_string()),
                messages: Vec::new(),
                tool_calls: Vec::new(),
                tool_decisions: Vec::new(),
                compaction_settings: CompactionSettings {
                    max_context_chars: resolved_settings.max_context_chars,
                    mode: resolved_settings.compaction_mode,
                    keep_last: resolved_settings.compaction_keep_last,
                    tool_result_persist: resolved_settings.tool_result_persist,
                },
                final_prompt_size_chars: 0,
                compaction_report: None,
                hook_invocations: Vec::new(),
                provider_retry_count: 0,
                provider_error_count: 0,
                token_usage: None,
                taint: None,
            }
        },
        _ = async {
            let _ = cancel_rx.changed().await;
        } => {
            agent::AgentOutcome {
                run_id: uuid::Uuid::new_v4().to_string(),
                started_at: trust::now_rfc3339(),
                finished_at: trust::now_rfc3339(),
                exit_reason: AgentExitReason::Cancelled,
                final_output: String::new(),
                error: Some("cancelled".to_string()),
                messages: Vec::new(),
                tool_calls: Vec::new(),
                tool_decisions: Vec::new(),
                compaction_settings: CompactionSettings {
                    max_context_chars: resolved_settings.max_context_chars,
                    mode: resolved_settings.compaction_mode,
                    keep_last: resolved_settings.compaction_keep_last,
                    tool_result_persist: resolved_settings.tool_result_persist,
                },
                final_prompt_size_chars: 0,
                compaction_report: None,
                hook_invocations: Vec::new(),
                provider_retry_count: 0,
                provider_error_count: 0,
                token_usage: None,
                taint: None,
            }
        }
    };

    if matches!(args.mode, planner::RunMode::PlannerWorker)
        && matches!(outcome.exit_reason, AgentExitReason::PlannerError)
        && outcome
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("worker requested replan transition")
    {
        let replanner_reason = outcome
            .error
            .clone()
            .unwrap_or_else(|| "worker requested replan transition".to_string());
        runtime_events::emit_event(
            &mut agent.event_sink,
            &run_id,
            0,
            EventKind::PlannerStart,
            serde_json::json!({
                "phase": "replan",
                "reason": replanner_reason
            }),
        );
        let prior_plan_json = planner_record
            .as_ref()
            .map(|p| p.plan_json.clone())
            .unwrap_or_else(|| serde_json::json!({}));
        let prior_plan_hash = planner_record
            .as_ref()
            .map(|p| p.plan_hash_hex.clone())
            .unwrap_or_default();
        let prior_plan_text =
            serde_json::to_string_pretty(&prior_plan_json).unwrap_or_else(|_| "{}".to_string());
        let replan_prompt = format!(
            "{prompt}\n\nREPLAN CONTEXT\nPrevious plan hash: {prior_plan_hash}\nPrevious normalized plan:\n{prior_plan_text}\n\nRuntime requested a replan because: {replanner_reason}\nReturn an updated openagent.plan.v1 JSON plan for remaining work only."
        );
        match planner_runtime::run_planner_phase(
            &agent.provider,
            &run_id,
            &planner_model,
            &replan_prompt,
            args.planner_max_steps,
            args.planner_output,
            planner_strict_effective,
            &mut agent.event_sink,
        )
        .await
        {
            Ok(replan_out) if !planner_strict_effective || replan_out.ok => {
                runtime_events::emit_event(
                    &mut agent.event_sink,
                    &run_id,
                    0,
                    EventKind::PlannerEnd,
                    serde_json::json!({
                        "phase": "replan",
                        "ok": replan_out.ok,
                        "planner_hash_hex": replan_out.plan_hash_hex,
                        "lineage_parent_plan_hash_hex": prior_plan_hash
                    }),
                );
                let replan_handoff = format!(
                    "{}\n\n{}",
                    planner::planner_handoff_content(&replan_out.plan_json)?,
                    planner::planner_worker_contract_content(&replan_out.plan_json)?
                );
                if matches!(
                    effective_plan_tool_enforcement,
                    PlanToolEnforcementMode::Soft | PlanToolEnforcementMode::Hard
                ) {
                    if let Ok(steps) = planner::extract_plan_step_tools(&replan_out.plan_json) {
                        agent.plan_step_constraints = steps
                            .into_iter()
                            .map(|s| agent::PlanStepConstraint {
                                step_id: s.step_id,
                                intended_tools: s.intended_tools,
                            })
                            .collect();
                    }
                }
                planner_record = Some(PlannerRunRecord {
                    model: planner_model.clone(),
                    max_steps: args.planner_max_steps,
                    strict: planner_strict_effective,
                    output_format: format!("{:?}", args.planner_output).to_lowercase(),
                    plan_json: replan_out.plan_json.clone(),
                    plan_hash_hex: replan_out.plan_hash_hex.clone(),
                    ok: replan_out.ok,
                    raw_output: replan_out.raw_output,
                    error: replan_out.error,
                });
                agent.gate_ctx.planner_hash_hex = Some(replan_out.plan_hash_hex.clone());
                if let Some(worker) = worker_record.as_mut() {
                    worker.injected_planner_hash_hex = Some(replan_out.plan_hash_hex.clone());
                }
                runtime_events::emit_event(
                    &mut agent.event_sink,
                    &run_id,
                    0,
                    EventKind::WorkerStart,
                    serde_json::json!({
                        "phase": "replan_resume",
                        "worker_model": worker_model,
                        "planner_hash_hex": replan_out.plan_hash_hex,
                        "enforce_plan_tools_effective": format!("{:?}", effective_plan_tool_enforcement).to_lowercase()
                    }),
                );
                let resume_session_messages = extract_session_messages(&outcome.messages);
                let replan_injected = runtime_paths::merge_injected_messages(
                    base_instruction_messages.clone(),
                    project_guidance_message.clone(),
                    repo_map_message.clone(),
                    pack_guidance_message.clone(),
                    base_task_memory.clone(),
                    Some(Message {
                        role: Role::Developer,
                        content: Some(replan_handoff),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    }),
                );
                outcome = tokio::select! {
                    out = agent.run(prompt, resume_session_messages, replan_injected) => out,
                    _ = tokio::signal::ctrl_c() => {
                        agent::AgentOutcome {
                            run_id: uuid::Uuid::new_v4().to_string(),
                            started_at: trust::now_rfc3339(),
                            finished_at: trust::now_rfc3339(),
                            exit_reason: AgentExitReason::Cancelled,
                            final_output: String::new(),
                            error: Some("cancelled".to_string()),
                            messages: Vec::new(),
                            tool_calls: Vec::new(),
                            tool_decisions: Vec::new(),
                            compaction_settings: CompactionSettings {
                                max_context_chars: resolved_settings.max_context_chars,
                                mode: resolved_settings.compaction_mode,
                                keep_last: resolved_settings.compaction_keep_last,
                                tool_result_persist: resolved_settings.tool_result_persist,
                            },
                            final_prompt_size_chars: 0,
                            compaction_report: None,
                            hook_invocations: Vec::new(),
                            provider_retry_count: 0,
                            provider_error_count: 0,
                            token_usage: None,
                            taint: None,
                        }
                    },
                    _ = async {
                        let _ = cancel_rx.changed().await;
                    } => {
                        agent::AgentOutcome {
                            run_id: uuid::Uuid::new_v4().to_string(),
                            started_at: trust::now_rfc3339(),
                            finished_at: trust::now_rfc3339(),
                            exit_reason: AgentExitReason::Cancelled,
                            final_output: String::new(),
                            error: Some("cancelled".to_string()),
                            messages: Vec::new(),
                            tool_calls: Vec::new(),
                            tool_decisions: Vec::new(),
                            compaction_settings: CompactionSettings {
                                max_context_chars: resolved_settings.max_context_chars,
                                mode: resolved_settings.compaction_mode,
                                keep_last: resolved_settings.compaction_keep_last,
                                tool_result_persist: resolved_settings.tool_result_persist,
                            },
                            final_prompt_size_chars: 0,
                            compaction_report: None,
                            hook_invocations: Vec::new(),
                            provider_retry_count: 0,
                            provider_error_count: 0,
                            token_usage: None,
                            taint: None,
                        }
                    }
                };
            }
            Ok(replan_out) => {
                outcome.exit_reason = AgentExitReason::PlannerError;
                outcome.error = Some(format!(
                    "replan failed strict validation: {}",
                    replan_out
                        .error
                        .unwrap_or_else(|| "planner validation failed".to_string())
                ));
            }
            Err(e) => {
                outcome.exit_reason = AgentExitReason::PlannerError;
                outcome.error = Some(format!("replan failed: {e}"));
            }
        }
    }

    if matches!(outcome.exit_reason, AgentExitReason::Cancelled) {
        if let Some(sink) = &mut agent.event_sink {
            if let Err(e) = sink.emit(Event::new(
                outcome.run_id.clone(),
                0,
                EventKind::RunEnd,
                serde_json::json!({"exit_reason":"cancelled"}),
            )) {
                eprintln!("WARN: failed to emit cancellation event: {e}");
            }
        }
    }
    if matches!(args.mode, planner::RunMode::PlannerWorker) {
        let mut step_result_json = None;
        let mut step_result_error = None;
        let mut step_result_valid = None;
        if let Some(plan) = planner_record.as_ref() {
            match planner::normalize_worker_step_result(&outcome.final_output, &plan.plan_json) {
                Ok(v) => {
                    step_result_json = Some(v);
                    step_result_valid = Some(true);
                }
                Err(e) => {
                    let err = e.to_string();
                    if planner_strict_effective
                        && matches!(outcome.exit_reason, AgentExitReason::Ok)
                    {
                        outcome.exit_reason = AgentExitReason::PlannerError;
                        outcome.error = Some(format!(
                            "worker step result validation failed in strict planner_worker mode: {err}"
                        ));
                    }
                    step_result_error = Some(err);
                    step_result_valid = Some(false);
                }
            }
        }
        if let Some(worker) = worker_record.as_mut() {
            worker.step_result_valid = step_result_valid;
            worker.step_result_json = step_result_json;
            worker.step_result_error = step_result_error;
        }
    }
    if let Some(h) = ui_join {
        if let Err(_e) = h.join() {
            eprintln!("WARN: tui thread ended unexpectedly");
        }
    }
    if !args.no_session {
        session_data.messages = extract_session_messages(&outcome.messages);
        session_data.settings = settings_from_run(&resolved_settings);
        if let Err(e) = session_store.save(&session_data, args.max_session_messages) {
            eprintln!("WARN: failed to save session: {e}");
        }
    }

    if worker_record.is_none() {
        worker_record = Some(WorkerRunRecord {
            model: worker_model.clone(),
            injected_planner_hash_hex: planner_record.as_ref().map(|p| p.plan_hash_hex.clone()),
            step_result_valid: None,
            step_result_json: None,
            step_result_error: None,
        });
    }
    let cli_config = runtime_paths::build_run_cli_config(runtime_paths::RunCliConfigInput {
        provider_kind,
        base_url,
        model: &worker_model,
        args,
        resolved_settings: &resolved_settings,
        hooks_config_path: &hooks_config_path,
        mcp_config_path: &mcp_config_path,
        tool_catalog: tool_catalog.clone(),
        mcp_tool_snapshot: mcp_tool_snapshot.clone(),
        mcp_tool_catalog_hash_hex: mcp_tool_catalog_hash_hex.clone(),
        policy_version,
        includes_resolved: includes_resolved.clone(),
        mcp_allowlist: mcp_allowlist.clone(),
        mode: args.mode,
        planner_model: Some(planner_model.clone()),
        worker_model: Some(worker_model.clone()),
        planner_max_steps: Some(args.planner_max_steps),
        planner_output: Some(format!("{:?}", args.planner_output).to_lowercase()),
        planner_strict: Some(planner_strict_effective),
        enforce_plan_tools: Some(format!("{:?}", effective_plan_tool_enforcement).to_lowercase()),
        instructions: &instruction_resolution,
        project_guidance: project_guidance_resolution.as_ref(),
        repo_map: repo_map_resolution.as_ref(),
        activated_packs: &activated_packs,
    });
    let config_fingerprint =
        runtime_paths::build_config_fingerprint(&cli_config, args, &worker_model, paths);
    let config_hash_hex = config_hash_hex(&config_fingerprint)?;
    let repro_record = repro::build_repro_record(
        args.repro,
        args.repro_env,
        repro::ReproBuildInput {
            run_id: outcome.run_id.clone(),
            created_at: crate::trust::now_rfc3339(),
            provider: provider_to_string(provider_kind),
            base_url: base_url.to_string(),
            model: worker_model.clone(),
            caps_source: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
            trust_mode: store::cli_trust_mode(args.trust),
            approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
            approval_key: args.approval_key.as_str().to_string(),
            policy_hash_hex: policy_hash_hex.clone(),
            includes_resolved: includes_resolved.clone(),
            hooks_mode: format!("{:?}", resolved_settings.hooks_mode).to_lowercase(),
            hooks_config_hash_hex: hooks_config_hash_hex.clone(),
            taint_mode: format!("{:?}", args.taint_mode).to_lowercase(),
            taint_policy_globs_hash_hex: policy_hash_hex.clone(),
            tool_schema_hash_hex_map: tool_schema_hash_hex_map.clone(),
            tool_catalog: tool_catalog.clone(),
            exec_target: format!("{:?}", args.exec_target).to_lowercase(),
            docker: if matches!(args.exec_target, ExecTargetKind::Docker) {
                Some(repro::ReproDocker {
                    image: args.docker_image.clone(),
                    workdir: args.docker_workdir.clone(),
                    network: format!("{:?}", args.docker_network).to_lowercase(),
                    user: args.docker_user.clone(),
                })
            } else {
                None
            },
            workdir: repro::stable_workdir_string(&args.workdir),
            config_hash_hex: config_hash_hex.clone(),
        },
    )?;
    if let Some(r) = &repro_record {
        runtime_events::emit_event(
            &mut agent.event_sink,
            &outcome.run_id,
            0,
            EventKind::ReproSnapshot,
            serde_json::json!({
                "enabled": true,
                "env_mode": r.env_mode,
                "repro_hash_hex": r.repro_hash_hex
            }),
        );
        if matches!(args.repro_env, ReproEnvMode::All) {
            eprintln!(
                "WARN: repro-env=all enabled; sensitive-like env vars are excluded from hash material."
            );
        }
        if let Some(path) = &args.repro_out {
            if let Err(e) = repro::write_repro_out(path, r) {
                eprintln!("WARN: failed to write repro snapshot: {e}");
            }
        }
    }
    agent.event_sink = None;
    let run_artifact_path = match store::write_run_record(
        paths,
        cli_config,
        store::PolicyRecordInfo {
            source: policy_source,
            hash_hex: policy_hash_hex,
            version: policy_version,
            includes_resolved,
            mcp_allowlist,
        },
        config_hash_hex,
        &outcome,
        args.mode,
        planner_record,
        worker_record,
        tool_schema_hash_hex_map,
        hooks_config_hash_hex,
        Some(config_fingerprint.clone()),
        repro_record,
        agent.mcp_runtime_trace.clone(),
        mcp_pin_snapshot,
    ) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("WARN: failed to write run artifact: {e}");
            None
        }
    };

    if !suppress_stdout_stream {
        if args.tui {
            if !outcome.final_output.is_empty() {
                println!("{}", outcome.final_output);
            }
        } else if !args.stream {
            println!("{}", outcome.final_output);
        }
    }

    Ok(RunExecutionResult {
        outcome,
        run_artifact_path,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct RunExecutionResult {
    pub(crate) outcome: agent::AgentOutcome,
    pub(crate) run_artifact_path: Option<PathBuf>,
}
