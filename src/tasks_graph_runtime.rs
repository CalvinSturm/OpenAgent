use anyhow::anyhow;

use crate::agent::AgentExitReason;
use crate::events::EventKind;
use crate::provider_runtime;
use crate::providers::mock::MockProvider;
use crate::providers::ollama::OllamaProvider;
use crate::providers::openai_compat::OpenAiCompatProvider;
use crate::runtime_events;
use crate::runtime_wiring;
use crate::store::{self, stable_path_string};
use crate::task_apply;
use crate::taskgraph;
use crate::trust;
use crate::{run_agent, ProviderKind, RunArgs, TasksRunArgs};

pub(crate) async fn run_tasks_graph(
    args: &TasksRunArgs,
    base_run: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<i32> {
    let (taskfile, taskfile_hash_hex, _raw_bytes) = taskgraph::load_taskfile(&args.taskfile)?;
    let order = taskgraph::topo_order(&taskfile)?;
    let checkpoint_path = args
        .checkpoint
        .clone()
        .unwrap_or_else(|| taskgraph::checkpoint_default_path(&paths.state_dir));
    let mut checkpoint =
        taskgraph::load_or_init_checkpoint(&checkpoint_path, &taskfile, &taskfile_hash_hex)?;
    taskgraph::ensure_resume_allowed(&checkpoint, args.resume)?;
    taskgraph::write_checkpoint(&checkpoint_path, &checkpoint)?;

    let graph_run_id = uuid::Uuid::new_v4().to_string();
    let graph_started = trust::now_rfc3339();
    let mut sink =
        runtime_wiring::build_event_sink(false, base_run.events.as_deref(), false, None, false)?;
    runtime_events::emit_event(
        &mut sink,
        &graph_run_id,
        0,
        EventKind::TaskgraphStart,
        serde_json::json!({
            "graph_run_id": graph_run_id,
            "taskfile_hash_hex": taskfile_hash_hex,
            "nodes": order.len()
        }),
    );

    let mut status = "ok".to_string();
    let mut node_records: std::collections::BTreeMap<String, taskgraph::TaskGraphNodeRecord> =
        std::collections::BTreeMap::new();
    let mut summaries: Vec<String> = Vec::new();
    let mut executed = 0u32;
    for (idx, node_id) in order.iter().enumerate() {
        if args.max_nodes > 0 && executed >= args.max_nodes {
            break;
        }
        let cp_node = checkpoint
            .nodes
            .get(node_id)
            .ok_or_else(|| anyhow!("checkpoint missing node {node_id}"))?
            .clone();
        if args.resume && cp_node.status == "done" {
            runtime_events::emit_event(
                &mut sink,
                &graph_run_id,
                idx as u32,
                EventKind::TaskgraphNodeEnd,
                serde_json::json!({
                    "node_id": node_id,
                    "status":"skipped",
                    "run_id": cp_node.run_id.unwrap_or_default(),
                    "exit_reason":"already_done"
                }),
            );
            continue;
        }

        runtime_events::emit_event(
            &mut sink,
            &graph_run_id,
            idx as u32,
            EventKind::TaskgraphNodeStart,
            serde_json::json!({
                "node_id": node_id,
                "index": idx + 1,
                "total": order.len()
            }),
        );
        let node = taskgraph::node_by_id(&taskfile, node_id)?;
        let mut node_args = base_run.clone();
        task_apply::apply_task_defaults(&mut node_args, &taskfile.defaults)?;
        task_apply::apply_node_overrides(&mut node_args, &node.settings)?;
        node_args.tui = false;
        node_args.stream = node_args.stream && !base_run.tui;
        let node_workdir = task_apply::resolve_node_workdir(&taskfile, node_id, &node_args.workdir)?;
        node_args.workdir = node_workdir;
        node_args.prompt = Some(
            if args.propagate_summaries.enabled() && !summaries.is_empty() {
                format!(
                    "NODE SUMMARIES (v1)\n{}\n\nTASK:\n{}",
                    summaries.join("\n"),
                    node.prompt
                )
            } else {
                node.prompt.clone()
            },
        );

        let run_id = uuid::Uuid::new_v4().to_string();
        if let Some(n) = checkpoint.nodes.get_mut(node_id) {
            n.status = "running".to_string();
            n.run_id = Some(run_id.clone());
            n.started_at = Some(trust::now_rfc3339());
            n.finished_at = None;
            n.exit_reason = None;
            n.error_short = None;
        }
        checkpoint.updated_at = trust::now_rfc3339();
        taskgraph::write_checkpoint(&checkpoint_path, &checkpoint)?;

        let provider_kind = node_args
            .provider
            .ok_or_else(|| anyhow!("provider must be set in task defaults or node settings"))?;
        let model = node_args
            .model
            .clone()
            .ok_or_else(|| anyhow!("model must be set in task defaults or node settings"))?;
        let base_url = node_args
            .base_url
            .clone()
            .unwrap_or_else(|| provider_runtime::default_base_url(provider_kind).to_string());
        let prompt = node_args
            .prompt
            .clone()
            .ok_or_else(|| anyhow!("node prompt missing"))?;

        let result = match provider_kind {
            ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
                let provider = OpenAiCompatProvider::new(
                    base_url.clone(),
                    node_args.api_key.clone(),
                    provider_runtime::http_config_from_run_args(&node_args),
                )?;
                run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    &prompt,
                    &node_args,
                    paths,
                )
                .await?
            }
            ProviderKind::Ollama => {
                let provider = OllamaProvider::new(
                    base_url.clone(),
                    provider_runtime::http_config_from_run_args(&node_args),
                )?;
                run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    &prompt,
                    &node_args,
                    paths,
                )
                .await?
            }
            ProviderKind::Mock => {
                let provider = MockProvider::new();
                run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    &prompt,
                    &node_args,
                    paths,
                )
                .await?
            }
        };
        executed = executed.saturating_add(1);
        let exit_reason = result.outcome.exit_reason.as_str().to_string();
        let node_status = if matches!(result.outcome.exit_reason, AgentExitReason::Ok) {
            "done".to_string()
        } else {
            "failed".to_string()
        };
        if matches!(result.outcome.exit_reason, AgentExitReason::Cancelled) {
            status = "cancelled".to_string();
        }
        if let Some(n) = checkpoint.nodes.get_mut(node_id) {
            n.status = node_status.clone();
            n.run_id = Some(result.outcome.run_id.clone());
            n.finished_at = Some(trust::now_rfc3339());
            n.exit_reason = Some(exit_reason.clone());
            n.artifact_path = result
                .run_artifact_path
                .as_ref()
                .map(|p| stable_path_string(p));
            n.error_short = result
                .outcome
                .error
                .as_deref()
                .map(runtime_events::short_error);
        }
        checkpoint.updated_at = trust::now_rfc3339();
        taskgraph::write_checkpoint(&checkpoint_path, &checkpoint)?;
        node_records.insert(
            node_id.clone(),
            taskgraph::TaskGraphNodeRecord {
                run_id: result.outcome.run_id.clone(),
                status: node_status.clone(),
                artifact_path: result
                    .run_artifact_path
                    .as_ref()
                    .map(|p| stable_path_string(p))
                    .unwrap_or_default(),
            },
        );

        runtime_events::emit_event(
            &mut sink,
            &graph_run_id,
            idx as u32,
            EventKind::TaskgraphNodeEnd,
            serde_json::json!({
                "node_id": node_id,
                "status": node_status,
                "run_id": result.outcome.run_id,
                "exit_reason": exit_reason
            }),
        );

        if args.propagate_summaries.enabled() {
            summaries.push(runtime_events::node_summary_line(
                node_id,
                result.outcome.exit_reason.as_str(),
                &result.outcome.final_output,
            ));
        }
        if args.fail_fast && !matches!(result.outcome.exit_reason, AgentExitReason::Ok) {
            if status != "cancelled" {
                status = "failed".to_string();
            }
            break;
        }
    }
    if status == "ok" {
        let any_failed = checkpoint.nodes.values().any(|n| n.status == "failed");
        if any_failed {
            status = "failed".to_string();
        }
    }
    runtime_events::emit_event(
        &mut sink,
        &graph_run_id,
        order.len() as u32,
        EventKind::TaskgraphEnd,
        serde_json::json!({"status": status}),
    );
    let graph = taskgraph::TaskGraphRunArtifact {
        schema_version: "openagent.taskgraph_run.v1".to_string(),
        graph_run_id: graph_run_id.clone(),
        taskfile_path: stable_path_string(&args.taskfile),
        taskfile_hash_hex: taskfile_hash_hex.clone(),
        started_at: graph_started,
        finished_at: trust::now_rfc3339(),
        status: status.clone(),
        node_order: order.clone(),
        nodes: node_records,
        config: serde_json::json!({
            "defaults": taskfile.defaults,
            "workdir": taskfile.workdir
        }),
        propagate_summaries: args.propagate_summaries.enabled(),
    };
    let graph_path = taskgraph::write_graph_run_artifact(&paths.state_dir, &graph)?;
    println!("task graph artifact: {}", graph_path.display());
    Ok(if status == "ok" { 0 } else { 1 })
}
