use std::path::PathBuf;

use anyhow::anyhow;
use clap::ValueEnum;

use crate::compaction::{CompactionMode, ToolResultPersist};
use crate::gate::{ApprovalMode, AutoApproveScope, ProviderKind, TrustMode};
use crate::hooks::config::HooksMode;
use crate::planner;
use crate::session::CapsMode;
use crate::taskgraph::{TaskDefaults, TaskFile, TaskNodeSettings};
use crate::RunArgs;

pub(crate) fn resolve_node_workdir(
    taskfile: &TaskFile,
    node_id: &str,
    run_workdir: &std::path::Path,
) -> anyhow::Result<PathBuf> {
    let base = if std::path::Path::new(&taskfile.workdir.path).is_absolute() {
        PathBuf::from(&taskfile.workdir.path)
    } else {
        run_workdir.join(&taskfile.workdir.path)
    };
    let mode = taskfile.workdir.mode.to_lowercase();
    if mode == "shared" {
        std::fs::create_dir_all(&base)?;
        return Ok(base);
    }
    if mode != "per_node" {
        return Err(anyhow!(
            "unsupported taskfile workdir.mode: {}",
            taskfile.workdir.mode
        ));
    }
    let template = if taskfile.workdir.per_node_dirname.is_empty() {
        "{id}"
    } else {
        taskfile.workdir.per_node_dirname.as_str()
    };
    let dirname = template.replace("{id}", node_id);
    let path = base.join(dirname);
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

pub(crate) fn apply_task_defaults(args: &mut RunArgs, d: &TaskDefaults) -> anyhow::Result<()> {
    apply_task_settings(args, d, None)
}

pub(crate) fn apply_node_overrides(
    args: &mut RunArgs,
    s: &TaskNodeSettings,
) -> anyhow::Result<()> {
    apply_task_settings(
        args,
        &TaskDefaults {
            mode: s.mode.clone(),
            provider: s.provider.clone(),
            base_url: s.base_url.clone(),
            model: s.model.clone(),
            planner_model: s.planner_model.clone(),
            worker_model: s.worker_model.clone(),
            trust: s.trust.clone(),
            approval_mode: s.approval_mode.clone(),
            auto_approve_scope: s.auto_approve_scope.clone(),
            caps: s.caps.clone(),
            hooks: s.hooks.clone(),
            compaction: s.compaction.clone(),
            limits: s.limits.clone(),
            flags: s.flags.clone(),
            mcp: s.mcp.clone().unwrap_or_default(),
        },
        s.mcp.as_ref(),
    )
}

fn apply_task_settings(
    args: &mut RunArgs,
    s: &TaskDefaults,
    explicit_mcp: Option<&Vec<String>>,
) -> anyhow::Result<()> {
    if let Some(v) = &s.mode {
        args.mode = parse_enum::<planner::RunMode>(v, "mode")?;
    }
    if let Some(v) = &s.provider {
        args.provider = Some(parse_enum::<ProviderKind>(v, "provider")?);
    }
    if let Some(v) = &s.base_url {
        args.base_url = Some(v.clone());
    }
    if let Some(v) = &s.model {
        args.model = Some(v.clone());
    }
    if let Some(v) = &s.planner_model {
        args.planner_model = Some(v.clone());
    }
    if let Some(v) = &s.worker_model {
        args.worker_model = Some(v.clone());
    }
    if let Some(v) = &s.trust {
        args.trust = parse_enum::<TrustMode>(v, "trust")?;
    }
    if let Some(v) = &s.approval_mode {
        args.approval_mode = parse_enum::<ApprovalMode>(v, "approval_mode")?;
    }
    if let Some(v) = &s.auto_approve_scope {
        args.auto_approve_scope = parse_enum::<AutoApproveScope>(v, "auto_approve_scope")?;
    }
    if let Some(v) = &s.caps {
        args.caps = parse_enum::<CapsMode>(v, "caps")?;
    }
    if let Some(v) = &s.hooks {
        args.hooks = parse_enum::<HooksMode>(v, "hooks")?;
    }
    if let Some(v) = s.compaction.max_context_chars {
        args.max_context_chars = v;
    }
    if let Some(v) = &s.compaction.mode {
        args.compaction_mode = parse_enum::<CompactionMode>(v, "compaction.mode")?;
    }
    if let Some(v) = s.compaction.keep_last {
        args.compaction_keep_last = v;
    }
    if let Some(v) = &s.compaction.tool_result_persist {
        args.tool_result_persist =
            parse_enum::<ToolResultPersist>(v, "compaction.tool_result_persist")?;
    }
    if let Some(v) = s.limits.max_read_bytes {
        args.max_read_bytes = v;
    }
    if let Some(v) = s.limits.max_tool_output_bytes {
        args.max_tool_output_bytes = v;
    }
    if let Some(v) = s.flags.enable_write_tools {
        args.enable_write_tools = v;
    }
    if let Some(v) = s.flags.allow_write {
        args.allow_write = v;
    }
    if let Some(v) = s.flags.allow_shell {
        args.allow_shell = v;
    }
    if let Some(v) = s.flags.stream {
        args.stream = v;
    }
    if let Some(mcp) = explicit_mcp {
        args.mcp = mcp.clone();
    } else if !s.mcp.is_empty() {
        args.mcp = s.mcp.clone();
    }
    Ok(())
}

fn parse_enum<T: ValueEnum + Clone>(value: &str, field: &str) -> anyhow::Result<T> {
    let normalized = value.replace('_', "-");
    T::from_str(&normalized, true).map_err(|_| anyhow!("invalid value '{}' for {}", value, field))
}
