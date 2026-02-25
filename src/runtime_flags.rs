use crate::agent::PlanToolEnforcementMode;
use crate::planner::RunMode;
use crate::session::ExplicitFlags;

pub(crate) fn parse_explicit_flags() -> ExplicitFlags {
    let mut out = ExplicitFlags::default();
    for arg in std::env::args() {
        if arg == "--max-context-chars" || arg.starts_with("--max-context-chars=") {
            out.max_context_chars = true;
        } else if arg == "--compaction-mode" || arg.starts_with("--compaction-mode=") {
            out.compaction_mode = true;
        } else if arg == "--compaction-keep-last" || arg.starts_with("--compaction-keep-last=") {
            out.compaction_keep_last = true;
        } else if arg == "--tool-result-persist" || arg.starts_with("--tool-result-persist=") {
            out.tool_result_persist = true;
        } else if arg == "--tool-args-strict" || arg.starts_with("--tool-args-strict=") {
            out.tool_args_strict = true;
        } else if arg == "--caps" || arg.starts_with("--caps=") {
            out.caps_mode = true;
        } else if arg == "--hooks" || arg.starts_with("--hooks=") {
            out.hooks_mode = true;
        }
    }
    out
}

pub(crate) fn has_explicit_plan_tool_enforcement_flag() -> bool {
    std::env::args()
        .any(|arg| arg == "--enforce-plan-tools" || arg.starts_with("--enforce-plan-tools="))
}

pub(crate) fn resolve_plan_tool_enforcement(
    mode: RunMode,
    configured: PlanToolEnforcementMode,
    explicit: bool,
) -> PlanToolEnforcementMode {
    if matches!(mode, RunMode::PlannerWorker)
        && matches!(configured, PlanToolEnforcementMode::Off)
        && !explicit
    {
        PlanToolEnforcementMode::Hard
    } else {
        configured
    }
}
