use crate::agent::ToolCallBudget;
use crate::types::SideEffects;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ToolCallBudgetUsage {
    pub(crate) total_tool_calls: usize,
    pub(crate) mcp_calls: usize,
    pub(crate) filesystem_read_calls: usize,
    pub(crate) filesystem_write_calls: usize,
    pub(crate) shell_calls: usize,
    pub(crate) network_calls: usize,
    pub(crate) browser_calls: usize,
}

pub(crate) fn check_and_consume_tool_budget(
    budget: &ToolCallBudget,
    usage: &mut ToolCallBudgetUsage,
    side_effects: SideEffects,
) -> Option<String> {
    let next_total = usage.total_tool_calls.saturating_add(1);
    if budget.max_total_tool_calls > 0 && next_total > budget.max_total_tool_calls {
        return Some(format!(
            "runtime budget exceeded: total tool calls {} > limit {}",
            next_total, budget.max_total_tool_calls
        ));
    }

    let side_effect_limit = budget_limit_for_side_effects(budget, side_effects);
    if side_effect_limit > 0 {
        let next_side_effect_count =
            budget_usage_for_side_effects(usage, side_effects).saturating_add(1);
        if next_side_effect_count > side_effect_limit {
            return Some(format!(
                "runtime budget exceeded: {} tool calls {} > limit {}",
                side_effect_limit_label(side_effects),
                next_side_effect_count,
                side_effect_limit
            ));
        }
    }

    increment_budget_usage(usage, side_effects);
    None
}

pub(crate) fn check_and_consume_mcp_budget(
    budget: &ToolCallBudget,
    usage: &mut ToolCallBudgetUsage,
    is_mcp_tool: bool,
) -> Option<String> {
    if !is_mcp_tool {
        return None;
    }
    let next_mcp = usage.mcp_calls.saturating_add(1);
    if budget.max_mcp_calls > 0 && next_mcp > budget.max_mcp_calls {
        return Some(format!(
            "runtime budget exceeded: mcp tool calls {} > limit {}",
            next_mcp, budget.max_mcp_calls
        ));
    }
    usage.mcp_calls = next_mcp;
    None
}

fn side_effect_limit_label(side_effects: SideEffects) -> &'static str {
    match side_effects {
        SideEffects::FilesystemRead => "filesystem_read",
        SideEffects::FilesystemWrite => "filesystem_write",
        SideEffects::ShellExec => "shell",
        SideEffects::Network => "network",
        SideEffects::Browser => "browser",
        SideEffects::None => "none",
    }
}

fn budget_limit_for_side_effects(budget: &ToolCallBudget, side_effects: SideEffects) -> usize {
    match side_effects {
        SideEffects::FilesystemRead => budget.max_filesystem_read_calls,
        SideEffects::FilesystemWrite => budget.max_filesystem_write_calls,
        SideEffects::ShellExec => budget.max_shell_calls,
        SideEffects::Network => budget.max_network_calls,
        SideEffects::Browser => budget.max_browser_calls,
        SideEffects::None => 0,
    }
}

fn budget_usage_for_side_effects(usage: &ToolCallBudgetUsage, side_effects: SideEffects) -> usize {
    match side_effects {
        SideEffects::FilesystemRead => usage.filesystem_read_calls,
        SideEffects::FilesystemWrite => usage.filesystem_write_calls,
        SideEffects::ShellExec => usage.shell_calls,
        SideEffects::Network => usage.network_calls,
        SideEffects::Browser => usage.browser_calls,
        SideEffects::None => 0,
    }
}

fn increment_budget_usage(usage: &mut ToolCallBudgetUsage, side_effects: SideEffects) {
    usage.total_tool_calls = usage.total_tool_calls.saturating_add(1);
    match side_effects {
        SideEffects::FilesystemRead => {
            usage.filesystem_read_calls = usage.filesystem_read_calls.saturating_add(1)
        }
        SideEffects::FilesystemWrite => {
            usage.filesystem_write_calls = usage.filesystem_write_calls.saturating_add(1)
        }
        SideEffects::ShellExec => usage.shell_calls = usage.shell_calls.saturating_add(1),
        SideEffects::Network => usage.network_calls = usage.network_calls.saturating_add(1),
        SideEffects::Browser => usage.browser_calls = usage.browser_calls.saturating_add(1),
        SideEffects::None => {}
    }
}
