use serde_json::Value;

use crate::types::Message;

use super::RunRecord;

pub fn render_replay(record: &RunRecord) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "run_id: {}\nmode: {}\nprovider: {}\nmodel: {}\nexit_reason: {}\nPolicy hash: {}\nConfig hash: {}\napproval_mode: {}\nauto_approve_scope: {}\nunsafe: {}\nno_limits: {}\nunsafe_bypass_allow_flags: {}\n",
        record.metadata.run_id,
        record.mode,
        record.cli.provider,
        record.cli.model,
        record.metadata.exit_reason,
        record.policy_hash_hex.as_deref().unwrap_or("-"),
        record.config_hash_hex,
        record.cli.approval_mode,
        record.cli.auto_approve_scope,
        record.cli.unsafe_mode,
        record.cli.no_limits,
        record.cli.unsafe_bypass_allow_flags
    ));
    out.push_str(&format!("exec_target: {}\n", record.cli.exec_target));
    if let Some(summary) = &record.cli.docker_config_summary {
        out.push_str(&format!("docker_config: {}\n", summary));
    }
    out.push_str(&format!("tui_enabled: {}\n", record.cli.tui_enabled));
    out.push_str(&format!(
        "taint: {} mode={} digest_bytes={}\n",
        record.cli.taint, record.cli.taint_mode, record.cli.taint_digest_bytes
    ));
    if let Some(planner) = &record.planner {
        let steps_count = planner
            .plan_json
            .get("steps")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let goal = planner
            .plan_json
            .get("goal")
            .and_then(Value::as_str)
            .unwrap_or_default();
        out.push_str(&format!(
            "planner: model={} ok={} steps={} hash={}\nplanner_goal: {}\n",
            planner.model, planner.ok, steps_count, planner.plan_hash_hex, goal
        ));
    }
    for m in &record.transcript {
        let content = m.content.clone().unwrap_or_default();
        match m.role {
            crate::types::Role::User => out.push_str(&format!("USER: {}\n", content)),
            crate::types::Role::Assistant => out.push_str(&format!("ASSISTANT: {}\n", content)),
            crate::types::Role::Tool => {
                let name = m.tool_name.clone().unwrap_or_else(|| "unknown".to_string());
                out.push_str(&format!("TOOL({}): {}\n", name, content));
            }
            crate::types::Role::System => out.push_str(&format!("SYSTEM: {}\n", content)),
            crate::types::Role::Developer => out.push_str(&format!("DEVELOPER: {}\n", content)),
        }
    }
    out
}

pub fn extract_session_messages(messages: &[Message]) -> Vec<Message> {
    messages
        .iter()
        .enumerate()
        .filter_map(|(idx, m)| {
            if idx == 0
                && matches!(m.role, crate::types::Role::System)
                && m.content
                    .as_deref()
                    .unwrap_or_default()
                    .contains("You are an agent that may call tools")
            {
                return None;
            }
            if matches!(m.role, crate::types::Role::Developer)
                && m.content
                    .as_deref()
                    .unwrap_or_default()
                    .starts_with(crate::session::TASK_MEMORY_HEADER)
            {
                return None;
            }
            if matches!(m.role, crate::types::Role::Developer)
                && m.content
                    .as_deref()
                    .unwrap_or_default()
                    .starts_with(crate::planner::PLANNER_HANDOFF_HEADER)
            {
                return None;
            }
            Some(m.clone())
        })
        .collect()
}
