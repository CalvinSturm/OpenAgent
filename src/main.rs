mod agent;
mod agent_budget;
mod agent_events;
mod agent_impl_guard;
mod agent_output_sanitize;
mod agent_queue_runtime;
mod agent_taint_helpers;
mod agent_tool_exec;
mod agent_utils;
mod agent_worker_protocol;

mod agent_runtime;

mod approvals_ops;

mod chat_commands;

mod chat_repl_runtime;

mod chat_runtime;

mod chat_tui_learn_adapter;
mod chat_tui_runtime;

mod chat_ui;

mod chat_view_utils;
mod checks;

mod cli_args;

mod cli_dispatch;
mod cli_dispatch_checks;
mod cli_dispatch_eval_replay;
mod cli_dispatch_learn;
mod cli_dispatch_misc_ops;

mod compaction;

mod eval;

mod events;

mod gate;

mod hooks;

mod instruction_runtime;

mod instructions;

mod mcp;

mod learning;

mod ops_helpers;

mod planner;

mod planner_runtime;

mod operator_queue;
mod packs;

mod project_guidance;

mod provider_runtime;

mod providers;

mod qualification;

mod reliability_profile;
mod repo_map;
mod repro;

mod run_prep;

mod runtime_config;

mod runtime_events;

mod runtime_flags;

mod runtime_paths;

mod runtime_wiring;

mod scaffold;

mod session;

mod session_ops;

mod startup_bootstrap;

mod startup_detect;

mod startup_init;

mod store;

mod taint;

mod target;

mod task_apply;

mod task_eval_profile;

mod taskgraph;

mod tasks_graph_runtime;

mod tools;

mod trust;

mod tui;

mod types;

pub(crate) use agent::AgentExitReason;

pub(crate) use agent_runtime::{run_agent, run_agent_with_ui, RunExecutionResult};

pub(crate) use cli_args::*;

pub(crate) use eval::baseline::{
    baseline_path, compare_results, create_baseline_from_results, delete_baseline, list_baselines,
    load_baseline,
};

pub(crate) use eval::bundle::{create_bundle, BundleSpec};

pub(crate) use eval::profile::{doctor_profile, list_profiles, load_profile};

pub(crate) use eval::report_compare::compare_results_files;

pub(crate) use eval::runner::{run_eval, EvalConfig};

pub(crate) use gate::ProviderKind;

pub(crate) use providers::mock::MockProvider;

pub(crate) use providers::ollama::OllamaProvider;

pub(crate) use providers::openai_compat::OpenAiCompatProvider;

pub(crate) use repro::{render_verify_report, verify_run_record};

pub(crate) use scaffold::{version_info, InitOptions};

pub(crate) use session::SessionStore;

pub(crate) use store::{resolve_state_paths, stable_path_string};

pub(crate) use trust::approvals::ApprovalsStore;

fn main() -> anyhow::Result<()> {
    let join = std::thread::Builder::new()
        .name("localagent-main".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(anyhow::Error::from)?;
            rt.block_on(cli_dispatch::run_cli())
        })
        .map_err(anyhow::Error::from)?;
    match join.join() {
        Ok(res) => res,
        Err(_) => Err(anyhow::anyhow!(
            "localagent main thread panicked during startup"
        )),
    }
}

#[cfg(test)]
mod main_tests;
