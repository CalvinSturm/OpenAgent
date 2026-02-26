mod agent;

mod agent_runtime;

mod approvals_ops;

mod chat_commands;

mod chat_repl_runtime;

mod chat_runtime;

mod chat_tui_runtime;

mod chat_ui;

mod chat_view_utils;
mod checks;

mod cli_args;

mod cli_dispatch;

mod compaction;

mod eval;

mod events;

mod gate;

mod hooks;

mod instruction_runtime;

mod instructions;

mod mcp;

mod ops_helpers;

mod planner;

mod planner_runtime;

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

#[tokio::main]

async fn main() -> anyhow::Result<()> {
    cli_dispatch::run_cli().await
}

#[cfg(test)]
mod main_tests;
