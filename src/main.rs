mod agent;
mod agent_runtime;
mod approvals_ops;
mod chat_commands;
mod chat_repl_runtime;
mod chat_runtime;
mod chat_tui_runtime;
mod chat_ui;
mod chat_view_utils;
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
mod provider_runtime;
mod providers;
mod qualification;
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
mod startup_detect;
mod startup_bootstrap;
mod startup_init;
mod store;
mod taint;
mod task_apply;
mod task_eval_profile;
mod tasks_graph_runtime;
mod target;
mod taskgraph;
mod tools;
mod trust;
mod tui;
mod types;
pub(crate) use agent_runtime::{run_agent, run_agent_with_ui, RunExecutionResult};

use std::path::PathBuf;

use crate::mcp::registry::{
    doctor_server as mcp_doctor_server, list_servers as mcp_list_servers,
};
use agent::{
    AgentExitReason, McpPinEnforcementMode, PlanToolEnforcementMode,
};
use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand, ValueEnum};
use compaction::{CompactionMode, ToolResultPersist};
use eval::baseline::{
    baseline_path, compare_results, create_baseline_from_results, delete_baseline, list_baselines,
    load_baseline,
};
use eval::bundle::{create_bundle, BundleSpec};
use eval::profile::{doctor_profile, list_profiles, load_profile};
use eval::report_compare::compare_results_files;
use eval::runner::{run_eval, EvalConfig};
use eval::tasks::EvalPack;
use gate::{ApprovalKeyVersion, ApprovalMode, AutoApproveScope, ProviderKind, TrustMode};
use hooks::config::HooksMode;
use providers::mock::MockProvider;
use providers::ollama::OllamaProvider;
use providers::openai_compat::OpenAiCompatProvider;
use repro::{render_verify_report, verify_run_record, ReproEnvMode, ReproMode};
use scaffold::{version_info, InitOptions};
use session::{CapsMode, SessionStore};
use store::{
    provider_to_string, resolve_state_paths, stable_path_string,
};
use taint::{TaintMode, TaintToggle};
use target::ExecTargetKind;
use taskgraph::PropagateSummaries;
use tools::ToolArgsStrict;
use trust::approvals::ApprovalsStore;

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    Run,
    Exec,
    Version(VersionArgs),
    Init(InitArgs),
    Template(TemplateArgs),
    Chat(ChatArgs),
    Doctor(DoctorArgs),
    Mcp(McpArgs),
    Hooks(HooksArgs),
    Policy(PolicyArgs),
    Approvals(ApprovalsArgs),
    Approve(ApproveArgs),
    Deny(DenyArgs),
    Replay(ReplayArgs),
    Session(SessionArgs),
    Eval(Box<EvalCmd>),
    Tui(TuiArgs),
    Tasks(TasksArgs),
}

#[derive(Debug, Parser)]
struct VersionArgs {
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Debug, Parser)]
struct InitArgs {
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    workdir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    force: bool,
    #[arg(long, default_value_t = false)]
    print: bool,
}

#[derive(Debug, Subcommand)]
enum TemplateSubcommand {
    List,
    Show {
        name: String,
    },
    Write {
        name: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Parser)]
struct TemplateArgs {
    #[command(subcommand)]
    command: TemplateSubcommand,
}

#[derive(Debug, Clone, Parser)]
struct ChatArgs {
    #[arg(long, default_value_t = false)]
    tui: bool,
    #[arg(long, default_value_t = false)]
    plain_tui: bool,
    #[arg(long, default_value_t = false)]
    no_banner: bool,
}

#[derive(Debug, Subcommand)]
enum TasksSubcommand {
    Run(TasksRunArgs),
    Status(TasksStatusArgs),
    Reset(TasksResetArgs),
}

#[derive(Debug, Parser)]
struct TasksArgs {
    #[command(subcommand)]
    command: TasksSubcommand,
}

#[derive(Debug, Clone, Parser)]
pub(crate) struct TasksRunArgs {
    #[arg(long)]
    taskfile: PathBuf,
    #[arg(long, default_value_t = false)]
    resume: bool,
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    fail_fast: bool,
    #[arg(long, default_value_t = 0)]
    max_nodes: u32,
    #[arg(long, value_enum, default_value_t = PropagateSummaries::On)]
    propagate_summaries: PropagateSummaries,
}

#[derive(Debug, Clone, Parser)]
struct TasksStatusArgs {
    #[arg(long)]
    checkpoint: PathBuf,
}

#[derive(Debug, Clone, Parser)]
struct TasksResetArgs {
    #[arg(long)]
    checkpoint: PathBuf,
}

#[derive(Debug, Clone, Subcommand)]
enum EvalProfileSubcommand {
    List,
    Show {
        name: String,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        profile_path: Option<PathBuf>,
    },
    Doctor {
        name: String,
        #[arg(long)]
        profile_path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum EvalBaselineSubcommand {
    Create {
        name: String,
        #[arg(long)]
        from: PathBuf,
    },
    Show {
        name: String,
    },
    Delete {
        name: String,
    },
    List,
}

#[derive(Debug, Clone, Subcommand)]
enum EvalSubcommand {
    Profile {
        #[command(subcommand)]
        command: EvalProfileSubcommand,
    },
    Baseline {
        #[command(subcommand)]
        command: EvalBaselineSubcommand,
    },
    Report {
        #[command(subcommand)]
        command: EvalReportSubcommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum EvalReportSubcommand {
    Compare {
        #[arg(long)]
        a: PathBuf,
        #[arg(long)]
        b: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Parser)]
struct EvalCmd {
    #[command(subcommand)]
    command: Option<EvalSubcommand>,
    #[command(flatten)]
    run: EvalArgs,
}

#[derive(Debug, Subcommand)]
enum SessionMemorySubcommand {
    Add {
        #[arg(long)]
        title: String,
        #[arg(long)]
        content: String,
    },
    List,
    Show {
        id: String,
    },
    Update {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        content: Option<String>,
    },
    Delete {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum SessionSubcommand {
    Info,
    Show {
        #[arg(long, default_value_t = 20)]
        last: usize,
    },
    Drop {
        #[arg(long)]
        from: Option<usize>,
        #[arg(long)]
        last: Option<usize>,
    },
    Reset,
    Memory {
        #[command(subcommand)]
        command: SessionMemorySubcommand,
    },
}

#[derive(Debug, Parser)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionSubcommand,
}

#[derive(Debug, Subcommand)]
enum TuiSubcommand {
    Tail {
        #[arg(long)]
        events: PathBuf,
        #[arg(long, default_value_t = 50)]
        refresh_ms: u64,
    },
}

#[derive(Debug, Parser)]
struct TuiArgs {
    #[command(subcommand)]
    command: TuiSubcommand,
}

#[derive(Debug, Subcommand)]
enum McpSubcommand {
    List,
    Doctor { name: String },
}

#[derive(Debug, Parser)]
struct McpArgs {
    #[command(subcommand)]
    command: McpSubcommand,
}

#[derive(Debug, Subcommand)]
enum HooksSubcommand {
    List,
    Doctor,
}

#[derive(Debug, Parser)]
struct HooksArgs {
    #[command(subcommand)]
    command: HooksSubcommand,
}

#[derive(Debug, Subcommand)]
enum PolicySubcommand {
    Doctor {
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    PrintEffective {
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Test {
        #[arg(long)]
        cases: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[derive(Debug, Parser)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicySubcommand,
}

#[derive(Debug, Subcommand)]
enum ApprovalsSubcommand {
    List,
    Prune,
}

#[derive(Debug, Parser)]
struct ApprovalsArgs {
    #[command(subcommand)]
    command: ApprovalsSubcommand,
}

#[derive(Debug, Parser)]
struct ApproveArgs {
    id: String,
    #[arg(long)]
    ttl_hours: Option<u32>,
    #[arg(long)]
    max_uses: Option<u32>,
}

#[derive(Debug, Parser)]
struct DenyArgs {
    id: String,
}

#[derive(Debug, Subcommand)]
enum ReplaySubcommand {
    Verify {
        run_id: String,
        #[arg(long, default_value_t = false)]
        strict: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Parser)]
struct ReplayArgs {
    run_id: Option<String>,
    #[command(subcommand)]
    command: Option<ReplaySubcommand>,
}

#[derive(Debug, Clone, Parser)]
struct EvalArgs {
    #[arg(long, value_enum, default_value_t = ProviderKind::Ollama)]
    provider: ProviderKind,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    models: Option<String>,
    #[arg(long, value_enum, default_value_t = EvalPack::All)]
    pack: EvalPack,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    junit: Option<PathBuf>,
    #[arg(long = "summary-md")]
    summary_md: Option<PathBuf>,
    #[arg(long)]
    cost_model: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    runs_per_task: usize,
    #[arg(long, default_value_t = 30)]
    max_steps: usize,
    #[arg(long, default_value_t = 0)]
    max_wall_time_ms: u64,
    #[arg(long, default_value_t = 0)]
    max_mcp_calls: usize,
    #[arg(long, default_value_t = 600)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 0.0)]
    min_pass_rate: f64,
    #[arg(long, default_value_t = false)]
    fail_on_any: bool,
    #[arg(long)]
    max_avg_steps: Option<f64>,
    #[arg(long, value_enum, default_value_t = TrustMode::On)]
    trust: TrustMode,
    #[arg(long, value_enum, default_value_t = ApprovalMode::Auto)]
    approval_mode: ApprovalMode,
    #[arg(long, value_enum, default_value_t = AutoApproveScope::Run)]
    auto_approve_scope: AutoApproveScope,
    #[arg(long, value_enum, default_value_t = ApprovalKeyVersion::V1)]
    approval_key: ApprovalKeyVersion,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable write tools exposure for coding tasks (some eval tasks are skipped without this)"
    )]
    enable_write_tools: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow write tool execution (some eval tasks are skipped without this)"
    )]
    allow_write: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow shell tool execution (some eval tasks are skipped without this)"
    )]
    allow_shell: bool,
    #[arg(long = "unsafe", default_value_t = false)]
    unsafe_mode: bool,
    #[arg(long, default_value_t = false)]
    no_limits: bool,
    #[arg(long, default_value_t = false)]
    unsafe_bypass_allow_flags: bool,
    #[arg(
        long = "mcp",
        help = "Enable MCP servers (browser eval uses only local fixture pages; use --mcp playwright)"
    )]
    mcp: Vec<String>,
    #[arg(long)]
    mcp_config: Option<PathBuf>,
    #[arg(long, default_value = "default")]
    session: String,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    no_session: bool,
    #[arg(long, default_value_t = 40)]
    max_session_messages: usize,
    #[arg(long, default_value_t = false)]
    use_session_settings: bool,
    #[arg(long, default_value_t = 0)]
    max_context_chars: usize,
    #[arg(long, value_enum, default_value_t = CompactionMode::Off)]
    compaction_mode: CompactionMode,
    #[arg(long, default_value_t = 20)]
    compaction_keep_last: usize,
    #[arg(long, value_enum, default_value_t = ToolResultPersist::Digest)]
    tool_result_persist: ToolResultPersist,
    #[arg(long, value_enum, default_value_t = HooksMode::Off)]
    hooks: HooksMode,
    #[arg(long)]
    hooks_config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    hooks_strict: bool,
    #[arg(long, default_value_t = 2000)]
    hooks_timeout_ms: u64,
    #[arg(long, default_value_t = 200_000)]
    hooks_max_stdout_bytes: usize,
    #[arg(long, value_enum, default_value_t = ToolArgsStrict::On)]
    tool_args_strict: ToolArgsStrict,
    #[arg(long, value_enum, default_value_t = TaintToggle::Off)]
    taint: TaintToggle,
    #[arg(long, value_enum, default_value_t = TaintMode::Propagate)]
    taint_mode: TaintMode,
    #[arg(long, default_value_t = 4096)]
    taint_digest_bytes: usize,
    #[arg(long, value_enum, default_value_t = ReproMode::Off)]
    repro: ReproMode,
    #[arg(long)]
    repro_out: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ReproEnvMode::Safe)]
    repro_env: ReproEnvMode,
    #[arg(long, value_enum, default_value_t = CapsMode::Off)]
    caps: CapsMode,
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    profile_path: Option<PathBuf>,
    #[arg(long)]
    baseline: Option<String>,
    #[arg(long)]
    compare_baseline: Option<String>,
    #[arg(long, default_value_t = false)]
    fail_on_regression: bool,
    #[arg(long)]
    bundle: Option<PathBuf>,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    bundle_on_fail: bool,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    workdir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    keep_workdir: bool,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    approvals: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long, default_value_t = 2)]
    http_max_retries: u32,
    #[arg(long, default_value_t = 0)]
    http_timeout_ms: u64,
    #[arg(long, default_value_t = 2_000)]
    http_connect_timeout_ms: u64,
    #[arg(long, default_value_t = 0)]
    http_stream_idle_timeout_ms: u64,
    #[arg(long, default_value_t = 10_000_000)]
    http_max_response_bytes: usize,
    #[arg(long, default_value_t = 200_000)]
    http_max_line_bytes: usize,
    #[arg(long, value_enum, default_value_t = planner::RunMode::Single)]
    mode: planner::RunMode,
    #[arg(long)]
    planner_model: Option<String>,
    #[arg(long)]
    worker_model: Option<String>,
}

#[derive(Debug, Parser)]
#[command(name = "localagent")]
#[command(about = "LocalAgent: local-runtime agent loop with tool calling", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Debug, Clone, Parser)]
struct RunArgs {
    #[arg(long, value_enum)]
    provider: Option<ProviderKind>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long)]
    prompt: Option<String>,
    #[arg(long, default_value_t = 20)]
    max_steps: usize,
    #[arg(long, default_value_t = 0)]
    max_wall_time_ms: u64,
    #[arg(long, default_value_t = 0)]
    max_total_tool_calls: usize,
    #[arg(long, default_value_t = 0)]
    max_mcp_calls: usize,
    #[arg(long, default_value_t = 0)]
    max_filesystem_read_calls: usize,
    #[arg(long, default_value_t = 0)]
    max_filesystem_write_calls: usize,
    #[arg(long, default_value_t = 0)]
    max_shell_calls: usize,
    #[arg(long, default_value_t = 0)]
    max_network_calls: usize,
    #[arg(long, default_value_t = 0)]
    max_browser_calls: usize,
    #[arg(long, default_value = ".")]
    workdir: PathBuf,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long = "mcp")]
    mcp: Vec<String>,
    #[arg(long)]
    mcp_config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    allow_shell: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow shell tool only when cwd is omitted or a non-escaping relative path under the current workdir (command content is not sandboxed)"
    )]
    allow_shell_in_workdir: bool,
    #[arg(long, default_value_t = false)]
    allow_write: bool,
    #[arg(long, default_value_t = false)]
    enable_write_tools: bool,
    #[arg(long, value_enum, default_value_t = ExecTargetKind::Host)]
    exec_target: ExecTargetKind,
    #[arg(long, default_value = "ubuntu:24.04")]
    docker_image: String,
    #[arg(long, default_value = "/work")]
    docker_workdir: String,
    #[arg(long, value_enum, default_value_t = DockerNetwork::None)]
    docker_network: DockerNetwork,
    #[arg(long)]
    docker_user: Option<String>,
    #[arg(long, default_value_t = 200_000)]
    max_tool_output_bytes: usize,
    #[arg(long, default_value_t = 200_000)]
    max_read_bytes: usize,
    #[arg(long, value_enum, default_value_t = TrustMode::Off)]
    trust: TrustMode,
    #[arg(long, value_enum, default_value_t = ApprovalMode::Interrupt)]
    approval_mode: ApprovalMode,
    #[arg(long, value_enum, default_value_t = AutoApproveScope::Run)]
    auto_approve_scope: AutoApproveScope,
    #[arg(long, value_enum, default_value_t = ApprovalKeyVersion::V1)]
    approval_key: ApprovalKeyVersion,
    #[arg(long = "unsafe", default_value_t = false)]
    unsafe_mode: bool,
    #[arg(long, default_value_t = false)]
    no_limits: bool,
    #[arg(long, default_value_t = false)]
    unsafe_bypass_allow_flags: bool,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    approvals: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(long, default_value = "default")]
    session: String,
    #[arg(long, default_value_t = false)]
    no_session: bool,
    #[arg(long, default_value_t = false)]
    reset_session: bool,
    #[arg(long, default_value_t = 40)]
    max_session_messages: usize,
    #[arg(long, default_value_t = false)]
    use_session_settings: bool,
    #[arg(long, default_value_t = 0)]
    max_context_chars: usize,
    #[arg(long, value_enum, default_value_t = CompactionMode::Off)]
    compaction_mode: CompactionMode,
    #[arg(long, default_value_t = 20)]
    compaction_keep_last: usize,
    #[arg(long, value_enum, default_value_t = ToolResultPersist::Digest)]
    tool_result_persist: ToolResultPersist,
    #[arg(long, value_enum, default_value_t = HooksMode::Off)]
    hooks: HooksMode,
    #[arg(long)]
    hooks_config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    hooks_strict: bool,
    #[arg(long, default_value_t = 2000)]
    hooks_timeout_ms: u64,
    #[arg(long, default_value_t = 200_000)]
    hooks_max_stdout_bytes: usize,
    #[arg(long, value_enum, default_value_t = ToolArgsStrict::On)]
    tool_args_strict: ToolArgsStrict,
    #[arg(long)]
    instructions_config: Option<PathBuf>,
    #[arg(long)]
    instruction_model_profile: Option<String>,
    #[arg(long)]
    instruction_task_profile: Option<String>,
    #[arg(long)]
    task_kind: Option<String>,
    #[arg(long, value_enum, default_value_t = TaintToggle::Off)]
    taint: TaintToggle,
    #[arg(long, value_enum, default_value_t = TaintMode::Propagate)]
    taint_mode: TaintMode,
    #[arg(long, default_value_t = 4096)]
    taint_digest_bytes: usize,
    #[arg(long, value_enum, default_value_t = ReproMode::Off)]
    repro: ReproMode,
    #[arg(long)]
    repro_out: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ReproEnvMode::Safe)]
    repro_env: ReproEnvMode,
    #[arg(long, value_enum, default_value_t = CapsMode::Off)]
    caps: CapsMode,
    #[arg(long, default_value_t = false)]
    stream: bool,
    #[arg(long)]
    events: Option<PathBuf>,
    #[arg(long, default_value_t = 2)]
    http_max_retries: u32,
    #[arg(long, default_value_t = 0)]
    http_timeout_ms: u64,
    #[arg(long, default_value_t = 2_000)]
    http_connect_timeout_ms: u64,
    #[arg(long, default_value_t = 0)]
    http_stream_idle_timeout_ms: u64,
    #[arg(long, default_value_t = 10_000_000)]
    http_max_response_bytes: usize,
    #[arg(long, default_value_t = 200_000)]
    http_max_line_bytes: usize,
    #[arg(long, default_value_t = false)]
    tui: bool,
    #[arg(long, default_value_t = 50)]
    tui_refresh_ms: u64,
    #[arg(long, default_value_t = 200)]
    tui_max_log_lines: usize,
    #[arg(long, value_enum, default_value_t = planner::RunMode::Single)]
    mode: planner::RunMode,
    #[arg(long)]
    planner_model: Option<String>,
    #[arg(long)]
    worker_model: Option<String>,
    #[arg(long, default_value_t = 2)]
    planner_max_steps: u32,
    #[arg(long, value_enum, default_value_t = planner::PlannerOutput::Json)]
    planner_output: planner::PlannerOutput,
    #[arg(long, value_enum, default_value_t = PlanToolEnforcementMode::Off)]
    enforce_plan_tools: PlanToolEnforcementMode,
    #[arg(long, value_enum, default_value_t = McpPinEnforcementMode::Hard)]
    mcp_pin_enforcement: McpPinEnforcementMode,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    planner_strict: bool,
    #[arg(long, default_value_t = false)]
    no_planner_strict: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DockerNetwork {
    None,
    Bridge,
}

#[derive(Debug, Parser)]
struct DoctorArgs {
    #[arg(long, value_enum)]
    provider: ProviderKind,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    api_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.run.no_limits && !cli.run.unsafe_mode {
        return Err(anyhow!("--no-limits requires --unsafe"));
    }
    if cli.run.unsafe_mode {
        eprintln!("WARN: unsafe mode enabled");
    }
    let workdir = std::fs::canonicalize(&cli.run.workdir)
        .with_context(|| format!("failed to resolve workdir: {}", cli.run.workdir.display()))?;
    let paths = resolve_state_paths(
        &workdir,
        cli.run.state_dir.clone(),
        cli.run.policy.clone(),
        cli.run.approvals.clone(),
        cli.run.audit.clone(),
    );
    if paths.using_legacy_dir {
        eprintln!(
            "WARN: using legacy state dir at {}",
            paths.state_dir.display()
        );
    }
    startup_init::maybe_auto_init_state(
        &cli.command,
        cli.run.state_dir.clone(),
        &workdir,
        &paths,
    )?;

    match &cli.command {
        Some(Commands::Run) | Some(Commands::Exec) => {}
        Some(Commands::Version(args)) => {
            let info = version_info();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("LocalAgent {}", info.version);
                println!("git_sha: {}", info.git_sha);
                println!("target: {}", info.target);
                println!("build_time_utc: {}", info.build_time_utc);
            }
            return Ok(());
        }
        Some(Commands::Init(args)) => {
            let init_workdir = if let Some(w) = &args.workdir {
                std::fs::canonicalize(w)
                    .with_context(|| format!("failed to resolve workdir: {}", w.display()))?
            } else {
                workdir.clone()
            };
            let out = scaffold::run_init(&InitOptions {
                workdir: init_workdir,
                state_dir_override: args.state_dir.clone(),
                force: args.force,
                print_only: args.print,
            })?;
            print!("{out}");
            return Ok(());
        }
        Some(Commands::Template(args)) => {
            match &args.command {
                TemplateSubcommand::List => {
                    for name in scaffold::list_templates() {
                        println!("{name}");
                    }
                }
                TemplateSubcommand::Show { name } => {
                    let content = scaffold::template_content(name)
                        .ok_or_else(|| anyhow!("unknown template '{}'", name))?;
                    print!("{content}");
                }
                TemplateSubcommand::Write { name, out, force } => {
                    scaffold::write_template(name, out, *force)?;
                    println!("wrote template {} to {}", name, out.display());
                }
            }
            return Ok(());
        }
        Some(Commands::Chat(args)) => {
            chat_repl_runtime::run_chat_repl(args, &cli.run, &paths).await?;
            return Ok(());
        }
        Some(Commands::Doctor(args)) => match provider_runtime::doctor_check(args).await {
            Ok(ok_msg) => {
                println!("{ok_msg}");
                return Ok(());
            }
            Err(fail_reason) => {
                println!("FAIL: {fail_reason}");
                std::process::exit(1);
            }
        },
        Some(Commands::Mcp(args)) => {
            let mcp_config_path = runtime_paths::resolved_mcp_config_path(&cli.run, &paths.state_dir);
            match &args.command {
                McpSubcommand::List => {
                    let names = mcp_list_servers(&mcp_config_path)?;
                    for n in names {
                        println!("{n}");
                    }
                    return Ok(());
                }
                McpSubcommand::Doctor { name } => {
                    match mcp_doctor_server(&mcp_config_path, name).await {
                        Ok(count) => {
                            println!("OK: mcp {} tool_count={}", name, count);
                            return Ok(());
                        }
                        Err(e) => {
                            println!("FAIL: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Some(Commands::Hooks(args)) => {
            let hooks_path = runtime_paths::resolved_hooks_config_path(&cli.run, &paths.state_dir);
            match &args.command {
                HooksSubcommand::List => {
                    ops_helpers::handle_hooks_list(&hooks_path)?;
                    return Ok(());
                }
                HooksSubcommand::Doctor => {
                    if let Err(e) = ops_helpers::handle_hooks_doctor(
                        &hooks_path,
                        &cli.run,
                        provider_to_string(ProviderKind::Ollama),
                    )
                    .await
                    {
                        println!("FAIL: {e}");
                        std::process::exit(1);
                    }
                    println!("OK: hooks doctor");
                    return Ok(());
                }
            }
        }
        Some(Commands::Policy(args)) => match &args.command {
            PolicySubcommand::Doctor { policy } => {
                let policy_path = policy.clone().unwrap_or_else(|| paths.policy_path.clone());
                match ops_helpers::policy_doctor_output(&policy_path) {
                    Ok(text) => {
                        println!("{text}");
                        return Ok(());
                    }
                    Err(e) => {
                        println!("FAIL: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            PolicySubcommand::PrintEffective { policy, json } => {
                let policy_path = policy.clone().unwrap_or_else(|| paths.policy_path.clone());
                println!("{}", ops_helpers::policy_effective_output(&policy_path, *json)?);
                return Ok(());
            }
            PolicySubcommand::Test {
                cases,
                json,
                policy,
            } => {
                let policy_path = policy.clone().unwrap_or_else(|| paths.policy_path.clone());
                let report = trust::policy_test::run_policy_tests(&policy_path, cases)?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    for case in &report.cases {
                        println!(
                            "{}\t{}\texpected={}\tgot={}\treason={}\tsource={}",
                            if case.pass { "PASS" } else { "FAIL" },
                            case.name,
                            case.expected,
                            case.got,
                            case.reason.as_deref().unwrap_or("-"),
                            case.source.as_deref().unwrap_or("-")
                        );
                    }
                    println!("summary: passed={} failed={}", report.passed, report.failed);
                }
                if report.failed > 0 {
                    std::process::exit(1);
                }
                return Ok(());
            }
        },
        Some(Commands::Approvals(args)) => {
            approvals_ops::handle_approvals_command(&paths.approvals_path, &args.command)?;
            return Ok(());
        }
        Some(Commands::Approve(args)) => {
            let store = ApprovalsStore::new(paths.approvals_path.clone());
            store.approve(&args.id, args.ttl_hours, args.max_uses)?;
            println!("approved {}", args.id);
            return Ok(());
        }
        Some(Commands::Deny(args)) => {
            let store = ApprovalsStore::new(paths.approvals_path.clone());
            store.deny(&args.id)?;
            println!("denied {}", args.id);
            return Ok(());
        }
        Some(Commands::Replay(args)) => match &args.command {
            Some(ReplaySubcommand::Verify {
                run_id,
                strict,
                json,
            }) => {
                let record = store::load_run_record(&paths.state_dir, run_id).map_err(|e| {
                    anyhow!(
                        "failed to load run '{}': {}. runs dir: {}",
                        run_id,
                        e,
                        paths.runs_dir.display()
                    )
                })?;
                let report = verify_run_record(&record, *strict)?;
                if *json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", render_verify_report(&report));
                }
                if report.status == "fail" {
                    std::process::exit(1);
                }
                return Ok(());
            }
            None => {
                let run_id = args
                    .run_id
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing run_id. use `localagent replay <run_id>`"))?;
                match store::load_run_record(&paths.state_dir, run_id) {
                    Ok(record) => {
                        print!("{}", store::render_replay(&record));
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "failed to load run '{}': {}. runs dir: {}",
                            run_id,
                            e,
                            paths.runs_dir.display()
                        ));
                    }
                }
            }
        },
        Some(Commands::Session(args)) => {
            if cli.run.no_session {
                return Err(anyhow!(
                    "session commands require sessions enabled (remove --no-session)"
                ));
            }
            let session_path = paths.sessions_dir.join(format!("{}.json", cli.run.session));
            let store = SessionStore::new(session_path, cli.run.session.clone());
            session_ops::handle_session_command(&store, &args.command)?;
            return Ok(());
        }
        Some(Commands::Eval(eval_cmd)) => {
            if let Some(sub) = &eval_cmd.command {
                match sub {
                    EvalSubcommand::Profile { command } => {
                        match command {
                            EvalProfileSubcommand::List => {
                                for p in list_profiles(&paths.state_dir)? {
                                    println!("{p}");
                                }
                            }
                            EvalProfileSubcommand::Show {
                                name,
                                json,
                                profile_path,
                            } => {
                                let loaded = load_profile(
                                    &paths.state_dir,
                                    Some(name.as_str()),
                                    profile_path.as_deref(),
                                )?;
                                if *json {
                                    println!("{}", serde_json::to_string_pretty(&loaded.profile)?);
                                } else {
                                    println!("{}", serde_yaml::to_string(&loaded.profile)?);
                                }
                            }
                            EvalProfileSubcommand::Doctor { name, profile_path } => {
                                let loaded = load_profile(
                                    &paths.state_dir,
                                    Some(name.as_str()),
                                    profile_path.as_deref(),
                                )?;
                                let req = doctor_profile(&loaded.profile)?;
                                let provider = match loaded.profile.provider.as_deref() {
                                    Some("lmstudio") => ProviderKind::Lmstudio,
                                    Some("llamacpp") => ProviderKind::Llamacpp,
                                    Some("mock") => ProviderKind::Mock,
                                    _ => ProviderKind::Ollama,
                                };
                                let base_url =
                                    loaded.profile.base_url.clone().unwrap_or_else(|| {
                                        provider_runtime::default_base_url(provider).to_string()
                                    });
                                match provider_runtime::doctor_check(&DoctorArgs {
                                    provider,
                                    base_url: Some(base_url.clone()),
                                    api_key: None,
                                })
                                .await
                                {
                                    Ok(ok) => println!("{ok}"),
                                    Err(e) => {
                                        eprintln!("FAIL: {e}");
                                        std::process::exit(1);
                                    }
                                }
                                if req.is_empty() {
                                    println!("Required flags: (none)");
                                } else {
                                    println!("Required flags: {}", req.join(" "));
                                }
                            }
                        }
                        return Ok(());
                    }
                    EvalSubcommand::Baseline { command } => {
                        match command {
                            EvalBaselineSubcommand::Create { name, from } => {
                                let path =
                                    create_baseline_from_results(&paths.state_dir, name, from)?;
                                println!("created baseline {} at {}", name, path.display());
                            }
                            EvalBaselineSubcommand::Show { name } => {
                                let b = load_baseline(&paths.state_dir, name)?;
                                println!("{}", serde_json::to_string_pretty(&b)?);
                            }
                            EvalBaselineSubcommand::Delete { name } => {
                                delete_baseline(&paths.state_dir, name)?;
                                println!("deleted baseline {name}");
                            }
                            EvalBaselineSubcommand::List => {
                                for n in list_baselines(&paths.state_dir)? {
                                    println!("{n}");
                                }
                            }
                        }
                        return Ok(());
                    }
                    EvalSubcommand::Report { command } => {
                        match command {
                            EvalReportSubcommand::Compare { a, b, out, json } => {
                                compare_results_files(a, b, out, json.as_deref())?;
                                println!("compare report written: {}", out.display());
                                if let Some(j) = json {
                                    println!("compare json written: {}", j.display());
                                }
                            }
                        }
                        return Ok(());
                    }
                }
            }
            let mut args = eval_cmd.run.clone();
            let loaded_profile =
                task_eval_profile::apply_eval_profile_overrides(&mut args, &paths.state_dir)?;

            if args.no_limits && !args.unsafe_mode {
                return Err(anyhow!("--no-limits requires --unsafe"));
            }
            if args.unsafe_mode {
                eprintln!("WARN: unsafe mode enabled");
            }
            let models = args
                .models
                .clone()
                .ok_or_else(|| anyhow!("--models is required and must not be empty"))?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if models.is_empty() {
                return Err(anyhow!("--models is required and must not be empty"));
            }
            let mut enable_write_tools = args.enable_write_tools;
            if matches!(args.pack, EvalPack::Coding | EvalPack::All) && !args.enable_write_tools {
                enable_write_tools = true;
            }
            let cfg = EvalConfig {
                provider: args.provider,
                base_url: args.base_url.clone().unwrap_or_else(|| {
                    provider_runtime::default_base_url(args.provider).to_string()
                }),
                api_key: args.api_key.clone(),
                models,
                pack: args.pack,
                out: args.out.clone(),
                junit: args.junit.clone(),
                summary_md: args.summary_md.clone(),
                cost_model_path: args.cost_model.clone(),
                runs_per_task: args.runs_per_task,
                max_steps: args.max_steps,
                max_wall_time_ms: args.max_wall_time_ms,
                max_mcp_calls: args.max_mcp_calls,
                timeout_seconds: args.timeout_seconds,
                trust: args.trust,
                approval_mode: args.approval_mode,
                auto_approve_scope: args.auto_approve_scope,
                approval_key: args.approval_key,
                enable_write_tools,
                allow_write: args.allow_write,
                allow_shell: args.allow_shell,
                unsafe_mode: args.unsafe_mode,
                no_limits: args.no_limits,
                unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
                mcp: args.mcp.clone(),
                mcp_config: args.mcp_config.clone(),
                session: args.session.clone(),
                no_session: args.no_session,
                max_session_messages: args.max_session_messages,
                max_context_chars: args.max_context_chars,
                compaction_mode: args.compaction_mode,
                compaction_keep_last: args.compaction_keep_last,
                tool_result_persist: args.tool_result_persist,
                hooks_mode: args.hooks,
                hooks_config: args.hooks_config.clone(),
                hooks_strict: args.hooks_strict,
                hooks_timeout_ms: args.hooks_timeout_ms,
                hooks_max_stdout_bytes: args.hooks_max_stdout_bytes,
                tool_args_strict: args.tool_args_strict,
                tui_enabled: false,
                tui_refresh_ms: 50,
                tui_max_log_lines: 200,
                state_dir_override: args.state_dir.clone(),
                policy_override: args.policy.clone(),
                approvals_override: args.approvals.clone(),
                audit_override: args.audit.clone(),
                workdir_override: args.workdir.clone(),
                keep_workdir: args.keep_workdir,
                http: provider_runtime::http_config_from_eval_args(&args),
                mode: args.mode,
                planner_model: args.planner_model.clone(),
                worker_model: args.worker_model.clone(),
                min_pass_rate: args.min_pass_rate,
                fail_on_any: args.fail_on_any,
                max_avg_steps: args.max_avg_steps,
                resolved_profile_name: args.profile.clone(),
                resolved_profile_path: loaded_profile
                    .as_ref()
                    .map(|p| stable_path_string(&p.path))
                    .or_else(|| args.profile_path.as_ref().map(|p| stable_path_string(p))),
                resolved_profile_hash_hex: loaded_profile.as_ref().map(|p| p.hash_hex.clone()),
            };
            let cwd = std::env::current_dir().with_context(|| "failed to read current dir")?;
            let results_path = run_eval(cfg.clone(), &cwd).await?;
            let mut exit_fail = false;
            let mut results: eval::runner::EvalResults =
                serde_json::from_slice(&std::fs::read(&results_path)?)?;

            if let Some(name) = args.baseline.clone() {
                let created = create_baseline_from_results(&paths.state_dir, &name, &results_path)?;
                println!("baseline created: {} ({})", name, created.display());
            }

            let avg_steps = eval::baseline::avg_steps(&results);
            let mut threshold_failures = Vec::new();
            if results.summary.pass_rate < args.min_pass_rate {
                threshold_failures.push(format!(
                    "pass_rate {} < min_pass_rate {}",
                    results.summary.pass_rate, args.min_pass_rate
                ));
            }
            if let Some(max_avg) = args.max_avg_steps {
                if avg_steps > max_avg {
                    threshold_failures.push(format!(
                        "avg_steps {} > max_avg_steps {}",
                        avg_steps, max_avg
                    ));
                }
            }
            if args.fail_on_any && results.summary.failed > 0 {
                threshold_failures.push(format!("failed runs present: {}", results.summary.failed));
            }
            if !threshold_failures.is_empty() {
                exit_fail = true;
                eprintln!("THRESHOLDS: FAIL");
                for f in &threshold_failures {
                    eprintln!(" - {f}");
                }
            }

            if let Some(name) = args.compare_baseline.clone() {
                let path = baseline_path(&paths.state_dir, &name);
                let baseline = load_baseline(&paths.state_dir, &name)?;
                let mut profile_hash_mismatch = false;
                if baseline.profile_hash_hex != results.config.resolved_profile_hash_hex {
                    profile_hash_mismatch = true;
                    eprintln!(
                        "WARN: baseline profile hash mismatch (baseline={:?}, current={:?})",
                        baseline.profile_hash_hex, results.config.resolved_profile_hash_hex
                    );
                }
                let reg = compare_results(&baseline, &results);
                println!(
                    "REGRESSION: {}",
                    if reg.passed {
                        "PASS".to_string()
                    } else {
                        format!("FAIL ({} failures)", reg.failures.len())
                    }
                );
                if args.fail_on_regression && !reg.passed {
                    exit_fail = true;
                }
                results.baseline = Some(eval::runner::EvalBaselineStatus {
                    name,
                    path: stable_path_string(&path),
                    loaded: true,
                    profile_hash_mismatch,
                });
                results.regression = Some(reg);
                std::fs::write(&results_path, serde_json::to_string_pretty(&results)?)?;
            }

            if let Some(bundle_path) = args.bundle.clone() {
                let should_bundle = !args.bundle_on_fail || exit_fail;
                if should_bundle {
                    let out = create_bundle(&BundleSpec {
                        bundle_path,
                        state_dir: paths.state_dir.clone(),
                        results_path: results_path.clone(),
                        junit_path: args.junit.clone(),
                        summary_md_path: args.summary_md.clone(),
                        baseline_name: args.compare_baseline.clone(),
                        profile_name: args.profile.clone(),
                        profile_hash_hex: results.config.resolved_profile_hash_hex.clone(),
                    })?;
                    println!("bundle written: {}", out.display());
                }
            }

            if exit_fail {
                std::process::exit(1);
            }
            return Ok(());
        }
        Some(Commands::Tui(args)) => match &args.command {
            TuiSubcommand::Tail { events, refresh_ms } => {
                if let Err(e) = tui::tail::run_tail(events, *refresh_ms) {
                    eprintln!("FAIL: {e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
        },
        Some(Commands::Tasks(args)) => {
            match &args.command {
                TasksSubcommand::Status(s) => {
                    let raw = std::fs::read_to_string(&s.checkpoint).with_context(|| {
                        format!("failed reading checkpoint {}", s.checkpoint.display())
                    })?;
                    let cp: taskgraph::TasksCheckpoint =
                        serde_json::from_str(&raw).context("failed parsing checkpoint JSON")?;
                    println!("{}", serde_json::to_string_pretty(&cp)?);
                }
                TasksSubcommand::Reset(s) => {
                    if s.checkpoint.exists() {
                        std::fs::remove_file(&s.checkpoint).with_context(|| {
                            format!("failed deleting checkpoint {}", s.checkpoint.display())
                        })?;
                    }
                    println!("checkpoint reset: {}", s.checkpoint.display());
                }
                TasksSubcommand::Run(s) => {
                    let exit = tasks_graph_runtime::run_tasks_graph(s, &cli.run, &paths).await?;
                    if exit != 0 {
                        std::process::exit(exit);
                    }
                }
            }
            return Ok(());
        }
        None => {}
    }

    if cli.command.is_none()
        && cli.run.provider.is_none()
        && cli.run.model.is_none()
        && cli.run.prompt.is_none()
    {
        startup_bootstrap::run_startup_bootstrap(&cli.run, &paths).await?;
        return Ok(());
    }

    let provider_kind = cli
        .run
        .provider
        .ok_or_else(|| anyhow!("--provider is required in run mode"))?;
    let model = cli
        .run
        .model
        .clone()
        .ok_or_else(|| anyhow!("--model is required in run mode"))?;
    let prompt = cli
        .run
        .prompt
        .clone()
        .ok_or_else(|| anyhow!("--prompt is required in run mode"))?;
    let base_url = cli
        .run
        .base_url
        .clone()
        .unwrap_or_else(|| provider_runtime::default_base_url(provider_kind).to_string());

    match provider_kind {
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
            let provider = OpenAiCompatProvider::new(
                base_url.clone(),
                cli.run.api_key.clone(),
                provider_runtime::http_config_from_run_args(&cli.run),
            )?;
            let res = run_agent(
                provider,
                provider_kind,
                &base_url,
                &model,
                &prompt,
                &cli.run,
                &paths,
            )
            .await?;
            if matches!(res.outcome.exit_reason, AgentExitReason::ProviderError) {
                let err = res
                    .outcome
                    .error
                    .unwrap_or_else(|| "provider error".to_string());
                return Err(anyhow!(
                    "{}\nHint: run `localagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
                    err,
                    provider_runtime::provider_cli_name(provider_kind),
                    base_url,
                    provider_runtime::provider_cli_name(provider_kind),
                    provider_runtime::default_base_url(provider_kind)
                ));
            }
        }
        ProviderKind::Ollama => {
            let provider = OllamaProvider::new(
                base_url.clone(),
                provider_runtime::http_config_from_run_args(&cli.run),
            )?;
            let res = run_agent(
                provider,
                provider_kind,
                &base_url,
                &model,
                &prompt,
                &cli.run,
                &paths,
            )
            .await?;
            if matches!(res.outcome.exit_reason, AgentExitReason::ProviderError) {
                let err = res
                    .outcome
                    .error
                    .unwrap_or_else(|| "provider error".to_string());
                return Err(anyhow!(
                    "{}\nHint: run `localagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
                    err,
                    provider_runtime::provider_cli_name(provider_kind),
                    base_url,
                    provider_runtime::provider_cli_name(provider_kind),
                    provider_runtime::default_base_url(provider_kind)
                ));
            }
        }
        ProviderKind::Mock => {
            let provider = MockProvider::new();
            let _ = run_agent(
                provider,
                provider_kind,
                &base_url,
                &model,
                &prompt,
                &cli.run,
                &paths,
            )
            .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use async_trait::async_trait;
    use tempfile::tempdir;

    use crate::providers::{ModelProvider, StreamDelta};
    use crate::target::ExecTargetKind;
    use crate::taskgraph::{TaskCompaction, TaskFlags, TaskLimits};
    use crate::types::{GenerateRequest, GenerateResponse, Message, Role};

    use super::{DockerNetwork, ProviderKind};
    use crate::{ops_helpers, provider_runtime};

    struct CaptureSink {
        events: Arc<Mutex<Vec<crate::events::Event>>>,
    }

    impl crate::events::EventSink for CaptureSink {
        fn emit(&mut self, event: crate::events::Event) -> anyhow::Result<()> {
            self.events.lock().expect("lock").push(event);
            Ok(())
        }
    }

    struct PlannerTestProvider {
        seen_tools_none: Arc<Mutex<Vec<bool>>>,
    }

    #[async_trait]
    impl ModelProvider for PlannerTestProvider {
        async fn generate(&self, req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            self.seen_tools_none
                .lock()
                .expect("lock")
                .push(req.tools.is_none());
            Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: Some("not-json".to_string()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls: Vec::new(),
                usage: None,
            })
        }

        async fn generate_streaming(
            &self,
            req: GenerateRequest,
            _on_delta: &mut (dyn FnMut(StreamDelta) + Send),
        ) -> anyhow::Result<GenerateResponse> {
            self.generate(req).await
        }
    }

    enum QualificationProbeMode {
        NativePass,
        InlinePass,
        FailNoTool,
    }

    struct QualificationTestProvider {
        calls: Arc<AtomicUsize>,
        mode: QualificationProbeMode,
    }

    #[async_trait]
    impl ModelProvider for QualificationTestProvider {
        async fn generate(&self, _req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (assistant_content, tool_calls) = match self.mode {
                QualificationProbeMode::NativePass => (
                    Some(String::new()),
                    vec![crate::types::ToolCall {
                        id: "q1".to_string(),
                        name: "list_dir".to_string(),
                        arguments: serde_json::json!({"path":"."}),
                    }],
                ),
                QualificationProbeMode::InlinePass => (
                    Some("{\"name\":\"list_dir\",\"arguments\":{\"path\":\".\"}}".to_string()),
                    Vec::new(),
                ),
                QualificationProbeMode::FailNoTool => (Some("no tool".to_string()), Vec::new()),
            };
            Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content: assistant_content,
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls,
                usage: None,
            })
        }

        async fn generate_streaming(
            &self,
            req: GenerateRequest,
            _on_delta: &mut (dyn FnMut(StreamDelta) + Send),
        ) -> anyhow::Result<GenerateResponse> {
            self.generate(req).await
        }
    }

    #[test]
    fn doctor_url_construction_openai_compat() {
        let urls = provider_runtime::doctor_probe_urls(ProviderKind::Lmstudio, "http://localhost:1234/v1/");
        assert_eq!(urls[0], "http://localhost:1234/v1/models");
        assert_eq!(urls[1], "http://localhost:1234/v1");
    }

    #[test]
    fn policy_doctor_helper_works() {
        let tmp = tempdir().expect("tmp");
        let p = tmp.path().join("policy.yaml");
        std::fs::write(
            &p,
            r#"
version: 2
default: deny
rules:
  - tool: "read_file"
    decision: allow
"#,
        )
        .expect("write");
        let out = ops_helpers::policy_doctor_output(&p).expect("doctor");
        assert!(out.contains("version=2"));
        assert!(out.contains("rules=1"));
    }

    #[test]
    fn policy_effective_helper_json_contains_rules() {
        let tmp = tempdir().expect("tmp");
        let p = tmp.path().join("policy.yaml");
        std::fs::write(
            &p,
            r#"
version: 2
default: deny
rules:
  - tool: "read_file"
    decision: allow
"#,
        )
        .expect("write");
        let out = ops_helpers::policy_effective_output(&p, true).expect("print");
        assert!(out.contains("\"rules\""));
        assert!(out.contains("read_file"));
    }

    #[test]
    fn probe_parser_accepts_inline_json_tool_call() {
        let resp = GenerateResponse {
            assistant: Message {
                role: Role::Assistant,
                content: Some("{\"name\":\"list_dir\",\"arguments\":{\"path\":\".\"}}".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            tool_calls: Vec::new(),
            usage: None,
        };
        let tc = super::qualification::probe_response_to_tool_call(&resp).expect("tool call");
        assert_eq!(tc.name, "list_dir");
        assert_eq!(tc.arguments, serde_json::json!({"path":"."}));
    }

    #[test]
    fn probe_parser_accepts_fenced_json_tool_call() {
        let resp = GenerateResponse {
            assistant: Message {
                role: Role::Assistant,
                content: Some(
                    "```json\n{\"name\":\"list_dir\",\"arguments\":{\"path\":\".\"}}\n```"
                        .to_string(),
                ),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            tool_calls: Vec::new(),
            usage: None,
        };
        let tc = super::qualification::probe_response_to_tool_call(&resp).expect("tool call");
        assert_eq!(tc.name, "list_dir");
        assert_eq!(tc.arguments, serde_json::json!({"path":"."}));
    }

    #[tokio::test]
    async fn planner_phase_omits_tools_and_emits_tool_count_zero() {
        let seen = Arc::new(Mutex::new(Vec::<bool>::new()));
        let provider = PlannerTestProvider {
            seen_tools_none: seen.clone(),
        };
        let events = Arc::new(Mutex::new(Vec::<crate::events::Event>::new()));
        let mut sink: Option<Box<dyn crate::events::EventSink>> = Some(Box::new(CaptureSink {
            events: events.clone(),
        }));
        let out = super::planner_runtime::run_planner_phase(
            &provider,
            "run_test",
            "m",
            "do thing",
            1,
            crate::planner::PlannerOutput::Json,
            false,
            &mut sink,
        )
        .await
        .expect("planner");
        assert!(out.plan_json.get("schema_version").is_some());
        assert_eq!(seen.lock().expect("lock").as_slice(), &[true]);
        let model_start = events
            .lock()
            .expect("lock")
            .iter()
            .find(|e| matches!(e.kind, crate::events::EventKind::ModelRequestStart))
            .cloned()
            .expect("model request event");
        assert_eq!(
            model_start.data.get("tool_count").and_then(|v| v.as_u64()),
            Some(0)
        );
    }

    #[test]
    fn task_settings_merge_defaults_then_overrides() {
        let mut args = default_run_args();
        let defaults = crate::taskgraph::TaskDefaults {
            mode: Some("planner_worker".to_string()),
            provider: Some("ollama".to_string()),
            base_url: Some("http://localhost:11434".to_string()),
            model: Some("m1".to_string()),
            planner_model: Some("pm".to_string()),
            worker_model: Some("wm".to_string()),
            trust: Some("on".to_string()),
            approval_mode: Some("auto".to_string()),
            auto_approve_scope: Some("run".to_string()),
            caps: Some("strict".to_string()),
            hooks: Some("auto".to_string()),
            compaction: TaskCompaction {
                max_context_chars: Some(111),
                mode: Some("summary".to_string()),
                keep_last: Some(7),
                tool_result_persist: Some("digest".to_string()),
            },
            limits: TaskLimits {
                max_read_bytes: Some(123),
                max_tool_output_bytes: Some(456),
            },
            flags: TaskFlags {
                enable_write_tools: Some(true),
                allow_write: Some(true),
                allow_shell: Some(false),
                stream: Some(false),
            },
            mcp: vec!["playwright".to_string()],
        };
        super::task_apply::apply_task_defaults(&mut args, &defaults).expect("defaults");
        let override_s = crate::taskgraph::TaskNodeSettings {
            model: Some("m2".to_string()),
            flags: TaskFlags {
                allow_shell: Some(true),
                ..TaskFlags::default()
            },
            ..crate::taskgraph::TaskNodeSettings::default()
        };
        super::task_apply::apply_node_overrides(&mut args, &override_s).expect("overrides");
        assert_eq!(args.model.as_deref(), Some("m2"));
        assert!(args.allow_shell);
        assert!(matches!(args.mode, crate::planner::RunMode::PlannerWorker));
        assert_eq!(args.mcp, vec!["playwright".to_string()]);
    }

    #[test]
    fn node_summary_line_is_deterministic() {
        let a = super::runtime_events::node_summary_line("N1", "ok", "hello\nworld");
        let b = super::runtime_events::node_summary_line("N1", "ok", "hello\nworld");
        assert_eq!(a, b);
        assert!(a.contains("output_sha256="));
    }

    #[test]
    fn planner_worker_defaults_plan_enforcement_to_hard_when_not_explicit() {
        let resolved = super::runtime_flags::resolve_plan_tool_enforcement(
            crate::planner::RunMode::PlannerWorker,
            crate::agent::PlanToolEnforcementMode::Off,
            false,
        );
        assert!(matches!(
            resolved,
            crate::agent::PlanToolEnforcementMode::Hard
        ));
    }

    #[test]
    fn planner_worker_respects_explicit_off_override() {
        let resolved = super::runtime_flags::resolve_plan_tool_enforcement(
            crate::planner::RunMode::PlannerWorker,
            crate::agent::PlanToolEnforcementMode::Off,
            true,
        );
        assert!(matches!(
            resolved,
            crate::agent::PlanToolEnforcementMode::Off
        ));
    }

    #[test]
    fn planner_worker_respects_explicit_soft_override() {
        let resolved = super::runtime_flags::resolve_plan_tool_enforcement(
            crate::planner::RunMode::PlannerWorker,
            crate::agent::PlanToolEnforcementMode::Soft,
            true,
        );
        assert!(matches!(
            resolved,
            crate::agent::PlanToolEnforcementMode::Soft
        ));
    }

    #[test]
    fn timeout_command_off_disables_request_and_stream_idle() {
        let mut args = default_run_args();
        let msg =
            super::runtime_config::apply_timeout_input(&mut args, "off").expect("timeout off");
        assert_eq!(args.http_timeout_ms, 0);
        assert_eq!(args.http_stream_idle_timeout_ms, 0);
        assert!(msg.contains("disabled"));
        assert!(super::runtime_config::timeout_settings_summary(&args).contains("request=off"));
        assert!(super::runtime_config::timeout_settings_summary(&args).contains("stream-idle=off"));
    }

    #[tokio::test]
    async fn qualification_failure_is_cached_and_short_circuits_future_attempts() {
        let tmp = tempdir().expect("tmp");
        let cache = tmp.path().join("qual_cache.json");
        let tools = crate::tools::builtin_tools_enabled(true, false);
        let model = format!(
            "qual_model_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        );
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first = QualificationTestProvider {
            calls: first_calls.clone(),
            mode: QualificationProbeMode::FailNoTool,
        };
        let err = super::qualification::ensure_orchestrator_qualified(
            &first,
            ProviderKind::Lmstudio,
            "http://localhost:1234/v1",
            &model,
            &tools,
            &cache,
        )
        .await
        .expect_err("expected fail");
        assert!(err.to_string().contains("no tool call returned"));
        assert!(first_calls.load(Ordering::SeqCst) >= 1);

        let second_calls = Arc::new(AtomicUsize::new(0));
        let second = QualificationTestProvider {
            calls: second_calls,
            mode: QualificationProbeMode::NativePass,
        };
        let err2 = super::qualification::ensure_orchestrator_qualified(
            &second,
            ProviderKind::Lmstudio,
            "http://localhost:1234/v1",
            &model,
            &tools,
            &cache,
        )
        .await
        .expect_err("cache should fail fast");
        assert!(err2
            .to_string()
            .contains("failed previously for this model/session"));
    }

    #[tokio::test]
    async fn qualification_fallback_disables_write_tools_and_continues() {
        let tmp = tempdir().expect("tmp");
        let cache = tmp.path().join("qual_cache.json");
        let mut tools = crate::tools::builtin_tools_enabled(true, false);
        assert!(tools
            .iter()
            .any(|t| t.side_effects == crate::types::SideEffects::FilesystemWrite));

        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QualificationTestProvider {
            calls,
            mode: QualificationProbeMode::FailNoTool,
        };
        let mut args = default_run_args();
        args.enable_write_tools = true;
        args.allow_write = true;

        let note = super::qualification::qualify_or_enable_readonly_fallback(
            &provider,
            ProviderKind::Lmstudio,
            "http://localhost:1234/v1",
            "fallback-model",
            args.enable_write_tools || args.allow_write,
            &mut tools,
            &cache,
        )
        .await
        .expect("fallback should not error")
        .expect("fallback note");
        assert!(note.contains("read-only fallback"));
        assert!(!tools
            .iter()
            .any(|t| t.side_effects == crate::types::SideEffects::FilesystemWrite));
    }

    #[tokio::test]
    async fn qualification_fallback_keeps_write_tools_when_probe_passes() {
        let tmp = tempdir().expect("tmp");
        let cache = tmp.path().join("qual_cache.json");
        let mut tools = crate::tools::builtin_tools_enabled(true, false);
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QualificationTestProvider {
            calls,
            mode: QualificationProbeMode::InlinePass,
        };
        let mut args = default_run_args();
        args.enable_write_tools = true;
        args.allow_write = true;
        let note = super::qualification::qualify_or_enable_readonly_fallback(
            &provider,
            ProviderKind::Lmstudio,
            "http://localhost:1234/v1",
            "pass-model",
            args.enable_write_tools || args.allow_write,
            &mut tools,
            &cache,
        )
        .await
        .expect("qualification ok");
        assert!(note.is_none());
        assert!(tools
            .iter()
            .any(|t| t.side_effects == crate::types::SideEffects::FilesystemWrite));
    }

    #[test]
    fn protocol_hint_detects_tool_call_format_issues() {
        let hint = super::runtime_config::protocol_remediation_hint(
            "MODEL_TOOL_PROTOCOL_VIOLATION: repeated malformed tool calls (tool='list_dir', error='...')",
        )
        .expect("hint");
        assert!(hint.contains("native tool call JSON"));
    }

    #[test]
    fn protocol_hint_detects_invalid_patch_format() {
        let hint = super::runtime_config::protocol_remediation_hint(
            "MODEL_TOOL_PROTOCOL_VIOLATION: repeated invalid patch format for apply_patch",
        )
        .expect("hint");
        assert!(hint.contains("valid unified diff"));
    }

    #[test]
    fn protocol_hint_ignores_non_protocol_errors() {
        assert!(super::runtime_config::protocol_remediation_hint("provider timeout").is_none());
    }

    fn default_run_args() -> super::RunArgs {
        super::RunArgs {
            provider: None,
            model: None,
            base_url: None,
            api_key: None,
            prompt: None,
            max_steps: 20,
            max_wall_time_ms: 0,
            max_total_tool_calls: 0,
            max_mcp_calls: 0,
            max_filesystem_read_calls: 0,
            max_filesystem_write_calls: 0,
            max_shell_calls: 0,
            max_network_calls: 0,
            max_browser_calls: 0,
            workdir: std::path::PathBuf::from("."),
            state_dir: None,
            mcp: Vec::new(),
            mcp_config: None,
            allow_shell: false,
            allow_shell_in_workdir: false,
            allow_write: false,
            enable_write_tools: false,
            exec_target: ExecTargetKind::Host,
            docker_image: "ubuntu:24.04".to_string(),
            docker_workdir: "/work".to_string(),
            docker_network: DockerNetwork::None,
            docker_user: None,
            max_tool_output_bytes: 200_000,
            max_read_bytes: 200_000,
            trust: crate::gate::TrustMode::Off,
            approval_mode: crate::gate::ApprovalMode::Interrupt,
            auto_approve_scope: crate::gate::AutoApproveScope::Run,
            approval_key: crate::gate::ApprovalKeyVersion::V1,
            unsafe_mode: false,
            no_limits: false,
            unsafe_bypass_allow_flags: false,
            policy: None,
            approvals: None,
            audit: None,
            session: "default".to_string(),
            no_session: false,
            reset_session: false,
            max_session_messages: 40,
            use_session_settings: false,
            max_context_chars: 0,
            compaction_mode: crate::compaction::CompactionMode::Off,
            compaction_keep_last: 20,
            tool_result_persist: crate::compaction::ToolResultPersist::Digest,
            hooks: crate::hooks::config::HooksMode::Off,
            hooks_config: None,
            hooks_strict: false,
            hooks_timeout_ms: 2000,
            hooks_max_stdout_bytes: 200_000,
            tool_args_strict: crate::tools::ToolArgsStrict::On,
            instructions_config: None,
            instruction_model_profile: None,
            instruction_task_profile: None,
            task_kind: None,
            taint: crate::taint::TaintToggle::Off,
            taint_mode: crate::taint::TaintMode::Propagate,
            taint_digest_bytes: 4096,
            repro: crate::repro::ReproMode::Off,
            repro_out: None,
            repro_env: crate::repro::ReproEnvMode::Safe,
            caps: crate::session::CapsMode::Off,
            stream: false,
            events: None,
            http_max_retries: 2,
            http_timeout_ms: 0,
            http_connect_timeout_ms: 2_000,
            http_stream_idle_timeout_ms: 0,
            http_max_response_bytes: 10_000_000,
            http_max_line_bytes: 200_000,
            tui: false,
            tui_refresh_ms: 50,
            tui_max_log_lines: 200,
            mode: crate::planner::RunMode::Single,
            planner_model: None,
            worker_model: None,
            planner_max_steps: 2,
            planner_output: crate::planner::PlannerOutput::Json,
            enforce_plan_tools: crate::agent::PlanToolEnforcementMode::Off,
            mcp_pin_enforcement: crate::agent::McpPinEnforcementMode::Hard,
            planner_strict: true,
            no_planner_strict: false,
        }
    }
}





