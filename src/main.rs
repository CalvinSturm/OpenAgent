mod agent;
mod approvals_ops;
mod chat_commands;
mod chat_runtime;
mod chat_ui;
mod chat_view_utils;
mod compaction;
mod eval;
mod events;
mod gate;
mod hooks;
mod instructions;
mod mcp;
mod ops_helpers;
mod planner;
mod provider_runtime;
mod providers;
mod qualification;
mod repro;
mod run_prep;
mod runtime_config;
mod runtime_flags;
mod runtime_wiring;
mod scaffold;
mod session;
mod startup_detect;
mod startup_bootstrap;
mod store;
mod taint;
mod task_apply;
mod task_eval_profile;
mod target;
mod taskgraph;
mod tools;
mod trust;
mod tui;
mod types;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use crate::mcp::registry::{
    doctor_server as mcp_doctor_server, list_servers as mcp_list_servers, McpRegistry,
};
use agent::{
    Agent, AgentExitReason, McpPinEnforcementMode, PlanToolEnforcementMode, PolicyLoadedInfo,
    ToolCallBudget,
};
use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand, ValueEnum};
use compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event as CEvent, KeyCode, KeyEventKind, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use eval::baseline::{
    baseline_path, compare_results, create_baseline_from_results, delete_baseline, list_baselines,
    load_baseline,
};
use eval::bundle::{create_bundle, BundleSpec};
use eval::profile::{doctor_profile, list_profiles, load_profile};
use eval::report_compare::compare_results_files;
use eval::runner::{run_eval, EvalConfig};
use eval::tasks::EvalPack;
use events::{Event, EventKind, EventSink};
use gate::{
    ApprovalKeyVersion, ApprovalMode, AutoApproveScope, GateContext, ProviderKind, TrustMode,
};
use hooks::config::HooksMode;
use hooks::runner::{HookManager, HookRuntimeConfig};
use instructions::InstructionResolution;
use providers::mock::MockProvider;
use providers::ollama::OllamaProvider;
use providers::openai_compat::OpenAiCompatProvider;
use providers::ModelProvider;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use repro::{render_verify_report, verify_run_record, ReproEnvMode, ReproMode};
use scaffold::{version_info, InitOptions};
use session::{
    settings_from_run, task_memory_message, CapsMode, RunSettingInputs, SessionStore,
};
use store::{
    config_hash_hex, extract_session_messages, provider_to_string, resolve_state_paths,
    stable_path_string, ConfigFingerprintV1, PlannerRunRecord, RunCliConfig, WorkerRunRecord,
};
use taint::{TaintMode, TaintToggle};
use target::{DockerTarget, ExecTarget, ExecTargetKind, HostTarget};
use taskgraph::PropagateSummaries;
use tokio::sync::watch;
use tools::{ToolArgsStrict, ToolRuntime};
use trust::approvals::ApprovalsStore;
use trust::policy::{McpAllowSummary, Policy};
use tui::state::UiState;
use types::{GenerateRequest, Message, Role};

#[derive(Debug, Subcommand)]
enum Commands {
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
struct TasksRunArgs {
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

fn should_auto_init_state(command: &Option<Commands>) -> bool {
    !matches!(
        command,
        Some(Commands::Version(_)) | Some(Commands::Init(_)) | Some(Commands::Template(_))
    )
}

fn maybe_auto_init_state(
    cli: &Cli,
    workdir: &std::path::Path,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    if !should_auto_init_state(&cli.command) || paths.state_dir.exists() {
        return Ok(());
    }
    let _ = scaffold::run_init(&InitOptions {
        workdir: workdir.to_path_buf(),
        state_dir_override: cli.run.state_dir.clone(),
        force: false,
        print_only: false,
    })?;
    eprintln!(
        "INFO: initialized LocalAgent state at {}",
        paths.state_dir.display()
    );
    Ok(())
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
    maybe_auto_init_state(&cli, &workdir, &paths)?;

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
            run_chat_repl(args, &cli.run, &paths).await?;
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
            let mcp_config_path = resolved_mcp_config_path(&cli.run, &paths.state_dir);
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
            let hooks_path = resolved_hooks_config_path(&cli.run, &paths.state_dir);
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
            handle_session_command(&store, &args.command)?;
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
                    let exit = run_tasks_graph(s, &cli.run, &paths).await?;
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

async fn run_chat_repl(
    chat: &ChatArgs,
    base_run: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    if chat.tui {
        return run_chat_tui(chat, base_run, paths).await;
    }
    let provider_kind = base_run
        .provider
        .ok_or_else(|| anyhow!("--provider is required in chat mode"))?;
    let model = base_run
        .model
        .clone()
        .ok_or_else(|| anyhow!("--model is required in chat mode"))?;
    let base_url = base_run
        .base_url
        .clone()
        .unwrap_or_else(|| provider_runtime::default_base_url(provider_kind).to_string());
    let mut active_run = base_run.clone();
    let mut pending_timeout_input = false;
    let mut pending_params_input = false;
    let mut timeout_notice_active = false;

    println!(
        "LocalAgent chat started (provider={} model={} tui={}).",
        provider_runtime::provider_cli_name(provider_kind),
        model,
        chat.tui
    );
    println!(
        "Commands: /help, /mode <safe|coding|web|custom>, /timeout [seconds|+N|-N|off], /params [key value], /dismiss, /exit, /clear"
    );

    loop {
        print!("You> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if pending_params_input && !input.starts_with('/') {
            if input.eq_ignore_ascii_case("cancel") {
                pending_params_input = false;
                println!("params update cancelled");
                continue;
            }
            match runtime_config::apply_params_input(&mut active_run, input) {
                Ok(msg) => {
                    pending_params_input = false;
                    println!("{msg}");
                }
                Err(msg) => {
                    println!("{msg}");
                    println!("enter '<key> <value>' or 'cancel'");
                }
            }
            continue;
        }
        if pending_timeout_input && !input.starts_with('/') {
            if input.eq_ignore_ascii_case("cancel") {
                pending_timeout_input = false;
                println!("timeout update cancelled");
                continue;
            }
            match runtime_config::apply_timeout_input(&mut active_run, input) {
                Ok(msg) => {
                    pending_timeout_input = false;
                    println!("{msg}");
                }
                Err(msg) => {
                    println!("{msg}");
                    println!("enter seconds, +N, -N, or 'cancel'");
                }
            }
            continue;
        }
        if input.starts_with('/') {
            match input {
                "/exit" => break,
                "/help" => {
                    println!("/help  show commands");
                    println!("/mode  show current mode");
                    println!("/mode <safe|coding|web|custom>  switch mode");
                    println!("/timeout  show timeout settings and wait for input");
                    println!("/timeout <seconds|+N|-N|off>  set/adjust timeout (off disables request+stream idle timeout)");
                    println!(
                        "/params  show current tuning params and wait for '<key> <value>' input"
                    );
                    println!("/params <key> <value>  set a tuning param");
                    println!("/dismiss  dismiss timeout notification");
                    println!("/clear clear current session messages");
                    println!("/exit  quit chat");
                }
                "/mode" => {
                    println!(
                        "current mode: {} (use /mode <safe|coding|web|custom>)",
                        chat_runtime::chat_mode_label(&active_run)
                    );
                }
                "/timeout" => {
                    pending_timeout_input = true;
                    println!("{}", runtime_config::timeout_settings_summary(&active_run));
                    println!("enter seconds, +N, -N, or 'cancel'");
                }
                "/params" => {
                    pending_params_input = true;
                    println!("{}", runtime_config::params_settings_summary(&active_run));
                    println!(
                        "editable keys: max_steps, max_context_chars, compaction_mode(off|summary), compaction_keep_last, tool_result_persist(all|digest|none), max_tool_output_bytes, max_read_bytes, stream(on|off), allow_shell(on|off), allow_write(on|off), enable_write_tools(on|off), allow_shell_in_workdir(on|off)"
                    );
                    println!("enter '<key> <value>' or 'cancel'");
                }
                "/dismiss" => {
                    if timeout_notice_active {
                        timeout_notice_active = false;
                        println!("timeout notification dismissed");
                    } else {
                        println!("no active timeout notification");
                    }
                }
                "/clear" => {
                    if active_run.no_session {
                        println!("sessions are disabled (--no-session), nothing to clear");
                    } else {
                        let session_path = paths
                            .sessions_dir
                            .join(format!("{}.json", active_run.session));
                        let store = SessionStore::new(session_path, active_run.session.clone());
                        store.reset()?;
                        println!("session '{}' cleared", active_run.session);
                    }
                }
                _ if input.starts_with("/mode ") => {
                    let mode = input["/mode ".len()..].trim();
                    if runtime_config::apply_chat_mode(&mut active_run, mode).is_some() {
                        println!(
                            "mode switched to {}",
                            chat_runtime::chat_mode_label(&active_run)
                        );
                    } else {
                        println!("unknown mode: {mode}. expected safe|coding|web|custom");
                    }
                }
                _ if input.starts_with("/timeout ") => {
                    let value = input["/timeout ".len()..].trim();
                    match runtime_config::apply_timeout_input(&mut active_run, value) {
                        Ok(msg) => println!("{msg}"),
                        Err(msg) => println!("{msg}"),
                    }
                }
                _ if input.starts_with("/params ") => {
                    let value = input["/params ".len()..].trim();
                    match runtime_config::apply_params_input(&mut active_run, value) {
                        Ok(msg) => println!("{msg}"),
                        Err(msg) => println!("{msg}"),
                    }
                }
                _ => println!("unknown command: {input}"),
            }
            continue;
        }

        let mut turn_args = active_run.clone();
        turn_args.prompt = Some(input.to_string());
        turn_args.tui = chat.tui;
        if !chat.tui && !turn_args.stream {
            turn_args.stream = true;
        }

        match provider_kind {
            ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
                let provider = OpenAiCompatProvider::new(
                    base_url.clone(),
                    turn_args.api_key.clone(),
                    provider_runtime::http_config_from_run_args(&turn_args),
                )?;
                let res = run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    input,
                    &turn_args,
                    paths,
                )
                .await?;
                if matches!(res.outcome.exit_reason, AgentExitReason::ProviderError) {
                    let err = res
                        .outcome
                        .error
                        .unwrap_or_else(|| "provider error".to_string());
                    eprintln!(
                        "{}\nHint: run `localagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
                        err,
                        provider_runtime::provider_cli_name(provider_kind),
                        base_url,
                        provider_runtime::provider_cli_name(provider_kind),
                        provider_runtime::default_base_url(provider_kind)
                    );
                    if runtime_config::is_timeout_error_text(&err) && !timeout_notice_active {
                        timeout_notice_active = true;
                        eprintln!("{}", runtime_config::timeout_notice_text(&active_run));
                    }
                }
            }
            ProviderKind::Ollama => {
                let provider = OllamaProvider::new(
                    base_url.clone(),
                    provider_runtime::http_config_from_run_args(&turn_args),
                )?;
                let res = run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    input,
                    &turn_args,
                    paths,
                )
                .await?;
                if matches!(res.outcome.exit_reason, AgentExitReason::ProviderError) {
                    let err = res
                        .outcome
                        .error
                        .unwrap_or_else(|| "provider error".to_string());
                    eprintln!(
                        "{}\nHint: run `localagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
                        err,
                        provider_runtime::provider_cli_name(provider_kind),
                        base_url,
                        provider_runtime::provider_cli_name(provider_kind),
                        provider_runtime::default_base_url(provider_kind)
                    );
                    if runtime_config::is_timeout_error_text(&err) && !timeout_notice_active {
                        timeout_notice_active = true;
                        eprintln!("{}", runtime_config::timeout_notice_text(&active_run));
                    }
                }
            }
            ProviderKind::Mock => {
                let provider = MockProvider::new();
                let _ = run_agent(
                    provider,
                    provider_kind,
                    &base_url,
                    &model,
                    input,
                    &turn_args,
                    paths,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn run_chat_tui(
    chat: &ChatArgs,
    base_run: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    let provider_kind = base_run
        .provider
        .ok_or_else(|| anyhow!("--provider is required in chat mode"))?;
    let model = base_run
        .model
        .clone()
        .ok_or_else(|| anyhow!("--model is required in chat mode"))?;
    let base_url = base_run
        .base_url
        .clone()
        .unwrap_or_else(|| provider_runtime::default_base_url(provider_kind).to_string());
    let cwd_label = chat_runtime::normalize_path_for_display(
        std::fs::canonicalize(&base_run.workdir)
            .or_else(|_| std::env::current_dir())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| base_run.workdir.display().to_string()),
    );
    let mut active_run = base_run.clone();

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    if chat.plain_tui {
        execute!(stdout, DisableMouseCapture, EnableBracketedPaste)?;
    } else {
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste
        )?;
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input = String::new();
    let mut prompt_history: Vec<String> = Vec::new();
    let mut history_idx: Option<usize> = None;
    let mut transcript: Vec<(String, String)> = vec![];
    let show_banner = !chat.no_banner;
    let mut logs: Vec<String> = Vec::new();
    let max_logs = base_run.tui_max_log_lines;
    let mut status = "idle".to_string();
    let mut status_detail = String::new();
    let mut provider_connected = true;
    let mut think_tick: u64 = 0;
    let mut ui_tick: u64 = 0;
    let mut approvals_selected = 0usize;
    let mut show_tools = false;
    let mut show_approvals = false;
    let mut show_logs = false;
    let mut transcript_scroll: usize = 0;
    let mut follow_output = true;
    let mut compact_tools = true;
    let mut tools_selected = 0usize;
    let mut tools_focus = true;
    let mut show_tool_details = false;
    let palette_items = [
        "toggle tools pane",
        "toggle approvals pane",
        "toggle logs pane",
        "toggle tool row density",
        "clear transcript",
        "jump to latest",
    ];
    let mut palette_open = false;
    let mut palette_selected = 0usize;
    let mut search_mode = false;
    let mut search_query = String::new();
    let mut search_line_cursor = 0usize;
    let mut slash_menu_index: usize = 0;
    let mut shared_chat_mcp_registry: Option<std::sync::Arc<McpRegistry>> = None;
    let mut pending_timeout_input = false;
    let mut pending_params_input = false;
    let mut timeout_notice_active = false;
    let mut ui_state = UiState::new(max_logs);
    ui_state.provider = provider_runtime::provider_cli_name(provider_kind).to_string();
    ui_state.model = model.clone();
    ui_state.caps_source = format!("{:?}", base_run.caps).to_lowercase();
    ui_state.policy_hash = "-".to_string();
    let mut streaming_assistant = String::new();

    let run_result: anyhow::Result<()> = async {
        loop {
            ui_state.on_tick(Instant::now());
            let tool_row_count = if compact_tools { 20 } else { 12 };
            let visible_tool_count = ui_state.tool_calls.len().min(tool_row_count);
            if visible_tool_count == 0 {
                tools_selected = 0;
                show_tool_details = false;
            } else {
                tools_selected = tools_selected.min(visible_tool_count.saturating_sub(1));
            }
            if ui_state.pending_approvals.is_empty() {
                approvals_selected = 0;
            } else {
                approvals_selected =
                    approvals_selected.min(ui_state.pending_approvals.len().saturating_sub(1));
            }
            if show_tools && !show_approvals {
                tools_focus = true;
            } else if show_approvals && !show_tools {
                tools_focus = false;
            }
            if !show_tools {
                show_tool_details = false;
            }

            terminal.draw(|f| {
                chat_ui::draw_chat_frame(
                    f,
                    chat_runtime::chat_mode_label(&active_run),
                    provider_runtime::provider_cli_name(provider_kind),
                    provider_connected,
                    &model,
                    &status,
                    &status_detail,
                    &transcript,
                    &streaming_assistant,
                    &ui_state,
                    tools_selected,
                    tools_focus,
                    show_tool_details,
                    approvals_selected,
                    &cwd_label,
                    &input,
                    &logs,
                    think_tick,
                    base_run.tui_refresh_ms,
                    show_tools,
                    show_approvals,
                    show_logs,
                    transcript_scroll,
                    compact_tools,
                    show_banner,
                    ui_tick,
                    if palette_open {
                        Some(format!(
                            "⌘ {}  (Up/Down, Enter, Esc)",
                            palette_items[palette_selected]
                        ))
                    } else if search_mode {
                        Some(format!(
                            "🔎 {}  (Enter next, Esc close)",
                            search_query
                        ))
                    } else if input.starts_with('/') {
                        chat_commands::slash_overlay_text(&input, slash_menu_index)
                    } else if input.starts_with('?') {
                        chat_commands::keybinds_overlay_text()
                    } else {
                        None
                    },
                );
            })?;

            if event::poll(Duration::from_millis(base_run.tui_refresh_ms))? {
                match event::read()? {
                    CEvent::Mouse(me) => {
                        if let Some(delta) = chat_runtime::mouse_scroll_delta(&me) {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, delta, max_scroll);
                            follow_output = false;
                        }
                    }
                    CEvent::Paste(pasted) => {
                        input.push_str(&chat_runtime::normalize_pasted_text(&pasted));
                        history_idx = None;
                        slash_menu_index = 0;
                    }
                    CEvent::Key(key) => {
                    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        continue;
                    }
                    if key.code == KeyCode::Esc {
                        break;
                    }
                    if key.code == KeyCode::End {
                        follow_output = true;
                        transcript_scroll = usize::MAX;
                        continue;
                    }
                    if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        palette_open = !palette_open;
                        search_mode = false;
                        continue;
                    }
                    if key.code == KeyCode::Char('f') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        search_mode = true;
                        palette_open = false;
                        continue;
                    }
                    if palette_open {
                        match key.code {
                            KeyCode::Esc => palette_open = false,
                            KeyCode::Up => {
                                palette_selected = palette_selected.saturating_sub(1);
                            }
                            KeyCode::Down => {
                                if palette_selected + 1 < palette_items.len() {
                                    palette_selected += 1;
                                }
                            }
                            KeyCode::Enter => {
                                match palette_selected {
                                    0 => show_tools = !show_tools,
                                    1 => show_approvals = !show_approvals,
                                    2 => show_logs = !show_logs,
                                    3 => compact_tools = !compact_tools,
                                    4 => {
                                        transcript.clear();
                                        ui_state.tool_calls.clear();
                                        streaming_assistant.clear();
                                        transcript_scroll = 0;
                                        follow_output = true;
                                    }
                                    5 => {
                                        follow_output = true;
                                        transcript_scroll = usize::MAX;
                                    }
                                    _ => {}
                                }
                                palette_open = false;
                            }
                            _ => {}
                        }
                        continue;
                    }
                    if search_mode {
                        let mut do_search = false;
                        match key.code {
                            KeyCode::Esc => search_mode = false,
                            KeyCode::Backspace => {
                                search_query.pop();
                                search_line_cursor = 0;
                                do_search = true;
                            }
                            KeyCode::Enter => {
                                do_search = true;
                                search_line_cursor = search_line_cursor.saturating_add(1);
                            }
                            KeyCode::Char(c) if chat_runtime::is_text_input_mods(key.modifiers) => {
                                search_query.push(c);
                                search_line_cursor = 0;
                                do_search = true;
                            }
                            _ => {}
                        }
                        if do_search && !search_query.is_empty() {
                            let hay = transcript
                                .iter()
                                .map(|(role, text)| format!("{}: {}", role.to_uppercase(), text))
                                .collect::<Vec<_>>()
                                .join("\n\n");
                            let lines: Vec<&str> = hay.lines().collect();
                            let query = search_query.to_lowercase();
                            let mut found = None;
                            for (idx, line) in lines.iter().enumerate().skip(search_line_cursor) {
                                if line.to_lowercase().contains(&query) {
                                    found = Some(idx);
                                    break;
                                }
                            }
                            if found.is_none() {
                                for (idx, line) in lines.iter().enumerate().take(search_line_cursor) {
                                    if line.to_lowercase().contains(&query) {
                                        found = Some(idx);
                                        break;
                                    }
                                }
                            }
                            if let Some(idx) = found {
                                transcript_scroll = idx;
                                follow_output = false;
                                search_line_cursor = idx;
                            }
                        }
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                        KeyCode::Up => {
                            if input.starts_with('/') {
                                let matches_len = chat_commands::slash_match_count(&input);
                                if matches_len > 0 {
                                    slash_menu_index = if slash_menu_index == 0 {
                                        matches_len - 1
                                    } else {
                                        slash_menu_index - 1
                                    };
                                }
                                continue;
                            }
                            if !prompt_history.is_empty() {
                                let next = match history_idx {
                                    None => prompt_history.len().saturating_sub(1),
                                    Some(i) => i.saturating_sub(1),
                                };
                                history_idx = Some(next);
                                input = prompt_history[next].clone();
                            }
                        }
                        KeyCode::Down => {
                            if input.starts_with('/') {
                                let matches_len = chat_commands::slash_match_count(&input);
                                if matches_len > 0 {
                                    slash_menu_index = (slash_menu_index + 1) % matches_len;
                                }
                                continue;
                            }
                            if !prompt_history.is_empty() {
                                if let Some(i) = history_idx {
                                    let next = (i + 1).min(prompt_history.len());
                                    if next >= prompt_history.len() {
                                        history_idx = None;
                                        input.clear();
                                    } else {
                                        history_idx = Some(next);
                                        input = prompt_history[next].clone();
                                    }
                                }
                            }
                        }
                        KeyCode::PageUp => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, -12, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::PageDown => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, 12, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, -10, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            let max_scroll =
                                chat_runtime::transcript_max_scroll_lines(&transcript, &streaming_assistant);
                            transcript_scroll =
                                chat_runtime::adjust_transcript_scroll(transcript_scroll, 10, max_scroll);
                            follow_output = false;
                        }
                        KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_tools = !show_tools;
                        }
                        KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_approvals = !show_approvals;
                        }
                        KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_logs = !show_logs;
                        }
                        KeyCode::Tab => {
                            if show_tools && show_approvals {
                                tools_focus = !tools_focus;
                            }
                        }
                        KeyCode::Char('1') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_tools = !show_tools;
                        }
                        KeyCode::Char('2') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_approvals = !show_approvals;
                        }
                        KeyCode::Char('3') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            show_logs = !show_logs;
                        }
                        KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if show_tools && (!show_approvals || tools_focus) {
                                if tools_selected + 1 < visible_tool_count {
                                    tools_selected += 1;
                                }
                            } else if approvals_selected + 1 < ui_state.pending_approvals.len() {
                                approvals_selected += 1;
                            }
                        }
                        KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if show_tools && (!show_approvals || tools_focus) {
                                tools_selected = tools_selected.saturating_sub(1);
                            } else {
                                approvals_selected = approvals_selected.saturating_sub(1);
                            }
                        }
                        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Err(e) = ui_state.refresh_approvals(&paths.approvals_path) {
                                logs.push(format!("approvals refresh failed: {e}"));
                            }
                        }
                        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(row) = ui_state.pending_approvals.get(approvals_selected) {
                                let store = ApprovalsStore::new(paths.approvals_path.clone());
                                if let Err(e) = store.approve(&row.id, None, None) {
                                    logs.push(format!("approve failed: {e}"));
                                } else {
                                    logs.push(format!("approved {}", row.id));
                                }
                                let _ = ui_state.refresh_approvals(&paths.approvals_path);
                            }
                        }
                        KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            if let Some(row) = ui_state.pending_approvals.get(approvals_selected) {
                                let store = ApprovalsStore::new(paths.approvals_path.clone());
                                if let Err(e) = store.deny(&row.id) {
                                    logs.push(format!("deny failed: {e}"));
                                } else {
                                    logs.push(format!("denied {}", row.id));
                                }
                                let _ = ui_state.refresh_approvals(&paths.approvals_path);
                            }
                        }
                        KeyCode::Enter => {
                            let line = input.trim().to_string();
                            input.clear();
                            history_idx = None;
                            slash_menu_index = 0;
                            if line.is_empty() {
                                continue;
                            }
                            if pending_params_input && !line.starts_with('/') {
                                if line.eq_ignore_ascii_case("cancel") {
                                    pending_params_input = false;
                                    logs.push("params update cancelled".to_string());
                                } else {
                                    match runtime_config::apply_params_input(&mut active_run, &line) {
                                        Ok(msg) => {
                                            pending_params_input = false;
                                            logs.push(msg);
                                        }
                                        Err(msg) => logs.push(msg),
                                    }
                                }
                                show_logs = true;
                                continue;
                            }
                            if pending_timeout_input && !line.starts_with('/') {
                                if line.eq_ignore_ascii_case("cancel") {
                                    pending_timeout_input = false;
                                    logs.push("timeout update cancelled".to_string());
                                    show_logs = false;
                                } else {
                                    match runtime_config::apply_timeout_input(&mut active_run, &line) {
                                        Ok(msg) => {
                                            pending_timeout_input = false;
                                            logs.push(msg);
                                            show_logs = false;
                                        }
                                        Err(msg) => {
                                            logs.push(msg);
                                            show_logs = true;
                                        }
                                    }
                                }
                                continue;
                            }
                            if line.starts_with('/') {
                                let resolved = chat_commands::selected_slash_command(&line, slash_menu_index)
                                    .or_else(|| chat_commands::resolve_slash_command(&line))
                                    .unwrap_or(line.as_str());
                                match resolved {
                                    "/exit" => break,
                                    "/help" => {
                                        logs.push(
                                            "commands: /help /mode <safe|coding|web|custom> /timeout [seconds|+N|-N|off] /params [key value] /dismiss /clear /exit /hide tools|approvals|logs /show tools|approvals|logs|all ; slash dropdown: type / then Up/Down + Enter ; panes: Ctrl+T/Ctrl+Y/Ctrl+G (Ctrl+1/2/3 aliases, terminal-dependent) ; scroll: PgUp/PgDn, Ctrl+U/Ctrl+D, mouse wheel ; approvals: Ctrl+J/K select, Ctrl+A approve, Ctrl+X deny, Ctrl+R refresh ; history: Up/Down ; Esc quits"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/mode" => {
                                        logs.push(format!(
                                            "current mode: {} (use /mode <safe|coding|web|custom>)",
                                            chat_runtime::chat_mode_label(&active_run)
                                        ));
                                        show_logs = true;
                                    }
                                    "/timeout" => {
                                        pending_timeout_input = true;
                                        logs.push(runtime_config::timeout_settings_summary(&active_run));
                                        logs.push(
                                            "enter seconds, +N, -N, or 'cancel' on the next line"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/params" => {
                                        pending_params_input = true;
                                        logs.push(runtime_config::params_settings_summary(&active_run));
                                        logs.push(
                                            "editable keys: max_steps, max_context_chars, compaction_mode(off|summary), compaction_keep_last, tool_result_persist(all|digest|none), max_tool_output_bytes, max_read_bytes, stream(on|off), allow_shell(on|off), allow_write(on|off), enable_write_tools(on|off), allow_shell_in_workdir(on|off)"
                                                .to_string(),
                                        );
                                        logs.push(
                                            "enter '<key> <value>' or 'cancel' on the next line"
                                                .to_string(),
                                        );
                                        show_logs = true;
                                    }
                                    "/dismiss" => {
                                        if timeout_notice_active {
                                            timeout_notice_active = false;
                                            logs.retain(|l| !l.starts_with("[timeout-notice]"));
                                            logs.push("timeout notification dismissed".to_string());
                                        } else {
                                            logs.push("no active timeout notification".to_string());
                                        }
                                        show_logs = true;
                                    }
                                    "/clear" => {
                                        if active_run.no_session {
                                            transcript.clear();
                                            ui_state.tool_calls.clear();
                                            streaming_assistant.clear();
                                            transcript_scroll = 0;
                                            follow_output = true;
                                            logs.push("cleared chat transcript".to_string());
                                        } else {
                                            let session_path =
                                                paths.sessions_dir.join(format!("{}.json", active_run.session));
                                            let store = SessionStore::new(session_path, active_run.session.clone());
                                            store.reset()?;
                                            transcript.clear();
                                            ui_state.tool_calls.clear();
                                            streaming_assistant.clear();
                                            transcript_scroll = 0;
                                            follow_output = true;
                                            logs.push(format!(
                                                "session '{}' and transcript cleared",
                                                active_run.session
                                            ));
                                        }
                                    }
                                    "/hide tools" => show_tools = false,
                                    "/hide approvals" => show_approvals = false,
                                    "/hide logs" => show_logs = false,
                                    "/show tools" => show_tools = true,
                                    "/show approvals" => show_approvals = true,
                                    "/show logs" => show_logs = true,
                                    "/show all" => {
                                        show_tools = true;
                                        show_approvals = true;
                                        show_logs = true;
                                    }
                                    _ if resolved.starts_with("/mode ") => {
                                        let mode = resolved["/mode ".len()..].trim();
                                        if runtime_config::apply_chat_mode(&mut active_run, mode).is_some() {
                                            logs.push(format!(
                                                "mode switched to {}",
                                                chat_runtime::chat_mode_label(&active_run)
                                            ));
                                        } else {
                                            logs.push(format!(
                                                "unknown mode: {mode}. expected safe|coding|web|custom"
                                            ));
                                        }
                                        show_logs = true;
                                    }
                                    _ if resolved.starts_with("/timeout ") => {
                                        let value = resolved["/timeout ".len()..].trim();
                                        match runtime_config::apply_timeout_input(&mut active_run, value) {
                                            Ok(msg) => {
                                                logs.push(msg);
                                                show_logs = false;
                                            }
                                            Err(msg) => {
                                                logs.push(msg);
                                                show_logs = true;
                                            }
                                        }
                                    }
                                    _ if resolved.starts_with("/params ") => {
                                        let value = resolved["/params ".len()..].trim();
                                        match runtime_config::apply_params_input(&mut active_run, value) {
                                            Ok(msg) => logs.push(msg),
                                            Err(msg) => logs.push(msg),
                                        }
                                        show_logs = true;
                                    }
                                    _ => logs.push(format!("unknown command: {}", line)),
                                }
                                continue;
                            }

                            if line.is_empty() && show_tools && (!show_approvals || tools_focus) {
                                if visible_tool_count > 0 {
                                    show_tool_details = !show_tool_details;
                                    if show_tool_details {
                                        show_logs = false;
                                    }
                                }
                                continue;
                            }

                            prompt_history.push(line.clone());
                            // Sending a new prompt should always re-anchor the transcript to latest.
                            follow_output = true;
                            transcript_scroll = usize::MAX;
                            transcript.push(("user".to_string(), line.clone()));
                            if line.starts_with('?') {
                                show_logs = true;
                                continue;
                            }
                            status = "running".to_string();
                            status_detail.clear();
                            streaming_assistant.clear();
                            think_tick = 0;
                            terminal.draw(|f| {
                                chat_ui::draw_chat_frame(
                                    f,
                                    chat_runtime::chat_mode_label(&active_run),
                                    provider_runtime::provider_cli_name(provider_kind),
                                    provider_connected,
                                    &model,
                                    &status,
                                    &status_detail,
                                    &transcript,
                                    &streaming_assistant,
                                    &ui_state,
                                    tools_selected,
                                    tools_focus,
                                    show_tool_details,
                                    approvals_selected,
                                    &cwd_label,
                                    &input,
                                    &logs,
                                    think_tick,
                                    base_run.tui_refresh_ms,
                                    show_tools,
                                    show_approvals,
                                    show_logs,
                                    transcript_scroll,
                                    compact_tools,
                                    show_banner,
                                    ui_tick,
                                    if palette_open {
                                        Some(format!(
                                            "⌘ {}  (Up/Down, Enter, Esc)",
                                            palette_items[palette_selected]
                                        ))
                                    } else if search_mode {
                                        Some(format!(
                                            "🔎 {}  (Enter next, Esc close)",
                                            search_query
                                        ))
                                    } else if input.starts_with('/') {
                                        chat_commands::slash_overlay_text(&input, slash_menu_index)
                                    } else if input.starts_with('?') {
                                        chat_commands::keybinds_overlay_text()
                                    } else {
                                        None
                                    },
                                );
                            })?;
                            ui_tick = ui_tick.saturating_add(1);

                            let (tx, rx) = std::sync::mpsc::channel::<Event>();
                            let mut turn_args = active_run.clone();
                            turn_args.prompt = Some(line.clone());
                            turn_args.tui = false;
                            turn_args.stream = true;

                            if !turn_args.mcp.is_empty() && shared_chat_mcp_registry.is_none() {
                                let mcp_config_path =
                                    resolved_mcp_config_path(&turn_args, &paths.state_dir);
                                match McpRegistry::from_config_path(
                                    &mcp_config_path,
                                    &turn_args.mcp,
                                    Duration::from_secs(30),
                                )
                                .await
                                {
                                    Ok(reg) => {
                                        shared_chat_mcp_registry = Some(std::sync::Arc::new(reg));
                                    }
                                    Err(e) => {
                                        let msg = format!("failed to initialize MCP session: {e}");
                                        logs.push(msg.clone());
                                        show_logs = true;
                                        transcript.push(("system".to_string(), msg));
                                        status = "idle".to_string();
                                        status_detail = "mcp init failed".to_string();
                                        if follow_output {
                                            transcript_scroll = usize::MAX;
                                        }
                                        continue;
                                    }
                                }
                            }

                            let mut fut: std::pin::Pin<
                                Box<
                                    dyn std::future::Future<
                                            Output = anyhow::Result<RunExecutionResult>,
                                        > + Send,
                                >,
                            > = match provider_kind {
                                ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
                                    let provider = OpenAiCompatProvider::new(
                                        base_url.clone(),
                                        turn_args.api_key.clone(),
                                        provider_runtime::http_config_from_run_args(&turn_args),
                                    )?;
                                    Box::pin(run_agent_with_ui(
                                        provider,
                                        provider_kind,
                                        &base_url,
                                        &model,
                                        &line,
                                        &turn_args,
                                        paths,
                                        Some(tx),
                                        shared_chat_mcp_registry.clone(),
                                        true,
                                    ))
                                }
                                ProviderKind::Ollama => {
                                    let provider = OllamaProvider::new(
                                        base_url.clone(),
                                        provider_runtime::http_config_from_run_args(&turn_args),
                                    )?;
                                    Box::pin(run_agent_with_ui(
                                        provider,
                                        provider_kind,
                                        &base_url,
                                        &model,
                                        &line,
                                        &turn_args,
                                        paths,
                                        Some(tx),
                                        shared_chat_mcp_registry.clone(),
                                        true,
                                    ))
                                }
                                ProviderKind::Mock => {
                                    let provider = MockProvider::new();
                                    Box::pin(run_agent_with_ui(
                                        provider,
                                        provider_kind,
                                        &base_url,
                                        &model,
                                        &line,
                                        &turn_args,
                                        paths,
                                        Some(tx),
                                        shared_chat_mcp_registry.clone(),
                                        true,
                                    ))
                                }
                            };

                            loop {
                                ui_state.on_tick(Instant::now());
                                while let Ok(ev) = rx.try_recv() {
                                    ui_state.apply_event(&ev);
                                    match ev.kind {
                                        EventKind::ModelDelta => {
                                            if let Some(d) = ev.data.get("delta").and_then(|v| v.as_str()) {
                                                streaming_assistant.push_str(d);
                                                if follow_output {
                                                    transcript_scroll = usize::MAX;
                                                }
                                            }
                                        }
                                        EventKind::ModelResponseEnd => {
                                            if streaming_assistant.is_empty() {
                                                if let Some(c) = ev.data.get("content").and_then(|v| v.as_str()) {
                                                    streaming_assistant.push_str(c);
                                                    if follow_output {
                                                        transcript_scroll = usize::MAX;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                while event::poll(Duration::from_millis(0))? {
                                    match event::read()? {
                                        CEvent::Mouse(me) => {
                                            if let Some(delta) = chat_runtime::mouse_scroll_delta(&me) {
                                                let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                    &transcript,
                                                    &streaming_assistant,
                                                );
                                                transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                    transcript_scroll,
                                                    delta,
                                                    max_scroll,
                                                );
                                                follow_output = false;
                                            }
                                        }
                                        CEvent::Paste(pasted) => {
                                            input.push_str(&chat_runtime::normalize_pasted_text(&pasted));
                                            history_idx = None;
                                            slash_menu_index = 0;
                                        }
                                        CEvent::Key(key)
                                            if matches!(
                                                key.kind,
                                                KeyEventKind::Press | KeyEventKind::Repeat
                                            ) =>
                                        {
                                            match key.code {
                                                KeyCode::Esc => {
                                                    let partial = agent::sanitize_user_visible_output(
                                                        &streaming_assistant,
                                                    );
                                                    if !partial.trim().is_empty() {
                                                        transcript.push((
                                                            "assistant".to_string(),
                                                            format!("{partial}\n\n[cancelled]"),
                                                        ));
                                                    }
                                                    logs.push(
                                                        "run cancelled by user (Esc/Ctrl+C)"
                                                            .to_string(),
                                                    );
                                                    show_logs = true;
                                                    streaming_assistant.clear();
                                                    status = "idle".to_string();
                                                    status_detail = "cancelled by user".to_string();
                                                    if follow_output {
                                                        transcript_scroll = usize::MAX;
                                                    }
                                                    break;
                                                }
                                                KeyCode::Char('c')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    let partial = agent::sanitize_user_visible_output(
                                                        &streaming_assistant,
                                                    );
                                                    if !partial.trim().is_empty() {
                                                        transcript.push((
                                                            "assistant".to_string(),
                                                            format!("{partial}\n\n[cancelled]"),
                                                        ));
                                                    }
                                                    logs.push(
                                                        "run cancelled by user (Esc/Ctrl+C)"
                                                            .to_string(),
                                                    );
                                                    show_logs = true;
                                                    streaming_assistant.clear();
                                                    status = "idle".to_string();
                                                    status_detail = "cancelled by user".to_string();
                                                    if follow_output {
                                                        transcript_scroll = usize::MAX;
                                                    }
                                                    break;
                                                }
                                                KeyCode::PageUp => {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        -12,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::PageDown => {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        12,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::Char('u')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        -10,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::Char('d')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    let max_scroll = chat_runtime::transcript_max_scroll_lines(
                                                        &transcript,
                                                        &streaming_assistant,
                                                    );
                                                    transcript_scroll = chat_runtime::adjust_transcript_scroll(
                                                        transcript_scroll,
                                                        10,
                                                        max_scroll,
                                                    );
                                                    follow_output = false;
                                                }
                                                KeyCode::Char('t')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_tools = !show_tools;
                                                }
                                                KeyCode::Char('y')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_approvals = !show_approvals;
                                                }
                                                KeyCode::Char('g')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_logs = !show_logs;
                                                }
                                                KeyCode::Tab => {
                                                    if show_tools && show_approvals {
                                                        tools_focus = !tools_focus;
                                                    }
                                                }
                                                KeyCode::Char('1')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_tools = !show_tools;
                                                }
                                                KeyCode::Char('2')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_approvals = !show_approvals;
                                                }
                                                KeyCode::Char('3')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    show_logs = !show_logs;
                                                }
                                                KeyCode::Char('j')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if show_tools && (!show_approvals || tools_focus) {
                                                        if tools_selected + 1 < visible_tool_count {
                                                            tools_selected += 1;
                                                        }
                                                    } else if approvals_selected + 1
                                                        < ui_state.pending_approvals.len()
                                                    {
                                                        approvals_selected += 1;
                                                    }
                                                }
                                                KeyCode::Char('k')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if show_tools && (!show_approvals || tools_focus) {
                                                        tools_selected = tools_selected.saturating_sub(1);
                                                    } else {
                                                        approvals_selected =
                                                            approvals_selected.saturating_sub(1);
                                                    }
                                                }
                                                KeyCode::Char('r')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if let Err(e) =
                                                        ui_state.refresh_approvals(&paths.approvals_path)
                                                    {
                                                        logs.push(format!(
                                                            "approvals refresh failed: {e}"
                                                        ));
                                                    }
                                                }
                                                KeyCode::Char('a')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if let Some(row) =
                                                        ui_state.pending_approvals.get(approvals_selected)
                                                    {
                                                        let store = ApprovalsStore::new(
                                                            paths.approvals_path.clone(),
                                                        );
                                                        if let Err(e) = store.approve(&row.id, None, None)
                                                        {
                                                            logs.push(format!("approve failed: {e}"));
                                                        } else {
                                                            logs.push(format!("approved {}", row.id));
                                                        }
                                                        let _ =
                                                            ui_state.refresh_approvals(&paths.approvals_path);
                                                    }
                                                }
                                                KeyCode::Char('x')
                                                    if key
                                                        .modifiers
                                                        .contains(KeyModifiers::CONTROL) =>
                                                {
                                                    if let Some(row) =
                                                        ui_state.pending_approvals.get(approvals_selected)
                                                    {
                                                        let store = ApprovalsStore::new(
                                                            paths.approvals_path.clone(),
                                                        );
                                                        if let Err(e) = store.deny(&row.id) {
                                                            logs.push(format!("deny failed: {e}"));
                                                        } else {
                                                            logs.push(format!("denied {}", row.id));
                                                        }
                                                        let _ =
                                                            ui_state.refresh_approvals(&paths.approvals_path);
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                if status == "idle" {
                                    break;
                                }

                                terminal.draw(|f| {
                                    chat_ui::draw_chat_frame(
                                        f,
                                        chat_runtime::chat_mode_label(&active_run),
                                        provider_runtime::provider_cli_name(provider_kind),
                                        provider_connected,
                                        &model,
                                        &status,
                                        &status_detail,
                                        &transcript,
                                        &streaming_assistant,
                                        &ui_state,
                                        tools_selected,
                                        tools_focus,
                                        show_tool_details,
                                        approvals_selected,
                                        &cwd_label,
                                        &input,
                                        &logs,
                                        think_tick,
                                        base_run.tui_refresh_ms,
                                        show_tools,
                                        show_approvals,
                                        show_logs,
                                        transcript_scroll,
                                        compact_tools,
                                        show_banner,
                                        ui_tick,
                                        if palette_open {
                                            Some(format!(
                                                "⌘ {}  (Up/Down, Enter, Esc)",
                                                palette_items[palette_selected]
                                            ))
                                        } else if search_mode {
                                            Some(format!(
                                                "🔎 {}  (Enter next, Esc close)",
                                                search_query
                                            ))
                                        } else if input.starts_with('/') {
                                            chat_commands::slash_overlay_text(&input, slash_menu_index)
                                        } else if input.starts_with('?') {
                                            chat_commands::keybinds_overlay_text()
                                        } else {
                                            None
                                        },
                                    );
                                })?;

                                let maybe_res = tokio::select! {
                                    r = &mut fut => Some(r),
                                    _ = tokio::time::sleep(Duration::from_millis(base_run.tui_refresh_ms)) => None,
                                };
                                if let Some(res) = maybe_res {
                                    match res {
                                        Ok(out) => {
                                            let outcome = out.outcome;
                                            let exit_reason = outcome.exit_reason;
                                            let outcome_error =
                                                outcome.error.unwrap_or_else(String::new);
                                            let final_text = if outcome.final_output.is_empty() {
                                                agent::sanitize_user_visible_output(
                                                    &streaming_assistant,
                                                )
                                            } else {
                                                outcome.final_output
                                            };
                                            if matches!(exit_reason, AgentExitReason::ProviderError) {
                                                let err = if outcome_error.trim().is_empty() {
                                                    "provider error".to_string()
                                                } else {
                                                    outcome_error.clone()
                                                };
                                                provider_connected = false;
                                                logs.push(err.clone());
                                                if runtime_config::is_timeout_error_text(&err) && !timeout_notice_active {
                                                    timeout_notice_active = true;
                                                    logs.push(runtime_config::timeout_notice_text(&active_run));
                                                }
                                                show_logs = true;
                                                status_detail = format!(
                                                    "{}: {}",
                                                    exit_reason.as_str(),
                                                    chat_view_utils::compact_status_detail(&err, 120)
                                                );
                                                transcript.push((
                                                    "system".to_string(),
                                                    format!("Provider error: {err}"),
                                                ));
                                                if let Some(hint) = runtime_config::protocol_remediation_hint(&err) {
                                                    logs.push(hint.clone());
                                                    transcript.push((
                                                        "system".to_string(),
                                                        hint,
                                                    ));
                                                    show_logs = true;
                                                }
                                            } else {
                                                provider_connected = true;
                                                if matches!(exit_reason, AgentExitReason::Ok) {
                                                    status_detail.clear();
                                                } else {
                                                    let reason_text = if !outcome_error.trim().is_empty() {
                                                        outcome_error.clone()
                                                    } else if !final_text.trim().is_empty() {
                                                        final_text.clone()
                                                    } else {
                                                        exit_reason.as_str().to_string()
                                                    };
                                                    let reason_short =
                                                        chat_view_utils::compact_status_detail(&reason_text, 120);
                                                    status_detail = format!(
                                                        "{}: {}",
                                                        exit_reason.as_str(),
                                                        reason_short
                                                    );
                                                    transcript.push((
                                                        "system".to_string(),
                                                        format!(
                                                            "Run ended with {}: {}",
                                                            exit_reason.as_str(),
                                                            chat_view_utils::compact_status_detail(&reason_text, 220)
                                                        ),
                                                    ));
                                                    if let Some(hint) =
                                                        runtime_config::protocol_remediation_hint(&reason_text)
                                                    {
                                                        logs.push(hint.clone());
                                                        transcript.push((
                                                            "system".to_string(),
                                                            hint,
                                                        ));
                                                        show_logs = true;
                                                    }
                                                }
                                            }
                                            if !final_text.trim().is_empty() {
                                                transcript.push(("assistant".to_string(), final_text));
                                            }
                                            if follow_output {
                                                transcript_scroll = usize::MAX;
                                            }
                                        }
                                        Err(e) => {
                                            let msg = format!("run failed: {e}");
                                            if runtime_config::is_timeout_error_text(&msg) {
                                                provider_connected = false;
                                            }
                                            logs.push(msg.clone());
                                            show_logs = true;
                                            transcript.push(("system".to_string(), msg));
                                            status_detail = format!(
                                                "run failed: {}",
                                                chat_view_utils::compact_status_detail(&e.to_string(), 120)
                                            );
                                            if let Some(hint) = runtime_config::protocol_remediation_hint(
                                                &format!("{e}"),
                                            ) {
                                                logs.push(hint.clone());
                                                transcript.push(("system".to_string(), hint));
                                                show_logs = true;
                                            }
                                            if follow_output {
                                                transcript_scroll = usize::MAX;
                                            }
                                        }
                                    }
                                    streaming_assistant.clear();
                                    status = "idle".to_string();
                                    break;
                                }
                                think_tick = think_tick.saturating_add(1);
                                ui_tick = ui_tick.saturating_add(1);
                            }
                        }
                        KeyCode::Backspace => {
                            input.pop();
                            slash_menu_index = 0;
                        }
                        KeyCode::Char(c) => {
                            if chat_runtime::is_text_input_mods(key.modifiers) {
                                input.push(c);
                                if c == '/' && input.len() == 1 {
                                    slash_menu_index = 0;
                                }
                            }
                        }
                        _ => {}
                    }
                    if logs.len() > max_logs {
                        let drop_n = logs.len() - max_logs;
                        logs.drain(0..drop_n);
                    }
                    ui_tick = ui_tick.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
    .await;

    disable_raw_mode()?;
    if chat.plain_tui {
        execute!(
            terminal.backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture
        )?;
    } else {
        execute!(
            terminal.backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen
        )?;
    }
    terminal.show_cursor()?;
    run_result
}

#[allow(clippy::too_many_arguments)]
async fn run_agent<P: ModelProvider>(
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
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_agent_with_ui<P: ModelProvider>(
    provider: P,
    provider_kind: ProviderKind,
    base_url: &str,
    default_model: &str,
    prompt: &str,
    args: &RunArgs,
    paths: &store::StatePaths,
    external_ui_tx: Option<Sender<Event>>,
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
        resolve_instruction_messages(args, &paths.state_dir, &worker_model)?;

    let mcp_config_path = resolved_mcp_config_path(args, &paths.state_dir);
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

    let prep = run_prep::prepare_tools_and_qualification(
        &provider,
        provider_kind,
        base_url,
        &worker_model,
        args,
        &paths.state_dir,
        &mcp_config_path,
        mcp_registry.as_ref(),
        gate_build.policy_for_exposure.as_ref(),
    )
    .await?;
    let all_tools = prep.all_tools;
    let mcp_tool_snapshot = prep.mcp_tool_snapshot;
    let qualification_fallback_note = prep.qualification_fallback_note;
    if let Some(note) = &qualification_fallback_note {
        eprintln!("WARN: {note}");
    }
    let mcp_tool_catalog_hash_hex = prep.mcp_tool_catalog_hash_hex;
    let mcp_config_hash_hex = prep.mcp_config_hash_hex;
    let mcp_startup_live_catalog_hash_hex = prep.mcp_startup_live_catalog_hash_hex;
    let mcp_snapshot_pinned = prep.mcp_snapshot_pinned;
    let mcp_pin_enforcement = format!("{:?}", args.mcp_pin_enforcement).to_lowercase();
    let hooks_config_path = resolved_hooks_config_path(args, &paths.state_dir);
    let tool_schema_hash_hex_map = store::tool_schema_hash_hex_map(&all_tools);
    gate_ctx.tool_schema_hashes = tool_schema_hash_hex_map.clone();
    let hooks_config_hash_hex =
        ops_helpers::compute_hooks_config_hash_hex(resolved_settings.hooks_mode, &hooks_config_path);
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
    let mcp_pin_snapshot =
        if mcp_tool_catalog_hash_hex.is_some() || mcp_startup_live_catalog_hash_hex.is_some() {
            Some(store::McpPinSnapshotRecord {
                enforcement: mcp_pin_enforcement.clone(),
                configured_catalog_hash_hex: mcp_tool_catalog_hash_hex.clone().unwrap_or_default(),
                startup_live_catalog_hash_hex: mcp_startup_live_catalog_hash_hex.clone(),
                mcp_config_hash_hex: mcp_config_hash_hex.clone(),
                pinned: mcp_snapshot_pinned,
            })
        } else {
            None
        };
    emit_event(
        &mut event_sink,
        &run_id,
        0,
        EventKind::McpPinned,
        serde_json::json!({
            "enforcement": mcp_pin_enforcement,
            "configured_hash_hex": mcp_tool_catalog_hash_hex,
            "startup_live_hash_hex": mcp_startup_live_catalog_hash_hex,
            "mcp_config_hash_hex": mcp_config_hash_hex,
            "pinned": mcp_snapshot_pinned
        }),
    );
    if let Some(note) = &qualification_fallback_note {
        emit_event(
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
        emit_event(
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
        let planner_out = run_planner_phase(
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
                    emit_event(
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
                    let cli_config = build_run_cli_config(
                        provider_kind,
                        base_url,
                        &worker_model,
                        args,
                        &resolved_settings,
                        &hooks_config_path,
                        &mcp_config_path,
                        tool_catalog.clone(),
                        mcp_tool_snapshot.clone(),
                        mcp_tool_catalog_hash_hex.clone(),
                        policy_version,
                        includes_resolved.clone(),
                        mcp_allowlist.clone(),
                        args.mode,
                        Some(planner_model.clone()),
                        Some(worker_model.clone()),
                        Some(args.planner_max_steps),
                        Some(format!("{:?}", args.planner_output).to_lowercase()),
                        Some(planner_strict_effective),
                        Some(format!("{:?}", effective_plan_tool_enforcement).to_lowercase()),
                        &instruction_resolution,
                    );
                    let config_fingerprint =
                        build_config_fingerprint(&cli_config, args, &worker_model, paths);
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
                emit_event(
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
                emit_event(
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
                emit_event(
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
                let cli_config = build_run_cli_config(
                    provider_kind,
                    base_url,
                    &worker_model,
                    args,
                    &resolved_settings,
                    &hooks_config_path,
                    &mcp_config_path,
                    tool_catalog.clone(),
                    mcp_tool_snapshot.clone(),
                    mcp_tool_catalog_hash_hex.clone(),
                    policy_version,
                    includes_resolved.clone(),
                    mcp_allowlist.clone(),
                    args.mode,
                    Some(planner_model.clone()),
                    Some(worker_model.clone()),
                    Some(args.planner_max_steps),
                    Some(format!("{:?}", args.planner_output).to_lowercase()),
                    Some(planner_strict_effective),
                    Some(format!("{:?}", effective_plan_tool_enforcement).to_lowercase()),
                    &instruction_resolution,
                );
                let config_fingerprint =
                    build_config_fingerprint(&cli_config, args, &worker_model, paths);
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
    };

    let base_instruction_messages = instruction_resolution.messages.clone();
    let base_task_memory = task_memory.clone();
    let initial_injected_messages = merge_injected_messages(
        base_instruction_messages.clone(),
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
        emit_event(
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
        match run_planner_phase(
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
                emit_event(
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
                emit_event(
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
                let replan_injected = merge_injected_messages(
                    base_instruction_messages.clone(),
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
    let cli_config = build_run_cli_config(
        provider_kind,
        base_url,
        &worker_model,
        args,
        &resolved_settings,
        &hooks_config_path,
        &mcp_config_path,
        tool_catalog.clone(),
        mcp_tool_snapshot.clone(),
        mcp_tool_catalog_hash_hex.clone(),
        policy_version,
        includes_resolved.clone(),
        mcp_allowlist.clone(),
        args.mode,
        Some(planner_model.clone()),
        Some(worker_model.clone()),
        Some(args.planner_max_steps),
        Some(format!("{:?}", args.planner_output).to_lowercase()),
        Some(planner_strict_effective),
        Some(format!("{:?}", effective_plan_tool_enforcement).to_lowercase()),
        &instruction_resolution,
    );
    let config_fingerprint = build_config_fingerprint(&cli_config, args, &worker_model, paths);
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
        emit_event(
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

    if args.tui {
        if !outcome.final_output.is_empty() {
            println!("{}", outcome.final_output);
        }
    } else if !args.stream {
        println!("{}", outcome.final_output);
    }

    Ok(RunExecutionResult {
        outcome,
        run_artifact_path,
    })
}

#[derive(Debug, Clone)]
struct RunExecutionResult {
    outcome: agent::AgentOutcome,
    run_artifact_path: Option<PathBuf>,
}

async fn run_tasks_graph(
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
    emit_event(
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
            emit_event(
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

        emit_event(
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
        let node_workdir =
            task_apply::resolve_node_workdir(&taskfile, node_id, &node_args.workdir)?;
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
            n.error_short = result.outcome.error.as_deref().map(short_error);
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

        emit_event(
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
            summaries.push(node_summary_line(
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
    emit_event(
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

fn short_error(s: &str) -> String {
    s.chars().take(200).collect()
}

fn node_summary_line(node_id: &str, exit_reason: &str, final_output: &str) -> String {
    let digest = store::sha256_hex(final_output.as_bytes());
    let head = final_output
        .chars()
        .take(200)
        .collect::<String>()
        .replace('\n', " ");
    format!(
        "- [{}] exit_reason={} output_sha256={} head={}",
        node_id, exit_reason, digest, head
    )
}

#[derive(Debug, Clone)]
struct PlannerPhaseOutput {
    plan_json: serde_json::Value,
    plan_hash_hex: String,
    raw_output: Option<String>,
    error: Option<String>,
    ok: bool,
}

fn emit_event(
    sink: &mut Option<Box<dyn EventSink>>,
    run_id: &str,
    step: u32,
    kind: EventKind,
    data: serde_json::Value,
) {
    if let Some(s) = sink {
        if let Err(e) = s.emit(Event::new(run_id.to_string(), step, kind, data)) {
            eprintln!("WARN: failed to emit event: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_planner_phase<P: ModelProvider>(
    provider: &P,
    run_id: &str,
    planner_model: &str,
    prompt: &str,
    planner_max_steps: u32,
    planner_output: planner::PlannerOutput,
    planner_strict: bool,
    sink: &mut Option<Box<dyn EventSink>>,
) -> anyhow::Result<PlannerPhaseOutput> {
    let mut messages = vec![
        Message {
            role: Role::System,
            content: Some(
                "You are the planner. Do not call tools. Produce only JSON matching openagent.plan.v1 with fields: schema_version, goal, assumptions[], steps[] where each step includes summary, intended_tools[], done_criteria[], verifier_checks[], plus risks[] and success_criteria[]."
                    .to_string(),
            ),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        },
        Message {
            role: Role::User,
            content: Some(prompt.to_string()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        },
    ];

    let max_steps = planner_max_steps.max(1);
    let mut last_output = String::new();
    for step in 0..max_steps {
        emit_event(
            sink,
            run_id,
            step,
            EventKind::ModelRequestStart,
            serde_json::json!({
                "model": planner_model,
                "tool_count": 0,
                "stream": false,
                "phase": "planner"
            }),
        );
        let req = GenerateRequest {
            model: planner_model.to_string(),
            messages: messages.clone(),
            tools: None,
        };
        let resp = match provider.generate(req).await {
            Ok(resp) => resp,
            Err(e) => {
                if let Some(pe) = e.downcast_ref::<providers::http::ProviderError>() {
                    for r in &pe.retries {
                        emit_event(
                            sink,
                            run_id,
                            step,
                            EventKind::ProviderRetry,
                            serde_json::json!({
                                "attempt": r.attempt,
                                "max_attempts": r.max_attempts,
                                "kind": r.kind,
                                "status": r.status,
                                "backoff_ms": r.backoff_ms
                            }),
                        );
                    }
                    emit_event(
                        sink,
                        run_id,
                        step,
                        EventKind::ProviderError,
                        serde_json::json!({
                            "kind": pe.kind,
                            "status": pe.http_status,
                            "retryable": pe.retryable,
                            "attempt": pe.attempt,
                            "max_attempts": pe.max_attempts,
                            "message_short": providers::http::message_short(&pe.message)
                        }),
                    );
                }
                return Err(e);
            }
        };

        let output = resp.assistant.content.clone().unwrap_or_default();
        emit_event(
            sink,
            run_id,
            step,
            EventKind::ModelResponseEnd,
            serde_json::json!({
                "content": output,
                "tool_calls": resp.tool_calls.len(),
                "phase": "planner"
            }),
        );
        if !resp.tool_calls.is_empty() {
            let wrapped =
                planner::normalize_planner_output(&output, prompt, planner_output, false)?;
            return Ok(PlannerPhaseOutput {
                plan_json: wrapped.plan_json,
                plan_hash_hex: wrapped.plan_hash_hex,
                raw_output: wrapped.raw_output,
                error: Some(format!(
                    "planner emitted tool calls while tools are disabled (count={})",
                    resp.tool_calls.len()
                )),
                ok: false,
            });
        }
        messages.push(resp.assistant);
        last_output = output;
        if !last_output.trim().is_empty() {
            break;
        }
    }

    match planner::normalize_planner_output(&last_output, prompt, planner_output, planner_strict) {
        Ok(normalized) => Ok(PlannerPhaseOutput {
            plan_json: normalized.plan_json,
            plan_hash_hex: normalized.plan_hash_hex,
            raw_output: normalized.raw_output,
            error: normalized.error,
            ok: !normalized.used_wrapper,
        }),
        Err(e) => {
            let wrapped = planner::wrap_text_plan(prompt, &last_output);
            let hash = planner::hash_canonical_json(&wrapped)?;
            Ok(PlannerPhaseOutput {
                plan_json: wrapped,
                plan_hash_hex: hash,
                raw_output: Some(last_output),
                error: Some(e.to_string()),
                ok: false,
            })
        }
    }
}

fn merge_injected_messages(
    mut instruction_messages: Vec<Message>,
    task_memory: Option<Message>,
    planner_handoff: Option<Message>,
) -> Vec<Message> {
    if let Some(m) = task_memory {
        instruction_messages.push(m);
    }
    if let Some(m) = planner_handoff {
        instruction_messages.push(m);
    }
    instruction_messages
}

#[allow(clippy::too_many_arguments)]
fn build_run_cli_config(
    provider_kind: ProviderKind,
    base_url: &str,
    model: &str,
    args: &RunArgs,
    resolved_settings: &session::RunSettingResolution,
    hooks_config_path: &std::path::Path,
    mcp_config_path: &std::path::Path,
    tool_catalog: Vec<store::ToolCatalogEntry>,
    mcp_tool_snapshot: Vec<store::McpToolSnapshotEntry>,
    mcp_tool_catalog_hash_hex: Option<String>,
    policy_version: Option<u32>,
    includes_resolved: Vec<String>,
    mcp_allowlist: Option<McpAllowSummary>,
    mode: planner::RunMode,
    planner_model: Option<String>,
    worker_model: Option<String>,
    planner_max_steps: Option<u32>,
    planner_output: Option<String>,
    planner_strict: Option<bool>,
    enforce_plan_tools: Option<String>,
    instructions: &InstructionResolution,
) -> RunCliConfig {
    RunCliConfig {
        mode: format!("{:?}", mode).to_lowercase(),
        provider: provider_to_string(provider_kind),
        base_url: base_url.to_string(),
        model: model.to_string(),
        planner_model,
        worker_model,
        planner_max_steps,
        planner_output,
        planner_strict,
        enforce_plan_tools: enforce_plan_tools.unwrap_or_else(|| "off".to_string()),
        mcp_pin_enforcement: format!("{:?}", args.mcp_pin_enforcement).to_lowercase(),
        trust_mode: store::cli_trust_mode(args.trust),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        exec_target: format!("{:?}", args.exec_target).to_lowercase(),
        docker_image: if matches!(args.exec_target, ExecTargetKind::Docker) {
            Some(args.docker_image.clone())
        } else {
            None
        },
        docker_workdir: if matches!(args.exec_target, ExecTargetKind::Docker) {
            Some(args.docker_workdir.clone())
        } else {
            None
        },
        docker_network: if matches!(args.exec_target, ExecTargetKind::Docker) {
            Some(format!("{:?}", args.docker_network).to_lowercase())
        } else {
            None
        },
        docker_user: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_user.clone()
        } else {
            None
        },
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
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
        approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", args.auto_approve_scope).to_lowercase(),
        approval_key: args.approval_key.as_str().to_string(),
        unsafe_mode: args.unsafe_mode,
        no_limits: args.no_limits,
        unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
        stream: args.stream,
        events_path: args.events.as_ref().map(|p| p.display().to_string()),
        max_context_chars: resolved_settings.max_context_chars,
        compaction_mode: format!("{:?}", resolved_settings.compaction_mode).to_lowercase(),
        compaction_keep_last: resolved_settings.compaction_keep_last,
        tool_result_persist: format!("{:?}", resolved_settings.tool_result_persist).to_lowercase(),
        hooks_mode: format!("{:?}", resolved_settings.hooks_mode).to_lowercase(),
        caps_mode: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
        hooks_config_path: stable_path_string(hooks_config_path),
        hooks_strict: args.hooks_strict,
        hooks_timeout_ms: args.hooks_timeout_ms,
        hooks_max_stdout_bytes: args.hooks_max_stdout_bytes,
        tool_args_strict: format!("{:?}", resolved_settings.tool_args_strict).to_lowercase(),
        taint: format!("{:?}", args.taint).to_lowercase(),
        taint_mode: format!("{:?}", args.taint_mode).to_lowercase(),
        taint_digest_bytes: args.taint_digest_bytes,
        repro: format!("{:?}", args.repro).to_lowercase(),
        repro_env: format!("{:?}", args.repro_env).to_lowercase(),
        repro_out: args.repro_out.as_ref().map(|p| stable_path_string(p)),
        use_session_settings: args.use_session_settings,
        resolved_settings_source: resolved_settings.sources.clone(),
        http_max_retries: args.http_max_retries,
        http_timeout_ms: args.http_timeout_ms,
        http_connect_timeout_ms: args.http_connect_timeout_ms,
        http_stream_idle_timeout_ms: args.http_stream_idle_timeout_ms,
        http_max_response_bytes: args.http_max_response_bytes,
        http_max_line_bytes: args.http_max_line_bytes,
        tui_enabled: args.tui,
        tui_refresh_ms: args.tui_refresh_ms,
        tui_max_log_lines: args.tui_max_log_lines,
        tool_catalog,
        mcp_tool_snapshot,
        mcp_tool_catalog_hash_hex,
        mcp_servers: {
            let mut servers = args.mcp.clone();
            servers.sort();
            servers
        },
        mcp_config_path: Some(stable_path_string(mcp_config_path)),
        policy_version,
        includes_resolved,
        mcp_allowlist,
        instructions_config_path: instructions
            .config_path
            .as_ref()
            .map(|p| stable_path_string(p)),
        instructions_config_hash_hex: instructions.config_hash_hex.clone(),
        instruction_model_profile: instructions.selected_model_profile.clone(),
        instruction_task_profile: instructions.selected_task_profile.clone(),
        instruction_message_count: instructions.messages.len(),
    }
}

fn build_config_fingerprint(
    cli_config: &RunCliConfig,
    args: &RunArgs,
    model: &str,
    paths: &store::StatePaths,
) -> ConfigFingerprintV1 {
    ConfigFingerprintV1 {
        schema_version: "openagent.confighash.v1".to_string(),
        mode: cli_config.mode.clone(),
        provider: cli_config.provider.clone(),
        base_url: cli_config.base_url.clone(),
        model: model.to_string(),
        planner_model: cli_config.planner_model.clone().unwrap_or_default(),
        worker_model: cli_config.worker_model.clone().unwrap_or_default(),
        planner_max_steps: cli_config.planner_max_steps.unwrap_or_default(),
        planner_output: cli_config.planner_output.clone().unwrap_or_default(),
        planner_strict: cli_config.planner_strict.unwrap_or(false),
        enforce_plan_tools: cli_config.enforce_plan_tools.clone(),
        mcp_pin_enforcement: cli_config.mcp_pin_enforcement.clone(),
        trust_mode: store::cli_trust_mode(args.trust),
        state_dir: stable_path_string(&paths.state_dir),
        policy_path: stable_path_string(&paths.policy_path),
        approvals_path: stable_path_string(&paths.approvals_path),
        audit_path: stable_path_string(&paths.audit_path),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        exec_target: format!("{:?}", args.exec_target).to_lowercase(),
        docker_image: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_image.clone()
        } else {
            String::new()
        },
        docker_workdir: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_workdir.clone()
        } else {
            String::new()
        },
        docker_network: if matches!(args.exec_target, ExecTargetKind::Docker) {
            format!("{:?}", args.docker_network).to_lowercase()
        } else {
            String::new()
        },
        docker_user: if matches!(args.exec_target, ExecTargetKind::Docker) {
            args.docker_user.clone().unwrap_or_default()
        } else {
            String::new()
        },
        max_steps: args.max_steps,
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
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
        session_name: if args.no_session {
            String::new()
        } else {
            args.session.clone()
        },
        no_session: args.no_session,
        max_session_messages: args.max_session_messages,
        approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", args.auto_approve_scope).to_lowercase(),
        approval_key: args.approval_key.as_str().to_string(),
        unsafe_mode: args.unsafe_mode,
        no_limits: args.no_limits,
        unsafe_bypass_allow_flags: args.unsafe_bypass_allow_flags,
        stream: args.stream,
        events_path: args
            .events
            .as_ref()
            .map(|p| stable_path_string(p))
            .unwrap_or_default(),
        max_context_chars: cli_config.max_context_chars,
        compaction_mode: cli_config.compaction_mode.clone(),
        compaction_keep_last: cli_config.compaction_keep_last,
        tool_result_persist: cli_config.tool_result_persist.clone(),
        hooks_mode: cli_config.hooks_mode.clone(),
        caps_mode: cli_config.caps_mode.clone(),
        hooks_config_path: cli_config.hooks_config_path.clone(),
        hooks_strict: cli_config.hooks_strict,
        hooks_timeout_ms: cli_config.hooks_timeout_ms,
        hooks_max_stdout_bytes: cli_config.hooks_max_stdout_bytes,
        tool_args_strict: cli_config.tool_args_strict.clone(),
        taint: cli_config.taint.clone(),
        taint_mode: cli_config.taint_mode.clone(),
        taint_digest_bytes: cli_config.taint_digest_bytes,
        repro: cli_config.repro.clone(),
        repro_env: cli_config.repro_env.clone(),
        repro_out: cli_config.repro_out.clone().unwrap_or_default(),
        use_session_settings: cli_config.use_session_settings,
        resolved_settings_source: cli_config.resolved_settings_source.clone(),
        tui_enabled: cli_config.tui_enabled,
        tui_refresh_ms: cli_config.tui_refresh_ms,
        tui_max_log_lines: cli_config.tui_max_log_lines,
        http_max_retries: cli_config.http_max_retries,
        http_timeout_ms: cli_config.http_timeout_ms,
        http_connect_timeout_ms: cli_config.http_connect_timeout_ms,
        http_stream_idle_timeout_ms: cli_config.http_stream_idle_timeout_ms,
        http_max_response_bytes: cli_config.http_max_response_bytes,
        http_max_line_bytes: cli_config.http_max_line_bytes,
        tool_catalog_names: cli_config
            .tool_catalog
            .iter()
            .map(|t| t.name.clone())
            .collect(),
        mcp_tool_catalog_hash_hex: cli_config
            .mcp_tool_catalog_hash_hex
            .clone()
            .unwrap_or_default(),
        mcp_servers: cli_config.mcp_servers.clone(),
        mcp_config_path: cli_config.mcp_config_path.clone().unwrap_or_default(),
        policy_version: cli_config.policy_version,
        includes_resolved: cli_config.includes_resolved.clone(),
        mcp_allowlist: cli_config.mcp_allowlist.clone(),
        instructions_config_path: cli_config
            .instructions_config_path
            .clone()
            .unwrap_or_default(),
        instructions_config_hash_hex: cli_config
            .instructions_config_hash_hex
            .clone()
            .unwrap_or_default(),
        instruction_model_profile: cli_config
            .instruction_model_profile
            .clone()
            .unwrap_or_default(),
        instruction_task_profile: cli_config
            .instruction_task_profile
            .clone()
            .unwrap_or_default(),
        instruction_message_count: cli_config.instruction_message_count,
    }
}

fn resolved_mcp_config_path(args: &RunArgs, state_dir: &std::path::Path) -> PathBuf {
    args.mcp_config
        .clone()
        .unwrap_or_else(|| state_dir.join("mcp_servers.json"))
}

fn resolved_hooks_config_path(args: &RunArgs, state_dir: &std::path::Path) -> PathBuf {
    args.hooks_config
        .clone()
        .unwrap_or_else(|| state_dir.join("hooks.yaml"))
}

fn resolved_instructions_config_path(args: &RunArgs, state_dir: &std::path::Path) -> PathBuf {
    args.instructions_config
        .clone()
        .unwrap_or_else(|| instructions::default_config_path(state_dir))
}

fn resolve_instruction_messages(
    args: &RunArgs,
    state_dir: &std::path::Path,
    model: &str,
) -> anyhow::Result<InstructionResolution> {
    let cfg_path = resolved_instructions_config_path(args, state_dir);
    if !cfg_path.exists() {
        return Ok(InstructionResolution::empty());
    }
    let (cfg, hash_hex) = instructions::load_config(&cfg_path)?;
    let (messages, selected_model, selected_task) = instructions::resolve_messages(
        &cfg,
        model,
        args.task_kind.as_deref(),
        args.instruction_model_profile.as_deref(),
        args.instruction_task_profile.as_deref(),
    )?;
    Ok(InstructionResolution {
        config_path: Some(cfg_path),
        config_hash_hex: Some(hash_hex),
        selected_model_profile: selected_model,
        selected_task_profile: selected_task,
        messages,
    })
}

fn handle_session_command(store: &SessionStore, cmd: &SessionSubcommand) -> anyhow::Result<()> {
    match cmd {
        SessionSubcommand::Info => {
            let data = store.load()?;
            println!(
                "session={} messages={} memory={} updated_at={}",
                data.name,
                data.messages.len(),
                data.task_memory.len(),
                data.updated_at
            );
        }
        SessionSubcommand::Show { last } => {
            let data = store.load()?;
            let len = data.messages.len();
            let start = len.saturating_sub(*last);
            for (idx, m) in data.messages.iter().enumerate().skip(start) {
                let role = format!("{:?}", m.role).to_uppercase();
                println!(
                    "{} {}: {}",
                    idx,
                    role,
                    m.content.clone().unwrap_or_default().replace('\n', " ")
                );
            }
        }
        SessionSubcommand::Drop { from, last } => match (from, last) {
            (Some(i), None) => {
                store.drop_from(*i)?;
                println!("dropped messages from index {}", i);
            }
            (None, Some(n)) => {
                store.drop_last(*n)?;
                println!("dropped last {} messages", n);
            }
            _ => return Err(anyhow!("provide exactly one of --from or --last")),
        },
        SessionSubcommand::Reset => {
            store.reset()?;
            println!("session reset");
        }
        SessionSubcommand::Memory { command } => match command {
            SessionMemorySubcommand::Add { title, content } => {
                let id = store.add_memory(title, content)?;
                println!("added memory {}", id);
            }
            SessionMemorySubcommand::List => {
                let data = store.load()?;
                let mut blocks = data.task_memory.clone();
                blocks.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
                for b in blocks {
                    println!("{}\t{}\t{}", b.id, b.title, b.updated_at);
                }
            }
            SessionMemorySubcommand::Show { id } => {
                let data = store.load()?;
                let Some(b) = data.task_memory.iter().find(|m| m.id == *id) else {
                    return Err(anyhow!("memory id not found: {}", id));
                };
                println!(
                    "id={}\ntitle={}\ncreated_at={}\nupdated_at={}\ncontent={}",
                    b.id, b.title, b.created_at, b.updated_at, b.content
                );
            }
            SessionMemorySubcommand::Update { id, title, content } => {
                store.update_memory(id, title.as_deref(), content.as_deref())?;
                println!("updated memory {}", id);
            }
            SessionMemorySubcommand::Delete { id } => {
                store.delete_memory(id)?;
                println!("deleted memory {}", id);
            }
        },
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

    use super::{
        doctor_probe_urls, policy_doctor_output, policy_effective_output, DockerNetwork,
        ProviderKind,
    };

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
        let out = super::run_planner_phase(
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
        let a = super::node_summary_line("N1", "ok", "hello\nworld");
        let b = super::node_summary_line("N1", "ok", "hello\nworld");
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


