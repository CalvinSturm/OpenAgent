use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::agent::{McpPinEnforcementMode, PlanToolEnforcementMode};

use crate::compaction::{CompactionMode, ToolResultPersist};

use crate::eval::tasks::EvalPack;

use crate::gate::{ApprovalKeyVersion, ApprovalMode, AutoApproveScope, ProviderKind, TrustMode};

use crate::hooks::config::HooksMode;

use crate::planner;

use crate::repro::{ReproEnvMode, ReproMode};

use crate::session::CapsMode;

use crate::taint::{TaintMode, TaintToggle};

use crate::target::ExecTargetKind;

use crate::taskgraph::PropagateSummaries;

use crate::tools::ToolArgsStrict;

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

    Check(CheckArgs),

    Repo(RepoArgs),

    Profile(ProfileArgs),

    Pack(PackArgs),

    Learn(LearnArgs),

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

pub(crate) struct VersionArgs {
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(Debug, Parser)]

pub(crate) struct InitArgs {
    #[arg(long)]
    pub(crate) state_dir: Option<PathBuf>,

    #[arg(long)]
    pub(crate) workdir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub(crate) force: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) print: bool,
}

#[derive(Debug, Subcommand)]

pub(crate) enum TemplateSubcommand {
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

pub(crate) struct TemplateArgs {
    #[command(subcommand)]
    pub(crate) command: TemplateSubcommand,
}

#[derive(Debug, Clone, Parser)]

pub(crate) struct ChatArgs {
    #[arg(long, default_value_t = false)]
    pub(crate) tui: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) plain_tui: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) no_banner: bool,
}

#[derive(Debug, Subcommand)]

pub(crate) enum TasksSubcommand {
    Run(TasksRunArgs),

    Status(TasksStatusArgs),

    Reset(TasksResetArgs),
}

#[derive(Debug, Parser)]

pub(crate) struct TasksArgs {
    #[command(subcommand)]
    pub(crate) command: TasksSubcommand,
}

#[derive(Debug, Clone, Parser)]

pub(crate) struct TasksRunArgs {
    #[arg(long)]
    pub(crate) taskfile: PathBuf,

    #[arg(long, default_value_t = false)]
    pub(crate) resume: bool,

    #[arg(long)]
    pub(crate) checkpoint: Option<PathBuf>,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub(crate) fail_fast: bool,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_nodes: u32,

    #[arg(long, value_enum, default_value_t = PropagateSummaries::On)]
    pub(crate) propagate_summaries: PropagateSummaries,
}

#[derive(Debug, Clone, Parser)]

pub(crate) struct TasksStatusArgs {
    #[arg(long)]
    pub(crate) checkpoint: PathBuf,
}

#[derive(Debug, Clone, Parser)]

pub(crate) struct TasksResetArgs {
    #[arg(long)]
    pub(crate) checkpoint: PathBuf,
}

#[derive(Debug, Clone, Subcommand)]

pub(crate) enum EvalProfileSubcommand {
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

pub(crate) enum EvalBaselineSubcommand {
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

pub(crate) enum EvalSubcommand {
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

pub(crate) enum EvalReportSubcommand {
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

pub(crate) struct EvalCmd {
    #[command(subcommand)]
    pub(crate) command: Option<EvalSubcommand>,

    #[command(flatten)]
    pub(crate) run: EvalArgs,
}

#[derive(Debug, Subcommand)]

pub(crate) enum SessionMemorySubcommand {
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

pub(crate) enum SessionSubcommand {
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

pub(crate) struct SessionArgs {
    #[command(subcommand)]
    pub(crate) command: SessionSubcommand,
}

#[derive(Debug, Subcommand)]

pub(crate) enum TuiSubcommand {
    Tail {
        #[arg(long)]
        events: PathBuf,

        #[arg(long, default_value_t = 50)]
        refresh_ms: u64,
    },
}

#[derive(Debug, Parser)]

pub(crate) struct TuiArgs {
    #[command(subcommand)]
    pub(crate) command: TuiSubcommand,
}

#[derive(Debug, Subcommand)]

pub(crate) enum McpSubcommand {
    List,

    Doctor { name: String },
}

#[derive(Debug, Parser)]

pub(crate) struct McpArgs {
    #[command(subcommand)]
    pub(crate) command: McpSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CheckSubcommand {
    Run {
        #[arg(long)]
        path: Option<PathBuf>,

        #[arg(long)]
        json_out: Option<PathBuf>,

        #[arg(long)]
        junit_out: Option<PathBuf>,

        #[arg(long)]
        max_checks: Option<usize>,
    },
}

#[derive(Debug, Parser)]
pub(crate) struct CheckArgs {
    #[command(subcommand)]
    pub(crate) command: CheckSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RepoSubcommand {
    Map {
        #[arg(long, default_value_t = false)]
        print_content: bool,

        #[arg(long, default_value_t = false)]
        no_write: bool,

        #[arg(long, default_value_t = 2000)]
        max_files: usize,

        #[arg(long, default_value_t = 4 * 1024 * 1024)]
        max_scan_bytes: usize,

        #[arg(long, default_value_t = 64 * 1024)]
        max_out_bytes: usize,
    },
}

#[derive(Debug, Parser)]
pub(crate) struct RepoArgs {
    #[command(subcommand)]
    pub(crate) command: RepoSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProfileSubcommand {
    List,
    Show { name: String },
}

#[derive(Debug, Parser)]
pub(crate) struct ProfileArgs {
    #[command(subcommand)]
    pub(crate) command: ProfileSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PackSubcommand {
    List,
    Show { pack_id: String },
}

#[derive(Debug, Parser)]
pub(crate) struct PackArgs {
    #[command(subcommand)]
    pub(crate) command: PackSubcommand,
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum LearnCategoryArg {
    WorkflowHint,
    PromptGuidance,
    CheckCandidate,
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum LearnStatusArg {
    Captured,
    Promoted,
    Archived,
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum LearnEvidenceKindArg {
    RunId,
    EventId,
    ArtifactPath,
    ToolCallId,
    ReasonCode,
    ExitReason,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum LearnPromoteTargetArg {
    Check,
    Pack,
    Agents,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LearnSubcommand {
    Capture {
        #[arg(long)]
        run: Option<String>,

        #[arg(long, value_enum)]
        category: LearnCategoryArg,

        #[arg(long)]
        summary: String,

        #[arg(long = "task-summary")]
        task_summary: Option<String>,

        #[arg(long)]
        profile: Option<String>,

        #[arg(long = "guidance-text")]
        guidance_text: Option<String>,

        #[arg(long = "check-text")]
        check_text: Option<String>,

        #[arg(long = "tag")]
        tags: Vec<String>,

        #[arg(long = "evidence")]
        evidence: Vec<String>,

        #[arg(long = "evidence-note")]
        evidence_notes: Vec<String>,
    },
    List {
        #[arg(long = "status", value_enum)]
        statuses: Vec<LearnStatusArg>,

        #[arg(long = "category", value_enum)]
        categories: Vec<LearnCategoryArg>,

        #[arg(long, default_value_t = 50)]
        limit: usize,

        #[arg(long, default_value_t = false)]
        show_archived: bool,

        #[arg(long, default_value = "table")]
        format: String,
    },
    Show {
        id: String,

        #[arg(long, default_value = "text")]
        format: String,

        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        show_evidence: bool,

        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        show_proposed: bool,
    },
    Promote {
        id: String,

        #[arg(long, value_enum)]
        to: LearnPromoteTargetArg,

        #[arg(long)]
        slug: Option<String>,

        #[arg(long = "pack-id")]
        pack_id: Option<String>,

        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Parser)]
pub(crate) struct LearnArgs {
    #[command(subcommand)]
    pub(crate) command: LearnSubcommand,
}

#[derive(Debug, Subcommand)]

pub(crate) enum HooksSubcommand {
    List,

    Doctor,
}

#[derive(Debug, Parser)]

pub(crate) struct HooksArgs {
    #[command(subcommand)]
    pub(crate) command: HooksSubcommand,
}

#[derive(Debug, Subcommand)]

pub(crate) enum PolicySubcommand {
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

pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub(crate) command: PolicySubcommand,
}

#[derive(Debug, Subcommand)]

pub(crate) enum ApprovalsSubcommand {
    List,

    Prune,
}

#[derive(Debug, Parser)]

pub(crate) struct ApprovalsArgs {
    #[command(subcommand)]
    pub(crate) command: ApprovalsSubcommand,
}

#[derive(Debug, Parser)]

pub(crate) struct ApproveArgs {
    pub(crate) id: String,

    #[arg(long)]
    pub(crate) ttl_hours: Option<u32>,

    #[arg(long)]
    pub(crate) max_uses: Option<u32>,
}

#[derive(Debug, Parser)]

pub(crate) struct DenyArgs {
    pub(crate) id: String,
}

#[derive(Debug, Subcommand)]

pub(crate) enum ReplaySubcommand {
    Verify {
        run_id: String,

        #[arg(long, default_value_t = false)]
        strict: bool,

        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Debug, Parser)]

pub(crate) struct ReplayArgs {
    pub(crate) run_id: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Option<ReplaySubcommand>,
}

#[derive(Debug, Clone, Parser)]

pub(crate) struct EvalArgs {
    #[arg(long, value_enum, default_value_t = ProviderKind::Ollama)]
    pub(crate) provider: ProviderKind,

    #[arg(long)]
    pub(crate) base_url: Option<String>,

    #[arg(long)]
    pub(crate) models: Option<String>,

    #[arg(long, value_enum, default_value_t = EvalPack::All)]
    pub(crate) pack: EvalPack,

    #[arg(long)]
    pub(crate) out: Option<PathBuf>,

    #[arg(long)]
    pub(crate) junit: Option<PathBuf>,

    #[arg(long = "summary-md")]
    pub(crate) summary_md: Option<PathBuf>,

    #[arg(long)]
    pub(crate) cost_model: Option<PathBuf>,

    #[arg(long, default_value_t = 1)]
    pub(crate) runs_per_task: usize,

    #[arg(long, default_value_t = 30)]
    pub(crate) max_steps: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_wall_time_ms: u64,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_mcp_calls: usize,

    #[arg(long, default_value_t = 600)]
    pub(crate) timeout_seconds: u64,

    #[arg(long, default_value_t = 0.0)]
    pub(crate) min_pass_rate: f64,

    #[arg(long, default_value_t = false)]
    pub(crate) fail_on_any: bool,

    #[arg(long)]
    pub(crate) max_avg_steps: Option<f64>,

    #[arg(long, value_enum, default_value_t = TrustMode::On)]
    pub(crate) trust: TrustMode,

    #[arg(long, value_enum, default_value_t = ApprovalMode::Auto)]
    pub(crate) approval_mode: ApprovalMode,

    #[arg(long, value_enum, default_value_t = AutoApproveScope::Run)]
    pub(crate) auto_approve_scope: AutoApproveScope,

    #[arg(long, value_enum, default_value_t = ApprovalKeyVersion::V1)]
    pub(crate) approval_key: ApprovalKeyVersion,

    #[arg(
        long,
        default_value_t = false,
        help = "Enable write tools exposure for coding tasks (some eval tasks are skipped without this)"
    )]
    pub(crate) enable_write_tools: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Allow write tool execution (some eval tasks are skipped without this)"
    )]
    pub(crate) allow_write: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Allow shell tool execution (some eval tasks are skipped without this)"
    )]
    pub(crate) allow_shell: bool,

    #[arg(long = "unsafe", default_value_t = false)]
    pub(crate) unsafe_mode: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) no_limits: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) unsafe_bypass_allow_flags: bool,

    #[arg(
        long = "mcp",
        help = "Enable MCP servers (browser eval uses only local fixture pages; use --mcp playwright)"
    )]
    pub(crate) mcp: Vec<String>,

    #[arg(long)]
    pub(crate) mcp_config: Option<PathBuf>,

    #[arg(long, default_value = "default")]
    pub(crate) session: String,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub(crate) no_session: bool,

    #[arg(long, default_value_t = 40)]
    pub(crate) max_session_messages: usize,

    #[arg(long, default_value_t = false)]
    pub(crate) use_session_settings: bool,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_context_chars: usize,

    #[arg(long, default_value_t = false)]
    pub(crate) use_repomap: bool,

    #[arg(long, default_value_t = 32 * 1024)]
    pub(crate) repomap_max_bytes: usize,

    #[arg(long, value_enum, default_value_t = CompactionMode::Off)]
    pub(crate) compaction_mode: CompactionMode,

    #[arg(long, default_value_t = 20)]
    pub(crate) compaction_keep_last: usize,

    #[arg(long, value_enum, default_value_t = ToolResultPersist::Digest)]
    pub(crate) tool_result_persist: ToolResultPersist,

    #[arg(long, value_enum, default_value_t = HooksMode::Off)]
    pub(crate) hooks: HooksMode,

    #[arg(long)]
    pub(crate) hooks_config: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub(crate) hooks_strict: bool,

    #[arg(long, default_value_t = 2000)]
    pub(crate) hooks_timeout_ms: u64,

    #[arg(long, default_value_t = 200_000)]
    pub(crate) hooks_max_stdout_bytes: usize,

    #[arg(long, value_enum, default_value_t = ToolArgsStrict::On)]
    pub(crate) tool_args_strict: ToolArgsStrict,

    #[arg(long, value_enum, default_value_t = TaintToggle::Off)]
    pub(crate) taint: TaintToggle,

    #[arg(long, value_enum, default_value_t = TaintMode::Propagate)]
    pub(crate) taint_mode: TaintMode,

    #[arg(long, default_value_t = 4096)]
    pub(crate) taint_digest_bytes: usize,

    #[arg(long, value_enum, default_value_t = ReproMode::Off)]
    pub(crate) repro: ReproMode,

    #[arg(long)]
    pub(crate) repro_out: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = ReproEnvMode::Safe)]
    pub(crate) repro_env: ReproEnvMode,

    #[arg(long, value_enum, default_value_t = CapsMode::Off)]
    pub(crate) caps: CapsMode,

    #[arg(long)]
    pub(crate) profile: Option<String>,

    #[arg(long)]
    pub(crate) profile_path: Option<PathBuf>,

    #[arg(long)]
    pub(crate) baseline: Option<String>,

    #[arg(long)]
    pub(crate) compare_baseline: Option<String>,

    #[arg(long, default_value_t = false)]
    pub(crate) fail_on_regression: bool,

    #[arg(long)]
    pub(crate) bundle: Option<PathBuf>,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub(crate) bundle_on_fail: bool,

    #[arg(long)]
    pub(crate) state_dir: Option<PathBuf>,

    #[arg(long)]
    pub(crate) workdir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub(crate) keep_workdir: bool,

    #[arg(long)]
    pub(crate) policy: Option<PathBuf>,

    #[arg(long)]
    pub(crate) approvals: Option<PathBuf>,

    #[arg(long)]
    pub(crate) audit: Option<PathBuf>,

    #[arg(long)]
    pub(crate) api_key: Option<String>,

    #[arg(long, default_value_t = 2)]
    pub(crate) http_max_retries: u32,

    #[arg(long, default_value_t = 0)]
    pub(crate) http_timeout_ms: u64,

    #[arg(long, default_value_t = 2_000)]
    pub(crate) http_connect_timeout_ms: u64,

    #[arg(long, default_value_t = 0)]
    pub(crate) http_stream_idle_timeout_ms: u64,

    #[arg(long, default_value_t = 10_000_000)]
    pub(crate) http_max_response_bytes: usize,

    #[arg(long, default_value_t = 200_000)]
    pub(crate) http_max_line_bytes: usize,

    #[arg(long, value_enum, default_value_t = planner::RunMode::Single)]
    pub(crate) mode: planner::RunMode,

    #[arg(long)]
    pub(crate) planner_model: Option<String>,

    #[arg(long)]
    pub(crate) worker_model: Option<String>,
}

#[derive(Debug, Parser)]
#[command(name = "localagent")]
#[command(about = "LocalAgent: local-runtime agent loop with tool calling", long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,

    #[command(flatten)]
    pub(crate) run: RunArgs,
}

#[derive(Debug, Clone, Parser)]

pub(crate) struct RunArgs {
    #[arg(long, value_enum)]
    pub(crate) provider: Option<ProviderKind>,

    #[arg(long)]
    pub(crate) model: Option<String>,

    #[arg(long)]
    pub(crate) base_url: Option<String>,

    #[arg(long)]
    pub(crate) api_key: Option<String>,

    #[arg(long)]
    pub(crate) prompt: Option<String>,

    #[arg(long, default_value_t = 20)]
    pub(crate) max_steps: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_wall_time_ms: u64,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_total_tool_calls: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_mcp_calls: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_filesystem_read_calls: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_filesystem_write_calls: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_shell_calls: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_network_calls: usize,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_browser_calls: usize,

    #[arg(long, default_value = ".")]
    pub(crate) workdir: PathBuf,

    #[arg(long)]
    pub(crate) state_dir: Option<PathBuf>,

    #[arg(long = "mcp")]
    pub(crate) mcp: Vec<String>,

    #[arg(long = "pack")]
    pub(crate) packs: Vec<String>,

    #[arg(long)]
    pub(crate) mcp_config: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub(crate) allow_shell: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Allow shell tool only when cwd is omitted or a non-escaping relative path under the current workdir (command content is not sandboxed)"
    )]
    pub(crate) allow_shell_in_workdir: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) allow_write: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) enable_write_tools: bool,

    #[arg(long, value_enum, default_value_t = ExecTargetKind::Host)]
    pub(crate) exec_target: ExecTargetKind,

    #[arg(long, default_value = "ubuntu:24.04")]
    pub(crate) docker_image: String,

    #[arg(long, default_value = "/work")]
    pub(crate) docker_workdir: String,

    #[arg(long, value_enum, default_value_t = DockerNetwork::None)]
    pub(crate) docker_network: DockerNetwork,

    #[arg(long)]
    pub(crate) docker_user: Option<String>,

    #[arg(long, default_value_t = 200_000)]
    pub(crate) max_tool_output_bytes: usize,

    #[arg(long, default_value_t = 200_000)]
    pub(crate) max_read_bytes: usize,

    #[arg(long, value_enum, default_value_t = TrustMode::Off)]
    pub(crate) trust: TrustMode,

    #[arg(long, value_enum, default_value_t = ApprovalMode::Interrupt)]
    pub(crate) approval_mode: ApprovalMode,

    #[arg(long, value_enum, default_value_t = AutoApproveScope::Run)]
    pub(crate) auto_approve_scope: AutoApproveScope,

    #[arg(long, value_enum, default_value_t = ApprovalKeyVersion::V1)]
    pub(crate) approval_key: ApprovalKeyVersion,

    #[arg(long = "unsafe", default_value_t = false)]
    pub(crate) unsafe_mode: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) no_limits: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) unsafe_bypass_allow_flags: bool,

    #[arg(long)]
    pub(crate) policy: Option<PathBuf>,

    #[arg(long)]
    pub(crate) approvals: Option<PathBuf>,

    #[arg(long)]
    pub(crate) audit: Option<PathBuf>,

    #[arg(long, default_value = "default")]
    pub(crate) session: String,

    #[arg(long, default_value_t = false)]
    pub(crate) no_session: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) reset_session: bool,

    #[arg(long, default_value_t = 40)]
    pub(crate) max_session_messages: usize,

    #[arg(long, default_value_t = false)]
    pub(crate) use_session_settings: bool,

    #[arg(long, default_value_t = 0)]
    pub(crate) max_context_chars: usize,

    #[arg(long, default_value_t = false)]
    pub(crate) use_repomap: bool,

    #[arg(long, default_value_t = 32 * 1024)]
    pub(crate) repomap_max_bytes: usize,

    #[arg(long = "reliability-profile")]
    pub(crate) reliability_profile: Option<String>,

    #[arg(long, value_enum, default_value_t = CompactionMode::Off)]
    pub(crate) compaction_mode: CompactionMode,

    #[arg(long, default_value_t = 20)]
    pub(crate) compaction_keep_last: usize,

    #[arg(long, value_enum, default_value_t = ToolResultPersist::Digest)]
    pub(crate) tool_result_persist: ToolResultPersist,

    #[arg(long, value_enum, default_value_t = HooksMode::Off)]
    pub(crate) hooks: HooksMode,

    #[arg(long)]
    pub(crate) hooks_config: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub(crate) hooks_strict: bool,

    #[arg(long, default_value_t = 2000)]
    pub(crate) hooks_timeout_ms: u64,

    #[arg(long, default_value_t = 200_000)]
    pub(crate) hooks_max_stdout_bytes: usize,

    #[arg(long, value_enum, default_value_t = ToolArgsStrict::On)]
    pub(crate) tool_args_strict: ToolArgsStrict,

    #[arg(long)]
    pub(crate) instructions_config: Option<PathBuf>,

    #[arg(long)]
    pub(crate) instruction_model_profile: Option<String>,

    #[arg(long)]
    pub(crate) instruction_task_profile: Option<String>,

    #[arg(long)]
    pub(crate) task_kind: Option<String>,

    #[arg(long, value_enum, default_value_t = TaintToggle::Off)]
    pub(crate) taint: TaintToggle,

    #[arg(long, value_enum, default_value_t = TaintMode::Propagate)]
    pub(crate) taint_mode: TaintMode,

    #[arg(long, default_value_t = 4096)]
    pub(crate) taint_digest_bytes: usize,

    #[arg(long, value_enum, default_value_t = ReproMode::Off)]
    pub(crate) repro: ReproMode,

    #[arg(long)]
    pub(crate) repro_out: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = ReproEnvMode::Safe)]
    pub(crate) repro_env: ReproEnvMode,

    #[arg(long, value_enum, default_value_t = CapsMode::Off)]
    pub(crate) caps: CapsMode,

    #[arg(long, default_value_t = false)]
    pub(crate) stream: bool,

    #[arg(long)]
    pub(crate) events: Option<PathBuf>,

    #[arg(long, default_value_t = 2)]
    pub(crate) http_max_retries: u32,

    #[arg(long, default_value_t = 0)]
    pub(crate) http_timeout_ms: u64,

    #[arg(long, default_value_t = 2_000)]
    pub(crate) http_connect_timeout_ms: u64,

    #[arg(long, default_value_t = 0)]
    pub(crate) http_stream_idle_timeout_ms: u64,

    #[arg(long, default_value_t = 10_000_000)]
    pub(crate) http_max_response_bytes: usize,

    #[arg(long, default_value_t = 200_000)]
    pub(crate) http_max_line_bytes: usize,

    #[arg(long, default_value_t = false)]
    pub(crate) tui: bool,

    #[arg(long, default_value_t = 50)]
    pub(crate) tui_refresh_ms: u64,

    #[arg(long, default_value_t = 200)]
    pub(crate) tui_max_log_lines: usize,

    #[arg(long, value_enum, default_value_t = planner::RunMode::Single)]
    pub(crate) mode: planner::RunMode,

    #[arg(long)]
    pub(crate) planner_model: Option<String>,

    #[arg(long)]
    pub(crate) worker_model: Option<String>,

    #[arg(long, default_value_t = 2)]
    pub(crate) planner_max_steps: u32,

    #[arg(long, value_enum, default_value_t = planner::PlannerOutput::Json)]
    pub(crate) planner_output: planner::PlannerOutput,

    #[arg(long, value_enum, default_value_t = PlanToolEnforcementMode::Off)]
    pub(crate) enforce_plan_tools: PlanToolEnforcementMode,

    #[arg(long, value_enum, default_value_t = McpPinEnforcementMode::Hard)]
    pub(crate) mcp_pin_enforcement: McpPinEnforcementMode,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub(crate) planner_strict: bool,

    #[arg(long, default_value_t = false)]
    pub(crate) no_planner_strict: bool,

    #[arg(skip)]
    pub(crate) resolved_reliability_profile_source: Option<String>,

    #[arg(skip)]
    pub(crate) resolved_reliability_profile_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]

pub(crate) enum DockerNetwork {
    None,

    Bridge,
}

#[derive(Debug, Parser)]

pub(crate) struct DoctorArgs {
    #[arg(long, default_value_t = false)]
    pub(crate) docker: bool,

    #[arg(long, value_enum, required_unless_present = "docker")]
    pub(crate) provider: Option<ProviderKind>,

    #[arg(long)]
    pub(crate) base_url: Option<String>,

    #[arg(long)]
    pub(crate) api_key: Option<String>,
}
