mod agent;
mod compaction;
mod eval;
mod events;
mod gate;
mod hooks;
mod mcp;
mod planner;
mod providers;
mod session;
mod store;
mod tools;
mod trust;
mod tui;
mod types;

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::mcp::registry::{
    doctor_server as mcp_doctor_server, list_servers as mcp_list_servers, McpRegistry,
};
use agent::{Agent, AgentExitReason, PolicyLoadedInfo};
use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use compaction::{CompactionMode, CompactionSettings, ToolResultPersist};
use eval::baseline::{
    baseline_path, compare_results, create_baseline_from_results, delete_baseline, list_baselines,
    load_baseline,
};
use eval::bundle::{create_bundle, BundleSpec};
use eval::profile::{doctor_profile, list_profiles, load_profile};
use eval::report_compare::compare_results_files;
use eval::runner::{run_eval, EvalConfig};
use eval::tasks::EvalPack;
use events::{Event, EventKind, EventSink, JsonlFileSink, MultiSink, StdoutSink};
use gate::{
    compute_policy_hash_hex, ApprovalMode, AutoApproveScope, GateContext, NoGate, ProviderKind,
    ToolGate, TrustGate, TrustMode,
};
use hooks::config::HooksMode;
use hooks::protocol::{PreModelCompactionPayload, PreModelPayload, ToolResultPayload};
use hooks::runner::{make_pre_model_input, make_tool_result_input, HookManager, HookRuntimeConfig};
use providers::http::HttpConfig;
use providers::ollama::OllamaProvider;
use providers::openai_compat::OpenAiCompatProvider;
use providers::ModelProvider;
use reqwest::Client;
use session::{
    settings_from_run, task_memory_message, CapsMode, ExplicitFlags, RunSettingInputs, SessionStore,
};
use store::{
    config_hash_hex, extract_session_messages, provider_to_string, resolve_state_paths,
    stable_path_string, ConfigFingerprintV1, PlannerRunRecord, RunCliConfig, WorkerRunRecord,
};
use tokio::sync::watch;
use tools::{builtin_tools_enabled, ToolArgsStrict, ToolRuntime};
use trust::approvals::ApprovalsStore;
use trust::audit::AuditLog;
use trust::policy::{McpAllowSummary, Policy};
use types::{GenerateRequest, Message, Role};

#[derive(Debug, Subcommand)]
enum Commands {
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

#[derive(Debug, Parser)]
struct ReplayArgs {
    run_id: String,
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
    #[arg(long, default_value_t = 60_000)]
    http_timeout_ms: u64,
    #[arg(long, default_value_t = 2_000)]
    http_connect_timeout_ms: u64,
    #[arg(long, default_value_t = 15_000)]
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
#[command(name = "openagent")]
#[command(about = "Local-runtime OpenAgent loop with tool calling", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Debug, Parser)]
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
    #[arg(long, default_value_t = false)]
    allow_write: bool,
    #[arg(long, default_value_t = false)]
    enable_write_tools: bool,
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
    #[arg(long, value_enum, default_value_t = CapsMode::Off)]
    caps: CapsMode,
    #[arg(long, default_value_t = false)]
    stream: bool,
    #[arg(long)]
    events: Option<PathBuf>,
    #[arg(long, default_value_t = 2)]
    http_max_retries: u32,
    #[arg(long, default_value_t = 60_000)]
    http_timeout_ms: u64,
    #[arg(long, default_value_t = 2_000)]
    http_connect_timeout_ms: u64,
    #[arg(long, default_value_t = 15_000)]
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
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    planner_strict: bool,
    #[arg(long, default_value_t = false)]
    no_planner_strict: bool,
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

    match &cli.command {
        Some(Commands::Doctor(args)) => match doctor_check(args).await {
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
                    handle_hooks_list(&hooks_path)?;
                    return Ok(());
                }
                HooksSubcommand::Doctor => {
                    if let Err(e) = handle_hooks_doctor(
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
                match policy_doctor_output(&policy_path) {
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
                println!("{}", policy_effective_output(&policy_path, *json)?);
                return Ok(());
            }
        },
        Some(Commands::Approvals(args)) => {
            handle_approvals_command(&paths.approvals_path, &args.command)?;
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
        Some(Commands::Replay(args)) => {
            match store::load_run_record(&paths.state_dir, &args.run_id) {
                Ok(record) => {
                    print!("{}", store::render_replay(&record));
                    return Ok(());
                }
                Err(e) => {
                    return Err(anyhow!(
                        "failed to load run '{}': {}. runs dir: {}",
                        args.run_id,
                        e,
                        paths.runs_dir.display()
                    ));
                }
            }
        }
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
                                    _ => ProviderKind::Ollama,
                                };
                                let base_url = loaded
                                    .profile
                                    .base_url
                                    .clone()
                                    .unwrap_or_else(|| default_base_url(provider).to_string());
                                match doctor_check(&DoctorArgs {
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
            let loaded_profile = apply_eval_profile_overrides(&mut args, &paths.state_dir)?;

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
                base_url: args
                    .base_url
                    .clone()
                    .unwrap_or_else(|| default_base_url(args.provider).to_string()),
                api_key: args.api_key.clone(),
                models,
                pack: args.pack,
                out: args.out.clone(),
                junit: args.junit.clone(),
                summary_md: args.summary_md.clone(),
                cost_model_path: args.cost_model.clone(),
                runs_per_task: args.runs_per_task,
                max_steps: args.max_steps,
                timeout_seconds: args.timeout_seconds,
                trust: args.trust,
                approval_mode: args.approval_mode,
                auto_approve_scope: args.auto_approve_scope,
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
                http: http_config_from_eval_args(&args),
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
        None => {}
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
        .unwrap_or_else(|| default_base_url(provider_kind).to_string());

    match provider_kind {
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
            let provider = OpenAiCompatProvider::new(
                base_url.clone(),
                cli.run.api_key.clone(),
                http_config_from_run_args(&cli.run),
            )?;
            run_agent(
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
        ProviderKind::Ollama => {
            let provider =
                OllamaProvider::new(base_url.clone(), http_config_from_run_args(&cli.run))?;
            run_agent(
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

fn handle_approvals_command(
    path: &std::path::Path,
    command: &ApprovalsSubcommand,
) -> anyhow::Result<()> {
    let store = ApprovalsStore::new(path.to_path_buf());
    match command {
        ApprovalsSubcommand::List => {
            let data = store.list()?;
            if data.requests.is_empty() {
                println!("no approval requests");
                return Ok(());
            }
            for (id, req) in data.requests {
                let expires_at = req.expires_at.unwrap_or_else(|| "-".to_string());
                let uses = req.uses.unwrap_or(0);
                let uses_info = match req.max_uses {
                    Some(max) => format!("{uses}/{max}"),
                    None => "-".to_string(),
                };
                println!(
                    "{id}\t{:?}\t{}\t{}\t{}\t{}",
                    req.status, req.tool, req.created_at, expires_at, uses_info
                );
            }
        }
        ApprovalsSubcommand::Prune => {
            let removed = store.prune()?;
            println!("removed {} entries", removed);
        }
    }
    Ok(())
}

async fn run_agent<P: ModelProvider>(
    provider: P,
    provider_kind: ProviderKind,
    base_url: &str,
    default_model: &str,
    prompt: &str,
    args: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    let workdir = std::fs::canonicalize(&args.workdir)
        .with_context(|| format!("failed to resolve workdir: {}", args.workdir.display()))?;
    let mut gate_ctx = GateContext {
        workdir: workdir.clone(),
        allow_shell: args.allow_shell,
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
    };
    let gate_build = build_gate(args, paths)?;
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
    let explicit_flags = parse_explicit_flags();
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

    let mcp_config_path = resolved_mcp_config_path(args, &paths.state_dir);
    let mcp_registry = if args.mcp.is_empty() {
        None
    } else {
        Some(
            McpRegistry::from_config_path(&mcp_config_path, &args.mcp, Duration::from_secs(30))
                .await?,
        )
    };

    let mut all_tools = builtin_tools_enabled(args.enable_write_tools);
    if let Some(reg) = &mcp_registry {
        let mut mcp_defs = reg.tool_defs();
        if let Some(policy) = &gate_build.policy_for_exposure {
            mcp_defs.retain(|t| policy.mcp_tool_allowed(&t.name).is_ok());
        }
        all_tools.extend(mcp_defs);
    }
    let hooks_config_path = resolved_hooks_config_path(args, &paths.state_dir);
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
        (None, None)
    };
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let ui_join = if let Some(rx) = ui_rx {
        let approvals_path = paths.approvals_path.clone();
        let cfg = tui::TuiConfig {
            refresh_ms: args.tui_refresh_ms,
            max_log_lines: args.tui_max_log_lines,
            provider: provider_to_string(provider_kind),
            model: worker_model.clone(),
            caps_source: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
            policy_hash: policy_hash_hex.clone().unwrap_or_default(),
        };
        Some(std::thread::spawn(move || {
            tui::run_live(rx, approvals_path, cfg, cancel_tx.clone())
        }))
    } else {
        None
    };
    let mut event_sink = build_event_sink(args.stream, args.events.as_deref(), args.tui, ui_tx)?;

    let run_id = uuid::Uuid::new_v4().to_string();
    let mut planner_record: Option<PlannerRunRecord> = None;
    let mut worker_record: Option<WorkerRunRecord> = None;
    let mut planner_injected_message: Option<Message> = None;

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
                "planner_strict": planner_strict_effective
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
                    });
                    let cli_config = build_run_cli_config(
                        provider_kind,
                        base_url,
                        &worker_model,
                        args,
                        &resolved_settings,
                        &hooks_config_path,
                        tool_catalog.clone(),
                        policy_version,
                        includes_resolved.clone(),
                        mcp_allowlist.clone(),
                        args.mode,
                        Some(planner_model.clone()),
                        Some(worker_model.clone()),
                        Some(args.planner_max_steps),
                        Some(format!("{:?}", args.planner_output).to_lowercase()),
                        Some(planner_strict_effective),
                    );
                    let config_fingerprint =
                        build_config_fingerprint(&cli_config, args, &worker_model, paths);
                    let cfg_hash = config_hash_hex(&config_fingerprint)?;
                    if let Err(write_err) = store::write_run_record(
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
                    ) {
                        eprintln!("WARN: failed to write run artifact: {write_err}");
                    }
                    if let Some(h) = ui_join {
                        let _ = h.join();
                    }
                    return Err(anyhow!(outcome
                        .error
                        .unwrap_or_else(|| "planner error".to_string())));
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
                let handoff = planner::planner_handoff_content(&out.plan_json)?;
                planner_injected_message = Some(Message {
                    role: Role::Developer,
                    content: Some(handoff),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                });
                worker_record = Some(WorkerRunRecord {
                    model: worker_model.clone(),
                    injected_planner_hash_hex: Some(out.plan_hash_hex.clone()),
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
                        "planner_hash_hex": planner_record.as_ref().map(|p| p.plan_hash_hex.clone()).unwrap_or_default()
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
                };
                let cli_config = build_run_cli_config(
                    provider_kind,
                    base_url,
                    &worker_model,
                    args,
                    &resolved_settings,
                    &hooks_config_path,
                    tool_catalog.clone(),
                    policy_version,
                    includes_resolved.clone(),
                    mcp_allowlist.clone(),
                    args.mode,
                    Some(planner_model.clone()),
                    Some(worker_model.clone()),
                    Some(args.planner_max_steps),
                    Some(format!("{:?}", args.planner_output).to_lowercase()),
                    Some(planner_strict_effective),
                );
                let config_fingerprint =
                    build_config_fingerprint(&cli_config, args, &worker_model, paths);
                let cfg_hash = config_hash_hex(&config_fingerprint)?;
                if let Err(write_err) = store::write_run_record(
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
                ) {
                    eprintln!("WARN: failed to write run artifact: {write_err}");
                }
                if let Some(h) = ui_join {
                    let _ = h.join();
                }
                return Err(anyhow!(outcome
                    .error
                    .unwrap_or_else(|| "planner error".to_string())));
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
        run_id_override: Some(run_id.clone()),
        omit_tools_field_when_empty: false,
    };

    let outcome = tokio::select! {
        out = agent.run(prompt, session_messages, merge_injected_messages(task_memory, planner_injected_message)) => out,
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
            }
        }
    };
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
    agent.event_sink = None;
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
        });
    }
    let cli_config = build_run_cli_config(
        provider_kind,
        base_url,
        &worker_model,
        args,
        &resolved_settings,
        &hooks_config_path,
        tool_catalog.clone(),
        policy_version,
        includes_resolved.clone(),
        mcp_allowlist.clone(),
        args.mode,
        Some(planner_model.clone()),
        Some(worker_model.clone()),
        Some(args.planner_max_steps),
        Some(format!("{:?}", args.planner_output).to_lowercase()),
        Some(planner_strict_effective),
    );
    let config_fingerprint = build_config_fingerprint(&cli_config, args, &worker_model, paths);
    let config_hash_hex = config_hash_hex(&config_fingerprint)?;
    if let Err(e) = store::write_run_record(
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
    ) {
        eprintln!("WARN: failed to write run artifact: {e}");
    }

    if args.tui {
        if !outcome.final_output.is_empty() {
            println!("{}", outcome.final_output);
        }
    } else if !args.stream {
        println!("{}", outcome.final_output);
    }

    if matches!(outcome.exit_reason, AgentExitReason::ProviderError) {
        let err = outcome
            .error
            .unwrap_or_else(|| "provider error".to_string());
        return Err(anyhow!(
            "{}\nHint: run `openagent doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
            err,
            provider_cli_name(provider_kind),
            base_url,
            provider_cli_name(provider_kind),
            default_base_url(provider_kind)
        ));
    }

    Ok(())
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
                "You are the planner. Do not call tools. Produce only the requested plan output."
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
    task_memory: Option<Message>,
    planner_handoff: Option<Message>,
) -> Vec<Message> {
    match (task_memory, planner_handoff) {
        (None, None) => Vec::new(),
        (Some(m), None) => vec![m],
        (None, Some(m)) => vec![m],
        (Some(a), Some(b)) => vec![a, b],
    }
}

#[allow(clippy::too_many_arguments)]
fn build_run_cli_config(
    provider_kind: ProviderKind,
    base_url: &str,
    model: &str,
    args: &RunArgs,
    resolved_settings: &session::RunSettingResolution,
    hooks_config_path: &std::path::Path,
    tool_catalog: Vec<store::ToolCatalogEntry>,
    policy_version: Option<u32>,
    includes_resolved: Vec<String>,
    mcp_allowlist: Option<McpAllowSummary>,
    mode: planner::RunMode,
    planner_model: Option<String>,
    worker_model: Option<String>,
    planner_max_steps: Option<u32>,
    planner_output: Option<String>,
    planner_strict: Option<bool>,
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
        trust_mode: store::cli_trust_mode(args.trust),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
        approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", args.auto_approve_scope).to_lowercase(),
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
        policy_version,
        includes_resolved,
        mcp_allowlist,
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
        trust_mode: store::cli_trust_mode(args.trust),
        state_dir: stable_path_string(&paths.state_dir),
        policy_path: stable_path_string(&paths.policy_path),
        approvals_path: stable_path_string(&paths.approvals_path),
        audit_path: stable_path_string(&paths.audit_path),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        max_steps: args.max_steps,
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
        session_name: if args.no_session {
            String::new()
        } else {
            args.session.clone()
        },
        no_session: args.no_session,
        max_session_messages: args.max_session_messages,
        approval_mode: format!("{:?}", args.approval_mode).to_lowercase(),
        auto_approve_scope: format!("{:?}", args.auto_approve_scope).to_lowercase(),
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
        policy_version: cli_config.policy_version,
        includes_resolved: cli_config.includes_resolved.clone(),
        mcp_allowlist: cli_config.mcp_allowlist.clone(),
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

fn handle_hooks_list(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.exists() {
        println!("no hooks config at {}", path.display());
        return Ok(());
    }
    let loaded = hooks::config::LoadedHooks::load(path)?;
    if loaded.hooks.is_empty() {
        println!("no hooks configured");
        return Ok(());
    }
    for hook in loaded.hooks {
        let stages = hook
            .cfg
            .stages
            .iter()
            .map(|s| format!("{:?}", s).to_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        let cmd = if hook.cfg.args.is_empty() {
            hook.cfg.command.clone()
        } else {
            format!("{} {}", hook.cfg.command, hook.cfg.args.join(" "))
        };
        println!("{}\t{}\t{}", hook.cfg.name, stages, cmd);
    }
    Ok(())
}

fn policy_doctor_output(policy_path: &std::path::Path) -> anyhow::Result<String> {
    let p = Policy::from_path(policy_path)?;
    let mut out = format!(
        "OK: policy loaded version={} rules={} includes={}",
        p.version(),
        p.rules_len(),
        p.includes_resolved().len()
    );
    if let Some(mcp) = p.mcp_allowlist_summary() {
        out.push_str(&format!(
            "\nMCP allowlist: servers={} tools={}",
            mcp.allow_servers.len(),
            mcp.allow_tools.len()
        ));
    }
    Ok(out)
}

fn policy_effective_output(policy_path: &std::path::Path, as_json: bool) -> anyhow::Result<String> {
    let p = Policy::from_path(policy_path)?;
    let effective = p.to_effective_policy();
    if as_json {
        Ok(serde_json::to_string_pretty(&effective)?)
    } else {
        Ok(serde_yaml::to_string(&effective)?)
    }
}

async fn handle_hooks_doctor(
    path: &std::path::Path,
    run: &RunArgs,
    provider: String,
) -> anyhow::Result<()> {
    let manager = HookManager::build(HookRuntimeConfig {
        mode: HooksMode::On,
        config_path: path.to_path_buf(),
        strict: true,
        timeout_ms: run.hooks_timeout_ms,
        max_stdout_bytes: run.hooks_max_stdout_bytes,
    })?;
    if manager.list().is_empty() {
        println!("no hooks configured");
        return Ok(());
    }
    let run_id = uuid::Uuid::new_v4().to_string();
    for hook in manager.list() {
        if hook.has_stage(hooks::config::HookStage::PreModel) {
            let payload = PreModelPayload {
                messages: vec![],
                tools: vec![],
                stream: false,
                compaction: PreModelCompactionPayload::from(&CompactionSettings {
                    max_context_chars: run.max_context_chars,
                    mode: run.compaction_mode,
                    keep_last: run.compaction_keep_last,
                    tool_result_persist: run.tool_result_persist,
                }),
            };
            let input = make_pre_model_input(
                &run_id,
                0,
                &provider,
                run.model.as_deref().unwrap_or("doctor"),
                &run.workdir,
                serde_json::to_value(payload)?,
            );
            let one = HookManager {
                mode: manager.mode,
                strict: true,
                timeout_ms: manager.timeout_ms,
                max_stdout_bytes: manager.max_stdout_bytes,
                config_path: manager.config_path.clone(),
                hooks: vec![hook.clone()],
            };
            one.run_pre_model_hooks(input)
                .await
                .map_err(|e| anyhow!(e.message))?;
        }
        if hook.has_stage(hooks::config::HookStage::ToolResult) {
            let payload = ToolResultPayload {
                tool_call_id: "doctor_tc".to_string(),
                tool_name: "read_file".to_string(),
                ok: true,
                content: "sample".to_string(),
                truncated: false,
            };
            let input = make_tool_result_input(
                &run_id,
                0,
                &provider,
                run.model.as_deref().unwrap_or("doctor"),
                &run.workdir,
                serde_json::to_value(payload)?,
            );
            let one = HookManager {
                mode: manager.mode,
                strict: true,
                timeout_ms: manager.timeout_ms,
                max_stdout_bytes: manager.max_stdout_bytes,
                config_path: manager.config_path.clone(),
                hooks: vec![hook.clone()],
            };
            one.run_tool_result_hooks(input, "read_file", "sample", false)
                .await
                .map_err(|e| anyhow!(e.message))?;
        }
        println!("OK: hook {}", hook.cfg.name);
    }
    Ok(())
}

fn build_event_sink(
    stream: bool,
    events_path: Option<&std::path::Path>,
    tui_enabled: bool,
    ui_tx: Option<Sender<Event>>,
) -> anyhow::Result<Option<Box<dyn EventSink>>> {
    let mut multi = MultiSink::new();
    if stream && !tui_enabled {
        multi.push(Box::new(StdoutSink::new()));
    }
    if let Some(tx) = ui_tx {
        multi.push(Box::new(tui::UiSink::new(tx)));
    }
    if let Some(path) = events_path {
        multi.push(Box::new(JsonlFileSink::new(path)?));
    }
    if multi.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Box::new(multi)))
    }
}

struct GateBuild {
    gate: Box<dyn ToolGate>,
    policy_hash_hex: Option<String>,
    policy_source: &'static str,
    policy_for_exposure: Option<Policy>,
    policy_version: Option<u32>,
    includes_resolved: Vec<String>,
    mcp_allowlist: Option<McpAllowSummary>,
}

fn build_gate(args: &RunArgs, paths: &store::StatePaths) -> anyhow::Result<GateBuild> {
    match args.trust {
        TrustMode::Off => Ok(GateBuild {
            gate: Box::new(NoGate::new()),
            policy_hash_hex: None,
            policy_source: "none",
            policy_for_exposure: None,
            policy_version: None,
            includes_resolved: Vec::new(),
            mcp_allowlist: None,
        }),
        TrustMode::Auto => {
            if !paths.policy_path.exists() {
                return Ok(GateBuild {
                    gate: Box::new(NoGate::new()),
                    policy_hash_hex: None,
                    policy_source: "none",
                    policy_for_exposure: None,
                    policy_version: None,
                    includes_resolved: Vec::new(),
                    mcp_allowlist: None,
                });
            }
            let policy_bytes = std::fs::read(&paths.policy_path).with_context(|| {
                format!(
                    "failed reading policy file: {}",
                    paths.policy_path.display()
                )
            })?;
            let policy = Policy::from_path(&paths.policy_path).with_context(|| {
                format!(
                    "failed parsing policy file: {}",
                    paths.policy_path.display()
                )
            })?;
            let policy_hash_hex = compute_policy_hash_hex(&policy_bytes);
            let policy_version = policy.version();
            let includes_resolved = policy.includes_resolved().to_vec();
            let mcp_allowlist = policy.mcp_allowlist_summary();
            Ok(GateBuild {
                gate: Box::new(TrustGate::new(
                    policy.clone(),
                    ApprovalsStore::new(paths.approvals_path.clone()),
                    AuditLog::new(paths.audit_path.clone()),
                    TrustMode::Auto,
                    policy_hash_hex.clone(),
                )),
                policy_hash_hex: Some(policy_hash_hex),
                policy_source: "file",
                policy_for_exposure: Some(policy),
                policy_version: Some(policy_version),
                includes_resolved,
                mcp_allowlist,
            })
        }
        TrustMode::On => {
            let (policy, policy_hash_hex, policy_source) = if paths.policy_path.exists() {
                let policy_bytes = std::fs::read(&paths.policy_path).with_context(|| {
                    format!(
                        "failed reading policy file: {}",
                        paths.policy_path.display()
                    )
                })?;
                let policy = Policy::from_path(&paths.policy_path).with_context(|| {
                    format!(
                        "failed parsing policy file: {}",
                        paths.policy_path.display()
                    )
                })?;
                (policy, compute_policy_hash_hex(&policy_bytes), "file")
            } else {
                let repr = trust::policy::safe_default_policy_repr();
                (
                    Policy::safe_default(),
                    compute_policy_hash_hex(repr.as_bytes()),
                    "default",
                )
            };
            let policy_version = policy.version();
            let includes_resolved = policy.includes_resolved().to_vec();
            let mcp_allowlist = policy.mcp_allowlist_summary();
            Ok(GateBuild {
                gate: Box::new(TrustGate::new(
                    policy.clone(),
                    ApprovalsStore::new(paths.approvals_path.clone()),
                    AuditLog::new(paths.audit_path.clone()),
                    TrustMode::On,
                    policy_hash_hex.clone(),
                )),
                policy_hash_hex: Some(policy_hash_hex),
                policy_source,
                policy_for_exposure: Some(policy),
                policy_version: Some(policy_version),
                includes_resolved,
                mcp_allowlist,
            })
        }
    }
}

async fn doctor_check(args: &DoctorArgs) -> Result<String, String> {
    let base_url = args
        .base_url
        .clone()
        .unwrap_or_else(|| default_base_url(args.provider).to_string());
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    match args.provider {
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
            let urls = doctor_probe_urls(args.provider, &base_url);
            let models_url = &urls[0];
            let health_url = &urls[1];

            match get_with_optional_bearer(&client, models_url, args.api_key.as_deref()).await {
                Ok(models_resp) => {
                    if models_resp.status().is_success() {
                        return Ok(format!(
                            "OK: {} reachable at {}",
                            provider_cli_name(args.provider),
                            base_url
                        ));
                    }

                    if models_resp.status() == reqwest::StatusCode::NOT_FOUND {
                        let health_resp =
                            get_with_optional_bearer(&client, health_url, args.api_key.as_deref())
                                .await
                                .map_err(|e| {
                                    format!("{} not reachable after /models 404: {e}", health_url)
                                })?;
                        if health_resp.status().is_success() {
                            return Ok(format!(
                                "OK: {} reachable at {} (reachable but endpoint differs)",
                                provider_cli_name(args.provider),
                                base_url
                            ));
                        }
                    }

                    Err(format!(
                        "{} responded with HTTP {} at {}",
                        provider_cli_name(args.provider),
                        models_resp.status(),
                        models_url
                    ))
                }
                Err(models_err) => {
                    let health_resp =
                        get_with_optional_bearer(&client, health_url, args.api_key.as_deref())
                            .await
                            .map_err(|health_err| {
                                format!(
                                    "could not reach {} ({models_err}); fallback {} also failed: {health_err}",
                                    models_url, health_url
                                )
                            })?;
                    if health_resp.status().is_success() {
                        Ok(format!(
                            "OK: {} reachable at {} (reachable but endpoint differs)",
                            provider_cli_name(args.provider),
                            base_url
                        ))
                    } else {
                        Err(format!(
                            "{} responded with HTTP {} at fallback {}",
                            provider_cli_name(args.provider),
                            health_resp.status(),
                            health_url
                        ))
                    }
                }
            }
        }
        ProviderKind::Ollama => {
            let tags_url = doctor_probe_urls(args.provider, &base_url)
                .into_iter()
                .next()
                .ok_or_else(|| "internal error building Ollama doctor URL".to_string())?;
            let resp = client
                .get(&tags_url)
                .send()
                .await
                .map_err(|e| format!("could not reach {tags_url}: {e}"))?;
            if resp.status().is_success() {
                Ok(format!("OK: ollama reachable at {}", base_url))
            } else {
                Err(format!(
                    "ollama responded with HTTP {} at {}",
                    resp.status(),
                    tags_url
                ))
            }
        }
    }
}

async fn get_with_optional_bearer(
    client: &Client,
    url: &str,
    api_key: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut req = client.get(url);
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    req.send().await
}

fn default_base_url(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Lmstudio => "http://localhost:1234/v1",
        ProviderKind::Llamacpp => "http://localhost:8080/v1",
        ProviderKind::Ollama => "http://localhost:11434",
    }
}

fn http_config_from_run_args(args: &RunArgs) -> HttpConfig {
    HttpConfig {
        connect_timeout_ms: args.http_connect_timeout_ms,
        request_timeout_ms: args.http_timeout_ms,
        stream_idle_timeout_ms: args.http_stream_idle_timeout_ms,
        max_response_bytes: args.http_max_response_bytes,
        max_line_bytes: args.http_max_line_bytes,
        http_max_retries: args.http_max_retries,
        ..HttpConfig::default()
    }
}

fn http_config_from_eval_args(args: &EvalArgs) -> HttpConfig {
    HttpConfig {
        connect_timeout_ms: args.http_connect_timeout_ms,
        request_timeout_ms: args.http_timeout_ms,
        stream_idle_timeout_ms: args.http_stream_idle_timeout_ms,
        max_response_bytes: args.http_max_response_bytes,
        max_line_bytes: args.http_max_line_bytes,
        http_max_retries: args.http_max_retries,
        ..HttpConfig::default()
    }
}

fn cli_has_flag(flag: &str) -> bool {
    std::env::args().any(|a| a == flag || a.starts_with(&format!("{flag}=")))
}

fn apply_eval_profile_overrides(
    args: &mut EvalArgs,
    state_dir: &std::path::Path,
) -> anyhow::Result<Option<eval::profile::LoadedProfile>> {
    let loaded = if args.profile.is_some() || args.profile_path.is_some() {
        Some(load_profile(
            state_dir,
            args.profile.as_deref(),
            args.profile_path.as_deref(),
        )?)
    } else {
        None
    };
    let Some(loaded) = loaded else {
        return Ok(None);
    };
    let p = &loaded.profile;

    if !cli_has_flag("--provider") {
        if let Some(v) = &p.provider {
            args.provider = match v.as_str() {
                "lmstudio" => ProviderKind::Lmstudio,
                "llamacpp" => ProviderKind::Llamacpp,
                _ => ProviderKind::Ollama,
            };
        }
    }
    if !cli_has_flag("--base-url") {
        if let Some(v) = &p.base_url {
            args.base_url = Some(v.clone());
        }
    }
    if !cli_has_flag("--models") {
        if let Some(v) = &p.models {
            args.models = Some(v.join(","));
        }
    }
    if !cli_has_flag("--pack") {
        if let Some(v) = &p.pack {
            args.pack = match v.as_str() {
                "coding" => EvalPack::Coding,
                "browser" => EvalPack::Browser,
                _ => EvalPack::All,
            };
        }
    }
    if !cli_has_flag("--runs-per-task") {
        if let Some(v) = p.runs_per_task {
            args.runs_per_task = v;
        }
    }
    if !cli_has_flag("--caps") {
        if let Some(v) = &p.caps {
            args.caps = match v.as_str() {
                "off" => CapsMode::Off,
                "strict" => CapsMode::Strict,
                _ => CapsMode::Auto,
            };
        }
    }
    if !cli_has_flag("--trust") {
        if let Some(v) = &p.trust {
            args.trust = match v.as_str() {
                "off" => TrustMode::Off,
                "auto" => TrustMode::Auto,
                _ => TrustMode::On,
            };
        }
    }
    if !cli_has_flag("--approval-mode") {
        if let Some(v) = &p.approval_mode {
            args.approval_mode = match v.as_str() {
                "interrupt" => ApprovalMode::Interrupt,
                "fail" => ApprovalMode::Fail,
                _ => ApprovalMode::Auto,
            };
        }
    }
    if !cli_has_flag("--auto-approve-scope") {
        if let Some(v) = &p.auto_approve_scope {
            args.auto_approve_scope = match v.as_str() {
                "session" => AutoApproveScope::Session,
                _ => AutoApproveScope::Run,
            };
        }
    }
    if !cli_has_flag("--mcp") {
        if let Some(v) = &p.mcp {
            args.mcp = v.clone();
        }
    }
    if let Some(flags) = &p.flags {
        if !cli_has_flag("--enable-write-tools") {
            if let Some(v) = flags.enable_write_tools {
                args.enable_write_tools = v;
            }
        }
        if !cli_has_flag("--allow-write") {
            if let Some(v) = flags.allow_write {
                args.allow_write = v;
            }
        }
        if !cli_has_flag("--allow-shell") {
            if let Some(v) = flags.allow_shell {
                args.allow_shell = v;
            }
        }
    }
    if let Some(th) = &p.thresholds {
        if !cli_has_flag("--min-pass-rate") {
            if let Some(v) = th.min_pass_rate {
                args.min_pass_rate = v;
            }
        }
        if !cli_has_flag("--fail-on-any") {
            if let Some(v) = th.fail_on_any {
                args.fail_on_any = v;
            }
        }
        if !cli_has_flag("--max-avg-steps") {
            if let Some(v) = th.max_avg_steps {
                args.max_avg_steps = Some(v);
            }
        }
    }
    Ok(Some(loaded))
}

fn provider_cli_name(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Lmstudio => "lmstudio",
        ProviderKind::Llamacpp => "llamacpp",
        ProviderKind::Ollama => "ollama",
    }
}

fn doctor_probe_urls(provider: ProviderKind, base_url: &str) -> Vec<String> {
    let trimmed = base_url.trim_end_matches('/').to_string();
    match provider {
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
            vec![format!("{trimmed}/models"), trimmed]
        }
        ProviderKind::Ollama => vec![format!("{trimmed}/api/tags")],
    }
}

fn parse_explicit_flags() -> ExplicitFlags {
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use tempfile::tempdir;

    use crate::providers::{ModelProvider, StreamDelta};
    use crate::types::{GenerateRequest, GenerateResponse, Message, Role};

    use super::{doctor_probe_urls, policy_doctor_output, policy_effective_output, ProviderKind};

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

    #[test]
    fn doctor_url_construction_openai_compat() {
        let urls = doctor_probe_urls(ProviderKind::Lmstudio, "http://localhost:1234/v1/");
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
        let out = policy_doctor_output(&p).expect("doctor");
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
        let out = policy_effective_output(&p, true).expect("print");
        assert!(out.contains("\"rules\""));
        assert!(out.contains("read_file"));
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
}
