mod agent;
mod compaction;
mod eval;
mod events;
mod gate;
mod hooks;
mod mcp;
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
    stable_path_string, ConfigFingerprintV1, RunCliConfig,
};
use tokio::sync::watch;
use tools::{builtin_tools_enabled, ToolArgsStrict, ToolRuntime};
use trust::approvals::ApprovalsStore;
use trust::audit::AuditLog;
use trust::policy::{McpAllowSummary, Policy};

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
    Eval(Box<EvalArgs>),
    Tui(TuiArgs),
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

#[derive(Debug, Parser)]
struct EvalArgs {
    #[arg(long, value_enum, default_value_t = ProviderKind::Ollama)]
    provider: ProviderKind,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    models: String,
    #[arg(long, value_enum, default_value_t = EvalPack::All)]
    pack: EvalPack,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    runs_per_task: usize,
    #[arg(long, default_value_t = 30)]
    max_steps: usize,
    #[arg(long, default_value_t = 600)]
    timeout_seconds: u64,
    #[arg(long, value_enum, default_value_t = TrustMode::On)]
    trust: TrustMode,
    #[arg(long, value_enum, default_value_t = ApprovalMode::Auto)]
    approval_mode: ApprovalMode,
    #[arg(long, value_enum, default_value_t = AutoApproveScope::Run)]
    auto_approve_scope: AutoApproveScope,
    #[arg(long, default_value_t = false)]
    enable_write_tools: bool,
    #[arg(long, default_value_t = false)]
    allow_write: bool,
    #[arg(long, default_value_t = false)]
    allow_shell: bool,
    #[arg(long = "unsafe", default_value_t = false)]
    unsafe_mode: bool,
    #[arg(long, default_value_t = false)]
    no_limits: bool,
    #[arg(long, default_value_t = false)]
    unsafe_bypass_allow_flags: bool,
    #[arg(long = "mcp")]
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
        Some(Commands::Eval(args)) => {
            if args.no_limits && !args.unsafe_mode {
                return Err(anyhow!("--no-limits requires --unsafe"));
            }
            if args.unsafe_mode {
                eprintln!("WARN: unsafe mode enabled");
            }
            let models = args
                .models
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
                http: http_config_from_eval_args(args),
            };
            let cwd = std::env::current_dir().with_context(|| "failed to read current dir")?;
            run_eval(cfg, &cwd).await?;
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
    model: &str,
    prompt: &str,
    args: &RunArgs,
    paths: &store::StatePaths,
) -> anyhow::Result<()> {
    let workdir = std::fs::canonicalize(&args.workdir)
        .with_context(|| format!("failed to resolve workdir: {}", args.workdir.display()))?;
    let gate_ctx = GateContext {
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
        model: model.to_string(),
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

    let mut agent = Agent {
        provider,
        model: model.to_string(),
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
        event_sink: None,
        compaction_settings: CompactionSettings {
            max_context_chars: resolved_settings.max_context_chars,
            mode: resolved_settings.compaction_mode,
            keep_last: resolved_settings.compaction_keep_last,
            tool_result_persist: resolved_settings.tool_result_persist,
        },
        hooks: hook_manager,
        policy_loaded: policy_loaded_info,
    };

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
            model: model.to_string(),
            caps_source: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
            policy_hash: policy_hash_hex.clone().unwrap_or_default(),
        };
        Some(std::thread::spawn(move || {
            tui::run_live(rx, approvals_path, cfg, cancel_tx.clone())
        }))
    } else {
        None
    };
    agent.event_sink = build_event_sink(args.stream, args.events.as_deref(), args.tui, ui_tx)?;

    let outcome = tokio::select! {
        out = agent.run(prompt, session_messages, task_memory) => out,
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

    let cli_config = RunCliConfig {
        provider: provider_to_string(provider_kind),
        base_url: base_url.to_string(),
        model: model.to_string(),
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
        hooks_config_path: stable_path_string(&hooks_config_path),
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
        tool_catalog: tool_catalog.clone(),
        policy_version,
        includes_resolved: includes_resolved.clone(),
        mcp_allowlist: mcp_allowlist.clone(),
    };
    let config_fingerprint = ConfigFingerprintV1 {
        schema_version: "openagent.confighash.v1".to_string(),
        provider: provider_to_string(provider_kind),
        base_url: base_url.to_string(),
        model: model.to_string(),
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
        max_context_chars: resolved_settings.max_context_chars,
        compaction_mode: format!("{:?}", resolved_settings.compaction_mode).to_lowercase(),
        compaction_keep_last: resolved_settings.compaction_keep_last,
        tool_result_persist: format!("{:?}", resolved_settings.tool_result_persist).to_lowercase(),
        hooks_mode: format!("{:?}", resolved_settings.hooks_mode).to_lowercase(),
        caps_mode: format!("{:?}", resolved_settings.caps_mode).to_lowercase(),
        hooks_config_path: stable_path_string(&hooks_config_path),
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
        tool_catalog_names: tool_catalog.iter().map(|t| t.name.clone()).collect(),
        policy_version,
        includes_resolved: includes_resolved.clone(),
        mcp_allowlist: mcp_allowlist.clone(),
    };
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
    use tempfile::tempdir;

    use super::{doctor_probe_urls, policy_doctor_output, policy_effective_output, ProviderKind};

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
}
