mod agent;
mod gate;
mod providers;
mod tools;
mod trust;
mod types;

use std::path::PathBuf;
use std::time::Duration;

use agent::Agent;
use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use gate::{GateContext, NoGate, ProviderKind, ToolGate, TrustGate, TrustMode};
use providers::ollama::OllamaProvider;
use providers::openai_compat::OpenAiCompatProvider;
use providers::ModelProvider;
use reqwest::Client;
use tools::{builtin_tools_enabled, ToolRuntime};
use trust::approvals::ApprovalsStore;
use trust::audit::AuditLog;
use trust::policy::Policy;

#[derive(Debug, Subcommand)]
enum Commands {
    Doctor(DoctorArgs),
    Approvals(ApprovalsArgs),
    Approve(ApproveArgs),
    Deny(DenyArgs),
}

#[derive(Debug, Subcommand)]
enum ApprovalsSubcommand {
    List,
}

#[derive(Debug, Parser)]
struct ApprovalsArgs {
    #[command(subcommand)]
    command: ApprovalsSubcommand,
}

#[derive(Debug, Parser)]
struct ApproveArgs {
    id: String,
}

#[derive(Debug, Parser)]
struct DenyArgs {
    id: String,
}

#[derive(Debug, Parser)]
#[command(name = "agentloop")]
#[command(about = "Local-runtime agent loop with tool calling", long_about = None)]
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
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    approvals: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
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
        Some(Commands::Approvals(args)) => {
            let workdir = std::fs::canonicalize(&cli.run.workdir).with_context(|| {
                format!("failed to resolve workdir: {}", cli.run.workdir.display())
            })?;
            let paths = trust::resolve_paths(
                &workdir,
                cli.run.policy.clone(),
                cli.run.approvals.clone(),
                cli.run.audit.clone(),
            );
            handle_approvals_command(&paths.approvals, &args.command)?;
            return Ok(());
        }
        Some(Commands::Approve(args)) => {
            let workdir = std::fs::canonicalize(&cli.run.workdir).with_context(|| {
                format!("failed to resolve workdir: {}", cli.run.workdir.display())
            })?;
            let paths = trust::resolve_paths(
                &workdir,
                cli.run.policy.clone(),
                cli.run.approvals.clone(),
                cli.run.audit.clone(),
            );
            let store = ApprovalsStore::new(paths.approvals);
            store.approve(&args.id)?;
            println!("approved {}", args.id);
            return Ok(());
        }
        Some(Commands::Deny(args)) => {
            let workdir = std::fs::canonicalize(&cli.run.workdir).with_context(|| {
                format!("failed to resolve workdir: {}", cli.run.workdir.display())
            })?;
            let paths = trust::resolve_paths(
                &workdir,
                cli.run.policy.clone(),
                cli.run.approvals.clone(),
                cli.run.audit.clone(),
            );
            let store = ApprovalsStore::new(paths.approvals);
            store.deny(&args.id)?;
            println!("denied {}", args.id);
            return Ok(());
        }
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
            let provider = OpenAiCompatProvider::new(base_url.clone(), cli.run.api_key.clone());
            run_agent(
                provider,
                provider_kind,
                &base_url,
                &model,
                &prompt,
                &cli.run,
            )
            .await?;
        }
        ProviderKind::Ollama => {
            let provider = OllamaProvider::new(base_url.clone());
            run_agent(
                provider,
                provider_kind,
                &base_url,
                &model,
                &prompt,
                &cli.run,
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
                println!("{id}\t{:?}\t{}\t{}", req.status, req.tool, req.created_at);
            }
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
) -> anyhow::Result<()> {
    let workdir = std::fs::canonicalize(&args.workdir)
        .with_context(|| format!("failed to resolve workdir: {}", args.workdir.display()))?;
    let gate_ctx = GateContext {
        workdir: workdir.clone(),
        allow_shell: args.allow_shell,
        allow_write: args.allow_write,
        enable_write_tools: args.enable_write_tools,
        max_tool_output_bytes: args.max_tool_output_bytes,
        max_read_bytes: args.max_read_bytes,
        provider: provider_kind,
        model: model.to_string(),
    };
    let gate = build_gate(args, &workdir)?;

    let mut agent = Agent {
        provider,
        model: model.to_string(),
        tools: builtin_tools_enabled(args.enable_write_tools),
        max_steps: args.max_steps,
        tool_rt: ToolRuntime {
            workdir,
            allow_shell: args.allow_shell,
            allow_write: args.allow_write,
            max_tool_output_bytes: args.max_tool_output_bytes,
            max_read_bytes: args.max_read_bytes,
        },
        gate,
        gate_ctx,
    };

    let output = agent.run(prompt).await.map_err(|e| {
        anyhow!(
            "{}\nHint: run `agentloop doctor --provider {} --base-url {}`\nDefault base URL for {} is {}",
            e,
            provider_cli_name(provider_kind),
            base_url,
            provider_cli_name(provider_kind),
            default_base_url(provider_kind)
        )
    })?;
    println!("{output}");
    Ok(())
}

fn build_gate(args: &RunArgs, workdir: &std::path::Path) -> anyhow::Result<Box<dyn ToolGate>> {
    let paths = trust::resolve_paths(
        workdir,
        args.policy.clone(),
        args.approvals.clone(),
        args.audit.clone(),
    );
    match args.trust {
        TrustMode::Off => Ok(Box::new(NoGate::new())),
        TrustMode::Auto => {
            if !paths.policy.exists() {
                return Ok(Box::new(NoGate::new()));
            }
            let policy_text = std::fs::read_to_string(&paths.policy).with_context(|| {
                format!("failed reading policy file: {}", paths.policy.display())
            })?;
            let policy = Policy::from_yaml(&policy_text).with_context(|| {
                format!("failed parsing policy file: {}", paths.policy.display())
            })?;
            Ok(Box::new(TrustGate::new(
                policy,
                ApprovalsStore::new(paths.approvals),
                AuditLog::new(paths.audit),
                TrustMode::Auto,
            )))
        }
        TrustMode::On => {
            let policy = if paths.policy.exists() {
                let policy_text = std::fs::read_to_string(&paths.policy).with_context(|| {
                    format!("failed reading policy file: {}", paths.policy.display())
                })?;
                Policy::from_yaml(&policy_text).with_context(|| {
                    format!("failed parsing policy file: {}", paths.policy.display())
                })?
            } else {
                Policy::safe_default()
            };
            Ok(Box::new(TrustGate::new(
                policy,
                ApprovalsStore::new(paths.approvals),
                AuditLog::new(paths.audit),
                TrustMode::On,
            )))
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

#[cfg(test)]
mod tests {
    use super::{doctor_probe_urls, ProviderKind};

    #[test]
    fn doctor_url_construction_openai_compat() {
        let urls = doctor_probe_urls(ProviderKind::Lmstudio, "http://localhost:1234/v1/");
        assert_eq!(urls[0], "http://localhost:1234/v1/models");
        assert_eq!(urls[1], "http://localhost:1234/v1");
    }
}
