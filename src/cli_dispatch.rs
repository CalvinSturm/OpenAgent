use anyhow::{anyhow, Context};

use clap::Parser;

use crate::cli_args::*;

use crate::eval::tasks::EvalPack;

use crate::mcp::registry::{doctor_server as mcp_doctor_server, list_servers as mcp_list_servers};

use crate::store::provider_to_string;

use crate::*;

use crate::{
    approvals_ops, chat_repl_runtime, eval, ops_helpers, provider_runtime, runtime_paths, scaffold,
    session_ops, startup_bootstrap, startup_init, store, task_eval_profile, taskgraph,
    tasks_graph_runtime, trust, tui,
};

pub(crate) async fn run_cli() -> anyhow::Result<()> {
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

    startup_init::maybe_auto_init_state(&cli.command, cli.run.state_dir.clone(), &workdir, &paths)?;

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
            let mcp_config_path =
                runtime_paths::resolved_mcp_config_path(&cli.run, &paths.state_dir);

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

                println!(
                    "{}",
                    ops_helpers::policy_effective_output(&policy_path, *json)?
                );

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
