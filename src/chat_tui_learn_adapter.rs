use anyhow::{anyhow, Context};
use clap::Parser;

use crate::cli_args::{
    LearnArgs, LearnCategoryArg, LearnPromoteTargetArg, LearnStatusArg, LearnSubcommand, RunArgs,
};
use crate::learning;
use crate::providers::ModelProvider;
use crate::store::StatePaths;
use crate::types::{GenerateRequest, Message, Role};

pub(crate) async fn parse_and_dispatch_learn_slash(
    line: &str,
    active_run: &RunArgs,
    paths: &StatePaths,
) -> anyhow::Result<String> {
    let tokens = tokenize_learn_slash(line)?;
    if tokens.is_empty() || tokens[0] == "help" {
        return Ok(render_tui_learn_help());
    }
    let mut argv = vec!["learn".to_string()];
    argv.extend(tokens);
    let args = LearnArgs::try_parse_from(argv).map_err(|e| anyhow!("learn parse error: {}", e))?;
    dispatch_learn_args(args, active_run, paths).await
}

async fn dispatch_learn_args(
    args: LearnArgs,
    active_run: &RunArgs,
    paths: &StatePaths,
) -> anyhow::Result<String> {
    match args.command {
        LearnSubcommand::Capture {
            run,
            assist,
            write,
            category,
            summary,
            task_summary,
            profile,
            guidance_text,
            check_text,
            tags,
            evidence,
            evidence_notes,
        } => {
            validate_capture_assist_flags(assist, write)?;
            let category = match category {
                LearnCategoryArg::WorkflowHint => learning::LearningCategoryV1::WorkflowHint,
                LearnCategoryArg::PromptGuidance => learning::LearningCategoryV1::PromptGuidance,
                LearnCategoryArg::CheckCandidate => learning::LearningCategoryV1::CheckCandidate,
            };
            let input = learning::build_capture_input(
                run,
                category,
                summary,
                task_summary,
                profile,
                guidance_text,
                check_text,
                tags,
                evidence,
                evidence_notes,
            );
            if assist {
                let assisted = generate_assisted_capture_preview(active_run, &input).await?;
                let mut out = vec![learning::render_assist_capture_preview(&assisted.preview)];
                if write {
                    let assist_meta = learning::build_assist_capture_meta(
                        &assisted.preview.provider,
                        &assisted.preview.model,
                        &assisted.preview.input_hash_hex,
                        input.run_id.as_deref(),
                        assisted.output_truncated,
                    );
                    let input = learning::apply_assisted_draft_to_capture_input(
                        input,
                        &assisted.preview.draft,
                        assist_meta,
                    );
                    let captured = learning::capture_learning_entry(&paths.state_dir, input)
                        .context("failed to capture assisted learning entry")?;
                    learning::emit_learning_captured_event(&paths.state_dir, &captured.entry)
                        .context("failed to emit learning_captured event")?;
                    out.push(learning::render_capture_confirmation(&captured.entry));
                }
                return Ok(out.join("\n"));
            }
            let out = learning::capture_learning_entry(&paths.state_dir, input)
                .context("failed to capture learning entry")?;
            learning::emit_learning_captured_event(&paths.state_dir, &out.entry)
                .context("failed to emit learning_captured event")?;
            Ok(learning::render_capture_confirmation(&out.entry))
        }
        LearnSubcommand::List {
            statuses,
            categories,
            limit,
            show_archived,
            format,
        } => {
            let mut entries = learning::list_learning_entries(&paths.state_dir)?;
            if !categories.is_empty() {
                let wanted = categories
                    .iter()
                    .map(|c| match c {
                        LearnCategoryArg::WorkflowHint => {
                            learning::LearningCategoryV1::WorkflowHint
                        }
                        LearnCategoryArg::PromptGuidance => {
                            learning::LearningCategoryV1::PromptGuidance
                        }
                        LearnCategoryArg::CheckCandidate => {
                            learning::LearningCategoryV1::CheckCandidate
                        }
                    })
                    .collect::<Vec<_>>();
                entries.retain(|e| wanted.contains(&e.category));
            }
            if !statuses.is_empty() {
                let wanted = statuses
                    .iter()
                    .map(|s| match s {
                        LearnStatusArg::Captured => learning::LearningStatusV1::Captured,
                        LearnStatusArg::Promoted => learning::LearningStatusV1::Promoted,
                        LearnStatusArg::Archived => learning::LearningStatusV1::Archived,
                    })
                    .collect::<Vec<_>>();
                entries.retain(|e| wanted.contains(&e.status));
            } else if !show_archived {
                entries.retain(|e| e.status != learning::LearningStatusV1::Archived);
            }
            if entries.len() > limit {
                entries.truncate(limit);
            }
            match format.as_str() {
                "table" => Ok(learning::render_learning_list_table(&entries)),
                "json" => learning::render_learning_list_json_preview(&entries),
                other => Err(anyhow!(
                    "unsupported learn list format '{other}' (expected table|json)"
                )),
            }
        }
        LearnSubcommand::Show {
            id,
            format,
            show_evidence,
            show_proposed,
        } => {
            let entry = learning::load_learning_entry(&paths.state_dir, &id)?;
            match format.as_str() {
                "text" => Ok(learning::render_learning_show_text(
                    &entry,
                    show_evidence,
                    show_proposed,
                )),
                "json" => learning::render_learning_show_json_preview(
                    &entry,
                    show_evidence,
                    show_proposed,
                ),
                other => Err(anyhow!(
                    "unsupported learn show format '{other}' (expected text|json)"
                )),
            }
        }
        LearnSubcommand::Archive { id } => {
            let out = learning::archive_learning_entry(&paths.state_dir, &id)?;
            Ok(learning::render_archive_confirmation(&out))
        }
        LearnSubcommand::Promote {
            id,
            to,
            slug,
            pack_id,
            force,
            check_run,
            replay_verify,
            replay_verify_run_id,
            replay_verify_strict,
        } => match to {
            LearnPromoteTargetArg::Check => {
                validate_promote_chain_flags(to, check_run, replay_verify, &replay_verify_run_id)?;
                let slug = slug
                    .as_deref()
                    .ok_or_else(|| anyhow!("--slug is required for --to check"))?;
                let out = learning::promote_learning_to_check(&paths.state_dir, &id, slug, force)
                    .with_context(|| {
                    format!("failed to promote learning entry {id} to check")
                })?;
                let mut logs = vec![learning::render_promote_to_check_confirmation(&out)];
                if check_run {
                    let check_out = crate::cli_dispatch_checks::run_check_command(
                        Some(out.target_path.clone()),
                        Some(1),
                        active_run,
                        &active_run.workdir,
                        paths,
                    )
                    .await
                    .context("chained check run failed")?;
                    logs.push(crate::cli_dispatch_checks::render_check_run_output(
                        &check_out,
                    )?);
                    if check_out.exit != crate::checks::runner::CheckRunExit::Ok {
                        return Err(anyhow!(
                            "check run failed with exit code {}",
                            check_out.exit as i32
                        ));
                    }
                }
                if replay_verify {
                    let (verify_text, failed) = run_chained_replay_verify_report(
                        paths,
                        &id,
                        replay_verify_run_id.as_deref(),
                        replay_verify_strict,
                    )?;
                    logs.push(verify_text);
                    if failed {
                        return Err(anyhow!("replay verify failed"));
                    }
                }
                Ok(logs.join("\n"))
            }
            LearnPromoteTargetArg::Pack => {
                validate_promote_chain_flags(to, check_run, replay_verify, &replay_verify_run_id)?;
                let pack_id = pack_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("--pack-id is required for --to pack"))?;
                let out = learning::promote_learning_to_pack(&paths.state_dir, &id, pack_id, force)
                    .with_context(|| format!("failed to promote learning entry {id} to pack"))?;
                let mut logs = vec![learning::render_promote_to_target_confirmation(&out)];
                if replay_verify {
                    let (verify_text, failed) = run_chained_replay_verify_report(
                        paths,
                        &id,
                        replay_verify_run_id.as_deref(),
                        replay_verify_strict,
                    )?;
                    logs.push(verify_text);
                    if failed {
                        return Err(anyhow!("replay verify failed"));
                    }
                }
                Ok(logs.join("\n"))
            }
            LearnPromoteTargetArg::Agents => {
                validate_promote_chain_flags(to, check_run, replay_verify, &replay_verify_run_id)?;
                let out = learning::promote_learning_to_agents(&paths.state_dir, &id, force)
                    .with_context(|| format!("failed to promote learning entry {id} to agents"))?;
                let mut logs = vec![learning::render_promote_to_target_confirmation(&out)];
                if replay_verify {
                    let (verify_text, failed) = run_chained_replay_verify_report(
                        paths,
                        &id,
                        replay_verify_run_id.as_deref(),
                        replay_verify_strict,
                    )?;
                    logs.push(verify_text);
                    if failed {
                        return Err(anyhow!("replay verify failed"));
                    }
                }
                Ok(logs.join("\n"))
            }
        },
    }
}

fn render_tui_learn_help() -> String {
    [
        "/learn help",
        "/learn list [--status <captured|promoted|archived>] [--category <workflow-hint|prompt-guidance|check-candidate>] [--limit N] [--show-archived] [--format table|json]",
        "/learn show <id> [--format text|json] [--show-evidence true|false] [--show-proposed true|false]",
        "/learn archive <id>",
        "/learn capture --category <...> --summary <...> [--assist] [--write] ...",
        "/learn promote <id> --to <check|pack|agents> [target flags] [--force] [--check-run] [--replay-verify ...]",
        "note: overlay Promote tab is simplified (target + force + arm/run). Use typed /learn promote for advanced flags.",
    ]
    .join("\n")
}

fn tokenize_learn_slash(line: &str) -> anyhow::Result<Vec<String>> {
    let rest = line
        .strip_prefix("/learn")
        .ok_or_else(|| anyhow!("internal parse error: expected /learn prefix"))?;
    split_shell_like(rest.trim())
}

fn split_shell_like(input: &str) -> anyhow::Result<Vec<String>> {
    #[derive(Clone, Copy)]
    enum Mode {
        Normal,
        Single,
        Double,
    }
    let mut mode = Mode::Normal;
    let mut out = Vec::<String>::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match mode {
            Mode::Normal => match ch {
                '\'' => mode = Mode::Single,
                '"' => mode = Mode::Double,
                '\\' => {
                    let next = chars
                        .next()
                        .ok_or_else(|| anyhow!("learn parse error: trailing escape"))?;
                    cur.push(next);
                }
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(ch),
            },
            Mode::Single => {
                if ch == '\'' {
                    mode = Mode::Normal;
                } else {
                    cur.push(ch);
                }
            }
            Mode::Double => match ch {
                '"' => mode = Mode::Normal,
                '\\' => {
                    let next = chars
                        .next()
                        .ok_or_else(|| anyhow!("learn parse error: trailing escape in quotes"))?;
                    cur.push(next);
                }
                _ => cur.push(ch),
            },
        }
    }
    match mode {
        Mode::Normal => {
            if !cur.is_empty() {
                out.push(cur);
            }
            Ok(out)
        }
        Mode::Single | Mode::Double => Err(anyhow!("learn parse error: unterminated quote")),
    }
}

fn validate_promote_chain_flags(
    target: LearnPromoteTargetArg,
    check_run: bool,
    replay_verify: bool,
    replay_verify_run_id: &Option<String>,
) -> anyhow::Result<()> {
    if check_run && !matches!(target, LearnPromoteTargetArg::Check) {
        return Err(anyhow!("--check-run is only valid with --to check"));
    }
    if replay_verify_run_id.is_some() && !replay_verify {
        return Err(anyhow!("--replay-verify-run-id requires --replay-verify"));
    }
    Ok(())
}

fn validate_capture_assist_flags(assist: bool, write: bool) -> anyhow::Result<()> {
    if write && !assist {
        return Err(anyhow!(
            "{}: --write requires --assist",
            learning::LEARN_ASSIST_WRITE_REQUIRES_ASSIST
        ));
    }
    Ok(())
}

fn run_chained_replay_verify_report(
    paths: &StatePaths,
    learning_id: &str,
    run_id_override: Option<&str>,
    strict: bool,
) -> anyhow::Result<(String, bool)> {
    let source_run_id = if run_id_override.is_none() {
        let entry =
            learning::load_learning_entry(&paths.state_dir, learning_id).with_context(|| {
                format!("failed to load learning entry {learning_id} for chained replay verify")
            })?;
        entry.source.run_id
    } else {
        None
    };
    let run_id = if let Some(override_id) = run_id_override {
        override_id.to_string()
    } else if let Some(source_id) = source_run_id {
        source_id
    } else {
        return Err(anyhow!(
            "no source run_id on learning entry {}; pass --replay-verify-run-id",
            learning_id
        ));
    };
    let record = crate::store::load_run_record(&paths.state_dir, &run_id).map_err(|e| {
        anyhow!(
            "failed to load run '{}': {}. runs dir: {}",
            run_id,
            e,
            paths.runs_dir.display()
        )
    })?;
    let report = crate::repro::verify_run_record(&record, strict)?;
    let rendered = crate::repro::render_verify_report(&report);
    Ok((rendered, report.status == "fail"))
}

struct AssistedPreviewBuild {
    preview: learning::AssistedCapturePreview,
    output_truncated: bool,
}

async fn generate_assisted_capture_preview(
    cli_run: &RunArgs,
    input: &learning::CaptureLearningInput,
) -> anyhow::Result<AssistedPreviewBuild> {
    let provider_kind = cli_run.provider.ok_or_else(|| {
        anyhow!(
            "{}: --provider is required for assisted capture",
            learning::LEARN_ASSIST_PROVIDER_REQUIRED
        )
    })?;
    let model = cli_run.model.clone().ok_or_else(|| {
        anyhow!(
            "{}: --model is required for assisted capture",
            learning::LEARN_ASSIST_MODEL_REQUIRED
        )
    })?;
    let provider_name = crate::provider_runtime::provider_cli_name(provider_kind).to_string();
    let base_url = cli_run
        .base_url
        .clone()
        .unwrap_or_else(|| crate::provider_runtime::default_base_url(provider_kind).to_string());

    let canonical = learning::build_assist_capture_input_canonical(input);
    let canonical_json = serde_json::to_string_pretty(&canonical)?;
    let input_hash_hex = learning::compute_assist_input_hash_hex(&canonical)?;

    let raw = call_assist_model(cli_run, provider_kind, &base_url, &model, &canonical_json).await?;
    let raw_trimmed = raw.trim().to_string();
    let draft = learning::parse_assisted_capture_draft(&raw_trimmed);
    Ok(AssistedPreviewBuild {
        preview: learning::AssistedCapturePreview {
            provider: provider_name,
            model,
            prompt_version: learning::LEARN_ASSIST_PROMPT_VERSION_V1.to_string(),
            input_hash_hex,
            draft,
            raw_model_output: raw_trimmed,
        },
        output_truncated: false,
    })
}

async fn call_assist_model(
    cli_run: &RunArgs,
    provider_kind: crate::ProviderKind,
    base_url: &str,
    model: &str,
    canonical_json: &str,
) -> anyhow::Result<String> {
    let req = GenerateRequest {
        model: model.to_string(),
        messages: vec![
            Message {
                role: Role::System,
                content: Some("You draft a LocalAgent learning capture. Return a JSON object with optional keys: category, summary, guidance_text, check_text. Keep outputs concise.".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            Message {
                role: Role::User,
                content: Some(format!(
                    "Draft a learning capture from this canonical input JSON:\n{}",
                    canonical_json
                )),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
        ],
        tools: None,
    };

    let resp = match provider_kind {
        crate::ProviderKind::Lmstudio | crate::ProviderKind::Llamacpp => {
            let provider = crate::OpenAiCompatProvider::new(
                base_url.to_string(),
                cli_run.api_key.clone(),
                crate::provider_runtime::http_config_from_run_args(cli_run),
            )?;
            provider.generate(req).await?
        }
        crate::ProviderKind::Ollama => {
            let provider = crate::OllamaProvider::new(
                base_url.to_string(),
                crate::provider_runtime::http_config_from_run_args(cli_run),
            )?;
            provider.generate(req).await?
        }
        crate::ProviderKind::Mock => {
            let provider = crate::MockProvider::new();
            provider.generate(req).await?
        }
    };
    Ok(resp.assistant.content.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use clap::Parser;
    use tempfile::tempdir;

    use super::{parse_and_dispatch_learn_slash, split_shell_like};
    use crate::learning;

    fn sample_run_args() -> crate::RunArgs {
        crate::RunArgs::parse_from(["runargs", "--provider", "mock", "--model", "mock-model"])
    }

    fn collect_state_files(state_dir: &Path) -> BTreeSet<String> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
            if let Ok(rd) = fs::read_dir(dir) {
                for ent in rd.flatten() {
                    let path = ent.path();
                    if path.is_dir() {
                        walk(&path, root, out);
                    } else if path.is_file() {
                        out.insert(
                            path.strip_prefix(root)
                                .unwrap_or(&path)
                                .to_string_lossy()
                                .replace('\\', "/"),
                        );
                    }
                }
            }
        }
        let mut out = BTreeSet::new();
        if state_dir.exists() {
            walk(state_dir, state_dir, &mut out);
        }
        out
    }

    #[test]
    fn split_shell_like_handles_quotes_and_escapes() {
        let t = split_shell_like(r#"show "id with spaces" --format \"json\""#).expect("tokens");
        assert_eq!(
            t,
            vec![
                "show".to_string(),
                "id with spaces".to_string(),
                "--format".to_string(),
                "\"json\"".to_string()
            ]
        );
    }

    #[test]
    fn split_shell_like_rejects_unterminated_quote() {
        let err = split_shell_like(r#"show "unterminated"#).expect_err("must fail");
        assert!(err.to_string().contains("unterminated quote"));
    }

    #[tokio::test]
    async fn parse_and_dispatch_help_and_phase_b_guardrail_removed() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let run = sample_run_args();
        let help = parse_and_dispatch_learn_slash("/learn help", &run, &state_paths)
            .await
            .expect("help");
        assert!(help.contains("/learn list"));
    }

    #[tokio::test]
    async fn parse_and_dispatch_archive_updates_status() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let out = learning::capture_learning_entry(
            &state_paths.state_dir,
            learning::CaptureLearningInput {
                category: learning::LearningCategoryV1::PromptGuidance,
                summary: "summary".to_string(),
                ..learning::CaptureLearningInput::default()
            },
        )
        .expect("capture");
        let run = sample_run_args();
        let msg = parse_and_dispatch_learn_slash(
            &format!("/learn archive {}", out.entry.id),
            &run,
            &state_paths,
        )
        .await
        .expect("archive");
        assert!(msg.contains("Archived learning"));
        let updated =
            learning::load_learning_entry(&state_paths.state_dir, &out.entry.id).expect("load");
        assert_eq!(updated.status, learning::LearningStatusV1::Archived);
    }

    #[tokio::test]
    async fn capture_assist_preview_performs_zero_learn_writes() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let run = sample_run_args();
        let before = collect_state_files(&state_paths.state_dir);
        let output = parse_and_dispatch_learn_slash(
            r#"/learn capture --assist --category prompt-guidance --summary "hello world""#,
            &run,
            &state_paths,
        )
        .await
        .expect("assist preview");
        assert!(output.contains("ASSIST DRAFT PREVIEW"));
        let after = collect_state_files(&state_paths.state_dir);
        assert_eq!(before, after);
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn capture_assist_write_persists_entry_with_assist_metadata() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let run = sample_run_args();
        let output = parse_and_dispatch_learn_slash(
            r#"/learn capture --assist --write --category prompt-guidance --summary "hello world""#,
            &run,
            &state_paths,
        )
        .await
        .expect("assist write");
        assert!(output.contains("ASSIST DRAFT PREVIEW"));
        assert!(output.contains("Captured learning"));
        let entries = learning::list_learning_entries(&state_paths.state_dir).expect("list");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        let assist = e.assist.as_ref().expect("assist");
        assert!(assist.enabled);
        assert_eq!(assist.provider, "mock");
        assert_eq!(assist.model, "mock-model");
        assert_eq!(
            assist.prompt_version,
            learning::LEARN_ASSIST_PROMPT_VERSION_V1
        );
        assert!(!assist.input_hash_hex.is_empty());
    }

    #[tokio::test]
    async fn promote_check_passthrough_updates_status_and_writes_check() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut e = learning::capture_learning_entry(
            &state_paths.state_dir,
            learning::CaptureLearningInput {
                category: learning::LearningCategoryV1::CheckCandidate,
                summary: "Ensure success marker".to_string(),
                check_text: Some("Check body".to_string()),
                ..learning::CaptureLearningInput::default()
            },
        )
        .expect("capture")
        .entry;
        e.entry_hash_hex = learning::compute_entry_hash_hex(&e).expect("hash");
        crate::store::write_json_atomic(
            &learning::learning_entry_path(&state_paths.state_dir, &e.id),
            &e,
        )
        .expect("rewrite");
        let run = sample_run_args();
        let output = parse_and_dispatch_learn_slash(
            &format!("/learn promote {} --to check --slug tui_check", e.id),
            &run,
            &state_paths,
        )
        .await
        .expect("promote");
        assert!(output.contains("Promoted learning"));
        let updated = learning::load_learning_entry(&state_paths.state_dir, &e.id).expect("load");
        assert_eq!(updated.status, learning::LearningStatusV1::Promoted);
        assert!(state_paths
            .state_dir
            .join("checks")
            .join("tui_check.md")
            .exists());
    }

    #[tokio::test]
    async fn promote_check_passthrough_emits_expected_telemetry_receipt_shape() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let mut e = learning::capture_learning_entry(
            &state_paths.state_dir,
            learning::CaptureLearningInput {
                category: learning::LearningCategoryV1::CheckCandidate,
                summary: "Ensure telemetry event contract remains stable".to_string(),
                check_text: Some("Check body".to_string()),
                ..learning::CaptureLearningInput::default()
            },
        )
        .expect("capture")
        .entry;
        e.entry_hash_hex = learning::compute_entry_hash_hex(&e).expect("hash");
        crate::store::write_json_atomic(
            &learning::learning_entry_path(&state_paths.state_dir, &e.id),
            &e,
        )
        .expect("rewrite");
        let run = sample_run_args();
        let output = parse_and_dispatch_learn_slash(
            &format!("/learn promote {} --to check --slug tui_receipt", e.id),
            &run,
            &state_paths,
        )
        .await
        .expect("promote");
        assert!(output.contains("Promoted learning"));

        let events_path = learning::learning_events_path(&state_paths.state_dir);
        let raw = fs::read_to_string(events_path).expect("read events");
        let last = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .last()
            .expect("event line");
        let v: serde_json::Value = serde_json::from_str(last).expect("parse event");
        assert_eq!(v["kind"], "learning_promoted");
        assert_eq!(
            v["data"]["schema"],
            learning::LEARNING_PROMOTED_SCHEMA_V1
        );
        assert_eq!(v["data"]["learning_id"], e.id);
        assert_eq!(v["data"]["target"], "check");
        assert_eq!(v["data"]["slug"], "tui_receipt");
        assert!(v["data"]["target_file_sha256_hex"]
            .as_str()
            .unwrap_or("")
            .len()
            > 0);
    }

    #[tokio::test]
    async fn capture_assist_write_failure_does_not_emit_event() {
        let tmp = tempdir().expect("tempdir");
        let state_paths = crate::store::resolve_state_paths(tmp.path(), None, None, None, None);
        let entries_dir = learning::learning_entries_dir(&state_paths.state_dir);
        fs::create_dir_all(entries_dir.parent().expect("learn parent")).expect("mkdir");
        fs::write(&entries_dir, "poison").expect("poison entries dir");
        let run = sample_run_args();
        let err = parse_and_dispatch_learn_slash(
            r#"/learn capture --assist --write --category prompt-guidance --summary "will fail""#,
            &run,
            &state_paths,
        )
        .await
        .expect_err("must fail");
        assert!(err
            .to_string()
            .contains("failed to capture assisted learning entry"));
        assert!(!learning::learning_events_path(&state_paths.state_dir).exists());
    }
}
