use anyhow::{anyhow, Context};

use crate::cli_args::{
    LearnArgs, LearnCategoryArg, LearnPromoteTargetArg, LearnStatusArg, LearnSubcommand,
};
use crate::learning;
use crate::store::StatePaths;

pub(crate) async fn handle_learn_command(
    args: &LearnArgs,
    paths: &StatePaths,
) -> anyhow::Result<()> {
    match &args.command {
        LearnSubcommand::Capture {
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
        } => {
            let category = match category {
                LearnCategoryArg::WorkflowHint => learning::LearningCategoryV1::WorkflowHint,
                LearnCategoryArg::PromptGuidance => learning::LearningCategoryV1::PromptGuidance,
                LearnCategoryArg::CheckCandidate => learning::LearningCategoryV1::CheckCandidate,
            };
            let input = learning::build_capture_input(
                run.clone(),
                category,
                summary.clone(),
                task_summary.clone(),
                profile.clone(),
                guidance_text.clone(),
                check_text.clone(),
                tags.clone(),
                evidence.clone(),
                evidence_notes.clone(),
            );
            let out = learning::capture_learning_entry(&paths.state_dir, input)
                .context("failed to capture learning entry")?;
            learning::emit_learning_captured_event(&paths.state_dir, &out.entry)
                .context("failed to emit learning_captured event")?;
            println!("{}", learning::render_capture_confirmation(&out.entry));
            Ok(())
        }
        LearnSubcommand::List {
            statuses,
            categories,
            limit,
            show_archived,
            format,
        } => {
            let mut entries = learning::list_learning_entries(&paths.state_dir)
                .context("failed to list learning entries")?;
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
            let limit = *limit;
            if entries.len() > limit {
                entries.truncate(limit);
            }
            match format.as_str() {
                "table" => {
                    println!("{}", learning::render_learning_list_table(&entries));
                    Ok(())
                }
                "json" => {
                    println!(
                        "{}",
                        learning::render_learning_list_json_preview(&entries)
                            .context("failed to render learn list JSON preview")?
                    );
                    Ok(())
                }
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
            let entry = learning::load_learning_entry(&paths.state_dir, id)
                .with_context(|| format!("failed to load learning entry {id}"))?;
            match format.as_str() {
                "text" => {
                    println!(
                        "{}",
                        learning::render_learning_show_text(&entry, *show_evidence, *show_proposed)
                    );
                    Ok(())
                }
                "json" => {
                    println!(
                        "{}",
                        learning::render_learning_show_json_preview(
                            &entry,
                            *show_evidence,
                            *show_proposed
                        )
                        .context("failed to render learn show JSON preview")?
                    );
                    Ok(())
                }
                other => Err(anyhow!(
                    "unsupported learn show format '{other}' (expected text|json)"
                )),
            }
        }
        LearnSubcommand::Promote {
            id,
            to,
            slug,
            force,
        } => match to {
            LearnPromoteTargetArg::Check => {
                let out = learning::promote_learning_to_check(&paths.state_dir, id, slug, *force)
                    .with_context(|| {
                    format!("failed to promote learning entry {id} to check")
                })?;
                println!("{}", learning::render_promote_to_check_confirmation(&out));
                Ok(())
            }
        },
    }
}
