use anyhow::{anyhow, Context};

use crate::cli_args::{LearnArgs, LearnCategoryArg, LearnSubcommand};
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
        LearnSubcommand::List { .. } => Err(anyhow!(
            "learn list is not implemented yet (PR1 in progress: capture/list/show)"
        )),
        LearnSubcommand::Show { .. } => Err(anyhow!(
            "learn show is not implemented yet (PR1 in progress: capture/list/show)"
        )),
    }
}
