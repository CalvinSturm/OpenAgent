use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::events::{Event, EventKind, EventSink, JsonlFileSink};
use crate::store;

pub const LEARNING_ENTRY_SCHEMA_V1: &str = "openagent.learning_entry.v1";
const MAX_RUN_ID_CHARS: usize = 128;
const MAX_TASK_SUMMARY_CHARS: usize = 256;
const MAX_PROFILE_CHARS: usize = 128;
const MAX_SUMMARY_CHARS: usize = 512;
const MAX_GUIDANCE_TEXT_CHARS: usize = 2048;
const MAX_CHECK_TEXT_CHARS: usize = 4096;
const MAX_EVIDENCE_ITEMS: usize = 32;
const MAX_EVIDENCE_VALUE_CHARS: usize = 512;
const MAX_EVIDENCE_NOTE_CHARS: usize = 256;
const MAX_TAG_COUNT: usize = 16;
const MAX_TAG_CHARS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningEntryV1 {
    pub schema_version: String,
    pub id: String,
    pub created_at: String,
    pub source: LearningSourceV1,
    pub category: LearningCategoryV1,
    pub summary: String,
    pub evidence: Vec<EvidenceRefV1>,
    pub proposed_memory: ProposedMemoryV1,
    pub sensitivity_flags: SensitivityFlagsV1,
    pub status: LearningStatusV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncations: Vec<FieldTruncationV1>,
    pub entry_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LearningSourceV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LearningCategoryV1 {
    #[default]
    WorkflowHint,
    PromptGuidance,
    CheckCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRefV1 {
    pub kind: EvidenceKindV1,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKindV1 {
    RunId,
    EventId,
    ArtifactPath,
    ToolCallId,
    ReasonCode,
    ExitReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProposedMemoryV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SensitivityFlagsV1 {
    pub contains_paths: bool,
    pub contains_secrets_suspected: bool,
    pub contains_user_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningStatusV1 {
    Captured,
    Promoted,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldTruncationV1 {
    pub field: String,
    pub original_len: u32,
    pub truncated_to: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LearningEntryHashInputV1 {
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_profile: Option<String>,
    pub category: String,
    pub summary: String,
    pub evidence: Vec<EvidenceRefV1>,
    pub proposed_memory: ProposedMemoryV1,
    pub sensitivity_flags: SensitivityFlagsV1,
}

#[derive(Debug, Clone, Default)]
pub struct CaptureLearningInput {
    pub run_id: Option<String>,
    pub category: LearningCategoryV1,
    pub summary: String,
    pub task_summary: Option<String>,
    pub profile: Option<String>,
    pub guidance_text: Option<String>,
    pub check_text: Option<String>,
    pub tags: Vec<String>,
    pub evidence_specs: Vec<String>,
    pub evidence_notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CaptureLearningOutput {
    pub entry: LearningEntryV1,
}

pub fn capture_learning_entry(
    state_dir: &Path,
    input: CaptureLearningInput,
) -> anyhow::Result<CaptureLearningOutput> {
    let mut truncations = Vec::new();
    let id = Ulid::new().to_string();
    let created_at = crate::trust::now_rfc3339();
    let category = input.category;

    let source = LearningSourceV1 {
        run_id: input
            .run_id
            .map(|s| truncate_string(s, "source.run_id", MAX_RUN_ID_CHARS, &mut truncations)),
        task_summary: input.task_summary.map(|s| {
            truncate_string(
                s,
                "source.task_summary",
                MAX_TASK_SUMMARY_CHARS,
                &mut truncations,
            )
        }),
        profile: input
            .profile
            .map(|s| truncate_string(s, "source.profile", MAX_PROFILE_CHARS, &mut truncations)),
    };

    let summary = truncate_string(
        input.summary,
        "summary",
        MAX_SUMMARY_CHARS,
        &mut truncations,
    );

    let mut evidence = parse_evidence_specs(&input.evidence_specs, &mut truncations)?;
    attach_evidence_notes(&mut evidence, &input.evidence_notes, &mut truncations)?;

    let proposed_memory = build_proposed_memory(
        input.guidance_text,
        input.check_text,
        input.tags,
        &mut truncations,
    );

    let sensitivity_flags = infer_sensitivity_flags(&summary, &source, &evidence, &proposed_memory);

    let mut entry = LearningEntryV1 {
        schema_version: LEARNING_ENTRY_SCHEMA_V1.to_string(),
        id: id.clone(),
        created_at,
        source,
        category,
        summary,
        evidence,
        proposed_memory,
        sensitivity_flags,
        status: LearningStatusV1::Captured,
        truncations,
        entry_hash_hex: String::new(),
    };

    entry.entry_hash_hex = compute_entry_hash_hex(&entry)?;

    let path = learning_entry_path(state_dir, &id);
    store::write_json_atomic(&path, &entry)
        .with_context(|| format!("failed to write learning entry {}", path.display()))?;

    Ok(CaptureLearningOutput { entry })
}

pub fn emit_learning_captured_event(
    state_dir: &Path,
    entry: &LearningEntryV1,
) -> anyhow::Result<()> {
    let mut sink = JsonlFileSink::new(&learning_events_path(state_dir))?;
    let mut data = serde_json::json!({
        "schema": "openagent.learning_captured.v1",
        "learning_id": entry.id,
        "entry_hash_hex": entry.entry_hash_hex,
        "category": learning_category_str(&entry.category),
    });
    if let Some(run_id) = &entry.source.run_id {
        data["run_id"] = serde_json::Value::String(run_id.clone());
    }
    sink.emit(Event::new(
        format!("learn:{}", entry.id),
        0,
        EventKind::LearningCaptured,
        data,
    ))?;
    Ok(())
}

pub fn learning_entries_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("learn").join("entries")
}

pub fn learning_entry_path(state_dir: &Path, id: &str) -> PathBuf {
    learning_entries_dir(state_dir).join(format!("{id}.json"))
}

pub fn learning_events_path(state_dir: &Path) -> PathBuf {
    state_dir.join("learn").join("events.jsonl")
}

pub fn learning_entry_hash_input(entry: &LearningEntryV1) -> LearningEntryHashInputV1 {
    LearningEntryHashInputV1 {
        schema_version: entry.schema_version.clone(),
        source_run_id: entry.source.run_id.clone(),
        source_profile: entry.source.profile.clone(),
        category: learning_category_str(&entry.category).to_string(),
        summary: entry.summary.clone(),
        evidence: entry.evidence.clone(),
        proposed_memory: entry.proposed_memory.clone(),
        sensitivity_flags: entry.sensitivity_flags.clone(),
    }
}

pub fn compute_entry_hash_hex(entry: &LearningEntryV1) -> anyhow::Result<String> {
    let input = learning_entry_hash_input(entry);
    let bytes = serde_json::to_vec(&input)?;
    Ok(store::sha256_hex(&bytes))
}

fn parse_evidence_specs(
    specs: &[String],
    truncations: &mut Vec<FieldTruncationV1>,
) -> anyhow::Result<Vec<EvidenceRefV1>> {
    let mut out = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        if out.len() >= MAX_EVIDENCE_ITEMS {
            truncations.push(FieldTruncationV1 {
                field: "evidence".to_string(),
                original_len: specs.len() as u32,
                truncated_to: MAX_EVIDENCE_ITEMS as u32,
            });
            break;
        }
        let (kind_raw, value_raw) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid --evidence format (expected kind:value): {spec}"))?;
        if value_raw.is_empty() {
            return Err(anyhow!(
                "invalid --evidence format (missing value after kind:): {spec}"
            ));
        }
        let kind = parse_evidence_kind(kind_raw)?;
        out.push(EvidenceRefV1 {
            kind,
            value: truncate_string(
                value_raw.to_string(),
                &format!("evidence[{i}].value"),
                MAX_EVIDENCE_VALUE_CHARS,
                truncations,
            ),
            hash_hex: None,
            note: None,
        });
    }
    Ok(out)
}

fn parse_evidence_kind(raw: &str) -> anyhow::Result<EvidenceKindV1> {
    match raw {
        "run_id" => Ok(EvidenceKindV1::RunId),
        "event_id" => Ok(EvidenceKindV1::EventId),
        "artifact_path" => Ok(EvidenceKindV1::ArtifactPath),
        "tool_call_id" => Ok(EvidenceKindV1::ToolCallId),
        "reason_code" => Ok(EvidenceKindV1::ReasonCode),
        "exit_reason" => Ok(EvidenceKindV1::ExitReason),
        _ => Err(anyhow!("unknown --evidence kind '{raw}'")),
    }
}

fn attach_evidence_notes(
    evidence: &mut [EvidenceRefV1],
    notes: &[String],
    truncations: &mut Vec<FieldTruncationV1>,
) -> anyhow::Result<()> {
    if notes.is_empty() {
        return Ok(());
    }
    if evidence.is_empty() {
        return Err(anyhow!("--evidence-note requires a prior --evidence"));
    }
    if notes.len() > evidence.len() {
        return Err(anyhow!(
            "--evidence-note count ({}) exceeds --evidence count ({})",
            notes.len(),
            evidence.len()
        ));
    }
    for (idx, note) in notes.iter().enumerate() {
        evidence[idx].note = Some(truncate_string(
            note.clone(),
            &format!("evidence[{idx}].note"),
            MAX_EVIDENCE_NOTE_CHARS,
            truncations,
        ));
    }
    Ok(())
}

fn build_proposed_memory(
    guidance_text: Option<String>,
    check_text: Option<String>,
    tags: Vec<String>,
    truncations: &mut Vec<FieldTruncationV1>,
) -> ProposedMemoryV1 {
    let mut deduped = BTreeSet::new();
    let mut out_tags = Vec::new();
    for tag in tags {
        if out_tags.len() >= MAX_TAG_COUNT {
            truncations.push(FieldTruncationV1 {
                field: "proposed_memory.tags".to_string(),
                original_len: (out_tags.len() + 1) as u32,
                truncated_to: MAX_TAG_COUNT as u32,
            });
            break;
        }
        let normalized = truncate_string(
            tag,
            &format!("proposed_memory.tags[{}]", out_tags.len()),
            MAX_TAG_CHARS,
            truncations,
        );
        if deduped.insert(normalized.clone()) {
            out_tags.push(normalized);
        }
    }
    ProposedMemoryV1 {
        guidance_text: guidance_text.map(|s| {
            truncate_string(
                s,
                "proposed_memory.guidance_text",
                MAX_GUIDANCE_TEXT_CHARS,
                truncations,
            )
        }),
        check_text: check_text.map(|s| {
            truncate_string(
                s,
                "proposed_memory.check_text",
                MAX_CHECK_TEXT_CHARS,
                truncations,
            )
        }),
        tags: out_tags,
    }
}

fn infer_sensitivity_flags(
    summary: &str,
    source: &LearningSourceV1,
    evidence: &[EvidenceRefV1],
    proposed: &ProposedMemoryV1,
) -> SensitivityFlagsV1 {
    let mut text = String::new();
    text.push_str(summary);
    text.push('\n');
    if let Some(v) = &source.task_summary {
        text.push_str(v);
        text.push('\n');
    }
    if let Some(v) = &proposed.guidance_text {
        text.push_str(v);
        text.push('\n');
    }
    if let Some(v) = &proposed.check_text {
        text.push_str(v);
        text.push('\n');
    }
    for ev in evidence {
        text.push_str(&ev.value);
        text.push('\n');
        if let Some(note) = &ev.note {
            text.push_str(note);
            text.push('\n');
        }
    }
    let lower = text.to_ascii_lowercase();
    SensitivityFlagsV1 {
        contains_paths: text.contains('\\') || text.contains('/') || text.contains(":\\"),
        contains_secrets_suspected: lower.contains("begin private key")
            || lower.contains("ghp_")
            || lower.contains("github_pat_")
            || (lower.contains("aws") && lower.contains("secret")),
        contains_user_data: lower.contains("email") || lower.contains("phone"),
    }
}

fn truncate_string(
    s: String,
    field: &str,
    max_chars: usize,
    truncations: &mut Vec<FieldTruncationV1>,
) -> String {
    let original_len = s.chars().count();
    if original_len <= max_chars {
        return s;
    }
    let truncated: String = s.chars().take(max_chars).collect();
    truncations.push(FieldTruncationV1 {
        field: field.to_string(),
        original_len: original_len as u32,
        truncated_to: max_chars as u32,
    });
    truncated
}

pub fn learning_category_str(category: &LearningCategoryV1) -> &'static str {
    match category {
        LearningCategoryV1::WorkflowHint => "workflow_hint",
        LearningCategoryV1::PromptGuidance => "prompt_guidance",
        LearningCategoryV1::CheckCandidate => "check_candidate",
    }
}

pub fn render_capture_confirmation(entry: &LearningEntryV1) -> String {
    format!(
        "Captured learning {} (category={}, hash={})",
        entry.id,
        learning_category_str(&entry.category),
        entry.entry_hash_hex
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_capture_input(
    run: Option<String>,
    category: LearningCategoryV1,
    summary: String,
    task_summary: Option<String>,
    profile: Option<String>,
    guidance_text: Option<String>,
    check_text: Option<String>,
    tags: Vec<String>,
    evidence: Vec<String>,
    evidence_notes: Vec<String>,
) -> CaptureLearningInput {
    CaptureLearningInput {
        run_id: run,
        category,
        summary,
        task_summary,
        profile,
        guidance_text,
        check_text,
        tags,
        evidence_specs: evidence,
        evidence_notes,
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn sample_entry() -> LearningEntryV1 {
        LearningEntryV1 {
            schema_version: LEARNING_ENTRY_SCHEMA_V1.to_string(),
            id: "01JTESTENTRY".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            source: LearningSourceV1 {
                run_id: Some("run1".to_string()),
                task_summary: None,
                profile: Some("p".to_string()),
            },
            category: LearningCategoryV1::CheckCandidate,
            summary: "s".to_string(),
            evidence: vec![EvidenceRefV1 {
                kind: EvidenceKindV1::ReasonCode,
                value: "X".to_string(),
                hash_hex: None,
                note: None,
            }],
            proposed_memory: ProposedMemoryV1::default(),
            sensitivity_flags: SensitivityFlagsV1::default(),
            status: LearningStatusV1::Captured,
            truncations: Vec::new(),
            entry_hash_hex: String::new(),
        }
    }

    #[test]
    fn entry_hash_excludes_id_created_at_status() {
        let mut a = sample_entry();
        let mut b = sample_entry();
        a.id = "01JAAA".to_string();
        a.created_at = "2026-02-01T00:00:00Z".to_string();
        a.status = LearningStatusV1::Archived;
        b.id = "01JBBB".to_string();
        b.created_at = "2030-02-01T00:00:00Z".to_string();
        b.status = LearningStatusV1::Promoted;
        let ha = compute_entry_hash_hex(&a).expect("hash a");
        let hb = compute_entry_hash_hex(&b).expect("hash b");
        assert_eq!(ha, hb);
    }

    #[test]
    fn parse_evidence_specs_rejects_invalid() {
        let mut trunc = Vec::new();
        let err = parse_evidence_specs(&["bad".to_string()], &mut trunc).expect_err("invalid");
        assert!(err.to_string().contains("invalid --evidence format"));
    }

    #[test]
    fn capture_writes_under_learning_entries() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let out = capture_learning_entry(
            &state_dir,
            CaptureLearningInput {
                category: LearningCategoryV1::WorkflowHint,
                summary: "hello".to_string(),
                ..CaptureLearningInput::default()
            },
        )
        .expect("capture");
        let path = learning_entry_path(&state_dir, &out.entry.id);
        assert!(path.starts_with(state_dir.join("learn").join("entries")));
        assert!(path.exists());
    }

    #[test]
    fn truncation_metadata_recorded() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let long = "x".repeat(MAX_SUMMARY_CHARS + 10);
        let out = capture_learning_entry(
            &state_dir,
            CaptureLearningInput {
                category: LearningCategoryV1::PromptGuidance,
                summary: long,
                ..CaptureLearningInput::default()
            },
        )
        .expect("capture");
        assert!(out.entry.summary.len() <= MAX_SUMMARY_CHARS);
        assert!(out
            .entry
            .truncations
            .iter()
            .any(|t| t.field == "summary" && t.truncated_to == MAX_SUMMARY_CHARS as u32));
    }

    #[test]
    fn evidence_notes_require_evidence() {
        let mut evidence = Vec::<EvidenceRefV1>::new();
        let mut trunc = Vec::new();
        let err = attach_evidence_notes(&mut evidence, &["n".to_string()], &mut trunc)
            .expect_err("note without evidence");
        assert!(err
            .to_string()
            .contains("--evidence-note requires a prior --evidence"));
    }
}
