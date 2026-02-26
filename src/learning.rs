use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, Context};
use regex::Regex;
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
const LIST_SUMMARY_PREVIEW_CHARS: usize = 96;
const LEARN_SHOW_MAX_BYTES: usize = 8 * 1024;
const MAX_REDACTIONS_IN_DISPLAY: usize = 3;
const MAX_SCAN_BUNDLE_BYTES: usize = 64 * 1024;
const REDACTED_SECRET_TOKEN: &str = "[REDACTED_SECRET]";
#[allow(dead_code)]
pub const LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE: &str = "LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE";
#[allow(dead_code)]
pub const LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE: &str =
    "LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE";
#[allow(dead_code)]
pub const LEARN_PROMOTE_INVALID_SLUG: &str = "LEARN_PROMOTE_INVALID_SLUG";
pub const LEARNING_PROMOTED_SCHEMA_V1: &str = "openagent.learning_promoted.v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum LearningPromoteError {
    SensitiveRequiresForce,
    TargetExistsRequiresForce,
    InvalidSlug,
}

impl LearningPromoteError {
    #[allow(dead_code)]
    pub fn code(&self) -> &'static str {
        match self {
            LearningPromoteError::SensitiveRequiresForce => LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE,
            LearningPromoteError::TargetExistsRequiresForce => {
                LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE
            }
            LearningPromoteError::InvalidSlug => LEARN_PROMOTE_INVALID_SLUG,
        }
    }
}

impl std::fmt::Display for LearningPromoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LearningPromoteError::SensitiveRequiresForce => write!(
                f,
                "Sensitive content suspected (contains_secrets_suspected). Re-run with --force to promote."
            ),
            LearningPromoteError::TargetExistsRequiresForce => write!(
                f,
                "Promotion target already exists. Re-run with --force to overwrite."
            ),
            LearningPromoteError::InvalidSlug => write!(
                f,
                "Invalid slug. Use lowercase letters, numbers, '_' or '-', no path separators."
            ),
        }
    }
}

impl std::error::Error for LearningPromoteError {}

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

#[derive(Debug, Clone)]
pub struct PromoteToCheckResult {
    pub learning_id: String,
    pub slug: String,
    pub target_path: PathBuf,
    pub target_file_sha256_hex: String,
    pub forced: bool,
    pub entry_hash_hex: String,
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

pub fn promote_learning_to_check(
    state_dir: &Path,
    id: &str,
    slug: &str,
    force: bool,
) -> anyhow::Result<PromoteToCheckResult> {
    validate_promote_slug(slug)?;
    let mut entry = load_learning_entry(state_dir, id)?;
    require_force_for_sensitive_promotion(&entry, force)?;

    let target_path = learning_check_path(state_dir, slug);
    if target_path.exists() && !force {
        return Err(LearningPromoteError::TargetExistsRequiresForce.into());
    }

    let markdown = render_learning_to_check_markdown(&entry, slug)?;
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create check dir {}", parent.display()))?;
    }
    fs::write(&target_path, markdown.as_bytes())
        .with_context(|| format!("failed to write check file {}", target_path.display()))?;
    let target_file_sha256_hex = compute_file_sha256_hex(&target_path)?;

    update_learning_status(state_dir, &mut entry, LearningStatusV1::Promoted)?;
    emit_learning_promoted_event_for_check(
        state_dir,
        &entry,
        slug,
        &target_path,
        force,
        &target_file_sha256_hex,
    )?;

    Ok(PromoteToCheckResult {
        learning_id: entry.id.clone(),
        slug: slug.to_string(),
        target_path,
        target_file_sha256_hex,
        forced: force,
        entry_hash_hex: entry.entry_hash_hex.clone(),
    })
}

pub fn render_promote_to_check_confirmation(out: &PromoteToCheckResult) -> String {
    format!(
        "Promoted learning {} -> check {} (path={}, hash={}, entry_hash={}, forced={})",
        out.learning_id,
        out.slug,
        out.target_path.display(),
        out.target_file_sha256_hex,
        out.entry_hash_hex,
        out.forced
    )
}

pub fn render_learning_to_check_markdown(
    entry: &LearningEntryV1,
    slug: &str,
) -> anyhow::Result<String> {
    let fm = build_generated_check_from_learning(entry, slug);
    crate::checks::schema::validate_frontmatter(&fm)?;

    let name = serde_json::to_string(&fm.name)?;
    let description = serde_json::to_string(fm.description.as_deref().unwrap_or(""))?;
    let pass_value = serde_json::to_string(&fm.pass_criteria.value)?;
    let pass_kind = match fm.pass_criteria.kind {
        crate::checks::schema::PassCriteriaType::Contains => "output_contains",
        crate::checks::schema::PassCriteriaType::NotContains => "output_not_contains",
        crate::checks::schema::PassCriteriaType::Equals => "output_equals",
    };

    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("schema_version: {}\n", fm.schema_version));
    out.push_str(&format!("name: {name}\n"));
    out.push_str(&format!("description: {description}\n"));
    out.push_str(&format!("required: {}\n", fm.required));
    out.push_str("allowed_tools: []\n");
    out.push_str("pass_criteria:\n");
    out.push_str(&format!("  type: {pass_kind}\n"));
    out.push_str(&format!("  value: {pass_value}\n"));
    out.push_str("---\n");
    out.push_str(&render_generated_check_body(entry, slug));
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out.replace("\r\n", "\n").replace('\r', "\n"))
}

fn build_generated_check_from_learning(
    entry: &LearningEntryV1,
    slug: &str,
) -> crate::checks::schema::CheckFrontmatter {
    let summary_one_line = entry
        .summary
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let description = if summary_one_line.is_empty() {
        format!("Learned check candidate from learning {}", entry.id)
    } else {
        truncate_utf8_chars(&summary_one_line, 240)
    };
    crate::checks::schema::CheckFrontmatter {
        schema_version: 1,
        name: format!("learn_{slug}"),
        description: Some(description),
        required: false,
        allowed_tools: Some(vec![]),
        required_flags: Vec::new(),
        pass_criteria: crate::checks::schema::PassCriteria {
            kind: crate::checks::schema::PassCriteriaType::Contains,
            value: "TODO".to_string(),
        },
        budget: None,
    }
}

fn render_generated_check_body(entry: &LearningEntryV1, slug: &str) -> String {
    if let Some(text) = &entry.proposed_memory.check_text {
        let normalized = normalize_newlines(text);
        if !normalized.trim().is_empty() {
            return normalized;
        }
    }

    let mut out = String::new();
    out.push_str("# Learned Check Draft\n\n");
    out.push_str(&format!("Learning ID: {}\n", entry.id));
    out.push_str(&format!("Slug: {slug}\n\n"));
    out.push_str("Summary:\n");
    out.push_str(&normalize_newlines(&entry.summary));
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("\nTODO: Replace this placeholder with concrete check instructions and pass criteria evidence expectations.\n");
    out
}

fn update_learning_status(
    state_dir: &Path,
    entry: &mut LearningEntryV1,
    status: LearningStatusV1,
) -> anyhow::Result<()> {
    entry.status = status;
    write_learning_entry(state_dir, entry)
}

fn write_learning_entry(state_dir: &Path, entry: &LearningEntryV1) -> anyhow::Result<()> {
    let path = learning_entry_path(state_dir, &entry.id);
    store::write_json_atomic(&path, entry)
        .with_context(|| format!("failed to write learning entry {}", path.display()))
}

fn compute_file_sha256_hex(path: &Path) -> anyhow::Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read file {}", path.display()))?;
    Ok(store::sha256_hex(&bytes))
}

fn emit_learning_promoted_event_for_check(
    state_dir: &Path,
    entry: &LearningEntryV1,
    slug: &str,
    target_path: &Path,
    forced: bool,
    target_file_sha256_hex: &str,
) -> anyhow::Result<()> {
    let mut sink = JsonlFileSink::new(&learning_events_path(state_dir))?;
    let data = serde_json::json!({
        "schema": LEARNING_PROMOTED_SCHEMA_V1,
        "learning_id": entry.id,
        "entry_hash_hex": entry.entry_hash_hex,
        "target": "check",
        "target_path": stable_learning_target_path(state_dir, target_path),
        "slug": slug,
        "forced": forced,
        "target_file_sha256_hex": target_file_sha256_hex,
    });
    sink.emit(Event::new(
        format!("learn:{}", entry.id),
        0,
        EventKind::LearningPromoted,
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

fn learning_check_path(state_dir: &Path, slug: &str) -> PathBuf {
    state_dir.join("checks").join(format!("{slug}.md"))
}

pub fn load_learning_entry(state_dir: &Path, id: &str) -> anyhow::Result<LearningEntryV1> {
    let path = learning_entry_path(state_dir, id);
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read learning entry {}", path.display()))?;
    let entry: LearningEntryV1 = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse learning entry {}", path.display()))?;
    if entry.id != id {
        return Err(anyhow!(
            "learning entry id mismatch for {} (file id={}, entry id={})",
            path.display(),
            id,
            entry.id
        ));
    }
    Ok(entry)
}

pub fn list_learning_entries(state_dir: &Path) -> anyhow::Result<Vec<LearningEntryV1>> {
    let dir = learning_entries_dir(state_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for ent in fs::read_dir(&dir)
        .with_context(|| format!("failed to read learning entries dir {}", dir.display()))?
    {
        let ent = ent?;
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        paths.push(path);
    }
    paths.sort_by(|a, b| {
        a.file_name()
            .and_then(|s| s.to_str())
            .cmp(&b.file_name().and_then(|s| s.to_str()))
    });
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read learning entry {}", path.display()))?;
        let entry: LearningEntryV1 = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse learning entry {}", path.display()))?;
        out.push(entry);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
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
    let text = build_sensitivity_scan_bundle(summary, source, evidence, proposed);
    SensitivityFlagsV1 {
        contains_paths: detect_contains_paths(&text),
        contains_secrets_suspected: detect_contains_secrets_suspected(&text),
        contains_user_data: false,
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

pub fn render_learning_list_table(entries: &[LearningEntryV1]) -> String {
    let mut out = String::new();
    out.push_str("ID  STATUS  CATEGORY  RUN_ID  S  SUMMARY\n");
    for e in entries {
        let run_id = e.source.run_id.as_deref().unwrap_or("-");
        let sensitive = if has_any_sensitivity(&e.sensitivity_flags) {
            "!"
        } else {
            "-"
        };
        let summary = preview_text(&e.summary, LIST_SUMMARY_PREVIEW_CHARS);
        let summary = redact_and_bound_terminal_output(&summary, 512);
        out.push_str(&format!(
            "{}  {}  {}  {}  {}  {}\n",
            e.id,
            learning_status_str(&e.status),
            learning_category_str(&e.category),
            run_id,
            sensitive,
            summary
        ));
    }
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

pub fn render_learning_list_json_preview(entries: &[LearningEntryV1]) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec_pretty(entries)?;
    Ok(redact_and_bound_terminal_output(
        &String::from_utf8_lossy(&bytes),
        LEARN_SHOW_MAX_BYTES,
    ))
}

pub fn render_learning_show_text(
    entry: &LearningEntryV1,
    show_evidence: bool,
    show_proposed: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("id: {}\n", entry.id));
    out.push_str(&format!("status: {}\n", learning_status_str(&entry.status)));
    out.push_str(&format!(
        "category: {}\n",
        learning_category_str(&entry.category)
    ));
    out.push_str(&format!("hash: {}\n", entry.entry_hash_hex));
    out.push_str(&format!("created_at: {}\n", entry.created_at));
    out.push_str("source:\n");
    out.push_str(&format!(
        "  run_id: {}\n",
        entry.source.run_id.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "  task_summary: {}\n",
        entry.source.task_summary.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!(
        "  profile: {}\n",
        entry.source.profile.as_deref().unwrap_or("-")
    ));
    out.push_str("summary:\n");
    out.push_str(&entry.summary);
    out.push('\n');
    out.push_str("sensitivity:\n");
    out.push_str(&format!(
        "  contains_paths: {}\n  contains_secrets_suspected: {}\n  contains_user_data: {}\n",
        entry.sensitivity_flags.contains_paths,
        entry.sensitivity_flags.contains_secrets_suspected,
        entry.sensitivity_flags.contains_user_data
    ));
    if show_evidence {
        out.push_str("evidence:\n");
        if entry.evidence.is_empty() {
            out.push_str("  - none\n");
        } else {
            for ev in &entry.evidence {
                out.push_str(&format!(
                    "  - {}: {}\n",
                    evidence_kind_str(&ev.kind),
                    ev.value
                ));
                if let Some(hash) = &ev.hash_hex {
                    out.push_str(&format!("    hash_hex: {}\n", hash));
                }
                if let Some(note) = &ev.note {
                    out.push_str(&format!("    note: {}\n", note));
                }
            }
        }
    }
    if show_proposed {
        out.push_str("proposed_memory:\n");
        out.push_str(&format!(
            "  guidance_text: {}\n",
            entry
                .proposed_memory
                .guidance_text
                .as_deref()
                .unwrap_or("-")
        ));
        out.push_str(&format!(
            "  check_text: {}\n",
            entry.proposed_memory.check_text.as_deref().unwrap_or("-")
        ));
        out.push_str(&format!(
            "  tags: {}\n",
            if entry.proposed_memory.tags.is_empty() {
                "-".to_string()
            } else {
                entry.proposed_memory.tags.join(", ")
            }
        ));
    }
    if !entry.truncations.is_empty() {
        out.push_str("truncations:\n");
        for t in &entry.truncations {
            out.push_str(&format!(
                "  - {}: {} -> {}\n",
                t.field, t.original_len, t.truncated_to
            ));
        }
    }
    redact_and_bound_terminal_output(&out, LEARN_SHOW_MAX_BYTES)
}

pub fn render_learning_show_json_preview(
    entry: &LearningEntryV1,
    show_evidence: bool,
    show_proposed: bool,
) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(entry)?;
    if !show_evidence {
        value["evidence"] = serde_json::json!([]);
    }
    if !show_proposed {
        value["proposed_memory"] = serde_json::json!({});
    }
    let bytes = serde_json::to_vec_pretty(&value)?;
    Ok(redact_and_bound_terminal_output(
        &String::from_utf8_lossy(&bytes),
        LEARN_SHOW_MAX_BYTES,
    ))
}

fn has_any_sensitivity(flags: &SensitivityFlagsV1) -> bool {
    flags.contains_paths || flags.contains_secrets_suspected || flags.contains_user_data
}

fn learning_status_str(status: &LearningStatusV1) -> &'static str {
    match status {
        LearningStatusV1::Captured => "captured",
        LearningStatusV1::Promoted => "promoted",
        LearningStatusV1::Archived => "archived",
    }
}

fn evidence_kind_str(kind: &EvidenceKindV1) -> &'static str {
    match kind {
        EvidenceKindV1::RunId => "run_id",
        EvidenceKindV1::EventId => "event_id",
        EvidenceKindV1::ArtifactPath => "artifact_path",
        EvidenceKindV1::ToolCallId => "tool_call_id",
        EvidenceKindV1::ReasonCode => "reason_code",
        EvidenceKindV1::ExitReason => "exit_reason",
    }
}

fn preview_text(text: &str, max_chars: usize) -> String {
    let mut s: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        s.push_str("...");
    }
    s
}

fn redact_and_bound_terminal_output(input: &str, max_bytes: usize) -> String {
    let redacted = redact_secrets_for_display(input);
    truncate_utf8_bytes(redacted, max_bytes)
}

fn redact_secrets_for_display(input: &str) -> String {
    let mut matches = collect_secret_matches(input);
    matches.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
    let mut chosen = Vec::new();
    for m in matches {
        if chosen.len() >= MAX_REDACTIONS_IN_DISPLAY {
            break;
        }
        let overlaps = chosen
            .last()
            .map(|prev: &MatchRange| m.start < prev.end)
            .unwrap_or(false);
        if overlaps {
            continue;
        }
        chosen.push(m);
    }
    if chosen.is_empty() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    for m in chosen {
        out.push_str(&input[cursor..m.start]);
        out.push_str(REDACTED_SECRET_TOKEN);
        cursor = m.end;
    }
    out.push_str(&input[cursor..]);
    out
}

#[derive(Debug, Clone, Copy)]
struct MatchRange {
    start: usize,
    end: usize,
}

fn build_sensitivity_scan_bundle(
    summary: &str,
    source: &LearningSourceV1,
    evidence: &[EvidenceRefV1],
    proposed: &ProposedMemoryV1,
) -> String {
    let mut out = String::new();
    out.push_str("summary:\n");
    out.push_str(summary);
    out.push_str("\n\n");
    out.push_str("task_summary:\n");
    out.push_str(source.task_summary.as_deref().unwrap_or(""));
    out.push_str("\n\n");
    out.push_str("guidance_text:\n");
    out.push_str(proposed.guidance_text.as_deref().unwrap_or(""));
    out.push_str("\n\n");
    out.push_str("check_text:\n");
    out.push_str(proposed.check_text.as_deref().unwrap_or(""));
    out.push_str("\n\n");
    out.push_str("evidence:\n");
    for ev in evidence {
        out.push_str("- value: ");
        out.push_str(&ev.value);
        out.push('\n');
        if let Some(note) = &ev.note {
            out.push_str("  note: ");
            out.push_str(note);
            out.push('\n');
        }
    }
    truncate_utf8_bytes(out, MAX_SCAN_BUNDLE_BYTES)
}

fn detect_contains_secrets_suspected(text: &str) -> bool {
    secret_detection_patterns()
        .iter()
        .any(|re| re.find(text).is_some())
}

fn detect_contains_paths(text: &str) -> bool {
    if windows_path_pattern().is_match(text) {
        return true;
    }
    unix_path_pattern().is_match(text) || text.contains("~/")
}

fn validate_promote_slug(slug: &str) -> anyhow::Result<()> {
    if slug.is_empty()
        || slug.contains("..")
        || slug.contains('/')
        || slug.contains('\\')
        || slug.contains(':')
    {
        return Err(LearningPromoteError::InvalidSlug.into());
    }
    if !promote_slug_pattern().is_match(slug) {
        return Err(LearningPromoteError::InvalidSlug.into());
    }
    Ok(())
}

fn promote_slug_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,63}$").expect("promote slug regex"))
}

fn collect_secret_matches(input: &str) -> Vec<MatchRange> {
    let mut out = Vec::new();
    for re in secret_detection_patterns() {
        for m in re.find_iter(input) {
            out.push(MatchRange {
                start: m.start(),
                end: m.end(),
            });
        }
    }
    out
}

fn secret_detection_patterns() -> &'static [Regex] {
    static PATS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            Regex::new(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY").expect("private key regex"),
            Regex::new(r"ghp_[A-Za-z0-9]{20,}").expect("ghp regex"),
            Regex::new(r"github_pat_[A-Za-z0-9_]{20,}").expect("github pat regex"),
            Regex::new(r"AKIA[0-9A-Z]{16}").expect("aws akia regex"),
            Regex::new(r"ASIA[0-9A-Z]{16}").expect("aws asia regex"),
        ]
    })
}

fn windows_path_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|[^A-Za-z0-9_])[A-Za-z]:\\").expect("windows path regex"))
}

fn unix_path_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?m)(?:^|[\s"'(\[{])/(?:home|Users|etc|var)/"#).expect("unix path regex")
    })
}

#[allow(dead_code)]
pub fn require_force_for_sensitive_promotion(
    entry: &LearningEntryV1,
    force: bool,
) -> anyhow::Result<()> {
    if entry.sensitivity_flags.contains_secrets_suspected && !force {
        return Err(LearningPromoteError::SensitiveRequiresForce.into());
    }
    Ok(())
}

fn stable_forward_slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn stable_learning_target_path(state_dir: &Path, target_path: &Path) -> String {
    let base = state_dir.parent().unwrap_or(state_dir);
    let rel = target_path.strip_prefix(base).unwrap_or(target_path);
    stable_forward_slash_path(rel)
}

fn normalize_newlines(input: &str) -> String {
    input.replace("\r\n", "\n").replace('\r', "\n")
}

fn truncate_utf8_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn truncate_utf8_bytes(input: String, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input;
    }
    let suffix = "\n...[truncated]";
    let mut end = max_bytes.saturating_sub(suffix.len()).min(input.len());
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    if out.len() < input.len() {
        out.push_str(suffix);
    }
    out
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
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

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

    fn write_entry(state_dir: &Path, mut entry: LearningEntryV1) {
        if entry.entry_hash_hex.is_empty() {
            entry.entry_hash_hex = compute_entry_hash_hex(&entry).expect("hash");
        }
        let path = learning_entry_path(state_dir, &entry.id);
        store::write_json_atomic(&path, &entry).expect("write entry");
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

    #[test]
    fn list_learning_entries_sorts_by_id() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut a = sample_entry();
        a.id = "01JZZZ".to_string();
        let mut b = sample_entry();
        b.id = "01JAAA".to_string();
        write_entry(&state_dir, a);
        write_entry(&state_dir, b);
        let entries = list_learning_entries(&state_dir).expect("list");
        let ids = entries.into_iter().map(|e| e.id).collect::<Vec<_>>();
        assert_eq!(ids, vec!["01JAAA".to_string(), "01JZZZ".to_string()]);
    }

    #[test]
    fn load_learning_entry_unknown_id_errors() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let err = load_learning_entry(&state_dir, "01JNOPE").expect_err("missing");
        assert!(err.to_string().contains("failed to read learning entry"));
    }

    #[test]
    fn learn_show_redacts_and_bounds_output() {
        let mut e = sample_entry();
        e.summary = format!(
            "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234 and {}",
            "x".repeat(20_000)
        );
        let out = render_learning_show_text(&e, true, true);
        assert!(out.contains(REDACTED_SECRET_TOKEN));
        assert!(!out.contains("ghp_"));
        assert!(out.len() <= LEARN_SHOW_MAX_BYTES + "\n...[truncated]".len());
    }

    #[test]
    fn list_table_preview_is_bounded() {
        let mut e = sample_entry();
        e.summary = "x".repeat(300);
        let out = render_learning_list_table(&[e]);
        assert!(out.contains("..."));
    }

    #[test]
    fn list_show_do_not_modify_files() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let e = sample_entry();
        write_entry(&state_dir, e);
        let before = fs::read_dir(learning_entries_dir(&state_dir))
            .expect("read_dir")
            .map(|r| r.expect("dirent").file_name().to_string_lossy().to_string())
            .collect::<BTreeSet<_>>();
        let entries = list_learning_entries(&state_dir).expect("list");
        let _ = render_learning_list_json_preview(&entries).expect("list json");
        let loaded = load_learning_entry(&state_dir, &entries[0].id).expect("load");
        let _ = render_learning_show_json_preview(&loaded, true, true).expect("show json");
        let after = fs::read_dir(learning_entries_dir(&state_dir))
            .expect("read_dir")
            .map(|r| r.expect("dirent").file_name().to_string_lossy().to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(before, after);
    }

    #[test]
    fn sensitivity_detects_private_key_and_tokens_case_sensitive() {
        let flags = detect_contains_secrets_suspected("BEGIN PRIVATE KEY");
        assert!(flags);
        assert!(!detect_contains_secrets_suspected("Begin Private Key"));
        assert!(detect_contains_secrets_suspected(
            "x ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234 y"
        ));
        assert!(detect_contains_secrets_suspected(
            "github_pat_abcdefghijklmnopqrstuvwxyz_1234567890"
        ));
    }

    #[test]
    fn sensitivity_detects_paths_but_not_urls() {
        assert!(detect_contains_paths(r"C:\Users\Calvin\project"));
        assert!(detect_contains_paths("/home/calvin/project"));
        assert!(!detect_contains_paths("https://example.com/var/test"));
    }

    #[test]
    fn redaction_replaces_non_overlapping_left_to_right_with_cap() {
        let input = concat!(
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234 ",
            "github_pat_abcdefghijklmnopqrstuvwxyz_1234567890 ",
            "BEGIN PRIVATE KEY ",
            "AKIAABCDEFGHIJKLMNOP ",
            "ASIAABCDEFGHIJKLMNOP"
        );
        let out = redact_secrets_for_display(input);
        assert_eq!(
            out.matches(REDACTED_SECRET_TOKEN).count(),
            MAX_REDACTIONS_IN_DISPLAY
        );
        assert!(!out.contains("ghp_"));
        assert!(!out.contains("github_pat_"));
        assert!(!out.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn promotion_gating_requires_force_for_sensitive_entries() {
        let mut e = sample_entry();
        e.sensitivity_flags.contains_secrets_suspected = true;
        let err = require_force_for_sensitive_promotion(&e, false).expect_err("must fail");
        let typed = err
            .downcast_ref::<LearningPromoteError>()
            .expect("typed learning promote error");
        assert_eq!(typed.code(), "LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE");
        require_force_for_sensitive_promotion(&e, true).expect("force should pass");
        e.sensitivity_flags.contains_secrets_suspected = false;
        require_force_for_sensitive_promotion(&e, false).expect("non-sensitive should pass");
    }

    #[test]
    fn capture_persists_sensitivity_flags_from_secret_patterns() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let out = capture_learning_entry(
            &state_dir,
            CaptureLearningInput {
                category: LearningCategoryV1::PromptGuidance,
                summary: "Contains ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234".to_string(),
                ..CaptureLearningInput::default()
            },
        )
        .expect("capture");
        assert!(out.entry.sensitivity_flags.contains_secrets_suspected);
    }

    #[test]
    fn build_sensitivity_scan_bundle_is_bounded() {
        let summary = "x".repeat(MAX_SCAN_BUNDLE_BYTES * 2);
        let bundle = build_sensitivity_scan_bundle(
            &summary,
            &LearningSourceV1::default(),
            &[],
            &ProposedMemoryV1::default(),
        );
        assert!(bundle.len() <= MAX_SCAN_BUNDLE_BYTES + "\n...[truncated]".len());
    }

    fn sample_check_candidate_learning_entry() -> LearningEntryV1 {
        let mut e = sample_entry();
        e.id = "01JPR3ENTRY".to_string();
        e.summary = "Ensure output includes success marker".to_string();
        e.proposed_memory.check_text = Some("Check body line 1\nCheck body line 2\n".to_string());
        e
    }

    fn read_learning_events_lines(state_dir: &Path) -> Vec<String> {
        let path = learning_events_path(state_dir);
        if !path.exists() {
            return Vec::new();
        }
        fs::read_to_string(path)
            .expect("read events")
            .lines()
            .map(|s| s.to_string())
            .collect()
    }

    fn collect_state_files(state_dir: &Path) -> BTreeSet<String> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
            if let Ok(rd) = fs::read_dir(dir) {
                for ent in rd.flatten() {
                    let path = ent.path();
                    if path.is_dir() {
                        walk(&path, root, out);
                    } else if path.is_file() {
                        let rel = path
                            .strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .replace('\\', "/");
                        out.insert(rel);
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
    fn render_learning_to_check_markdown_is_deterministic_and_canonical() {
        let e = sample_check_candidate_learning_entry();
        let a = render_learning_to_check_markdown(&e, "my_check").expect("render a");
        let b = render_learning_to_check_markdown(&e, "my_check").expect("render b");
        assert_eq!(a, b);
        assert!(a.contains("\nallowed_tools: []\n"));
        assert!(a.ends_with('\n'));
        assert!(!a.contains("\r\n"));
        let i_schema = a.find("schema_version: 1\n").expect("schema");
        let i_name = a.find("\nname: ").expect("name");
        let i_desc = a.find("\ndescription: ").expect("desc");
        let i_required = a.find("\nrequired: false\n").expect("required");
        let i_allowed = a.find("\nallowed_tools: []\n").expect("allowed");
        let i_pass = a.find("\npass_criteria:\n").expect("pass");
        assert!(i_schema < i_name);
        assert!(i_name < i_desc);
        assert!(i_desc < i_required);
        assert!(i_required < i_allowed);
        assert!(i_allowed < i_pass);
        assert!(!a.contains("\nrequired_flags:"));
        assert!(!a.contains("\nbudget:"));
    }

    #[test]
    fn promote_to_check_creates_target_file_and_updates_status() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        let out = promote_learning_to_check(&state_dir, &e.id, "my_check", false).expect("promote");
        assert_eq!(out.slug, "my_check");
        assert!(out.target_path.exists());

        let updated = load_learning_entry(&state_dir, &e.id).expect("load updated");
        assert_eq!(updated.status, LearningStatusV1::Promoted);
    }

    #[test]
    fn promote_to_check_enforces_sensitive_requires_force() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.sensitivity_flags.contains_secrets_suspected = true;
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        let err = promote_learning_to_check(&state_dir, &e.id, "secure_check", false)
            .expect_err("must fail");
        let typed = err
            .downcast_ref::<LearningPromoteError>()
            .expect("typed promote error");
        assert_eq!(typed.code(), LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE);

        let ok = promote_learning_to_check(&state_dir, &e.id, "secure_check", true);
        assert!(ok.is_ok());
    }

    #[test]
    fn promote_to_check_enforces_overwrite_requires_force() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());
        let target = learning_check_path(&state_dir, "dup");
        fs::create_dir_all(target.parent().expect("parent")).expect("mkdirs");
        fs::write(&target, "existing").expect("seed target");

        let err =
            promote_learning_to_check(&state_dir, &e.id, "dup", false).expect_err("must fail");
        let typed = err
            .downcast_ref::<LearningPromoteError>()
            .expect("typed promote error");
        assert_eq!(typed.code(), LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE);

        promote_learning_to_check(&state_dir, &e.id, "dup", true).expect("overwrite promote");
        let body = fs::read_to_string(&target).expect("read target");
        assert!(body.contains("allowed_tools: []"));
    }

    #[test]
    fn promote_to_check_rejects_invalid_slug_with_stable_code() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        let err = promote_learning_to_check(&state_dir, &e.id, "../bad", false)
            .expect_err("invalid slug");
        let typed = err
            .downcast_ref::<LearningPromoteError>()
            .expect("typed promote error");
        assert_eq!(typed.code(), LEARN_PROMOTE_INVALID_SLUG);
    }

    #[test]
    fn promote_to_check_emits_learning_promoted_event_with_target_file_hash() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        let out =
            promote_learning_to_check(&state_dir, &e.id, "event_check", false).expect("promote");
        let lines = read_learning_events_lines(&state_dir);
        let last = lines.last().expect("event line");
        let v: serde_json::Value = serde_json::from_str(last).expect("parse event");
        assert_eq!(v["kind"], "learning_promoted");
        assert_eq!(v["data"]["schema"], LEARNING_PROMOTED_SCHEMA_V1);
        assert_eq!(v["data"]["learning_id"], e.id);
        assert_eq!(v["data"]["target"], "check");
        assert_eq!(v["data"]["slug"], "event_check");
        assert_eq!(
            v["data"]["target_file_sha256_hex"],
            out.target_file_sha256_hex
        );
    }

    #[test]
    fn promote_to_check_failed_check_write_is_atomic_no_status_no_event() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        let checks_path = state_dir.join("checks");
        if let Some(parent) = checks_path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(&checks_path, "not a dir").expect("poison checks path");

        let err = promote_learning_to_check(&state_dir, &e.id, "will_fail", false)
            .expect_err("write should fail");
        assert!(err.to_string().contains("failed to create check dir"));

        let updated = load_learning_entry(&state_dir, &e.id).expect("reload");
        assert_eq!(updated.status, LearningStatusV1::Captured);
        assert!(read_learning_events_lines(&state_dir).is_empty());
    }

    #[test]
    fn promote_to_check_path_safety_only_expected_files_modified() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        let before = collect_state_files(&state_dir);
        assert_eq!(
            before,
            BTreeSet::from([format!("learn/entries/{}.json", e.id)])
        );

        let _ = promote_learning_to_check(&state_dir, &e.id, "safe_paths", false).expect("promote");
        let after = collect_state_files(&state_dir);
        let expected = BTreeSet::from([
            format!("learn/entries/{}.json", e.id),
            "learn/events.jsonl".to_string(),
            "checks/safe_paths.md".to_string(),
        ]);
        assert_eq!(after, expected);
    }

    #[test]
    fn promote_to_check_generated_file_loads_as_schema_valid_check() {
        let tmp = tempdir().expect("tempdir");
        let state_dir = tmp.path().join(".localagent");
        let mut e = sample_check_candidate_learning_entry();
        e.entry_hash_hex = compute_entry_hash_hex(&e).expect("hash");
        write_entry(&state_dir, e.clone());

        promote_learning_to_check(&state_dir, &e.id, "schema_valid", false).expect("promote");
        let loaded = crate::checks::loader::load_checks(tmp.path(), None);
        assert!(loaded.errors.is_empty(), "errors: {:?}", loaded.errors);
        let check = loaded
            .checks
            .iter()
            .find(|c| c.path == ".localagent/checks/schema_valid.md")
            .expect("generated check");
        assert_eq!(check.frontmatter.schema_version, 1);
        assert_eq!(check.frontmatter.allowed_tools, Some(vec![]));
        assert_eq!(check.frontmatter.required_flags, Vec::<String>::new());
    }
}
