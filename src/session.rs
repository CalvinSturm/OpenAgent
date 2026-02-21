use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::compaction::{CompactionMode, ToolResultPersist};
use crate::hooks::config::HooksMode;
use crate::tools::ToolArgsStrict;
use crate::types::{Message, Role};

pub const TASK_MEMORY_HEADER: &str = "TASK MEMORY (user-authored, authoritative)";
const MAX_MEMORY_BLOCKS: usize = 20;
const MAX_MEMORY_CONTENT_CHARS: usize = 4000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CapsMode {
    Auto,
    Off,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCompactionSettings {
    pub max_context_chars: usize,
    pub mode: String,
    pub keep_last: usize,
    pub tool_result_persist: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSettings {
    pub compaction: SessionCompactionSettings,
    pub tool_args_strict: String,
    pub caps_mode: String,
    pub hooks_mode: String,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            compaction: SessionCompactionSettings {
                max_context_chars: 0,
                mode: "off".to_string(),
                keep_last: 20,
                tool_result_persist: "digest".to_string(),
            },
            tool_args_strict: "on".to_string(),
            caps_mode: "off".to_string(),
            hooks_mode: "off".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMemoryBlock {
    pub id: String,
    pub title: String,
    pub content: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFileV2 {
    pub schema_version: String,
    pub name: String,
    pub updated_at: String,
    pub messages: Vec<Message>,
    pub settings: SessionSettings,
    #[serde(default)]
    pub task_memory: Vec<TaskMemoryBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionFileV1 {
    pub schema_version: String,
    pub updated_at: String,
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone)]
pub struct SessionData {
    pub name: String,
    pub updated_at: String,
    pub messages: Vec<Message>,
    pub settings: SessionSettings,
    pub task_memory: Vec<TaskMemoryBlock>,
}

impl SessionData {
    pub fn empty(name: &str) -> Self {
        Self {
            name: name.to_string(),
            updated_at: crate::trust::now_rfc3339(),
            messages: Vec::new(),
            settings: SessionSettings::default(),
            task_memory: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    name: String,
}

impl SessionStore {
    pub fn new(path: PathBuf, name: String) -> Self {
        Self { path, name }
    }

    pub fn load(&self) -> anyhow::Result<SessionData> {
        if !self.path.exists() {
            return Ok(SessionData::empty(&self.name));
        }
        let raw = std::fs::read_to_string(&self.path)
            .with_context(|| format!("failed reading session file {}", self.path.display()))?;
        let val: serde_json::Value =
            serde_json::from_str(&raw).context("failed parsing session JSON")?;
        let schema = val
            .get("schema_version")
            .and_then(|v| v.as_str())
            .unwrap_or("openagent.session.v1");
        if schema == "openagent.session.v2" {
            let v2: SessionFileV2 =
                serde_json::from_value(val).context("failed decoding session v2")?;
            return Ok(SessionData {
                name: v2.name,
                updated_at: v2.updated_at,
                messages: v2.messages,
                settings: v2.settings,
                task_memory: v2.task_memory,
            });
        }
        let v1: SessionFileV1 = serde_json::from_str(&raw).context("failed decoding session v1")?;
        Ok(SessionData {
            name: self.name.clone(),
            updated_at: v1.updated_at,
            messages: v1.messages,
            settings: SessionSettings::default(),
            task_memory: Vec::new(),
        })
    }

    pub fn save(&self, data: &SessionData, max_messages: usize) -> anyhow::Result<()> {
        let mut msgs = data.messages.clone();
        if msgs.len() > max_messages {
            let keep_from = msgs.len() - max_messages;
            msgs = msgs[keep_from..].to_vec();
        }
        let mut mem = data.task_memory.clone();
        mem.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        let out = SessionFileV2 {
            schema_version: "openagent.session.v2".to_string(),
            name: data.name.clone(),
            updated_at: crate::trust::now_rfc3339(),
            messages: msgs,
            settings: data.settings.clone(),
            task_memory: mem,
        };
        write_json_atomic(&self.path, &out)
    }

    pub fn reset(&self) -> anyhow::Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    pub fn add_memory(&self, title: &str, content: &str) -> anyhow::Result<String> {
        enforce_memory_size(content)?;
        let mut data = self.load()?;
        if data.task_memory.len() >= MAX_MEMORY_BLOCKS {
            return Err(anyhow!(
                "max task memory blocks reached ({MAX_MEMORY_BLOCKS})"
            ));
        }
        let now = crate::trust::now_rfc3339();
        let id = Uuid::new_v4().to_string();
        data.task_memory.push(TaskMemoryBlock {
            id: id.clone(),
            title: title.to_string(),
            content: content.to_string(),
            created_at: now.clone(),
            updated_at: now,
        });
        self.save(&data, usize::MAX)?;
        Ok(id)
    }

    pub fn update_memory(
        &self,
        id: &str,
        title: Option<&str>,
        content: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(c) = content {
            enforce_memory_size(c)?;
        }
        let mut data = self.load()?;
        let Some(block) = data.task_memory.iter_mut().find(|b| b.id == id) else {
            return Err(anyhow!("memory id not found: {id}"));
        };
        if let Some(t) = title {
            block.title = t.to_string();
        }
        if let Some(c) = content {
            block.content = c.to_string();
        }
        block.updated_at = crate::trust::now_rfc3339();
        self.save(&data, usize::MAX)
    }

    pub fn delete_memory(&self, id: &str) -> anyhow::Result<()> {
        let mut data = self.load()?;
        let before = data.task_memory.len();
        data.task_memory.retain(|b| b.id != id);
        if data.task_memory.len() == before {
            return Err(anyhow!("memory id not found: {id}"));
        }
        self.save(&data, usize::MAX)
    }

    pub fn drop_from(&self, from_index: usize) -> anyhow::Result<()> {
        let mut data = self.load()?;
        if from_index >= data.messages.len() {
            return Err(anyhow!(
                "--from index {} is out of range (len={})",
                from_index,
                data.messages.len()
            ));
        }
        data.messages.truncate(from_index);
        self.save(&data, usize::MAX)
    }

    pub fn drop_last(&self, count: usize) -> anyhow::Result<()> {
        let mut data = self.load()?;
        if count >= data.messages.len() {
            data.messages.clear();
        } else {
            let keep = data.messages.len() - count;
            data.messages.truncate(keep);
        }
        self.save(&data, usize::MAX)
    }
}

fn enforce_memory_size(content: &str) -> anyhow::Result<()> {
    if content.chars().count() > MAX_MEMORY_CONTENT_CHARS {
        return Err(anyhow!(
            "task memory content exceeds {} chars",
            MAX_MEMORY_CONTENT_CHARS
        ));
    }
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    std::fs::write(&tmp_path, serde_json::to_string_pretty(value)?)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RunSettingResolution {
    pub max_context_chars: usize,
    pub compaction_mode: CompactionMode,
    pub compaction_keep_last: usize,
    pub tool_result_persist: ToolResultPersist,
    pub tool_args_strict: ToolArgsStrict,
    pub caps_mode: CapsMode,
    pub hooks_mode: HooksMode,
    pub sources: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExplicitFlags {
    pub max_context_chars: bool,
    pub compaction_mode: bool,
    pub compaction_keep_last: bool,
    pub tool_result_persist: bool,
    pub tool_args_strict: bool,
    pub caps_mode: bool,
    pub hooks_mode: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RunSettingInputs {
    pub max_context_chars: usize,
    pub compaction_mode: CompactionMode,
    pub compaction_keep_last: usize,
    pub tool_result_persist: ToolResultPersist,
    pub tool_args_strict: ToolArgsStrict,
    pub caps_mode: CapsMode,
    pub hooks_mode: HooksMode,
}

pub fn resolve_run_settings(
    use_session_settings: bool,
    session_enabled: bool,
    session: &SessionData,
    explicit: &ExplicitFlags,
    cli: RunSettingInputs,
) -> RunSettingResolution {
    let mut sources = BTreeMap::new();
    let can_use = use_session_settings && session_enabled;

    let max_context_chars = if explicit.max_context_chars {
        sources.insert("max_context_chars".to_string(), "cli".to_string());
        cli.max_context_chars
    } else if can_use {
        sources.insert("max_context_chars".to_string(), "session".to_string());
        session.settings.compaction.max_context_chars
    } else {
        sources.insert("max_context_chars".to_string(), "default".to_string());
        cli.max_context_chars
    };

    let compaction_mode = if explicit.compaction_mode {
        sources.insert("compaction_mode".to_string(), "cli".to_string());
        cli.compaction_mode
    } else if can_use {
        sources.insert("compaction_mode".to_string(), "session".to_string());
        parse_compaction_mode(&session.settings.compaction.mode).unwrap_or(cli.compaction_mode)
    } else {
        sources.insert("compaction_mode".to_string(), "default".to_string());
        cli.compaction_mode
    };

    let compaction_keep_last = if explicit.compaction_keep_last {
        sources.insert("compaction_keep_last".to_string(), "cli".to_string());
        cli.compaction_keep_last
    } else if can_use {
        sources.insert("compaction_keep_last".to_string(), "session".to_string());
        session.settings.compaction.keep_last
    } else {
        sources.insert("compaction_keep_last".to_string(), "default".to_string());
        cli.compaction_keep_last
    };

    let tool_result_persist = if explicit.tool_result_persist {
        sources.insert("tool_result_persist".to_string(), "cli".to_string());
        cli.tool_result_persist
    } else if can_use {
        sources.insert("tool_result_persist".to_string(), "session".to_string());
        parse_tool_result_persist(&session.settings.compaction.tool_result_persist)
            .unwrap_or(cli.tool_result_persist)
    } else {
        sources.insert("tool_result_persist".to_string(), "default".to_string());
        cli.tool_result_persist
    };

    let tool_args_strict = if explicit.tool_args_strict {
        sources.insert("tool_args_strict".to_string(), "cli".to_string());
        cli.tool_args_strict
    } else if can_use {
        sources.insert("tool_args_strict".to_string(), "session".to_string());
        parse_tool_args_strict(&session.settings.tool_args_strict).unwrap_or(cli.tool_args_strict)
    } else {
        sources.insert("tool_args_strict".to_string(), "default".to_string());
        cli.tool_args_strict
    };

    let caps_mode = if explicit.caps_mode {
        sources.insert("caps_mode".to_string(), "cli".to_string());
        cli.caps_mode
    } else if can_use {
        sources.insert("caps_mode".to_string(), "session".to_string());
        parse_caps_mode(&session.settings.caps_mode).unwrap_or(cli.caps_mode)
    } else {
        sources.insert("caps_mode".to_string(), "default".to_string());
        cli.caps_mode
    };

    let hooks_mode = if explicit.hooks_mode {
        sources.insert("hooks_mode".to_string(), "cli".to_string());
        cli.hooks_mode
    } else if can_use {
        sources.insert("hooks_mode".to_string(), "session".to_string());
        parse_hooks_mode(&session.settings.hooks_mode).unwrap_or(cli.hooks_mode)
    } else {
        sources.insert("hooks_mode".to_string(), "default".to_string());
        cli.hooks_mode
    };

    RunSettingResolution {
        max_context_chars,
        compaction_mode,
        compaction_keep_last,
        tool_result_persist,
        tool_args_strict,
        caps_mode,
        hooks_mode,
        sources,
    }
}

pub fn settings_from_run(resolved: &RunSettingResolution) -> SessionSettings {
    SessionSettings {
        compaction: SessionCompactionSettings {
            max_context_chars: resolved.max_context_chars,
            mode: format!("{:?}", resolved.compaction_mode).to_lowercase(),
            keep_last: resolved.compaction_keep_last,
            tool_result_persist: format!("{:?}", resolved.tool_result_persist).to_lowercase(),
        },
        tool_args_strict: format!("{:?}", resolved.tool_args_strict).to_lowercase(),
        caps_mode: format!("{:?}", resolved.caps_mode).to_lowercase(),
        hooks_mode: format!("{:?}", resolved.hooks_mode).to_lowercase(),
    }
}

pub fn task_memory_message(blocks: &[TaskMemoryBlock]) -> Option<Message> {
    if blocks.is_empty() {
        return None;
    }
    let mut sorted = blocks.to_vec();
    sorted.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    let mut content = String::new();
    content.push_str(TASK_MEMORY_HEADER);
    content.push('\n');
    for b in sorted {
        content.push_str(&format!("- [{}] {}: {}\n", b.id, b.title, b.content));
    }
    Some(Message {
        role: Role::Developer,
        content: Some(content.trim_end().to_string()),
        tool_call_id: None,
        tool_name: None,
        tool_calls: None,
    })
}

fn parse_compaction_mode(s: &str) -> Option<CompactionMode> {
    match s {
        "off" => Some(CompactionMode::Off),
        "summary" => Some(CompactionMode::Summary),
        _ => None,
    }
}

fn parse_tool_result_persist(s: &str) -> Option<ToolResultPersist> {
    match s {
        "all" => Some(ToolResultPersist::All),
        "digest" => Some(ToolResultPersist::Digest),
        "none" => Some(ToolResultPersist::None),
        _ => None,
    }
}

fn parse_tool_args_strict(s: &str) -> Option<ToolArgsStrict> {
    match s {
        "on" => Some(ToolArgsStrict::On),
        "off" => Some(ToolArgsStrict::Off),
        _ => None,
    }
}

fn parse_caps_mode(s: &str) -> Option<CapsMode> {
    match s {
        "auto" => Some(CapsMode::Auto),
        "off" => Some(CapsMode::Off),
        "strict" => Some(CapsMode::Strict),
        _ => None,
    }
}

fn parse_hooks_mode(s: &str) -> Option<HooksMode> {
    match s {
        "off" => Some(HooksMode::Off),
        "auto" => Some(HooksMode::Auto),
        "on" => Some(HooksMode::On),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{
        resolve_run_settings, settings_from_run, task_memory_message, CapsMode, ExplicitFlags,
        RunSettingInputs, SessionStore, TASK_MEMORY_HEADER,
    };
    use crate::compaction::{CompactionMode, ToolResultPersist};
    use crate::hooks::config::HooksMode;
    use crate::tools::ToolArgsStrict;
    use crate::types::{Message, Role};

    #[test]
    fn migrates_v1_to_v2_on_save() {
        let tmp = tempdir().expect("tmp");
        let p = tmp.path().join("s.json");
        std::fs::write(
            &p,
            serde_json::json!({
                "schema_version":"openagent.session.v1",
                "updated_at":"2026-01-01T00:00:00Z",
                "messages":[{"role":"user","content":"hi","tool_call_id":null,"tool_name":null,"tool_calls":null}]
            })
            .to_string(),
        )
        .expect("write");
        let store = SessionStore::new(p.clone(), "default".to_string());
        let data = store.load().expect("load");
        assert_eq!(data.messages.len(), 1);
        store.save(&data, 40).expect("save");
        let out = std::fs::read_to_string(p).expect("read");
        assert!(out.contains("openagent.session.v2"));
    }

    #[test]
    fn settings_precedence_cli_then_session_then_default() {
        let tmp = tempdir().expect("tmp");
        let p = tmp.path().join("s.json");
        let store = SessionStore::new(p, "default".to_string());
        let mut data = store.load().expect("load");
        data.settings.compaction.max_context_chars = 777;
        data.settings.compaction.mode = "summary".to_string();
        data.settings.tool_args_strict = "off".to_string();
        data.settings.caps_mode = "strict".to_string();
        data.settings.hooks_mode = "on".to_string();
        store.save(&data, 40).expect("save");
        let loaded = store.load().expect("load2");

        let r = resolve_run_settings(
            true,
            true,
            &loaded,
            &ExplicitFlags {
                compaction_mode: true,
                ..ExplicitFlags::default()
            },
            RunSettingInputs {
                max_context_chars: 0,
                compaction_mode: CompactionMode::Off,
                compaction_keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
                tool_args_strict: ToolArgsStrict::On,
                caps_mode: CapsMode::Off,
                hooks_mode: HooksMode::Off,
            },
        );
        assert_eq!(r.max_context_chars, 777);
        assert!(matches!(r.compaction_mode, CompactionMode::Off));
        assert!(matches!(r.tool_args_strict, ToolArgsStrict::Off));
        assert!(matches!(r.caps_mode, CapsMode::Strict));
        assert!(matches!(r.hooks_mode, HooksMode::On));
        assert_eq!(
            r.sources.get("max_context_chars").map(String::as_str),
            Some("session")
        );
        assert_eq!(
            r.sources.get("compaction_mode").map(String::as_str),
            Some("cli")
        );
    }

    #[test]
    fn memory_crud_and_caps() {
        let tmp = tempdir().expect("tmp");
        let store = SessionStore::new(tmp.path().join("s.json"), "default".to_string());
        let id = store.add_memory("t", "c").expect("add");
        let mut data = store.load().expect("load");
        assert_eq!(data.task_memory.len(), 1);
        store
            .update_memory(&id, Some("t2"), Some("c2"))
            .expect("update");
        data = store.load().expect("load2");
        assert_eq!(data.task_memory[0].title, "t2");
        let too_long = "x".repeat(4001);
        assert!(store.add_memory("x", &too_long).is_err());
        store.delete_memory(&id).expect("delete");
        assert!(store.load().expect("load3").task_memory.is_empty());
    }

    #[test]
    fn deterministic_task_memory_message() {
        let msg = task_memory_message(&[
            super::TaskMemoryBlock {
                id: "b".to_string(),
                title: "B".to_string(),
                content: "bb".to_string(),
                created_at: "2026-01-02T00:00:00Z".to_string(),
                updated_at: "2026-01-02T00:00:00Z".to_string(),
            },
            super::TaskMemoryBlock {
                id: "a".to_string(),
                title: "A".to_string(),
                content: "aa".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            },
        ])
        .expect("msg");
        assert!(matches!(msg.role, Role::Developer));
        let c = msg.content.expect("content");
        assert!(c.contains(TASK_MEMORY_HEADER));
        let idx_a = c.find("[a]").expect("a");
        let idx_b = c.find("[b]").expect("b");
        assert!(idx_a < idx_b);
    }

    #[test]
    fn drop_messages_variants() {
        let tmp = tempdir().expect("tmp");
        let store = SessionStore::new(tmp.path().join("s.json"), "default".to_string());
        let mut data = store.load().expect("load");
        data.messages = vec![
            Message {
                role: Role::User,
                content: Some("1".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            Message {
                role: Role::Assistant,
                content: Some("2".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            Message {
                role: Role::Tool,
                content: Some("3".to_string()),
                tool_call_id: None,
                tool_name: Some("x".to_string()),
                tool_calls: None,
            },
        ];
        data.settings = settings_from_run(&resolve_run_settings(
            false,
            false,
            &data,
            &ExplicitFlags::default(),
            RunSettingInputs {
                max_context_chars: 0,
                compaction_mode: CompactionMode::Off,
                compaction_keep_last: 20,
                tool_result_persist: ToolResultPersist::Digest,
                tool_args_strict: ToolArgsStrict::On,
                caps_mode: CapsMode::Off,
                hooks_mode: HooksMode::Off,
            },
        ));
        store.save(&data, 40).expect("save");
        store.drop_last(1).expect("drop");
        assert_eq!(store.load().expect("load2").messages.len(), 2);
        store.drop_from(1).expect("drop2");
        assert_eq!(store.load().expect("load3").messages.len(), 1);
    }
}
