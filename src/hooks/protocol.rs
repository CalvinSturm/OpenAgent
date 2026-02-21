use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::compaction::CompactionSettings;
use crate::types::{Message, ToolDef};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStageWire {
    PreModel,
    ToolResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInput {
    pub schema_version: String,
    pub stage: HookStageWire,
    pub run_id: String,
    pub step: u32,
    pub provider: String,
    pub model: String,
    pub workdir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<Value>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreModelPayload {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub stream: bool,
    pub compaction: PreModelCompactionPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreModelCompactionPayload {
    pub enabled: bool,
    pub max_context_chars: usize,
    pub mode: String,
    pub keep_last: usize,
    pub tool_result_persist: String,
}

impl From<&CompactionSettings> for PreModelCompactionPayload {
    fn from(value: &CompactionSettings) -> Self {
        Self {
            enabled: value.max_context_chars > 0
                && !matches!(value.mode, crate::compaction::CompactionMode::Off),
            max_context_chars: value.max_context_chars,
            mode: format!("{:?}", value.mode).to_lowercase(),
            keep_last: value.keep_last,
            tool_result_persist: format!("{:?}", value.tool_result_persist).to_lowercase(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPayload {
    pub tool_call_id: String,
    pub tool_name: String,
    pub ok: bool,
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookOutput {
    pub schema_version: String,
    pub action: HookAction,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    Pass,
    Modify,
    Abort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreModelModifyPayload {
    #[serde(default)]
    pub append_messages: Vec<AppendMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultModifyPayload {
    pub content: String,
    #[serde(default)]
    pub truncated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInvocationReport {
    pub ts: String,
    pub step: u32,
    pub stage: String,
    pub hook_name: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub modified: bool,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appended_message_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appended_digests: Option<Vec<String>>,
}
