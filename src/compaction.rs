use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{Message, Role};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CompactionMode {
    Off,
    Summary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultPersist {
    All,
    Digest,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionSettings {
    pub max_context_chars: usize,
    pub mode: CompactionMode,
    pub keep_last: usize,
    pub tool_result_persist: ToolResultPersist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionReport {
    pub before_chars: usize,
    pub after_chars: usize,
    pub before_messages: usize,
    pub after_messages: usize,
    pub compacted_messages: usize,
    pub summary_digest_sha256: String,
    pub summary_text: String,
}

#[derive(Debug, Clone)]
pub struct CompactionOutcome {
    pub messages: Vec<Message>,
    pub report: Option<CompactionReport>,
}

pub fn context_size_chars(messages: &[Message]) -> usize {
    messages.iter().map(message_size_chars).sum()
}

pub fn maybe_compact(
    messages: &[Message],
    settings: &CompactionSettings,
) -> anyhow::Result<CompactionOutcome> {
    if settings.max_context_chars == 0 || matches!(settings.mode, CompactionMode::Off) {
        return Ok(CompactionOutcome {
            messages: messages.to_vec(),
            report: None,
        });
    }

    let before_chars = context_size_chars(messages);
    if before_chars <= settings.max_context_chars {
        return Ok(CompactionOutcome {
            messages: messages.to_vec(),
            report: None,
        });
    }

    let split_at = messages.len().saturating_sub(settings.keep_last);
    let compacted = &messages[..split_at];
    let mut tail = messages[split_at..].to_vec();
    apply_tool_persistence(&mut tail, settings.tool_result_persist);

    let summary_text = build_summary(compacted);
    let summary_digest_sha256 = sha256_hex(summary_text.as_bytes());
    let summary_message = Message {
        role: Role::System,
        content: Some(summary_text.clone()),
        tool_call_id: None,
        tool_name: None,
        tool_calls: None,
    };

    let mut out_messages = Vec::with_capacity(1 + tail.len());
    out_messages.push(summary_message);
    out_messages.extend(tail);
    let after_chars = context_size_chars(&out_messages);
    let after_messages = out_messages.len();

    Ok(CompactionOutcome {
        messages: out_messages,
        report: Some(CompactionReport {
            before_chars,
            after_chars,
            before_messages: messages.len(),
            after_messages,
            compacted_messages: compacted.len(),
            summary_digest_sha256,
            summary_text,
        }),
    })
}

fn message_size_chars(message: &Message) -> usize {
    let mut size = 0usize;
    size += role_name(message.role.clone()).chars().count();
    if let Some(content) = &message.content {
        size += content.chars().count();
    }
    if let Some(id) = &message.tool_call_id {
        size += id.chars().count();
    }
    if let Some(name) = &message.tool_name {
        size += name.chars().count();
    }
    size
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::Developer => "developer",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

fn apply_tool_persistence(messages: &mut [Message], mode: ToolResultPersist) {
    if matches!(mode, ToolResultPersist::All) {
        return;
    }
    for message in messages {
        if !matches!(message.role, Role::Tool) {
            continue;
        }
        let original = message.content.clone().unwrap_or_default();
        message.content = Some(match mode {
            ToolResultPersist::All => original,
            ToolResultPersist::Digest => digest_tool_output(&original),
            ToolResultPersist::None => {
                summarize_tool_output_minimal(&original, message.tool_name.as_deref())
            }
        });
    }
}

fn digest_tool_output(content: &str) -> String {
    let head: String = content.chars().take(200).collect();
    format!(
        "TOOL_OUTPUT_DIGEST v1\nsha256={}\nlen={}\nhead={}\ntruncated=true",
        sha256_hex(content.as_bytes()),
        content.chars().count(),
        head
    )
}

fn summarize_tool_output_minimal(content: &str, tool_name: Option<&str>) -> String {
    let status = tool_status(content);
    format!(
        "TOOL_OUTPUT_OMITTED v1\ntool={}\nstatus={}",
        tool_name.unwrap_or("unknown"),
        status
    )
}

fn build_summary(messages: &[Message]) -> String {
    let mut lines = Vec::new();
    let mut digest_src = String::new();

    for m in messages {
        let content = m.content.clone().unwrap_or_default();
        let head: String = content.chars().take(200).collect();
        let entry_hash = sha256_hex(content.as_bytes());
        let line = match m.role {
            Role::User => format!("- user: {} [sha256={}]", head, entry_hash),
            Role::Assistant => format!("- assistant: {} [sha256={}]", head, entry_hash),
            Role::Tool => format!(
                "- tool({}): status={} {} [sha256={}]",
                m.tool_name.clone().unwrap_or_else(|| "unknown".to_string()),
                tool_status(&content),
                head,
                entry_hash
            ),
            Role::System => format!("- system: {} [sha256={}]", head, entry_hash),
            Role::Developer => format!("- developer: {} [sha256={}]", head, entry_hash),
        };
        digest_src.push_str(&line);
        digest_src.push('\n');
        lines.push(line);
    }

    let rolling_digest = sha256_hex(digest_src.as_bytes());
    let mut out = String::new();
    out.push_str("COMPACTED SUMMARY (v1)\n");
    out.push_str(&format!("rolling_digest_sha256={rolling_digest}\n"));
    out.push_str(&format!("compacted_messages={}\n", messages.len()));
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn tool_status(content: &str) -> &'static str {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => {
            if v.get("error").is_some() {
                "error"
            } else {
                "ok"
            }
        }
        Err(_) => "unknown",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use crate::types::ToolCall;

    use super::{
        context_size_chars, maybe_compact, CompactionMode, CompactionSettings, ToolResultPersist,
    };
    use crate::types::{Message, Role};

    fn msg(role: Role, content: &str) -> Message {
        Message {
            role,
            content: Some(content.to_string()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }
    }

    #[test]
    fn compaction_is_deterministic() {
        let messages = vec![
            msg(Role::System, "banner"),
            msg(Role::User, "hello"),
            msg(Role::Assistant, "world"),
        ];
        let settings = CompactionSettings {
            max_context_chars: 4,
            mode: CompactionMode::Summary,
            keep_last: 1,
            tool_result_persist: ToolResultPersist::Digest,
        };
        let a = maybe_compact(&messages, &settings).expect("compact a");
        let b = maybe_compact(&messages, &settings).expect("compact b");
        assert_eq!(
            a.report.as_ref().expect("report a").summary_digest_sha256,
            b.report.as_ref().expect("report b").summary_digest_sha256
        );
        assert_eq!(
            serde_json::to_string(&a.messages).expect("serialize a"),
            serde_json::to_string(&b.messages).expect("serialize b")
        );
    }

    #[test]
    fn keep_last_messages_are_preserved() {
        let messages = vec![
            msg(Role::User, "u1"),
            msg(Role::Assistant, "a1"),
            msg(Role::User, "u2"),
            msg(Role::Assistant, "a2"),
        ];
        let settings = CompactionSettings {
            max_context_chars: 3,
            mode: CompactionMode::Summary,
            keep_last: 2,
            tool_result_persist: ToolResultPersist::All,
        };
        let out = maybe_compact(&messages, &settings).expect("compact");
        assert_eq!(out.messages.len(), 3);
        assert!(out.messages[0]
            .content
            .as_deref()
            .unwrap_or("")
            .starts_with("COMPACTED SUMMARY (v1)"));
        assert_eq!(out.messages[1].content.as_deref(), Some("u2"));
        assert_eq!(out.messages[2].content.as_deref(), Some("a2"));
    }

    #[test]
    fn digest_mode_rewrites_tool_message_content() {
        let tool = Message {
            role: Role::Tool,
            content: Some("{\"ok\":true,\"value\":\"abcdef\"}".to_string()),
            tool_call_id: Some("tc1".to_string()),
            tool_name: Some("read_file".to_string()),
            tool_calls: Some(vec![ToolCall {
                id: "tc1".to_string(),
                name: "read_file".to_string(),
                arguments: serde_json::json!({}),
            }]),
        };
        let messages = vec![msg(Role::User, "hello"), tool, msg(Role::Assistant, "done")];
        let settings = CompactionSettings {
            max_context_chars: 5,
            mode: CompactionMode::Summary,
            keep_last: 2,
            tool_result_persist: ToolResultPersist::Digest,
        };
        let out = maybe_compact(&messages, &settings).expect("compact");
        let digest_msg = out.messages[1].content.as_deref().unwrap_or("");
        assert!(digest_msg.contains("TOOL_OUTPUT_DIGEST v1"));
        assert!(digest_msg.contains("sha256="));
    }

    #[test]
    fn budget_only_applies_when_enabled() {
        let messages = vec![msg(Role::User, "a very long message")];
        let off = CompactionSettings {
            max_context_chars: 0,
            mode: CompactionMode::Summary,
            keep_last: 1,
            tool_result_persist: ToolResultPersist::Digest,
        };
        let out = maybe_compact(&messages, &off).expect("off");
        assert!(out.report.is_none());
        assert_eq!(
            context_size_chars(&out.messages),
            context_size_chars(&messages)
        );
    }
}
