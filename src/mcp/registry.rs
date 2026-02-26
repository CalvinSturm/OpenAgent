use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::json;

use crate::mcp::client::McpClient;
use crate::mcp::types::{McpConfigFile, McpServerConfig};
use crate::store::{ensure_dir, mcp_tool_snapshot_hash_hex, sha256_hex, McpToolSnapshotEntry};
use crate::tools::{
    envelope_to_message, to_tool_result_envelope, tool_side_effects, validate_schema_args,
    ToolArgsStrict, ToolResultContentRef, ToolResultMeta,
};
use crate::types::{Message, ToolCall, ToolDef};

pub struct McpRegistry {
    clients: BTreeMap<String, McpClient>,
    tool_map: BTreeMap<String, (String, String)>,
    tool_schema_map: BTreeMap<String, Option<serde_json::Value>>,
    tool_doc_meta_map: BTreeMap<String, McpToolDocMeta>,
    tool_defs: Vec<ToolDef>,
    timeout: Duration,
    mcp_spool_dir: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct McpToolDocMeta {
    pub raw_description: Option<String>,
    pub raw_description_hash: Option<String>,
    pub raw_description_truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct McpCallMeta {
    pub progress_ticks: u32,
    pub elapsed_ms: u64,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct McpCallOutcome {
    pub message: Message,
    pub meta: McpCallMeta,
}

impl McpRegistry {
    pub async fn from_config_path(
        path: &Path,
        enabled: &[String],
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let config = load_or_create_config(path)?;
        let mut clients = BTreeMap::new();
        let mut tool_map = BTreeMap::new();
        let mut tool_schema_map = BTreeMap::new();
        let mut tool_doc_meta_map = BTreeMap::new();
        let mut tool_defs = Vec::new();
        let mcp_spool_dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("tmp")
            .join("mcp_spool");

        for name in enabled {
            let server = config
                .servers
                .get(name)
                .ok_or_else(|| anyhow!("MCP server '{}' not found in config", name))?;
            let client = McpClient::spawn(name, &server.command, &server.args).await?;
            client.initialize(Duration::from_secs(5)).await?;
            let tools = client.tools_list(timeout).await?;
            for tool in &tools {
                let namespaced = format!("mcp.{}.{}", name, tool.name);
                let raw_doc = build_mcp_tool_doc_meta(&tool.description);
                tool_map.insert(namespaced.clone(), (name.clone(), tool.name.clone()));
                tool_schema_map.insert(namespaced.clone(), tool.input_schema.clone());
                tool_doc_meta_map.insert(namespaced.clone(), raw_doc.clone());
                tool_defs.push(ToolDef {
                    name: namespaced.clone(),
                    description: model_facing_mcp_tool_description(name, &namespaced),
                    parameters: tool
                        .input_schema
                        .clone()
                        .unwrap_or_else(|| json!({"type":"object"})),
                    side_effects: tool_side_effects(&format!("mcp.{}.{}", name, tool.name)),
                });
            }
            clients.insert(name.clone(), client);
        }

        tool_defs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            clients,
            tool_map,
            tool_schema_map,
            tool_doc_meta_map,
            tool_defs,
            timeout,
            mcp_spool_dir,
        })
    }

    pub fn tool_defs(&self) -> Vec<ToolDef> {
        self.tool_defs.clone()
    }

    pub fn tool_doc_meta(&self, namespaced_tool: &str) -> Option<&McpToolDocMeta> {
        self.tool_doc_meta_map.get(namespaced_tool)
    }

    pub fn render_tool_docs_text(&self, tool_name: &str) -> String {
        let defs = self.tool_defs();
        let mut names = defs.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
        names.sort();
        let Some(def) = defs.into_iter().find(|t| t.name == tool_name) else {
            let suggestions = closest_tool_matches(&names, tool_name, 10);
            if suggestions.is_empty() {
                return format!("unknown tool: {tool_name}");
            }
            return format!(
                "unknown tool: {tool_name}\nclosest_matches: {}",
                suggestions.join(", ")
            );
        };
        let params = serde_json::to_string_pretty(&def.parameters)
            .unwrap_or_else(|e| format!("{{\"error\":\"schema serialize failed: {e}\"}}"));
        let (source, server) = parse_mcp_tool_source(&def.name);
        let raw_meta = self.tool_doc_meta(&def.name).cloned().unwrap_or_default();
        let raw_preview = raw_meta
            .raw_description
            .unwrap_or_else(|| "no docs available".to_string());
        let raw_hash = raw_meta
            .raw_description_hash
            .unwrap_or_else(|| "-".to_string());
        let docs_hash = self
            .tool_docs_hash_hex(&def.name)
            .ok()
            .flatten()
            .unwrap_or_else(|| "-".to_string());
        let catalog_hash = self
            .configured_tool_catalog_hash_hex()
            .unwrap_or_else(|_| "-".to_string());
        format!(
            "tool_name: {tool}\nsource: {source}\nserver: {server}\ndocs_hash_v1: {docs_hash}\ncatalog_hash_v1: {catalog_hash}\nraw_description_hash: {raw_hash}\nraw_description_truncated: {raw_truncated}\nraw_description_preview:\n{raw_preview}\nparameters:\n{params}",
            tool = def.name,
            source = source,
            server = server.unwrap_or("-"),
            docs_hash = docs_hash,
            catalog_hash = catalog_hash,
            raw_hash = raw_hash,
            raw_truncated = raw_meta.raw_description_truncated,
            raw_preview = indent_block(&raw_preview, 2),
            params = indent_block(&params, 2),
        )
    }

    pub fn validate_namespaced_tool_args(
        &self,
        tc: &ToolCall,
        strict: ToolArgsStrict,
    ) -> Result<(), String> {
        let schema = self.tool_schema_map.get(&tc.name).and_then(|s| s.as_ref());
        validate_schema_args(&tc.arguments, schema, strict)
    }

    pub fn configured_tool_catalog_hash_hex(&self) -> anyhow::Result<String> {
        let snapshot = self
            .tool_defs
            .iter()
            .map(|t| McpToolSnapshotEntry {
                name: t.name.clone(),
                parameters: t.parameters.clone(),
            })
            .collect::<Vec<_>>();
        mcp_tool_snapshot_hash_hex(&snapshot)
    }

    pub fn configured_tool_docs_hash_hex(&self) -> anyhow::Result<String> {
        let mut snapshot = self
            .tool_defs
            .iter()
            .map(|t| McpToolDocsSnapshotEntry {
                name: t.name.clone(),
                parameters: t.parameters.clone(),
                description_preview: self
                    .tool_doc_meta_map
                    .get(&t.name)
                    .and_then(|m| m.raw_description.as_deref())
                    .map(normalized_description_preview)
                    .unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|a, b| a.name.cmp(&b.name));
        mcp_tool_docs_snapshot_hash_hex(&snapshot)
    }

    pub async fn live_tool_catalog_hash_hex(&self) -> anyhow::Result<String> {
        let mut snapshot: Vec<McpToolSnapshotEntry> = Vec::new();
        for (server, client) in &self.clients {
            let tools = client.tools_list(self.timeout).await?;
            for tool in tools {
                snapshot.push(McpToolSnapshotEntry {
                    name: format!("mcp.{}.{}", server, tool.name),
                    parameters: tool
                        .input_schema
                        .clone()
                        .unwrap_or_else(|| json!({"type":"object"})),
                });
            }
        }
        mcp_tool_snapshot_hash_hex(&snapshot)
    }

    pub async fn live_tool_docs_hash_hex(&self) -> anyhow::Result<String> {
        let mut snapshot: Vec<McpToolDocsSnapshotEntry> = Vec::new();
        for (server, client) in &self.clients {
            let tools = client.tools_list(self.timeout).await?;
            for tool in tools {
                snapshot.push(McpToolDocsSnapshotEntry {
                    name: format!("mcp.{}.{}", server, tool.name),
                    parameters: tool
                        .input_schema
                        .clone()
                        .unwrap_or_else(|| json!({"type":"object"})),
                    description_preview: normalized_description_preview(&tool.description),
                });
            }
        }
        snapshot.sort_by(|a, b| a.name.cmp(&b.name));
        mcp_tool_docs_snapshot_hash_hex(&snapshot)
    }

    pub fn tool_docs_hash_hex(&self, namespaced_tool: &str) -> anyhow::Result<Option<String>> {
        let Some(def) = self.tool_defs.iter().find(|t| t.name == namespaced_tool) else {
            return Ok(None);
        };
        let preview = self
            .tool_doc_meta_map
            .get(namespaced_tool)
            .and_then(|m| m.raw_description.as_deref())
            .map(normalized_description_preview)
            .unwrap_or_default();
        let snapshot = [McpToolDocsSnapshotEntry {
            name: def.name.clone(),
            parameters: def.parameters.clone(),
            description_preview: preview,
        }];
        Ok(Some(mcp_tool_docs_snapshot_hash_hex(&snapshot)?))
    }

    pub async fn call_namespaced_tool(
        &self,
        tc: &ToolCall,
        strict: ToolArgsStrict,
    ) -> anyhow::Result<McpCallOutcome> {
        let (server, tool) = self
            .tool_map
            .get(&tc.name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown MCP tool '{}'", tc.name))?;
        let schema = self.tool_schema_map.get(&tc.name).and_then(|s| s.as_ref());
        if let Err(e) = validate_schema_args(&tc.arguments, schema, strict) {
            return Ok(McpCallOutcome {
                message: envelope_to_message(to_tool_result_envelope(
                    tc,
                    "mcp",
                    false,
                    format!("invalid tool arguments: {e}"),
                    false,
                    ToolResultMeta {
                        side_effects: tool_side_effects(&tc.name),
                        bytes: None,
                        exit_code: None,
                        stderr_truncated: None,
                        stdout_truncated: None,
                        source: "mcp".to_string(),
                        execution_target: "host".to_string(),
                        docker: None,
                    },
                )),
                meta: McpCallMeta::default(),
            });
        }
        let client = self
            .clients
            .get(&server)
            .ok_or_else(|| anyhow!("MCP server '{}' not active", server))?;

        let mut meta = McpCallMeta::default();
        let started = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_millis(750));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        let call_fut = client.tools_call(&tool, tc.arguments.clone(), self.timeout);
        tokio::pin!(call_fut);
        let result = loop {
            tokio::select! {
                result = &mut call_fut => break result,
                _ = interval.tick() => {
                    meta.progress_ticks = meta.progress_ticks.saturating_add(1);
                }
            }
        };
        meta.elapsed_ms = started.elapsed().as_millis() as u64;

        let result = match result {
            Ok(value) => value,
            Err(e) => {
                let err = e.to_string();
                if err.to_ascii_lowercase().contains("timed out") {
                    meta.cancelled = true;
                }
                return Ok(McpCallOutcome {
                    message: envelope_to_message(to_tool_result_envelope(
                        tc,
                        "mcp",
                        false,
                        format!("mcp call failed: {err}"),
                        false,
                        ToolResultMeta {
                            side_effects: tool_side_effects(&tc.name),
                            bytes: None,
                            exit_code: None,
                            stderr_truncated: None,
                            stdout_truncated: None,
                            source: "mcp".to_string(),
                            execution_target: "host".to_string(),
                            docker: None,
                        },
                    )),
                    meta,
                });
            }
        };
        let result_str = match result {
            serde_json::Value::String(s) => s,
            other => serde_json::to_string(&other)
                .unwrap_or_else(|e| format!("mcp result serialization failed: {e}")),
        };
        let (model_content, was_truncated) =
            truncate_utf8_to_bytes(&result_str, MCP_MAX_MODEL_RESULT_BYTES);
        let mut env = to_tool_result_envelope(
            tc,
            "mcp",
            true,
            model_content.clone(),
            was_truncated,
            ToolResultMeta {
                side_effects: tool_side_effects(&tc.name),
                bytes: Some(result_str.len() as u64),
                exit_code: None,
                stderr_truncated: None,
                stdout_truncated: None,
                source: "mcp".to_string(),
                execution_target: "host".to_string(),
                docker: None,
            },
        );
        if was_truncated {
            env.truncate_reason = Some("max_bytes".to_string());
            if let Some(output_ref) = spool_full_mcp_output(&self.mcp_spool_dir, tc, &result_str) {
                env.full_output_ref = Some(output_ref);
            }
        }
        Ok(McpCallOutcome {
            message: envelope_to_message(env),
            meta,
        })
    }
}

const MCP_MAX_MODEL_RESULT_BYTES: usize = 64 * 1024;
const MCP_MAX_RAW_DESCRIPTION_BYTES: usize = 8 * 1024;
const MCP_DOCS_HASH_PREVIEW_BYTES: usize = 1024;

fn model_facing_mcp_tool_description(server: &str, namespaced_tool: &str) -> String {
    format!("MCP tool from {server}. Use /tool docs {namespaced_tool} for details.")
}

fn build_mcp_tool_doc_meta(raw: &str) -> McpToolDocMeta {
    if raw.is_empty() {
        return McpToolDocMeta::default();
    }
    let (capped, truncated) = truncate_utf8_to_bytes(raw, MCP_MAX_RAW_DESCRIPTION_BYTES);
    McpToolDocMeta {
        raw_description: Some(capped),
        raw_description_hash: Some(sha256_hex(raw.as_bytes())),
        raw_description_truncated: truncated,
    }
}

#[derive(Debug, Clone, Serialize)]
struct McpToolDocsSnapshotEntry {
    name: String,
    parameters: serde_json::Value,
    description_preview: String,
}

fn mcp_tool_docs_snapshot_hash_hex(
    snapshot: &[McpToolDocsSnapshotEntry],
) -> anyhow::Result<String> {
    let canonical = serde_json::to_string(snapshot)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn normalized_description_preview(raw: &str) -> String {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    truncate_utf8_to_bytes(trimmed, MCP_DOCS_HASH_PREVIEW_BYTES).0
}

fn truncate_utf8_to_bytes(input: &str, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }
    let mut end = max_bytes.min(input.len());
    while !input.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    (input[..end].to_string(), true)
}

fn spool_full_mcp_output(
    spool_dir: &Path,
    tc: &ToolCall,
    full_output: &str,
) -> Option<ToolResultContentRef> {
    if ensure_dir(spool_dir).is_err() {
        return None;
    }
    let bytes = full_output.as_bytes();
    let sha256 = sha256_hex(bytes);
    let tool = sanitize_filename_component(&tc.name);
    let id = sanitize_filename_component(&tc.id);
    let file_name = format!("{tool}__{id}__{}.txt", &sha256[..16]);
    let path = spool_dir.join(file_name);
    if std::fs::write(&path, bytes).is_err() {
        return None;
    }
    Some(ToolResultContentRef {
        kind: "state_spool_path".to_string(),
        path: path.to_string_lossy().to_string(),
        sha256,
        bytes: bytes.len() as u64,
    })
}

fn sanitize_filename_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_');
        out.push(if ok { ch } else { '_' });
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn parse_mcp_tool_source(tool_name: &str) -> (&'static str, Option<&str>) {
    if let Some(rest) = tool_name.strip_prefix("mcp.") {
        let server = rest.split('.').next();
        ("mcp", server)
    } else {
        ("builtin", None)
    }
}

fn closest_tool_matches(tool_names: &[String], query: &str, limit: usize) -> Vec<String> {
    let q = query.to_ascii_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    let mut matches = tool_names
        .iter()
        .filter(|name| name.to_ascii_lowercase().contains(&q))
        .cloned()
        .collect::<Vec<_>>();
    matches.sort();
    matches.truncate(limit);
    matches
}

fn indent_block(input: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    input
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn default_config() -> McpConfigFile {
    let mut servers = BTreeMap::new();
    servers.insert(
        "playwright".to_string(),
        McpServerConfig {
            command: "npx".to_string(),
            args: vec!["@playwright/mcp@latest".to_string()],
        },
    );
    McpConfigFile {
        schema_version: "openagent.mcp_servers.v1".to_string(),
        servers,
    }
}

pub fn load_or_create_config(path: &Path) -> anyhow::Result<McpConfigFile> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let def = default_config();
        let write_result =
            std::fs::write(path, serde_json::to_string_pretty(&def).unwrap_or_default());
        if write_result.is_err() {
            return Ok(def);
        }
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read MCP config at {}", path.display()))?;
    let cfg: McpConfigFile = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse MCP config at {}", path.display()))?;
    Ok(cfg)
}

pub async fn doctor_server(path: &Path, name: &str) -> anyhow::Result<usize> {
    let cfg = load_or_create_config(path)?;
    let srv = cfg
        .servers
        .get(name)
        .ok_or_else(|| anyhow!("MCP server '{}' not found", name))?;
    let client = McpClient::spawn(name, &srv.command, &srv.args).await?;
    client.initialize(Duration::from_secs(5)).await?;
    let tools = client.tools_list(Duration::from_secs(5)).await?;
    Ok(tools.len())
}

pub fn list_servers(path: &Path) -> anyhow::Result<Vec<String>> {
    let cfg = load_or_create_config(path)?;
    let mut names = cfg.servers.keys().cloned().collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use crate::mcp::types::McpTool;
    use crate::types::SideEffects;
    use crate::types::ToolDef;

    fn tool_def_from_mcp(server: &str, tool: &McpTool) -> ToolDef {
        ToolDef {
            name: format!("mcp.{}.{}", server, tool.name),
            description: tool.description.clone(),
            parameters: tool
                .input_schema
                .clone()
                .unwrap_or_else(|| json!({"type":"object"})),
            side_effects: SideEffects::Network,
        }
    }

    #[test]
    fn naming_conversion() {
        let t = McpTool {
            name: "echo".to_string(),
            description: "Echo".to_string(),
            input_schema: Some(json!({"type":"object"})),
        };
        let out = tool_def_from_mcp("stub", &t);
        assert_eq!(out.name, "mcp.stub.echo");
    }

    #[test]
    fn configured_catalog_hash_is_stable_for_same_defs() {
        let defs = vec![ToolDef {
            name: "mcp.stub.echo".to_string(),
            description: "Echo".to_string(),
            parameters: json!({"type":"object","properties":{"x":{"type":"string"}}}),
            side_effects: SideEffects::Network,
        }];
        let reg_a = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: BTreeMap::new(),
            tool_defs: defs.clone(),
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        let reg_b = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: BTreeMap::new(),
            tool_defs: defs,
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        let a = reg_a.configured_tool_catalog_hash_hex().expect("hash a");
        let b = reg_b.configured_tool_catalog_hash_hex().expect("hash b");
        assert_eq!(a, b);
    }

    #[test]
    fn truncate_utf8_to_bytes_preserves_char_boundary() {
        let input = "abc🙂def";
        let (truncated, was_truncated) = super::truncate_utf8_to_bytes(input, 5);
        assert!(was_truncated);
        assert_eq!(truncated, "abc");
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());

        let (full, was_truncated) = super::truncate_utf8_to_bytes(input, input.len());
        assert!(!was_truncated);
        assert_eq!(full, input);
    }

    #[test]
    fn model_facing_mcp_description_is_local_generated() {
        let desc = super::model_facing_mcp_tool_description("stub", "mcp.stub.echo");
        assert_eq!(
            desc,
            "MCP tool from stub. Use /tool docs mcp.stub.echo for details."
        );
    }

    #[test]
    fn raw_doc_meta_caps_but_hashes_full_description() {
        let raw = format!(
            "{}🙂",
            "x".repeat(super::MCP_MAX_RAW_DESCRIPTION_BYTES + 32)
        );
        let meta = super::build_mcp_tool_doc_meta(&raw);
        assert!(meta.raw_description_truncated);
        let capped = meta.raw_description.expect("raw description");
        assert!(capped.len() <= super::MCP_MAX_RAW_DESCRIPTION_BYTES);
        assert!(std::str::from_utf8(capped.as_bytes()).is_ok());
        assert_eq!(
            meta.raw_description_hash,
            Some(crate::store::sha256_hex(raw.as_bytes()))
        );
    }

    #[test]
    fn docs_hash_changes_when_only_description_changes() {
        let defs = vec![ToolDef {
            name: "mcp.stub.echo".to_string(),
            description: "MCP tool from stub. Use /tool docs mcp.stub.echo for details."
                .to_string(),
            parameters: json!({"type":"object","properties":{"x":{"type":"string"}}}),
            side_effects: SideEffects::Network,
        }];
        let mut docs_a = BTreeMap::new();
        docs_a.insert(
            "mcp.stub.echo".to_string(),
            super::McpToolDocMeta {
                raw_description: Some("Echo arguments".to_string()),
                raw_description_hash: Some(crate::store::sha256_hex("Echo arguments".as_bytes())),
                raw_description_truncated: false,
            },
        );
        let mut docs_b = BTreeMap::new();
        docs_b.insert(
            "mcp.stub.echo".to_string(),
            super::McpToolDocMeta {
                raw_description: Some("Echo arguments but different docs".to_string()),
                raw_description_hash: Some(crate::store::sha256_hex(
                    "Echo arguments but different docs".as_bytes(),
                )),
                raw_description_truncated: false,
            },
        );
        let reg_a = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: docs_a,
            tool_defs: defs.clone(),
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        let reg_b = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: docs_b,
            tool_defs: defs,
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        assert_eq!(
            reg_a.configured_tool_catalog_hash_hex().expect("catalog a"),
            reg_b.configured_tool_catalog_hash_hex().expect("catalog b")
        );
        assert_ne!(
            reg_a.configured_tool_docs_hash_hex().expect("docs a"),
            reg_b.configured_tool_docs_hash_hex().expect("docs b")
        );
    }

    #[test]
    fn normalized_description_preview_collapses_whitespace() {
        let a = super::normalized_description_preview("Line1\n\n  Line2\tLine3");
        let b = super::normalized_description_preview("Line1 Line2 Line3");
        assert_eq!(a, "Line1 Line2 Line3");
        assert_eq!(a, b);
    }

    #[test]
    fn render_tool_docs_text_includes_docs_hash_and_preview() {
        let defs = vec![ToolDef {
            name: "mcp.stub.echo".to_string(),
            description: "MCP tool from stub. Use /tool docs mcp.stub.echo for details."
                .to_string(),
            parameters: json!({"type":"object","properties":{"msg":{"type":"string"}}}),
            side_effects: SideEffects::Network,
        }];
        let mut docs = BTreeMap::new();
        docs.insert(
            "mcp.stub.echo".to_string(),
            super::McpToolDocMeta {
                raw_description: Some("Echo arguments".to_string()),
                raw_description_hash: Some(crate::store::sha256_hex("Echo arguments".as_bytes())),
                raw_description_truncated: false,
            },
        );
        let reg = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: docs,
            tool_defs: defs,
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        let rendered = reg.render_tool_docs_text("mcp.stub.echo");
        assert!(rendered.contains("tool_name: mcp.stub.echo"));
        assert!(rendered.contains("docs_hash_v1: "));
        assert!(rendered.contains("raw_description_preview:\n  Echo arguments"));
        assert!(rendered.contains("parameters:\n  {"));
    }

    #[test]
    fn render_tool_docs_text_unknown_tool_shows_sorted_capped_matches() {
        let defs = vec![
            ToolDef {
                name: "mcp.alpha.echo".to_string(),
                description: "x".to_string(),
                parameters: json!({"type":"object"}),
                side_effects: SideEffects::Network,
            },
            ToolDef {
                name: "mcp.beta.echo".to_string(),
                description: "x".to_string(),
                parameters: json!({"type":"object"}),
                side_effects: SideEffects::Network,
            },
            ToolDef {
                name: "mcp.gamma.exec".to_string(),
                description: "x".to_string(),
                parameters: json!({"type":"object"}),
                side_effects: SideEffects::Network,
            },
        ];
        let reg = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: BTreeMap::new(),
            tool_defs: defs,
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        let rendered = reg.render_tool_docs_text("echo");
        assert!(rendered.starts_with("unknown tool: echo"));
        assert!(rendered.contains("closest_matches: mcp.alpha.echo, mcp.beta.echo"));
        assert!(!rendered.contains("mcp.gamma.exec"));
    }

    #[test]
    fn render_tool_docs_text_handles_missing_raw_docs() {
        let defs = vec![ToolDef {
            name: "mcp.stub.empty".to_string(),
            description: "MCP tool from stub. Use /tool docs mcp.stub.empty for details."
                .to_string(),
            parameters: json!({"type":"object"}),
            side_effects: SideEffects::Network,
        }];
        let reg = super::McpRegistry {
            clients: BTreeMap::new(),
            tool_map: BTreeMap::new(),
            tool_schema_map: BTreeMap::new(),
            tool_doc_meta_map: BTreeMap::new(),
            tool_defs: defs,
            timeout: std::time::Duration::from_secs(1),
            mcp_spool_dir: std::path::PathBuf::from("."),
        };
        let rendered = reg.render_tool_docs_text("mcp.stub.empty");
        assert!(rendered.contains("raw_description_hash: -"));
        assert!(rendered.contains("raw_description_truncated: false"));
        assert!(rendered.contains("raw_description_preview:\n  no docs available"));
    }
}
