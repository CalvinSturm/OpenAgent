use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use anyhow::{anyhow, Context};
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
    #[allow(dead_code)]
    tool_doc_meta_map: BTreeMap<String, McpToolDocMeta>,
    tool_defs: Vec<ToolDef>,
    timeout: Duration,
    mcp_spool_dir: PathBuf,
}

#[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn tool_doc_meta(&self, namespaced_tool: &str) -> Option<&McpToolDocMeta> {
        self.tool_doc_meta_map.get(namespaced_tool)
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
}
