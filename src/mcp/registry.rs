use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context};
use serde_json::json;

use crate::mcp::client::McpClient;
use crate::mcp::types::{McpConfigFile, McpServerConfig};
use crate::types::{Message, Role, ToolCall, ToolDef};

pub struct McpRegistry {
    clients: BTreeMap<String, McpClient>,
    tool_map: BTreeMap<String, (String, String)>,
    tool_defs: Vec<ToolDef>,
    timeout: Duration,
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
        let mut tool_defs = Vec::new();

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
                tool_map.insert(namespaced.clone(), (name.clone(), tool.name.clone()));
                tool_defs.push(ToolDef {
                    name: namespaced,
                    description: tool.description.clone(),
                    parameters: tool
                        .input_schema
                        .clone()
                        .unwrap_or_else(|| json!({"type":"object"})),
                });
            }
            clients.insert(name.clone(), client);
        }

        tool_defs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            clients,
            tool_map,
            tool_defs,
            timeout,
        })
    }

    pub fn tool_defs(&self) -> Vec<ToolDef> {
        self.tool_defs.clone()
    }

    pub async fn call_namespaced_tool(&self, tc: &ToolCall) -> anyhow::Result<Message> {
        let (server, tool) = self
            .tool_map
            .get(&tc.name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown MCP tool '{}'", tc.name))?;
        let client = self
            .clients
            .get(&server)
            .ok_or_else(|| anyhow!("MCP server '{}' not active", server))?;
        let result = client
            .tools_call(&tool, tc.arguments.clone(), self.timeout)
            .await?;
        Ok(Message {
            role: Role::Tool,
            content: Some(
                json!({
                    "mcp": {
                        "server": server,
                        "tool": tool,
                        "result": result
                    }
                })
                .to_string(),
            ),
            tool_call_id: Some(tc.id.clone()),
            tool_name: Some(tc.name.clone()),
            tool_calls: None,
        })
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
    use serde_json::json;

    use crate::mcp::types::McpTool;
    use crate::types::ToolDef;

    fn tool_def_from_mcp(server: &str, tool: &McpTool) -> ToolDef {
        ToolDef {
            name: format!("mcp.{}.{}", server, tool.name),
            description: tool.description.clone(),
            parameters: tool
                .input_schema
                .clone()
                .unwrap_or_else(|| json!({"type":"object"})),
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
}
