use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{oneshot, Mutex};

use crate::mcp::types::McpTool;

pub struct McpClient {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    next_id: AtomicU64,
}

impl McpClient {
    pub async fn spawn(name: &str, command: &str, args: &[String]) -> anyhow::Result<Self> {
        let mut child = Command::new(command);
        child
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = child
            .spawn()
            .with_context(|| format!("failed to spawn MCP server '{name}'"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open MCP stdin for '{name}'"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to open MCP stdout for '{name}'"))?;
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = Arc::clone(&pending);

        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            loop {
                match reader.next_line().await {
                    Ok(Some(line)) => {
                        let parsed: Result<Value, _> = serde_json::from_str(&line);
                        let Ok(msg) = parsed else {
                            continue;
                        };
                        let Some(id) = msg.get("id").and_then(|v| v.as_u64()) else {
                            continue;
                        };
                        let tx = {
                            let mut map = pending_reader.lock().await;
                            map.remove(&id)
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(msg);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            child,
            stdin: Arc::new(Mutex::new(stdin)),
            pending,
            next_id: AtomicU64::new(1),
        })
    }

    pub async fn initialize(&self, timeout: Duration) -> anyhow::Result<()> {
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "openagent", "version": "0.1.0" }
        });
        let _ = self.call("initialize", params, timeout).await?;
        Ok(())
    }

    pub async fn tools_list(&self, timeout: Duration) -> anyhow::Result<Vec<McpTool>> {
        let result = self.call("tools/list", json!({}), timeout).await?;
        let tools_value = result.get("tools").cloned().unwrap_or(Value::Array(vec![]));
        let tools: Vec<McpTool> = serde_json::from_value(tools_value)?;
        Ok(tools)
    }

    pub async fn tools_call(
        &self,
        name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> anyhow::Result<Value> {
        self.call(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments
            }),
            timeout,
        )
        .await
    }

    async fn call(&self, method: &str, params: Value, timeout: Duration) -> anyhow::Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = json!({
            "jsonrpc":"2.0",
            "id": id,
            "method": method,
            "params": params
        });
        let line = serde_json::to_string(&req)?;
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(id, tx);
        }
        {
            let mut stdin = self.stdin.lock().await;
            stdin
                .write_all(format!("{line}\n").as_bytes())
                .await
                .context("failed to write MCP request")?;
            stdin.flush().await.context("failed to flush MCP request")?;
        }

        let msg = tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| anyhow!("MCP call timed out for method '{method}'"))?
            .map_err(|_| anyhow!("MCP response channel closed for method '{method}'"))?;

        if let Some(err) = msg.get("error") {
            return Err(anyhow!("MCP error for method '{}': {}", method, err));
        }
        Ok(msg.get("result").cloned().unwrap_or(Value::Null))
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}
