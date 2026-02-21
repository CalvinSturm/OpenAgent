use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::{ModelProvider, StreamDelta, ToolCallFragment};
use crate::types::{GenerateRequest, GenerateResponse, Message, Role, ToolCall};

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    client: Client,
    base_url: String,
}

impl OllamaProvider {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct OllamaToolEnvelope {
    #[serde(rename = "type")]
    tool_type: String,
    function: OllamaToolFunction,
}

#[derive(Debug, Serialize)]
struct OllamaToolFunction {
    name: String,
    description: String,
    parameters: Value,
}

#[derive(Debug, Serialize)]
struct OllamaMessageOut {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessageOut>,
    tools: Vec<OllamaToolEnvelope>,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaMessageIn,
    #[serde(default)]
    done: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaMessageIn {
    content: Option<String>,
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[derive(Debug, Deserialize)]
struct OllamaToolCall {
    function: OllamaFunctionCall,
}

#[derive(Debug, Deserialize)]
struct OllamaFunctionCall {
    name: String,
    arguments: Value,
}

#[async_trait]
impl ModelProvider for OllamaProvider {
    async fn generate(&self, req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
        let url = format!("{}/api/chat", self.base_url);
        let tools = req
            .tools
            .into_iter()
            .map(|t| OllamaToolEnvelope {
                tool_type: "function".to_string(),
                function: OllamaToolFunction {
                    name: t.name,
                    description: t.description,
                    parameters: t.parameters,
                },
            })
            .collect::<Vec<_>>();

        let messages = req
            .messages
            .into_iter()
            .map(|m| {
                let role = match m.role {
                    Role::System | Role::Developer => "system",
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::Tool => "tool",
                }
                .to_string();
                OllamaMessageOut {
                    role,
                    content: m.content,
                    tool_name: m.tool_name,
                }
            })
            .collect::<Vec<_>>();

        let payload = OllamaRequest {
            model: req.model,
            messages,
            tools,
            stream: false,
        };

        let resp: OllamaResponse = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to call Ollama endpoint")?
            .error_for_status()
            .context("Ollama endpoint returned error status")?
            .json()
            .await
            .context("failed to parse Ollama JSON response")?;

        let tool_calls = resp
            .message
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(idx, tc)| ToolCall {
                id: format!("ollama_tc_{idx}"),
                name: tc.function.name,
                arguments: tc.function.arguments,
            })
            .collect::<Vec<_>>();

        Ok(GenerateResponse {
            assistant: Message {
                role: Role::Assistant,
                content: resp.message.content,
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            tool_calls,
        })
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    async fn generate_streaming(
        &self,
        req: GenerateRequest,
        on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    ) -> anyhow::Result<GenerateResponse> {
        let url = format!("{}/api/chat", self.base_url);
        let tools = req
            .tools
            .into_iter()
            .map(|t| OllamaToolEnvelope {
                tool_type: "function".to_string(),
                function: OllamaToolFunction {
                    name: t.name,
                    description: t.description,
                    parameters: t.parameters,
                },
            })
            .collect::<Vec<_>>();

        let messages = req
            .messages
            .into_iter()
            .map(|m| {
                let role = match m.role {
                    Role::System | Role::Developer => "system",
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::Tool => "tool",
                }
                .to_string();
                OllamaMessageOut {
                    role,
                    content: m.content,
                    tool_name: m.tool_name,
                }
            })
            .collect::<Vec<_>>();

        let payload = OllamaRequest {
            model: req.model,
            messages,
            tools,
            stream: true,
        };

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to call Ollama endpoint")?
            .error_for_status()
            .context("Ollama endpoint returned error status")?;

        let mut stream = response.bytes_stream();
        let mut text_buf = String::new();
        let mut content_accum = String::new();
        let mut tool_calls = Vec::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("failed reading Ollama stream chunk")?;
            text_buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = text_buf.find('\n') {
                let line = text_buf[..pos].trim().to_string();
                text_buf = text_buf[pos + 1..].to_string();
                if line.is_empty() {
                    continue;
                }
                handle_ollama_stream_json(&line, on_delta, &mut content_accum, &mut tool_calls)?;
            }
        }

        Ok(GenerateResponse {
            assistant: Message {
                role: Role::Assistant,
                content: if content_accum.is_empty() {
                    None
                } else {
                    Some(content_accum)
                },
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            tool_calls,
        })
    }
}

fn handle_ollama_stream_json(
    line: &str,
    on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    content_accum: &mut String,
    tool_calls: &mut Vec<ToolCall>,
) -> anyhow::Result<()> {
    let ev: OllamaResponse =
        serde_json::from_str(line).context("failed parsing Ollama stream event")?;
    if let Some(content) = ev.message.content {
        if !content.is_empty() {
            content_accum.push_str(&content);
            on_delta(StreamDelta::Content(content));
        }
    }
    if let Some(tcs) = ev.message.tool_calls {
        for tc in tcs {
            let idx = tool_calls.len();
            let id = format!("ollama_tc_{idx}");
            on_delta(StreamDelta::ToolCallFragment(ToolCallFragment {
                index: idx,
                id: Some(id.clone()),
                name: Some(tc.function.name.clone()),
                arguments_fragment: Some(tc.function.arguments.to_string()),
                complete: ev.done,
            }));
            tool_calls.push(ToolCall {
                id,
                name: tc.function.name,
                arguments: tc.function.arguments,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::handle_ollama_stream_json;
    use crate::providers::StreamDelta;

    #[test]
    fn parses_ollama_stream_json() {
        let mut deltas = Vec::new();
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        handle_ollama_stream_json(
            r#"{"message":{"content":"Hi","tool_calls":[{"function":{"name":"read_file","arguments":{"path":"a.txt"}}}]},"done":false}"#,
            &mut |d| deltas.push(d),
            &mut content,
            &mut tool_calls,
        )
        .expect("parse");
        assert_eq!(content, "Hi");
        assert_eq!(tool_calls.len(), 1);
        assert!(matches!(deltas[0], StreamDelta::Content(_)));
    }
}
