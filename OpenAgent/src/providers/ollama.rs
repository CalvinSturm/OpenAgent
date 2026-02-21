use anyhow::Context;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::ModelProvider;
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
}
