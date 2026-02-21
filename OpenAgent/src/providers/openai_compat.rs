use anyhow::{anyhow, Context};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::ModelProvider;
use crate::types::{GenerateRequest, GenerateResponse, Message, Role, ToolCall};

#[derive(Debug, Clone)]
pub struct OpenAiCompatProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl OpenAiCompatProvider {
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
        }
    }
}

#[derive(Debug, Serialize)]
struct OpenAiToolEnvelope {
    #[serde(rename = "type")]
    tool_type: String,
    function: OpenAiToolFunction,
}

#[derive(Debug, Serialize)]
struct OpenAiToolFunction {
    name: String,
    description: String,
    parameters: Value,
}

#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<Message>,
    tools: Vec<OpenAiToolEnvelope>,
    tool_choice: String,
    temperature: f32,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    content: Option<String>,
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Debug, Deserialize)]
struct OpenAiToolCall {
    id: String,
    function: OpenAiFunctionCall,
}

#[derive(Debug, Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    arguments: Value,
}

#[async_trait]
impl ModelProvider for OpenAiCompatProvider {
    async fn generate(&self, req: GenerateRequest) -> anyhow::Result<GenerateResponse> {
        let url = format!("{}/chat/completions", self.base_url);
        let tools = req
            .tools
            .into_iter()
            .map(|t| OpenAiToolEnvelope {
                tool_type: "function".to_string(),
                function: OpenAiToolFunction {
                    name: t.name,
                    description: t.description,
                    parameters: t.parameters,
                },
            })
            .collect::<Vec<_>>();

        let payload = OpenAiRequest {
            model: req.model,
            messages: req.messages,
            tools,
            tool_choice: "auto".to_string(),
            temperature: 0.2,
            stream: false,
        };

        let mut request = self.client.post(url).json(&payload);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let resp: OpenAiResponse = request
            .send()
            .await
            .context("failed to call OpenAI-compatible endpoint")?
            .error_for_status()
            .context("OpenAI-compatible endpoint returned error status")?
            .json()
            .await
            .context("failed to parse OpenAI-compatible JSON response")?;

        let first = resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("missing choices[0] in OpenAI-compatible response"))?;

        let mut tool_calls = Vec::new();
        if let Some(tcalls) = first.message.tool_calls {
            for tc in tcalls {
                let arguments = match tc.function.arguments {
                    Value::String(s) => match serde_json::from_str::<Value>(&s) {
                        Ok(v) => v,
                        Err(_) => Value::String(s),
                    },
                    other => other,
                };
                tool_calls.push(ToolCall {
                    id: tc.id,
                    name: tc.function.name,
                    arguments,
                });
            }
        }

        Ok(GenerateResponse {
            assistant: Message {
                role: Role::Assistant,
                content: first.message.content,
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            tool_calls,
        })
    }
}
