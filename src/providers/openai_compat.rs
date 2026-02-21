use anyhow::{anyhow, Context};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::{ModelProvider, StreamDelta, ToolCallFragment};
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
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: OpenAiMessage,
    #[serde(default)]
    delta: OpenAiMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Debug, Deserialize)]
struct OpenAiToolCall {
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    id: String,
    #[serde(default)]
    function: OpenAiFunctionCall,
}

#[derive(Debug, Default, Deserialize)]
struct OpenAiFunctionCall {
    #[serde(default)]
    name: String,
    #[serde(default)]
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

    fn supports_streaming(&self) -> bool {
        true
    }

    async fn generate_streaming(
        &self,
        req: GenerateRequest,
        on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    ) -> anyhow::Result<GenerateResponse> {
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
            stream: true,
        };

        let mut request = self.client.post(url).json(&payload);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let response = request
            .send()
            .await
            .context("failed to call OpenAI-compatible endpoint")?
            .error_for_status()
            .context("OpenAI-compatible endpoint returned error status")?;

        let mut stream = response.bytes_stream();
        let mut text_buf = String::new();
        let mut content_accum = String::new();
        let mut partials: Vec<PartialToolCall> = Vec::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("failed reading OpenAI-compatible stream chunk")?;
            text_buf.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(pos) = text_buf.find('\n') {
                let line = text_buf[..pos].trim().to_string();
                text_buf = text_buf[pos + 1..].to_string();
                if line.is_empty() || !line.starts_with("data:") {
                    continue;
                }
                let payload = line.trim_start_matches("data:").trim();
                if payload == "[DONE]" {
                    continue;
                }
                handle_openai_stream_json(payload, on_delta, &mut content_accum, &mut partials)?;
            }
        }

        let tool_calls = finalize_tool_calls(partials);
        let content = if content_accum.is_empty() {
            None
        } else {
            Some(content_accum)
        };

        Ok(GenerateResponse {
            assistant: Message {
                role: Role::Assistant,
                content,
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            },
            tool_calls,
        })
    }
}

#[derive(Debug, Default, Clone)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
}

fn handle_openai_stream_json(
    payload: &str,
    on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    content_accum: &mut String,
    partials: &mut Vec<PartialToolCall>,
) -> anyhow::Result<()> {
    let item: OpenAiResponse =
        serde_json::from_str(payload).context("failed parsing OpenAI-compatible stream event")?;
    if let Some(choice) = item.choices.into_iter().next() {
        if let Some(content) = choice.delta.content {
            if !content.is_empty() {
                content_accum.push_str(&content);
                on_delta(StreamDelta::Content(content));
            }
        }
        if let Some(tool_calls) = choice.delta.tool_calls {
            for tc in tool_calls {
                let idx = tc.index.unwrap_or(partials.len());
                ensure_partial_len(partials, idx + 1);
                let p = &mut partials[idx];
                if !tc.id.is_empty() {
                    p.id = tc.id.clone();
                }
                if !tc.function.name.is_empty() {
                    p.name = tc.function.name.clone();
                }
                if let Some(fragment) = value_to_string_fragment(&tc.function.arguments) {
                    p.arguments.push_str(&fragment);
                    on_delta(StreamDelta::ToolCallFragment(ToolCallFragment {
                        index: idx,
                        id: if p.id.is_empty() {
                            None
                        } else {
                            Some(p.id.clone())
                        },
                        name: if p.name.is_empty() {
                            None
                        } else {
                            Some(p.name.clone())
                        },
                        arguments_fragment: Some(fragment),
                        complete: choice.finish_reason.as_deref() == Some("tool_calls"),
                    }));
                }
            }
        }
    }
    Ok(())
}

fn ensure_partial_len(partials: &mut Vec<PartialToolCall>, len: usize) {
    while partials.len() < len {
        partials.push(PartialToolCall::default());
    }
}

fn value_to_string_fragment(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn finalize_tool_calls(partials: Vec<PartialToolCall>) -> Vec<ToolCall> {
    partials
        .into_iter()
        .enumerate()
        .filter(|(_, p)| !p.name.is_empty())
        .map(|(i, p)| ToolCall {
            id: if p.id.is_empty() {
                format!("openai_tc_{i}")
            } else {
                p.id
            },
            name: p.name,
            arguments: match serde_json::from_str::<Value>(&p.arguments) {
                Ok(v) => v,
                Err(_) => Value::String(p.arguments),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{finalize_tool_calls, handle_openai_stream_json, PartialToolCall};
    use crate::providers::StreamDelta;

    #[test]
    fn parses_openai_stream_content_and_tool() {
        let mut deltas = Vec::new();
        let mut content = String::new();
        let mut partials = Vec::<PartialToolCall>::new();
        handle_openai_stream_json(
            r#"{"choices":[{"delta":{"content":"hel"}}]}"#,
            &mut |d| deltas.push(d),
            &mut content,
            &mut partials,
        )
        .expect("parse1");
        handle_openai_stream_json(
            r#"{"choices":[{"delta":{"content":"lo","tool_calls":[{"index":0,"id":"c1","function":{"name":"list_dir","arguments":"{\"path\":\".\"}"}}]},"finish_reason":"tool_calls"}]}"#,
            &mut |d| deltas.push(d),
            &mut content,
            &mut partials,
        )
        .expect("parse2");
        let tc = finalize_tool_calls(partials);
        assert_eq!(content, "hello");
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0].name, "list_dir");
        assert!(matches!(deltas[0], StreamDelta::Content(_)));
    }
}
