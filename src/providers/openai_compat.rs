use anyhow::{anyhow, Context};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::http::{
    classify_reqwest_error, classify_status, deterministic_backoff_ms, HttpConfig, ProviderError,
    ProviderErrorKind, RetryRecord,
};
use crate::providers::{ModelProvider, StreamDelta, ToolCallFragment};
use crate::types::{GenerateRequest, GenerateResponse, Message, Role, TokenUsage, ToolCall};

#[derive(Debug, Clone)]
pub struct OpenAiCompatProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    http: HttpConfig,
}

impl OpenAiCompatProvider {
    pub fn new(
        base_url: String,
        api_key: Option<String>,
        http: HttpConfig,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .connect_timeout(http.connect_timeout())
            .timeout(http.request_timeout())
            .build()
            .context("failed to build OpenAI-compatible HTTP client")?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            http,
        })
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OpenAiToolEnvelope>>,
    tool_choice: String,
    temperature: f32,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
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

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
    #[serde(default)]
    total_tokens: Option<u64>,
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
        let payload = to_request(req, false);
        let max_attempts = self.http.http_max_retries + 1;
        let mut retries = Vec::<RetryRecord>::new();
        for attempt in 1..=max_attempts {
            let mut request = self.client.post(&url).json(&payload);
            if let Some(key) = &self.api_key {
                request = request.bearer_auth(key);
            }
            let sent = request.send().await;
            let response = match sent {
                Ok(r) => r,
                Err(e) => {
                    let cls = classify_reqwest_error(&e);
                    if cls.retryable && attempt < max_attempts {
                        let backoff = deterministic_backoff_ms(self.http, attempt - 1);
                        retries.push(RetryRecord {
                            attempt,
                            max_attempts,
                            kind: cls.kind,
                            status: cls.status,
                            backoff_ms: backoff,
                        });
                        tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                        continue;
                    }
                    return Err(anyhow!(ProviderError {
                        kind: cls.kind,
                        http_status: cls.status,
                        retryable: cls.retryable,
                        attempt,
                        max_attempts,
                        message: format!("failed to call OpenAI-compatible endpoint: {e}"),
                        retries,
                    }));
                }
            };
            let status = response.status();
            if !status.is_success() {
                let cls = classify_status(status.as_u16());
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<body unavailable>".to_string());
                if cls.retryable && attempt < max_attempts {
                    let backoff = deterministic_backoff_ms(self.http, attempt - 1);
                    retries.push(RetryRecord {
                        attempt,
                        max_attempts,
                        kind: cls.kind,
                        status: Some(status.as_u16()),
                        backoff_ms: backoff,
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                    continue;
                }
                return Err(anyhow!(ProviderError {
                    kind: cls.kind,
                    http_status: Some(status.as_u16()),
                    retryable: cls.retryable,
                    attempt,
                    max_attempts,
                    message: format!(
                        "OpenAI-compatible endpoint returned HTTP {}: {}",
                        status.as_u16(),
                        truncate_for_error(&body, 200)
                    ),
                    retries,
                }));
            }
            let bytes = response
                .bytes()
                .await
                .context("failed to read OpenAI-compatible response body")?;
            if bytes.len() > self.http.max_response_bytes {
                return Err(anyhow!(ProviderError {
                    kind: ProviderErrorKind::PayloadTooLarge,
                    http_status: Some(status.as_u16()),
                    retryable: false,
                    attempt,
                    max_attempts,
                    message: format!(
                        "response exceeded max bytes: {} > {}",
                        bytes.len(),
                        self.http.max_response_bytes
                    ),
                    retries,
                }));
            }
            let resp: OpenAiResponse = serde_json::from_slice(&bytes)
                .context("failed to parse OpenAI-compatible JSON response")?;
            return map_openai_response(resp).map_err(|e| {
                anyhow!(ProviderError {
                    kind: ProviderErrorKind::Parse,
                    http_status: Some(status.as_u16()),
                    retryable: false,
                    attempt,
                    max_attempts,
                    message: e.to_string(),
                    retries,
                })
            });
        }
        Err(anyhow!("unexpected retry loop termination"))
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
        let payload = to_request(req, true);
        let max_attempts = self.http.http_max_retries + 1;
        let mut retries = Vec::<RetryRecord>::new();

        for attempt in 1..=max_attempts {
            let mut request = self.client.post(&url).json(&payload);
            if let Some(key) = &self.api_key {
                request = request.bearer_auth(key);
            }
            let sent = request.send().await;
            let response = match sent {
                Ok(r) => r,
                Err(e) => {
                    let cls = classify_reqwest_error(&e);
                    if cls.retryable && attempt < max_attempts {
                        let backoff = deterministic_backoff_ms(self.http, attempt - 1);
                        retries.push(RetryRecord {
                            attempt,
                            max_attempts,
                            kind: cls.kind,
                            status: cls.status,
                            backoff_ms: backoff,
                        });
                        tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                        continue;
                    }
                    return Err(anyhow!(ProviderError {
                        kind: cls.kind,
                        http_status: cls.status,
                        retryable: cls.retryable,
                        attempt,
                        max_attempts,
                        message: format!("failed to call OpenAI-compatible endpoint: {e}"),
                        retries,
                    }));
                }
            };

            let status = response.status();
            if !status.is_success() {
                let cls = classify_status(status.as_u16());
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<body unavailable>".to_string());
                if cls.retryable && attempt < max_attempts {
                    let backoff = deterministic_backoff_ms(self.http, attempt - 1);
                    retries.push(RetryRecord {
                        attempt,
                        max_attempts,
                        kind: cls.kind,
                        status: Some(status.as_u16()),
                        backoff_ms: backoff,
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                    continue;
                }
                return Err(anyhow!(ProviderError {
                    kind: cls.kind,
                    http_status: Some(status.as_u16()),
                    retryable: cls.retryable,
                    attempt,
                    max_attempts,
                    message: format!(
                        "OpenAI-compatible endpoint returned HTTP {}: {}",
                        status.as_u16(),
                        truncate_for_error(&body, 200)
                    ),
                    retries,
                }));
            }

            let mut stream = response.bytes_stream();
            let mut text_buf = String::new();
            let mut content_accum = String::new();
            let mut partials: Vec<PartialToolCall> = Vec::new();
            let mut total_bytes: usize = 0;
            let mut emitted_any = false;
            let mut saw_done = false;

            loop {
                let next = tokio::time::timeout(self.http.idle_timeout(), stream.next()).await;
                let maybe_chunk = match next {
                    Ok(v) => v,
                    Err(_) => {
                        if !emitted_any && attempt < max_attempts {
                            let backoff = deterministic_backoff_ms(self.http, attempt - 1);
                            retries.push(RetryRecord {
                                attempt,
                                max_attempts,
                                kind: ProviderErrorKind::Timeout,
                                status: Some(status.as_u16()),
                                backoff_ms: backoff,
                            });
                            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                            break;
                        }
                        return Err(anyhow!(ProviderError {
                            kind: ProviderErrorKind::Timeout,
                            http_status: Some(status.as_u16()),
                            retryable: !emitted_any,
                            attempt,
                            max_attempts,
                            message: "stream idle timeout exceeded".to_string(),
                            retries,
                        }));
                    }
                };

                let Some(chunk_res) = maybe_chunk else {
                    break;
                };

                let chunk = match chunk_res {
                    Ok(c) => c,
                    Err(e) => {
                        let cls = classify_reqwest_error(&e);
                        if cls.retryable && !emitted_any && attempt < max_attempts {
                            let backoff = deterministic_backoff_ms(self.http, attempt - 1);
                            retries.push(RetryRecord {
                                attempt,
                                max_attempts,
                                kind: cls.kind,
                                status: cls.status.or(Some(status.as_u16())),
                                backoff_ms: backoff,
                            });
                            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                            break;
                        }
                        return Err(anyhow!(ProviderError {
                            kind: cls.kind,
                            http_status: cls.status.or(Some(status.as_u16())),
                            retryable: cls.retryable && !emitted_any,
                            attempt,
                            max_attempts,
                            message: format!("failed reading stream chunk: {e}"),
                            retries,
                        }));
                    }
                };

                total_bytes = total_bytes.saturating_add(chunk.len());
                if total_bytes > self.http.max_response_bytes {
                    return Err(anyhow!(ProviderError {
                        kind: ProviderErrorKind::PayloadTooLarge,
                        http_status: Some(status.as_u16()),
                        retryable: false,
                        attempt,
                        max_attempts,
                        message: format!(
                            "stream exceeded max bytes: {} > {}",
                            total_bytes, self.http.max_response_bytes
                        ),
                        retries,
                    }));
                }

                let mut chunk_text = String::from_utf8_lossy(&chunk).to_string();
                chunk_text = chunk_text.replace("\r\n", "\n").replace('\r', "\n");
                text_buf.push_str(&chunk_text);

                for raw_event in drain_sse_events(&mut text_buf) {
                    if raw_event.len() > self.http.max_line_bytes {
                        return Err(anyhow!(ProviderError {
                            kind: ProviderErrorKind::PayloadTooLarge,
                            http_status: Some(status.as_u16()),
                            retryable: false,
                            attempt,
                            max_attempts,
                            message: format!(
                                "sse event exceeded max bytes: {} > {}",
                                raw_event.len(),
                                self.http.max_line_bytes
                            ),
                            retries,
                        }));
                    }
                    match parse_sse_event_payload(&raw_event) {
                        Ok(Some(payload_text)) => {
                            if payload_text == "[DONE]" {
                                saw_done = true;
                                continue;
                            }
                            if let Err(e) = handle_openai_stream_json(
                                &payload_text,
                                on_delta,
                                &mut content_accum,
                                &mut partials,
                            ) {
                                return Err(anyhow!(ProviderError {
                                    kind: ProviderErrorKind::Parse,
                                    http_status: Some(status.as_u16()),
                                    retryable: false,
                                    attempt,
                                    max_attempts,
                                    message: format!(
                                        "malformed OpenAI-compatible stream event: {}",
                                        truncate_for_error(&format!("{e}"), 200)
                                    ),
                                    retries,
                                }));
                            }
                            emitted_any = true;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            return Err(anyhow!(ProviderError {
                                kind: ProviderErrorKind::Parse,
                                http_status: Some(status.as_u16()),
                                retryable: false,
                                attempt,
                                max_attempts,
                                message: format!(
                                    "invalid SSE event: {}",
                                    truncate_for_error(&format!("{e}"), 200)
                                ),
                                retries,
                            }));
                        }
                    }
                }
            }

            if attempt < max_attempts
                && !saw_done
                && !content_accum.is_empty()
                && partials.is_empty()
            {
                // stream ended unexpectedly after partial content; do not retry
            }

            if attempt < max_attempts && !saw_done && !emitted_any {
                continue;
            }

            let tool_calls = finalize_tool_calls(partials);
            let content = if content_accum.is_empty() {
                None
            } else {
                Some(content_accum)
            };
            return Ok(GenerateResponse {
                assistant: Message {
                    role: Role::Assistant,
                    content,
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: None,
                },
                tool_calls,
                usage: None,
            });
        }

        Err(anyhow!(ProviderError {
            kind: ProviderErrorKind::Other,
            http_status: None,
            retryable: false,
            attempt: self.http.http_max_retries + 1,
            max_attempts: self.http.http_max_retries + 1,
            message: "stream ended before response completed".to_string(),
            retries: Vec::new(),
        }))
    }
}

fn drain_sse_events(buf: &mut String) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(pos) = buf.find("\n\n") {
        out.push(buf[..pos].to_string());
        *buf = buf[pos + 2..].to_string();
    }
    out
}

fn to_request(req: GenerateRequest, stream: bool) -> OpenAiRequest {
    let tools = req.tools.map(|list| {
        list.into_iter()
            .map(|t| OpenAiToolEnvelope {
                tool_type: "function".to_string(),
                function: OpenAiToolFunction {
                    name: t.name,
                    description: t.description,
                    parameters: t.parameters,
                },
            })
            .collect::<Vec<_>>()
    });
    OpenAiRequest {
        model: req.model,
        messages: req.messages,
        tools,
        tool_choice: "auto".to_string(),
        temperature: 0.2,
        stream,
    }
}

fn map_openai_response(resp: OpenAiResponse) -> anyhow::Result<GenerateResponse> {
    let usage = resp.usage.as_ref().map(|u| TokenUsage {
        prompt_tokens: to_u32_opt(u.prompt_tokens),
        completion_tokens: to_u32_opt(u.completion_tokens),
        total_tokens: to_u32_opt(u.total_tokens),
    });
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
        usage,
    })
}

fn to_u32_opt(v: Option<u64>) -> Option<u32> {
    v.and_then(|x| u32::try_from(x).ok())
}

#[derive(Debug, Default, Clone)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
}

fn parse_sse_event_payload(raw_event: &str) -> anyhow::Result<Option<String>> {
    let mut data_lines = Vec::new();
    for line in raw_event.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(':') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("data:") {
            data_lines.push(rest.trim_start().to_string());
        }
    }
    if data_lines.is_empty() {
        return Ok(None);
    }
    Ok(Some(data_lines.join("\n")))
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

fn truncate_for_error(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        drain_sse_events, finalize_tool_calls, handle_openai_stream_json, map_openai_response,
        parse_sse_event_payload, OpenAiResponse, PartialToolCall,
    };
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

    #[test]
    fn parses_sse_data_block() {
        let event = "data: {\"x\":1}\n\n";
        let p = parse_sse_event_payload(event).expect("parse");
        assert_eq!(p.as_deref(), Some("{\"x\":1}"));
    }

    #[test]
    fn drains_sse_events_across_chunk_boundaries() {
        let mut buf = "data: {\"a\":1}\n".to_string();
        assert!(drain_sse_events(&mut buf).is_empty());
        buf.push('\n');
        buf.push_str("data: {\"b\":2}\n\n");
        let ev = drain_sse_events(&mut buf);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0], "data: {\"a\":1}");
        assert_eq!(ev[1], "data: {\"b\":2}");
    }

    #[test]
    fn parse_done_payload() {
        let p = parse_sse_event_payload("data: [DONE]\n\n").expect("parse");
        assert_eq!(p.as_deref(), Some("[DONE]"));
    }

    #[test]
    fn malformed_stream_json_returns_error() {
        let mut deltas = Vec::new();
        let mut content = String::new();
        let mut partials = Vec::<PartialToolCall>::new();
        let err = handle_openai_stream_json(
            "{\"choices\":[{\"delta\":{\"content\":\u{fffd}}}]}",
            &mut |d| deltas.push(d),
            &mut content,
            &mut partials,
        )
        .expect_err("expected parse error");
        assert!(err
            .to_string()
            .contains("failed parsing OpenAI-compatible stream event"));
    }

    #[test]
    fn maps_usage_tokens_when_present() {
        let resp: OpenAiResponse = serde_json::from_str(
            r#"{
                "choices":[{"message":{"content":"ok"}}],
                "usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}
            }"#,
        )
        .expect("parse");
        let mapped = map_openai_response(resp).expect("map");
        let usage = mapped.usage.expect("usage");
        assert_eq!(usage.prompt_tokens, Some(12));
        assert_eq!(usage.completion_tokens, Some(5));
        assert_eq!(usage.total_tokens, Some(17));
    }
}
