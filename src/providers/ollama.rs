use anyhow::{anyhow, Context};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::common::{
    build_http_client, build_tool_envelopes, map_token_usage_triplet, truncate_error_display,
    truncate_for_error, ToolEnvelope as SharedToolEnvelope,
};
use crate::providers::http::{
    classify_reqwest_error, classify_status, deterministic_backoff_ms, HttpConfig, ProviderError,
    ProviderErrorKind, RetryRecord,
};
use crate::providers::{ModelProvider, StreamDelta, ToolCallFragment};
use crate::types::{GenerateRequest, GenerateResponse, Message, Role, ToolCall};

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    client: Client,
    base_url: String,
    http: HttpConfig,
}

impl OllamaProvider {
    pub fn new(base_url: String, http: HttpConfig) -> anyhow::Result<Self> {
        let client = build_http_client(http, "failed to build Ollama HTTP client")?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }
}

type OllamaToolEnvelope = SharedToolEnvelope;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OllamaToolEnvelope>>,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaMessageIn,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
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
        let payload = to_request(req, false);
        let max_attempts = self.http.http_max_retries + 1;
        let mut retries = Vec::<RetryRecord>::new();
        for attempt in 1..=max_attempts {
            let sent = self.client.post(&url).json(&payload).send().await;
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
                        message: format!("failed to call Ollama endpoint: {e}"),
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
                        "Ollama endpoint returned HTTP {}: {}",
                        status.as_u16(),
                        truncate_for_error(&body, 200)
                    ),
                    retries,
                }));
            }
            let bytes = response
                .bytes()
                .await
                .context("failed to read Ollama response body")?;
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
            let resp: OllamaResponse =
                serde_json::from_slice(&bytes).context("failed to parse Ollama JSON response")?;
            return Ok(map_ollama_response(resp));
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
        let url = format!("{}/api/chat", self.base_url);
        let payload = to_request(req, true);
        let max_attempts = self.http.http_max_retries + 1;
        let mut retries = Vec::<RetryRecord>::new();

        for attempt in 1..=max_attempts {
            let sent = self.client.post(&url).json(&payload).send().await;
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
                        message: format!("failed to call Ollama endpoint: {e}"),
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
                        "Ollama endpoint returned HTTP {}: {}",
                        status.as_u16(),
                        truncate_for_error(&body, 200)
                    ),
                    retries,
                }));
            }

            let mut stream = response.bytes_stream();
            let mut text_buf = String::new();
            let mut content_accum = String::new();
            let mut tool_calls = Vec::new();
            let mut total_bytes = 0usize;
            let mut emitted_any = false;

            loop {
                let maybe_chunk = if let Some(idle) = self.http.idle_timeout_opt() {
                    let next = tokio::time::timeout(idle, stream.next()).await;
                    match next {
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
                    }
                } else {
                    stream.next().await
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
                text_buf.push_str(&String::from_utf8_lossy(&chunk));
                for mut line in drain_json_lines(&mut text_buf) {
                    line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if line.len() > self.http.max_line_bytes {
                        return Err(anyhow!(ProviderError {
                            kind: ProviderErrorKind::PayloadTooLarge,
                            http_status: Some(status.as_u16()),
                            retryable: false,
                            attempt,
                            max_attempts,
                            message: format!(
                                "json line exceeded max bytes: {} > {}",
                                line.len(),
                                self.http.max_line_bytes
                            ),
                            retries,
                        }));
                    }
                    handle_ollama_stream_json(&line, on_delta, &mut content_accum, &mut tool_calls)
                        .map_err(|e| {
                            anyhow!(ProviderError {
                                kind: ProviderErrorKind::Parse,
                                http_status: Some(status.as_u16()),
                                retryable: false,
                                attempt,
                                max_attempts,
                                message: format!(
                                    "malformed Ollama stream line: {}",
                                    truncate_error_display(&e, 200)
                                ),
                                retries: retries.clone(),
                            })
                        })?;
                    emitted_any = true;
                }
            }

            if attempt < max_attempts && !emitted_any {
                continue;
            }

            return Ok(GenerateResponse {
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

fn drain_json_lines(buf: &mut String) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(pos) = buf.find('\n') {
        out.push(buf[..pos].to_string());
        *buf = buf[pos + 1..].to_string();
    }
    out
}

fn to_request(req: GenerateRequest, stream: bool) -> OllamaRequest {
    let tools = build_tool_envelopes(req.tools);
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
    OllamaRequest {
        model: req.model,
        messages,
        tools,
        stream,
    }
}

fn map_ollama_response(resp: OllamaResponse) -> GenerateResponse {
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

    GenerateResponse {
        assistant: Message {
            role: Role::Assistant,
            content: resp.message.content,
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        },
        tool_calls,
        usage: Some(map_token_usage_triplet(
            resp.prompt_eval_count,
            resp.eval_count,
            match (resp.prompt_eval_count, resp.eval_count) {
                (Some(a), Some(b)) => Some(a.saturating_add(b)),
                _ => None,
            },
        )),
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
    use super::{drain_json_lines, handle_ollama_stream_json, map_ollama_response, OllamaResponse};
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

    #[test]
    fn drains_json_lines_with_partial_chunks() {
        let mut buf = "{\"a\":1}".to_string();
        assert!(drain_json_lines(&mut buf).is_empty());
        buf.push('\n');
        buf.push_str("{\"b\":2}\n");
        let lines = drain_json_lines(&mut buf);
        assert_eq!(
            lines,
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn malformed_ollama_line_returns_error() {
        let mut deltas = Vec::new();
        let mut content = String::new();
        let mut tool_calls = Vec::new();
        let err = handle_ollama_stream_json(
            "{\"message\":",
            &mut |d| deltas.push(d),
            &mut content,
            &mut tool_calls,
        )
        .expect_err("expected parse error");
        assert!(err
            .to_string()
            .contains("failed parsing Ollama stream event"));
    }

    #[test]
    fn maps_ollama_token_usage_when_present() {
        let resp: OllamaResponse = serde_json::from_str(
            r#"{
                "message":{"content":"ok"},
                "done":true,
                "prompt_eval_count":11,
                "eval_count":7
            }"#,
        )
        .expect("parse");
        let mapped = map_ollama_response(resp);
        let usage = mapped.usage.expect("usage");
        assert_eq!(usage.prompt_tokens, Some(11));
        assert_eq!(usage.completion_tokens, Some(7));
        assert_eq!(usage.total_tokens, Some(18));
    }
}
