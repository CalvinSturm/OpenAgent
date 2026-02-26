use anyhow::Context;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

use crate::providers::http::{
    deterministic_backoff_ms, HttpConfig, ProviderError, ProviderErrorKind, RetryRecord,
};
use crate::providers::to_u32_opt;
use crate::types::TokenUsage;
use crate::types::ToolDef;

#[derive(Debug, Serialize)]
pub(crate) struct ToolEnvelope {
    #[serde(rename = "type")]
    pub(crate) tool_type: String,
    pub(crate) function: ToolFunction,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolFunction {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) parameters: Value,
}

pub(crate) fn build_http_client(
    http: HttpConfig,
    context_msg: &'static str,
) -> anyhow::Result<Client> {
    let mut builder = Client::builder().connect_timeout(http.connect_timeout());
    if let Some(timeout) = http.request_timeout_opt() {
        builder = builder.timeout(timeout);
    }
    builder.build().context(context_msg)
}

pub(crate) fn truncate_for_error(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

pub(crate) fn truncate_error_display<E: std::fmt::Display>(err: E, max: usize) -> String {
    truncate_for_error(&err.to_string(), max)
}

pub(crate) fn format_http_error_body(body: &str) -> String {
    truncate_for_error(body, 200)
}

pub(crate) fn build_tool_envelopes(tools: Option<Vec<ToolDef>>) -> Option<Vec<ToolEnvelope>> {
    tools.map(|list| {
        list.into_iter()
            .map(|t| ToolEnvelope {
                tool_type: "function".to_string(),
                function: ToolFunction {
                    name: t.name,
                    description: t.description,
                    parameters: t.parameters,
                },
            })
            .collect()
    })
}

pub(crate) fn map_token_usage_triplet(
    prompt: Option<u64>,
    completion: Option<u64>,
    total: Option<u64>,
) -> TokenUsage {
    TokenUsage {
        prompt_tokens: to_u32_opt(prompt),
        completion_tokens: to_u32_opt(completion),
        total_tokens: to_u32_opt(total),
    }
}

pub(crate) struct ProviderRetryStepInput<'a> {
    pub(crate) http: HttpConfig,
    pub(crate) retry_index: u32,
    pub(crate) attempt: u32,
    pub(crate) max_attempts: u32,
    pub(crate) kind: ProviderErrorKind,
    pub(crate) status: Option<u16>,
    pub(crate) retries: &'a mut Vec<RetryRecord>,
}

pub(crate) async fn record_retry_and_sleep(input: ProviderRetryStepInput<'_>) {
    let backoff = deterministic_backoff_ms(input.http, input.retry_index);
    input.retries.push(RetryRecord {
        attempt: input.attempt,
        max_attempts: input.max_attempts,
        kind: input.kind,
        status: input.status,
        backoff_ms: backoff,
    });
    tokio::time::sleep(Duration::from_millis(backoff)).await;
}

pub(crate) fn provider_payload_too_large_error(
    status: u16,
    attempt: u32,
    max_attempts: u32,
    actual_bytes: usize,
    max_bytes: usize,
    retries: Vec<RetryRecord>,
) -> ProviderError {
    ProviderError {
        kind: ProviderErrorKind::PayloadTooLarge,
        http_status: Some(status),
        retryable: false,
        attempt,
        max_attempts,
        message: format!(
            "response exceeded max bytes: {} > {}",
            actual_bytes, max_bytes
        ),
        retries,
    }
}

pub(crate) fn provider_stream_payload_too_large_error(
    status: u16,
    attempt: u32,
    max_attempts: u32,
    actual_bytes: usize,
    max_bytes: usize,
    retries: Vec<RetryRecord>,
) -> ProviderError {
    ProviderError {
        kind: ProviderErrorKind::PayloadTooLarge,
        http_status: Some(status),
        retryable: false,
        attempt,
        max_attempts,
        message: format!(
            "stream exceeded max bytes: {} > {}",
            actual_bytes, max_bytes
        ),
        retries,
    }
}

pub(crate) fn provider_stream_incomplete_error(http: HttpConfig) -> ProviderError {
    let max_attempts = http.http_max_retries + 1;
    ProviderError {
        kind: ProviderErrorKind::Other,
        http_status: None,
        retryable: false,
        attempt: max_attempts,
        max_attempts,
        message: "stream ended before response completed".to_string(),
        retries: Vec::new(),
    }
}
