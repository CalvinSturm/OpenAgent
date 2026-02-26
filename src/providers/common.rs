use anyhow::Context;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;

use crate::providers::http::HttpConfig;
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
