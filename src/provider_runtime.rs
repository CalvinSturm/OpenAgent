use std::time::Duration;

use reqwest::Client;

use crate::gate::ProviderKind;
use crate::providers::http::HttpConfig;
use crate::{DoctorArgs, EvalArgs, RunArgs};

pub(crate) async fn doctor_check(args: &DoctorArgs) -> Result<String, String> {
    let base_url = args
        .base_url
        .clone()
        .unwrap_or_else(|| default_base_url(args.provider).to_string());
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    match args.provider {
        ProviderKind::Mock => Ok(format!("OK: mock provider ready at {}", base_url)),
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
            let urls = doctor_probe_urls(args.provider, &base_url);
            let models_url = &urls[0];
            let health_url = &urls[1];

            match get_with_optional_bearer(&client, models_url, args.api_key.as_deref()).await {
                Ok(models_resp) => {
                    if models_resp.status().is_success() {
                        return Ok(format!(
                            "OK: {} reachable at {}",
                            provider_cli_name(args.provider),
                            base_url
                        ));
                    }

                    if models_resp.status() == reqwest::StatusCode::NOT_FOUND {
                        let health_resp =
                            get_with_optional_bearer(&client, health_url, args.api_key.as_deref())
                                .await
                                .map_err(|e| {
                                    format!("{} not reachable after /models 404: {e}", health_url)
                                })?;
                        if health_resp.status().is_success() {
                            return Ok(format!(
                                "OK: {} reachable at {} (reachable but endpoint differs)",
                                provider_cli_name(args.provider),
                                base_url
                            ));
                        }
                    }

                    Err(format!(
                        "{} responded with HTTP {} at {}",
                        provider_cli_name(args.provider),
                        models_resp.status(),
                        models_url
                    ))
                }
                Err(models_err) => {
                    let health_resp =
                        get_with_optional_bearer(&client, health_url, args.api_key.as_deref())
                            .await
                            .map_err(|health_err| {
                                format!(
                                    "could not reach {} ({models_err}); fallback {} also failed: {health_err}",
                                    models_url, health_url
                                )
                            })?;
                    if health_resp.status().is_success() {
                        Ok(format!(
                            "OK: {} reachable at {} (reachable but endpoint differs)",
                            provider_cli_name(args.provider),
                            base_url
                        ))
                    } else {
                        Err(format!(
                            "{} responded with HTTP {} at fallback {}",
                            provider_cli_name(args.provider),
                            health_resp.status(),
                            health_url
                        ))
                    }
                }
            }
        }
        ProviderKind::Ollama => {
            let tags_url = doctor_probe_urls(args.provider, &base_url)
                .into_iter()
                .next()
                .ok_or_else(|| "internal error building Ollama doctor URL".to_string())?;
            let resp = client
                .get(&tags_url)
                .send()
                .await
                .map_err(|e| format!("could not reach {tags_url}: {e}"))?;
            if resp.status().is_success() {
                Ok(format!("OK: ollama reachable at {}", base_url))
            } else {
                Err(format!(
                    "ollama responded with HTTP {} at {}",
                    resp.status(),
                    tags_url
                ))
            }
        }
    }
}

async fn get_with_optional_bearer(
    client: &Client,
    url: &str,
    api_key: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut req = client.get(url);
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    req.send().await
}

pub(crate) fn default_base_url(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Lmstudio => "http://localhost:1234/v1",
        ProviderKind::Llamacpp => "http://localhost:8080/v1",
        ProviderKind::Ollama => "http://localhost:11434",
        ProviderKind::Mock => "mock://local",
    }
}

pub(crate) fn provider_cli_name(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Lmstudio => "lmstudio",
        ProviderKind::Llamacpp => "llamacpp",
        ProviderKind::Ollama => "ollama",
        ProviderKind::Mock => "mock",
    }
}

pub(crate) fn doctor_probe_urls(provider: ProviderKind, base_url: &str) -> Vec<String> {
    let trimmed = base_url.trim_end_matches('/').to_string();
    match provider {
        ProviderKind::Lmstudio | ProviderKind::Llamacpp => {
            vec![format!("{trimmed}/models"), trimmed]
        }
        ProviderKind::Ollama => vec![format!("{trimmed}/api/tags")],
        ProviderKind::Mock => vec![trimmed],
    }
}

pub(crate) fn http_config_from_run_args(args: &RunArgs) -> HttpConfig {
    HttpConfig {
        connect_timeout_ms: args.http_connect_timeout_ms,
        request_timeout_ms: args.http_timeout_ms,
        stream_idle_timeout_ms: args.http_stream_idle_timeout_ms,
        max_response_bytes: args.http_max_response_bytes,
        max_line_bytes: args.http_max_line_bytes,
        http_max_retries: args.http_max_retries,
        ..HttpConfig::default()
    }
}

pub(crate) fn http_config_from_eval_args(args: &EvalArgs) -> HttpConfig {
    HttpConfig {
        connect_timeout_ms: args.http_connect_timeout_ms,
        request_timeout_ms: args.http_timeout_ms,
        stream_idle_timeout_ms: args.http_stream_idle_timeout_ms,
        max_response_bytes: args.http_max_response_bytes,
        max_line_bytes: args.http_max_line_bytes,
        http_max_retries: args.http_max_retries,
        ..HttpConfig::default()
    }
}
