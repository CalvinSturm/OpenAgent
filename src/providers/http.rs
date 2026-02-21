use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct HttpConfig {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub stream_idle_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub max_line_bytes: usize,
    pub http_max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 2000,
            request_timeout_ms: 60_000,
            stream_idle_timeout_ms: 15_000,
            max_response_bytes: 10_000_000,
            max_line_bytes: 200_000,
            http_max_retries: 2,
            initial_backoff_ms: 200,
            max_backoff_ms: 1500,
        }
    }
}

impl HttpConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.stream_idle_timeout_ms)
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Connection,
    Timeout,
    RateLimit,
    Server,
    Client,
    Parse,
    PayloadTooLarge,
    Unauthorized,
    Other,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetryRecord {
    pub attempt: u32,
    pub max_attempts: u32,
    pub kind: ProviderErrorKind,
    pub status: Option<u16>,
    pub backoff_ms: u64,
}

#[derive(Debug)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub http_status: Option<u16>,
    pub retryable: bool,
    pub attempt: u32,
    pub max_attempts: u32,
    pub message: String,
    pub retries: Vec<RetryRecord>,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider {:?} error (attempt {}/{}): {}",
            self.kind, self.attempt, self.max_attempts, self.message
        )
    }
}

impl std::error::Error for ProviderError {}

#[derive(Debug, Clone, Copy)]
pub struct ClassifiedError {
    pub kind: ProviderErrorKind,
    pub retryable: bool,
    pub status: Option<u16>,
}

pub fn classify_status(status: u16) -> ClassifiedError {
    match status {
        429 => ClassifiedError {
            kind: ProviderErrorKind::RateLimit,
            retryable: true,
            status: Some(status),
        },
        401 | 403 => ClassifiedError {
            kind: ProviderErrorKind::Unauthorized,
            retryable: false,
            status: Some(status),
        },
        400 | 404 => ClassifiedError {
            kind: ProviderErrorKind::Client,
            retryable: false,
            status: Some(status),
        },
        502..=504 => ClassifiedError {
            kind: ProviderErrorKind::Server,
            retryable: true,
            status: Some(status),
        },
        500..=599 => ClassifiedError {
            kind: ProviderErrorKind::Server,
            retryable: false,
            status: Some(status),
        },
        _ => ClassifiedError {
            kind: ProviderErrorKind::Other,
            retryable: false,
            status: Some(status),
        },
    }
}

pub fn classify_reqwest_error(err: &reqwest::Error) -> ClassifiedError {
    if err.is_timeout() {
        return ClassifiedError {
            kind: ProviderErrorKind::Timeout,
            retryable: true,
            status: None,
        };
    }
    if err.is_connect() {
        return ClassifiedError {
            kind: ProviderErrorKind::Connection,
            retryable: true,
            status: None,
        };
    }
    if let Some(status) = err.status() {
        return classify_status(status.as_u16());
    }
    ClassifiedError {
        kind: ProviderErrorKind::Other,
        retryable: false,
        status: None,
    }
}

pub fn deterministic_backoff_ms(cfg: HttpConfig, retry_index: u32) -> u64 {
    let factor = 1u64 << retry_index.min(16);
    let ms = cfg.initial_backoff_ms.saturating_mul(factor);
    ms.min(cfg.max_backoff_ms)
}

pub fn message_short(s: &str) -> String {
    let single_line = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect::<String>();
    let trimmed = single_line.trim();
    if trimmed.chars().count() <= 200 {
        trimmed.to_string()
    } else {
        trimmed.chars().take(200).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_status, deterministic_backoff_ms, HttpConfig, ProviderErrorKind};

    #[test]
    fn backoff_is_deterministic_and_capped() {
        let cfg = HttpConfig::default();
        assert_eq!(deterministic_backoff_ms(cfg, 0), 200);
        assert_eq!(deterministic_backoff_ms(cfg, 1), 400);
        assert_eq!(deterministic_backoff_ms(cfg, 2), 800);
        assert_eq!(deterministic_backoff_ms(cfg, 3), 1500);
        assert_eq!(deterministic_backoff_ms(cfg, 4), 1500);
    }

    #[test]
    fn classify_status_mappings() {
        let r = classify_status(429);
        assert!(r.retryable);
        assert!(matches!(r.kind, ProviderErrorKind::RateLimit));
        let s = classify_status(400);
        assert!(!s.retryable);
        assert!(matches!(s.kind, ProviderErrorKind::Client));
        let u = classify_status(401);
        assert!(matches!(u.kind, ProviderErrorKind::Unauthorized));
    }
}
