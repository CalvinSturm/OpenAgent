pub mod approvals;
pub mod audit;
pub mod policy;

use std::path::{Path, PathBuf};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct TrustPaths {
    pub policy: PathBuf,
    pub approvals: PathBuf,
    pub audit: PathBuf,
}

pub fn resolve_paths(
    workdir: &Path,
    policy: Option<PathBuf>,
    approvals: Option<PathBuf>,
    audit: Option<PathBuf>,
) -> TrustPaths {
    TrustPaths {
        policy: policy.unwrap_or_else(|| workdir.join(".agentloop").join("policy.yaml")),
        approvals: approvals.unwrap_or_else(|| workdir.join(".agentloop").join("approvals.json")),
        audit: audit.unwrap_or_else(|| workdir.join(".agentloop").join("audit.jsonl")),
    }
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
