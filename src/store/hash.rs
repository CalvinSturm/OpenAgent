use std::collections::BTreeMap;
use std::path::Path;

use hex::encode as hex_encode;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::gate::TrustMode;

use super::{ConfigFingerprintV1, McpToolSnapshotEntry};

pub fn cli_trust_mode(mode: TrustMode) -> String {
    match mode {
        TrustMode::Auto => "auto".to_string(),
        TrustMode::On => "on".to_string(),
        TrustMode::Off => "off".to_string(),
    }
}

pub fn provider_to_string(provider: crate::gate::ProviderKind) -> String {
    match provider {
        crate::gate::ProviderKind::Lmstudio => "lmstudio".to_string(),
        crate::gate::ProviderKind::Llamacpp => "llamacpp".to_string(),
        crate::gate::ProviderKind::Ollama => "ollama".to_string(),
        crate::gate::ProviderKind::Mock => "mock".to_string(),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize())
}

pub fn stable_path_string(path: &Path) -> String {
    match std::fs::canonicalize(path) {
        Ok(p) => p.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

pub fn config_hash_hex(fingerprint: &ConfigFingerprintV1) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(fingerprint)?;
    Ok(sha256_hex(&bytes))
}

pub fn tool_schema_hash_hex_map(tools: &[crate::types::ToolDef]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for tool in tools {
        out.insert(tool.name.clone(), hash_tool_schema(&tool.parameters));
    }
    out
}

pub fn mcp_tool_snapshot_hash_hex(snapshot: &[McpToolSnapshotEntry]) -> anyhow::Result<String> {
    let mut sorted = snapshot.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let value = serde_json::to_value(&sorted)?;
    let canonical = crate::trust::approvals::canonical_json(&value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

pub fn hash_tool_schema(schema: &Value) -> String {
    let canonical = crate::trust::approvals::canonical_json(schema)
        .unwrap_or_else(|_| serde_json::to_string(schema).unwrap_or_else(|_| "null".to_string()));
    sha256_hex(canonical.as_bytes())
}
