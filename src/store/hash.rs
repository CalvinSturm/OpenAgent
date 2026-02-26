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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{hash_tool_schema, mcp_tool_snapshot_hash_hex, sha256_hex};
    use crate::store::McpToolSnapshotEntry;

    #[test]
    fn sha256_hex_matches_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_tool_schema_is_stable_for_semantically_equivalent_json() {
        let a = json!({
            "type": "object",
            "properties": {
                "x": {"type":"string"},
                "y": {"type":"number"}
            },
            "required": ["x"]
        });
        let b = json!({
            "required": ["x"],
            "properties": {
                "y": {"type":"number"},
                "x": {"type":"string"}
            },
            "type": "object"
        });

        assert_eq!(hash_tool_schema(&a), hash_tool_schema(&b));
    }

    #[test]
    fn mcp_tool_snapshot_hash_is_sorted_by_name() {
        let a = vec![
            McpToolSnapshotEntry {
                name: "mcp.a.beta".to_string(),
                parameters: json!({"type":"object","properties":{"b":{"type":"string"}}}),
            },
            McpToolSnapshotEntry {
                name: "mcp.a.alpha".to_string(),
                parameters: json!({"type":"object","properties":{"a":{"type":"string"}}}),
            },
        ];
        let mut b = a.clone();
        b.reverse();

        let ha = mcp_tool_snapshot_hash_hex(&a).expect("hash a");
        let hb = mcp_tool_snapshot_hash_hex(&b).expect("hash b");
        assert_eq!(ha, hb);
    }
}
