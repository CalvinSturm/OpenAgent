use std::sync::Arc;

use crate::gate::ProviderKind;
use crate::mcp::registry::McpRegistry;
use crate::providers::ModelProvider;
use crate::qualification;
use crate::store;
use crate::tools::builtin_tools_enabled;
use crate::trust::policy::Policy;
use crate::types;
use crate::RunArgs;

#[derive(Debug, Clone)]
pub(crate) struct PreparedTools {
    pub all_tools: Vec<types::ToolDef>,
    pub mcp_tool_snapshot: Vec<store::McpToolSnapshotEntry>,
    pub mcp_tool_catalog_hash_hex: Option<String>,
    pub mcp_config_hash_hex: Option<String>,
    pub mcp_startup_live_catalog_hash_hex: Option<String>,
    pub mcp_snapshot_pinned: bool,
    pub qualification_fallback_note: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_tools_and_qualification<P: ModelProvider>(
    provider: &P,
    provider_kind: ProviderKind,
    base_url: &str,
    worker_model: &str,
    args: &RunArgs,
    state_dir: &std::path::Path,
    mcp_config_path: &std::path::Path,
    mcp_registry: Option<&Arc<McpRegistry>>,
    policy_for_exposure: Option<&Policy>,
) -> anyhow::Result<PreparedTools> {
    let mut all_tools = builtin_tools_enabled(
        args.enable_write_tools,
        args.allow_shell || args.allow_shell_in_workdir,
    );
    let mut mcp_tool_snapshot: Vec<store::McpToolSnapshotEntry> = Vec::new();
    if let Some(reg) = mcp_registry {
        let mut mcp_defs = reg.tool_defs();
        mcp_tool_snapshot = mcp_defs
            .iter()
            .map(|t| store::McpToolSnapshotEntry {
                name: t.name.clone(),
                parameters: t.parameters.clone(),
            })
            .collect();
        mcp_tool_snapshot.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(policy) = policy_for_exposure {
            mcp_defs.retain(|t| policy.mcp_tool_allowed(&t.name).is_ok());
        }
        all_tools.extend(mcp_defs);
    }

    let qual_cache_path = state_dir.join("orchestrator_qualification_cache.json");
    let qualification_fallback_note = qualification::qualify_or_enable_readonly_fallback(
        provider,
        provider_kind,
        base_url,
        worker_model,
        args.enable_write_tools || args.allow_write,
        &mut all_tools,
        &qual_cache_path,
    )
    .await?;

    let mcp_tool_catalog_hash_hex = if mcp_tool_snapshot.is_empty() {
        None
    } else {
        Some(store::mcp_tool_snapshot_hash_hex(&mcp_tool_snapshot)?)
    };
    let mcp_config_hash_hex = if args.mcp.is_empty() {
        None
    } else {
        std::fs::read(mcp_config_path)
            .ok()
            .map(|bytes| store::sha256_hex(&bytes))
    };
    let mcp_startup_live_catalog_hash_hex = if let (Some(reg), Some(_expected_hash)) =
        (mcp_registry, mcp_tool_catalog_hash_hex.as_ref())
    {
        reg.live_tool_catalog_hash_hex().await.ok()
    } else {
        None
    };
    let mcp_snapshot_pinned = match (
        mcp_tool_catalog_hash_hex.as_ref(),
        mcp_startup_live_catalog_hash_hex.as_ref(),
    ) {
        (Some(expected), Some(actual)) => expected == actual,
        (None, _) => true,
        _ => false,
    };

    Ok(PreparedTools {
        all_tools,
        mcp_tool_snapshot,
        mcp_tool_catalog_hash_hex,
        mcp_config_hash_hex,
        mcp_startup_live_catalog_hash_hex,
        mcp_snapshot_pinned,
        qualification_fallback_note,
    })
}
