use crate::trust::approvals::ApprovalsStore;
use crate::ApprovalsSubcommand;

pub(crate) fn handle_approvals_command(
    path: &std::path::Path,
    command: &ApprovalsSubcommand,
) -> anyhow::Result<()> {
    let store = ApprovalsStore::new(path.to_path_buf());
    match command {
        ApprovalsSubcommand::List => {
            let data = store.list()?;
            if data.requests.is_empty() {
                println!("no approval requests");
                return Ok(());
            }
            for (id, req) in data.requests {
                let expires_at = req.expires_at.unwrap_or_else(|| "-".to_string());
                let uses = req.uses.unwrap_or(0);
                let uses_info = match req.max_uses {
                    Some(max) => format!("{uses}/{max}"),
                    None => "-".to_string(),
                };
                let key_version = req
                    .approval_key_version
                    .clone()
                    .unwrap_or_else(|| "v1".to_string());
                let key_prefix = req
                    .approval_key
                    .as_deref()
                    .map(|k| k.chars().take(8).collect::<String>())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{id}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}",
                    req.status,
                    req.tool,
                    req.created_at,
                    expires_at,
                    uses_info,
                    key_version,
                    key_prefix
                );
            }
        }
        ApprovalsSubcommand::Prune => {
            let removed = store.prune()?;
            println!("removed {} entries", removed);
        }
    }
    Ok(())
}
