use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalsData {
    pub schema_version: String,
    pub requests: BTreeMap<String, ApprovalRequest>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalRequest {
    pub created_at: String,
    pub tool: String,
    pub arguments: Value,
    pub status: StoredStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StoredStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
pub struct ApprovalsStore {
    path: PathBuf,
}

impl ApprovalsStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn list(&self) -> anyhow::Result<ApprovalsData> {
        self.load_data()
    }

    pub fn approve(&self, id: &str) -> anyhow::Result<()> {
        self.set_status(id, StoredStatus::Approved)
    }

    pub fn deny(&self, id: &str) -> anyhow::Result<()> {
        self.set_status(id, StoredStatus::Denied)
    }

    pub fn find_matching_status(
        &self,
        tool: &str,
        arguments: &Value,
    ) -> anyhow::Result<Option<(String, ApprovalStatus)>> {
        let data = self.load_data()?;
        let mut found_approved = None;
        let mut found_denied = None;
        let mut found_pending = None;
        for (id, req) in data.requests {
            if req.tool != tool || req.arguments != *arguments {
                continue;
            }
            match req.status {
                StoredStatus::Approved => {
                    if found_approved.is_none() {
                        found_approved = Some((id, ApprovalStatus::Approved));
                    }
                }
                StoredStatus::Denied => {
                    if found_denied.is_none() {
                        found_denied = Some((id, ApprovalStatus::Denied));
                    }
                }
                StoredStatus::Pending => {
                    if found_pending.is_none() {
                        found_pending = Some((id, ApprovalStatus::Pending));
                    }
                }
            }
        }
        Ok(found_approved.or(found_denied).or(found_pending))
    }

    pub fn create_pending(&self, tool: &str, arguments: &Value) -> anyhow::Result<String> {
        let mut data = self.load_data()?;
        let id = Uuid::new_v4().to_string();
        data.requests.insert(
            id.clone(),
            ApprovalRequest {
                created_at: crate::trust::now_rfc3339(),
                tool: tool.to_string(),
                arguments: arguments.clone(),
                status: StoredStatus::Pending,
            },
        );
        self.save_data(&data)?;
        Ok(id)
    }

    fn set_status(&self, id: &str, status: StoredStatus) -> anyhow::Result<()> {
        let mut data = self.load_data()?;
        let req = data
            .requests
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("approval id not found: {id}"))?;
        req.status = status;
        self.save_data(&data)
    }

    fn load_data(&self) -> anyhow::Result<ApprovalsData> {
        if !self.path.exists() {
            return Ok(empty_data());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        let data: ApprovalsData = serde_json::from_str(&raw)?;
        Ok(data)
    }

    fn save_data(&self, data: &ApprovalsData) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = self
            .path
            .with_extension(format!("tmp.{}", Uuid::new_v4().as_hyphenated()));
        let content = serde_json::to_string_pretty(data)?;
        std::fs::write(&tmp_path, content)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

fn empty_data() -> ApprovalsData {
    ApprovalsData {
        schema_version: "agentloop.approvals.v1".to_string(),
        requests: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::{ApprovalStatus, ApprovalsStore, StoredStatus};

    #[test]
    fn create_and_transition_approval() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("approvals.json");
        let store = ApprovalsStore::new(path);
        let id = store
            .create_pending("shell", &json!({"cmd":"echo","args":["hi"]}))
            .expect("create pending");

        let before = store
            .find_matching_status("shell", &json!({"cmd":"echo","args":["hi"]}))
            .expect("find matching")
            .expect("must exist");
        assert_eq!(before.0, id);
        assert_eq!(before.1, ApprovalStatus::Pending);

        store.approve(&id).expect("approve");
        let list = store.list().expect("list");
        let req = list.requests.get(&id).expect("exists");
        assert_eq!(req.status, StoredStatus::Approved);

        store.deny(&id).expect("deny");
        let list = store.list().expect("list");
        let req = list.requests.get(&id).expect("exists");
        assert_eq!(req.status, StoredStatus::Denied);
    }
}
