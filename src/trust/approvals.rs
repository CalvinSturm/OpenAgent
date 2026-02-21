use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Denied,
}

#[derive(Debug, Clone)]
pub struct ApprovalDecisionMatch {
    pub id: String,
    pub status: ApprovalStatus,
}

#[derive(Debug, Clone)]
pub struct ApprovedUsage {
    pub id: String,
    pub approval_key: String,
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
    #[serde(default)]
    pub approval_key: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub uses: Option<u32>,
    #[serde(default)]
    pub approval_key_version: Option<String>,
    #[serde(default)]
    pub tool_schema_hash_hex: Option<String>,
    #[serde(default)]
    pub hooks_config_hash_hex: Option<String>,
    #[serde(default)]
    pub exec_target: Option<String>,
    #[serde(default)]
    pub planner_hash_hex: Option<String>,
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

#[derive(Debug, Clone)]
pub struct ApprovalProvenance {
    pub approval_key_version: String,
    pub tool_schema_hash_hex: Option<String>,
    pub hooks_config_hash_hex: Option<String>,
    pub exec_target: Option<String>,
    pub planner_hash_hex: Option<String>,
}

impl ApprovalsStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn list(&self) -> anyhow::Result<ApprovalsData> {
        self.load_data()
    }

    pub fn approve(
        &self,
        id: &str,
        ttl_hours: Option<u32>,
        max_uses: Option<u32>,
    ) -> anyhow::Result<()> {
        let mut data = self.load_data()?;
        let req = data
            .requests
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("approval id not found: {id}"))?;
        req.status = StoredStatus::Approved;
        if let Some(hours) = ttl_hours {
            let expires = OffsetDateTime::now_utc() + Duration::hours(hours as i64);
            req.expires_at = Some(
                expires
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| crate::trust::now_rfc3339()),
            );
        }
        if let Some(mu) = max_uses {
            req.max_uses = Some(mu);
        }
        self.save_data(&data)
    }

    pub fn deny(&self, id: &str) -> anyhow::Result<()> {
        self.set_status(id, StoredStatus::Denied)
    }

    pub fn prune(&self) -> anyhow::Result<usize> {
        let mut data = self.load_data()?;
        let now = OffsetDateTime::now_utc();
        let before = data.requests.len();
        data.requests.retain(|_, req| {
            if req.status == StoredStatus::Denied {
                return false;
            }
            if is_expired(req, now) {
                return false;
            }
            if is_exhausted(req) {
                return false;
            }
            true
        });
        let removed = before.saturating_sub(data.requests.len());
        self.save_data(&data)?;
        Ok(removed)
    }

    pub fn find_matching_decision(
        &self,
        approval_key: &str,
        approval_key_version: &str,
    ) -> anyhow::Result<Option<ApprovalDecisionMatch>> {
        let data = self.load_data()?;
        let mut found_denied = None;
        for (id, req) in data.requests {
            if req.approval_key.as_deref() != Some(approval_key) {
                continue;
            }
            if !key_version_matches(req.approval_key_version.as_deref(), approval_key_version) {
                continue;
            }
            match req.status {
                StoredStatus::Denied => {
                    if found_denied.is_none() {
                        found_denied = Some(ApprovalDecisionMatch {
                            id,
                            status: ApprovalStatus::Denied,
                        });
                    }
                }
                StoredStatus::Pending => {
                    return Ok(Some(ApprovalDecisionMatch {
                        id,
                        status: ApprovalStatus::Pending,
                    }));
                }
                StoredStatus::Approved => {}
            }
        }
        Ok(found_denied)
    }

    pub fn consume_matching_approved(
        &self,
        approval_key: &str,
        approval_key_version: &str,
    ) -> anyhow::Result<Option<ApprovedUsage>> {
        let mut data = self.load_data()?;
        let now = OffsetDateTime::now_utc();
        let mut selected_id: Option<String> = None;
        for (id, req) in &data.requests {
            if req.approval_key.as_deref() != Some(approval_key) {
                continue;
            }
            if !key_version_matches(req.approval_key_version.as_deref(), approval_key_version) {
                continue;
            }
            if req.status != StoredStatus::Approved {
                continue;
            }
            if is_expired(req, now) || is_exhausted(req) {
                continue;
            }
            selected_id = Some(id.clone());
            break;
        }
        let Some(id) = selected_id else {
            return Ok(None);
        };

        let req = data
            .requests
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("approval id disappeared during consume: {id}"))?;
        req.uses = Some(req.uses.unwrap_or(0).saturating_add(1));
        self.save_data(&data)?;
        Ok(Some(ApprovedUsage {
            id,
            approval_key: approval_key.to_string(),
        }))
    }

    pub fn create_pending(
        &self,
        tool: &str,
        arguments: &Value,
        approval_key: Option<String>,
        provenance: Option<ApprovalProvenance>,
    ) -> anyhow::Result<String> {
        let mut data = self.load_data()?;
        let id = Uuid::new_v4().to_string();
        let prov = provenance.unwrap_or(ApprovalProvenance {
            approval_key_version: "v1".to_string(),
            tool_schema_hash_hex: None,
            hooks_config_hash_hex: None,
            exec_target: None,
            planner_hash_hex: None,
        });
        data.requests.insert(
            id.clone(),
            ApprovalRequest {
                created_at: crate::trust::now_rfc3339(),
                tool: tool.to_string(),
                arguments: arguments.clone(),
                status: StoredStatus::Pending,
                approval_key,
                expires_at: None,
                max_uses: None,
                uses: Some(0),
                approval_key_version: Some(prov.approval_key_version),
                tool_schema_hash_hex: prov.tool_schema_hash_hex,
                hooks_config_hash_hex: prov.hooks_config_hash_hex,
                exec_target: prov.exec_target,
                planner_hash_hex: prov.planner_hash_hex,
            },
        );
        self.save_data(&data)?;
        Ok(id)
    }

    pub fn ensure_approved_for_key(
        &self,
        tool: &str,
        arguments: &Value,
        approval_key: &str,
        provenance: Option<ApprovalProvenance>,
    ) -> anyhow::Result<String> {
        let mut data = self.load_data()?;
        let target_version = provenance
            .as_ref()
            .map(|p| p.approval_key_version.as_str())
            .unwrap_or("v1");
        let existing_id = data
            .requests
            .iter()
            .find(|(_, req)| {
                req.approval_key.as_deref() == Some(approval_key)
                    && key_version_matches(req.approval_key_version.as_deref(), target_version)
            })
            .map(|(id, _)| id.clone());
        if let Some(id) = existing_id {
            if let Some(req) = data.requests.get_mut(&id) {
                req.status = StoredStatus::Approved;
                if req.uses.is_none() {
                    req.uses = Some(0);
                }
            }
            self.save_data(&data)?;
            return Ok(id);
        }

        let prov = provenance.unwrap_or(ApprovalProvenance {
            approval_key_version: "v1".to_string(),
            tool_schema_hash_hex: None,
            hooks_config_hash_hex: None,
            exec_target: None,
            planner_hash_hex: None,
        });
        let id = Uuid::new_v4().to_string();
        data.requests.insert(
            id.clone(),
            ApprovalRequest {
                created_at: crate::trust::now_rfc3339(),
                tool: tool.to_string(),
                arguments: arguments.clone(),
                status: StoredStatus::Approved,
                approval_key: Some(approval_key.to_string()),
                expires_at: None,
                max_uses: None,
                uses: Some(0),
                approval_key_version: Some(prov.approval_key_version),
                tool_schema_hash_hex: prov.tool_schema_hash_hex,
                hooks_config_hash_hex: prov.hooks_config_hash_hex,
                exec_target: prov.exec_target,
                planner_hash_hex: prov.planner_hash_hex,
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

pub fn canonical_json(value: &Value) -> anyhow::Result<String> {
    let normalized = canonicalize_value(value);
    Ok(serde_json::to_string(&normalized)?)
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    out.insert(key, canonicalize_value(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        _ => value.clone(),
    }
}

fn is_exhausted(req: &ApprovalRequest) -> bool {
    match req.max_uses {
        Some(max) => req.uses.unwrap_or(0) >= max,
        None => false,
    }
}

fn is_expired(req: &ApprovalRequest, now: OffsetDateTime) -> bool {
    let Some(exp) = &req.expires_at else {
        return false;
    };
    match OffsetDateTime::parse(exp, &Rfc3339) {
        Ok(ts) => now > ts,
        Err(_) => false,
    }
}

fn empty_data() -> ApprovalsData {
    ApprovalsData {
        schema_version: "openagent.approvals.v1".to_string(),
        requests: BTreeMap::new(),
    }
}

fn key_version_matches(entry: Option<&str>, target: &str) -> bool {
    match target {
        "v1" => matches!(entry, None | Some("v1")),
        "v2" => matches!(entry, Some("v2")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::{canonical_json, ApprovalProvenance, ApprovalStatus, ApprovalsStore, StoredStatus};

    #[test]
    fn canonical_json_sorts_object_keys() {
        let a = json!({"b":1,"a":{"z":2,"y":1}});
        let b = json!({"a":{"y":1,"z":2},"b":1});
        let ca = canonical_json(&a).expect("canonical a");
        let cb = canonical_json(&b).expect("canonical b");
        assert_eq!(ca, cb);
    }

    #[test]
    fn create_and_transition_approval() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("approvals.json");
        let store = ApprovalsStore::new(path);
        let id = store
            .create_pending(
                "shell",
                &json!({"cmd":"echo","args":["hi"]}),
                Some("k".to_string()),
                None,
            )
            .expect("create pending");

        let before = store
            .find_matching_decision("k", "v1")
            .expect("find matching")
            .expect("must exist");
        assert_eq!(before.id, id);
        assert_eq!(before.status, ApprovalStatus::Pending);

        store.approve(&id, None, None).expect("approve");
        let list = store.list().expect("list");
        let req = list.requests.get(&id).expect("exists");
        assert_eq!(req.status, StoredStatus::Approved);

        store.deny(&id).expect("deny");
        let list = store.list().expect("list");
        let req = list.requests.get(&id).expect("exists");
        assert_eq!(req.status, StoredStatus::Denied);
    }

    #[test]
    fn max_uses_exhaustion() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("approvals.json");
        let store = ApprovalsStore::new(path);
        let id = store
            .create_pending(
                "shell",
                &json!({"cmd":"echo"}),
                Some("key1".to_string()),
                None,
            )
            .expect("create pending");
        store.approve(&id, None, Some(1)).expect("approve");
        let first = store
            .consume_matching_approved("key1", "v1")
            .expect("consume first");
        assert!(first.is_some());
        let second = store
            .consume_matching_approved("key1", "v1")
            .expect("consume second");
        assert!(second.is_none());
    }

    #[test]
    fn version_matching_isolated_between_v1_v2() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("approvals.json");
        let store = ApprovalsStore::new(path);
        let id_v2 = store
            .create_pending(
                "shell",
                &json!({"cmd":"echo"}),
                Some("k2".to_string()),
                Some(ApprovalProvenance {
                    approval_key_version: "v2".to_string(),
                    tool_schema_hash_hex: None,
                    hooks_config_hash_hex: None,
                    exec_target: Some("host".to_string()),
                    planner_hash_hex: None,
                }),
            )
            .expect("create");
        store.approve(&id_v2, None, None).expect("approve");
        assert!(store
            .consume_matching_approved("k2", "v1")
            .expect("consume v1")
            .is_none());
        assert!(store
            .consume_matching_approved("k2", "v2")
            .expect("consume v2")
            .is_some());
    }
}
