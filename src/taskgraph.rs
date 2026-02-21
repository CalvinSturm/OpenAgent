use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::store::{ensure_dir, sha256_hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PropagateSummaries {
    Off,
    On,
}

impl PropagateSummaries {
    pub fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskFile {
    pub schema_version: String,
    pub name: String,
    #[serde(default)]
    pub defaults: TaskDefaults,
    #[serde(default)]
    pub workdir: TaskWorkdir,
    pub nodes: Vec<TaskNode>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskDefaults {
    pub mode: Option<String>,
    pub provider: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub planner_model: Option<String>,
    pub worker_model: Option<String>,
    pub trust: Option<String>,
    pub approval_mode: Option<String>,
    pub auto_approve_scope: Option<String>,
    pub caps: Option<String>,
    pub hooks: Option<String>,
    #[serde(default)]
    pub compaction: TaskCompaction,
    #[serde(default)]
    pub limits: TaskLimits,
    #[serde(default)]
    pub flags: TaskFlags,
    #[serde(default)]
    pub mcp: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskCompaction {
    pub max_context_chars: Option<usize>,
    pub mode: Option<String>,
    pub keep_last: Option<usize>,
    pub tool_result_persist: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskLimits {
    pub max_read_bytes: Option<usize>,
    pub max_tool_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskFlags {
    pub enable_write_tools: Option<bool>,
    pub allow_write: Option<bool>,
    pub allow_shell: Option<bool>,
    pub stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskWorkdir {
    pub mode: String,
    pub path: String,
    pub per_node_dirname: String,
}

impl Default for TaskWorkdir {
    fn default() -> Self {
        Self {
            mode: "shared".to_string(),
            path: ".".to_string(),
            per_node_dirname: "{id}".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskNode {
    pub id: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub prompt: String,
    #[serde(default)]
    pub settings: TaskNodeSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskNodeSettings {
    pub mode: Option<String>,
    pub provider: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub planner_model: Option<String>,
    pub worker_model: Option<String>,
    pub trust: Option<String>,
    pub approval_mode: Option<String>,
    pub auto_approve_scope: Option<String>,
    pub caps: Option<String>,
    pub hooks: Option<String>,
    #[serde(default)]
    pub compaction: TaskCompaction,
    #[serde(default)]
    pub limits: TaskLimits,
    #[serde(default)]
    pub flags: TaskFlags,
    pub mcp: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TasksCheckpoint {
    pub schema_version: String,
    pub taskfile_hash_hex: String,
    pub created_at: String,
    pub updated_at: String,
    pub nodes: BTreeMap<String, CheckpointNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointNode {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_short: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskGraphRunArtifact {
    pub schema_version: String,
    pub graph_run_id: String,
    pub taskfile_path: String,
    pub taskfile_hash_hex: String,
    pub started_at: String,
    pub finished_at: String,
    pub status: String,
    pub node_order: Vec<String>,
    pub nodes: BTreeMap<String, TaskGraphNodeRecord>,
    pub config: Value,
    pub propagate_summaries: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskGraphNodeRecord {
    pub run_id: String,
    pub status: String,
    pub artifact_path: String,
}

pub fn load_taskfile(path: &Path) -> anyhow::Result<(TaskFile, String, Vec<u8>)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed reading taskfile {}", path.display()))?;
    let taskfile: TaskFile =
        serde_json::from_slice(&bytes).context("failed parsing taskfile JSON")?;
    if taskfile.schema_version != "openagent.taskfile.v1" {
        return Err(anyhow!(
            "unsupported taskfile schema_version: {}",
            taskfile.schema_version
        ));
    }
    if taskfile.nodes.is_empty() {
        return Err(anyhow!("taskfile nodes must not be empty"));
    }
    let hash = sha256_hex(&bytes);
    Ok((taskfile, hash, bytes))
}

pub fn topo_order(taskfile: &TaskFile) -> anyhow::Result<Vec<String>> {
    let mut ids = BTreeSet::new();
    for n in &taskfile.nodes {
        if !ids.insert(n.id.clone()) {
            return Err(anyhow!("duplicate node id: {}", n.id));
        }
    }
    let mut indegree: BTreeMap<String, usize> = taskfile
        .nodes
        .iter()
        .map(|n| (n.id.clone(), 0usize))
        .collect();
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in &taskfile.nodes {
        for dep in &n.depends_on {
            if !indegree.contains_key(dep) {
                return Err(anyhow!("node {} depends on unknown node {}", n.id, dep));
            }
            *indegree.get_mut(&n.id).expect("id exists") += 1;
            edges.entry(dep.clone()).or_default().push(n.id.clone());
        }
    }
    for out in edges.values_mut() {
        out.sort();
    }
    let mut q = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(id, _)| id.clone())
        .collect::<VecDeque<_>>();
    let mut out = Vec::new();
    while let Some(id) = q.pop_front() {
        out.push(id.clone());
        if let Some(next) = edges.get(&id) {
            for n in next {
                if let Some(d) = indegree.get_mut(n) {
                    *d -= 1;
                    if *d == 0 {
                        q.push_back(n.clone());
                    }
                }
            }
        }
        let mut v = q.into_iter().collect::<Vec<_>>();
        v.sort();
        q = v.into_iter().collect();
    }
    if out.len() != taskfile.nodes.len() {
        return Err(cycle_error(taskfile));
    }
    Ok(out)
}

fn cycle_error(taskfile: &TaskFile) -> anyhow::Error {
    fn dfs(
        id: &str,
        graph: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        if visiting.contains(id) {
            if let Some(pos) = stack.iter().position(|x| x == id) {
                let mut cycle = stack[pos..].to_vec();
                cycle.push(id.to_string());
                return Some(cycle);
            }
            return Some(vec![id.to_string(), id.to_string()]);
        }
        if visited.contains(id) {
            return None;
        }
        visiting.insert(id.to_string());
        stack.push(id.to_string());
        if let Some(next) = graph.get(id) {
            for n in next {
                if let Some(c) = dfs(n, graph, visiting, visited, stack) {
                    return Some(c);
                }
            }
        }
        stack.pop();
        visiting.remove(id);
        visited.insert(id.to_string());
        None
    }
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in &taskfile.nodes {
        graph.insert(n.id.clone(), n.depends_on.clone());
    }
    let mut ids = graph.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = Vec::new();
    for id in ids {
        if let Some(cycle) = dfs(&id, &graph, &mut visiting, &mut visited, &mut stack) {
            return anyhow!("dependency cycle detected: {}", cycle.join(" -> "));
        }
    }
    anyhow!("dependency cycle detected")
}

pub fn checkpoint_default_path(state_dir: &Path) -> PathBuf {
    state_dir.join("tasks").join("checkpoint.json")
}

pub fn load_or_init_checkpoint(
    path: &Path,
    taskfile: &TaskFile,
    taskfile_hash_hex: &str,
) -> anyhow::Result<TasksCheckpoint> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading checkpoint {}", path.display()))?;
        let cp: TasksCheckpoint =
            serde_json::from_str(&raw).context("failed parsing checkpoint JSON")?;
        if cp.schema_version != "openagent.tasks_checkpoint.v1" {
            return Err(anyhow!(
                "unsupported checkpoint schema_version: {}",
                cp.schema_version
            ));
        }
        if cp.taskfile_hash_hex != taskfile_hash_hex {
            return Err(anyhow!(
                "checkpoint taskfile hash mismatch: expected {}, got {}",
                taskfile_hash_hex,
                cp.taskfile_hash_hex
            ));
        }
        return Ok(cp);
    }

    let now = crate::trust::now_rfc3339();
    let mut nodes = BTreeMap::new();
    for n in &taskfile.nodes {
        nodes.insert(
            n.id.clone(),
            CheckpointNode {
                status: "pending".to_string(),
                run_id: None,
                started_at: None,
                finished_at: None,
                exit_reason: None,
                artifact_path: None,
                error_short: None,
            },
        );
    }
    Ok(TasksCheckpoint {
        schema_version: "openagent.tasks_checkpoint.v1".to_string(),
        taskfile_hash_hex: taskfile_hash_hex.to_string(),
        created_at: now.clone(),
        updated_at: now,
        nodes,
    })
}

pub fn write_checkpoint(path: &Path, cp: &TasksCheckpoint) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    std::fs::write(&tmp, serde_json::to_string_pretty(cp)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn ensure_resume_allowed(cp: &TasksCheckpoint, resume: bool) -> anyhow::Result<()> {
    let any_done = cp.nodes.values().any(|n| n.status == "done");
    if any_done && !resume {
        return Err(anyhow!(
            "checkpoint has completed nodes; re-run with --resume or reset checkpoint"
        ));
    }
    Ok(())
}

pub fn graph_runs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("tasks").join("runs")
}

pub fn write_graph_run_artifact(
    state_dir: &Path,
    artifact: &TaskGraphRunArtifact,
) -> anyhow::Result<PathBuf> {
    let dir = graph_runs_dir(state_dir);
    ensure_dir(&dir)?;
    let path = dir.join(format!("{}.json", artifact.graph_run_id));
    let tmp = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    std::fs::write(&tmp, serde_json::to_string_pretty(artifact)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn node_by_id<'a>(taskfile: &'a TaskFile, id: &str) -> anyhow::Result<&'a TaskNode> {
    taskfile
        .nodes
        .iter()
        .find(|n| n.id == id)
        .ok_or_else(|| anyhow!("node not found: {id}"))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{
        ensure_resume_allowed, load_or_init_checkpoint, topo_order, write_checkpoint,
        write_graph_run_artifact, TaskDefaults, TaskFile, TaskGraphNodeRecord,
        TaskGraphRunArtifact, TaskNode, TaskNodeSettings, TaskWorkdir, TasksCheckpoint,
    };

    #[test]
    fn topo_order_is_stable_with_tie_breaks() {
        let tf = TaskFile {
            schema_version: "openagent.taskfile.v1".to_string(),
            name: "x".to_string(),
            defaults: TaskDefaults::default(),
            workdir: TaskWorkdir::default(),
            nodes: vec![
                TaskNode {
                    id: "B".to_string(),
                    depends_on: vec![],
                    prompt: "p".to_string(),
                    settings: TaskNodeSettings::default(),
                },
                TaskNode {
                    id: "A".to_string(),
                    depends_on: vec![],
                    prompt: "p".to_string(),
                    settings: TaskNodeSettings::default(),
                },
                TaskNode {
                    id: "C".to_string(),
                    depends_on: vec!["A".to_string()],
                    prompt: "p".to_string(),
                    settings: TaskNodeSettings::default(),
                },
            ],
        };
        let order = topo_order(&tf).expect("order");
        assert_eq!(order, vec!["A", "B", "C"]);
    }

    #[test]
    fn cycle_detection_errors() {
        let tf = TaskFile {
            schema_version: "openagent.taskfile.v1".to_string(),
            name: "x".to_string(),
            defaults: TaskDefaults::default(),
            workdir: TaskWorkdir::default(),
            nodes: vec![
                TaskNode {
                    id: "A".to_string(),
                    depends_on: vec!["B".to_string()],
                    prompt: "p".to_string(),
                    settings: TaskNodeSettings::default(),
                },
                TaskNode {
                    id: "B".to_string(),
                    depends_on: vec!["A".to_string()],
                    prompt: "p".to_string(),
                    settings: TaskNodeSettings::default(),
                },
            ],
        };
        let err = topo_order(&tf).expect_err("cycle");
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn checkpoint_resume_guard_and_atomic_write() {
        let dir = tempdir().expect("tmp");
        let cp_path = dir.path().join("checkpoint.json");
        let tf = TaskFile {
            schema_version: "openagent.taskfile.v1".to_string(),
            name: "x".to_string(),
            defaults: TaskDefaults::default(),
            workdir: TaskWorkdir::default(),
            nodes: vec![TaskNode {
                id: "A".to_string(),
                depends_on: vec![],
                prompt: "p".to_string(),
                settings: TaskNodeSettings::default(),
            }],
        };
        let mut cp = load_or_init_checkpoint(&cp_path, &tf, "hash").expect("init");
        cp.nodes.get_mut("A").expect("A").status = "done".to_string();
        write_checkpoint(&cp_path, &cp).expect("write");
        let loaded: TasksCheckpoint =
            serde_json::from_str(&std::fs::read_to_string(&cp_path).expect("read")).expect("parse");
        assert!(ensure_resume_allowed(&loaded, true).is_ok());
        assert!(ensure_resume_allowed(&loaded, false).is_err());
    }

    #[test]
    fn graph_artifact_persists_expected_fields() {
        let dir = tempdir().expect("tmp");
        let artifact = TaskGraphRunArtifact {
            schema_version: "openagent.taskgraph_run.v1".to_string(),
            graph_run_id: "g1".to_string(),
            taskfile_path: "taskfile.json".to_string(),
            taskfile_hash_hex: "abc".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:01Z".to_string(),
            status: "ok".to_string(),
            node_order: vec!["A".to_string()],
            nodes: [(
                "A".to_string(),
                TaskGraphNodeRecord {
                    run_id: "r1".to_string(),
                    status: "done".to_string(),
                    artifact_path: "runs/r1.json".to_string(),
                },
            )]
            .into_iter()
            .collect(),
            config: serde_json::json!({"x":1}),
            propagate_summaries: true,
        };
        let path = write_graph_run_artifact(dir.path(), &artifact).expect("write");
        let raw = std::fs::read_to_string(path).expect("read");
        assert!(raw.contains("openagent.taskgraph_run.v1"));
        assert!(raw.contains("\"graph_run_id\": \"g1\""));
    }
}
