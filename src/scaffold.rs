use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::Serialize;

use crate::store::resolve_state_paths;

#[derive(Debug, Clone, Copy)]
pub struct TemplateSpec {
    pub name: &'static str,
    pub rel_path: &'static str,
    pub content: &'static str,
}

const TEMPLATE_POLICY: &str = r#"version: 2
default: deny
rules:
  - tool: "list_dir"
    decision: allow
  - tool: "read_file"
    decision: allow
  - tool: "shell"
    decision: require_approval
    reason: "shell execution requires explicit approval"
  - tool: "write_file"
    decision: require_approval
    reason: "file writes require explicit approval"
  - tool: "apply_patch"
    decision: require_approval
    reason: "file patching requires explicit approval"
"#;

const TEMPLATE_APPROVALS: &str =
    "{\n  \"schema_version\": \"openagent.approvals.v1\",\n  \"requests\": {}\n}\n";

const TEMPLATE_HOOKS: &str = r#"version: 1
hooks: []
# Hooks are off by default. Enable at runtime with --hooks on or --hooks auto.
# Example:
# - name: redact
#   stages: ["tool_result"]
#   command: "python3"
#   args: ["scripts/redact.py"]
#   match:
#     tools: ["shell", "read_file", "mcp.playwright.*"]
"#;

const TEMPLATE_INSTRUCTIONS: &str = r#"version: 1
base:
  - role: system
    content: "Ground all claims in tool output from this run. If evidence is missing, say so."
model_profiles:
  - name: strict_tool_use
    selector: "*"
    messages:
      - role: developer
        content: "Call tools before asserting file contents or command outcomes."
task_profiles:
  - name: coding
    selector: coding
    messages:
      - role: developer
        content: "Prefer concise diffs, deterministic steps, and explicit verification."
"#;

const TEMPLATE_MCP_SERVERS: &str = "{\n  \"schema_version\": \"openagent.mcp_servers.v1\",\n  \"servers\": {\n    \"playwright\": {\n      \"command\": \"npx\",\n      \"args\": [\n        \"@playwright/mcp@latest\"\n      ]\n    }\n  }\n}\n";

const TEMPLATE_EVAL_PROFILE_LOCAL_OLLAMA: &str = r#"version: 1
name: local-ollama
provider: ollama
base_url: http://localhost:11434
models: ["qwen3:8b"]
pack: all
runs_per_task: 1
caps: strict
trust: on
approval_mode: auto
auto_approve_scope: run
flags:
  enable_write_tools: false
  allow_write: false
  allow_shell: false
  stream: false
thresholds:
  min_pass_rate: 0.0
  fail_on_any: false
"#;

const TEMPLATE_COST_MODEL: &str = r#"schema_version: "openagent.cost_model.v1"
rules:
  - model_glob: "qwen3:*"
    prompt_per_1k: 0.0
    completion_per_1k: 0.0
"#;

const TEMPLATE_EXAMPLE_TASKFILE: &str = "{\n  \"schema_version\": \"openagent.taskfile.v1\",\n  \"name\": \"example-task-graph\",\n  \"defaults\": {\n    \"mode\": \"single\",\n    \"provider\": \"ollama\",\n    \"base_url\": \"http://localhost:11434\",\n    \"model\": \"qwen3:8b\",\n    \"trust\": \"off\",\n    \"approval_mode\": \"interrupt\",\n    \"auto_approve_scope\": \"run\",\n    \"caps\": \"auto\",\n    \"hooks\": \"off\",\n    \"flags\": {\n      \"enable_write_tools\": false,\n      \"allow_write\": false,\n      \"allow_shell\": false,\n      \"stream\": false\n    },\n    \"limits\": {\n      \"max_read_bytes\": 200000,\n      \"max_tool_output_bytes\": 200000\n    },\n    \"compaction\": {\n      \"max_context_chars\": 0,\n      \"mode\": \"off\",\n      \"keep_last\": 20,\n      \"tool_result_persist\": \"digest\"\n    },\n    \"mcp\": []\n  },\n  \"workdir\": {\n    \"mode\": \"shared\",\n    \"path\": \".\",\n    \"per_node_dirname\": \"{id}\"\n  },\n  \"nodes\": [\n    {\n      \"id\": \"T1\",\n      \"depends_on\": [],\n      \"prompt\": \"List files in the current directory and summarize what you find.\",\n      \"settings\": {}\n    }\n  ]\n}\n";

const TEMPLATE_POLICY_CASES: &str = r#"version: 1
cases:
  - name: deny shell by default
    tool: shell
    arguments:
      cmd: rm
      args: ["-rf", "/"]
    context:
      workdir: /tmp/openagent
      exec_target: host
      mode: single
      planner_hash_hex: null
      hooks_hash_hex: null
    expect:
      decision: require_approval
      reason_contains: shell
      source_contains: policy
"#;

const TEMPLATES: &[TemplateSpec] = &[
    TemplateSpec {
        name: "policy.yaml",
        rel_path: "policy.yaml",
        content: TEMPLATE_POLICY,
    },
    TemplateSpec {
        name: "hooks.yaml",
        rel_path: "hooks.yaml",
        content: TEMPLATE_HOOKS,
    },
    TemplateSpec {
        name: "instructions.yaml",
        rel_path: "instructions.yaml",
        content: TEMPLATE_INSTRUCTIONS,
    },
    TemplateSpec {
        name: "mcp_servers.json",
        rel_path: "mcp_servers.json",
        content: TEMPLATE_MCP_SERVERS,
    },
    TemplateSpec {
        name: "eval_profile_local_ollama.yaml",
        rel_path: "eval/profiles/local_ollama.yaml",
        content: TEMPLATE_EVAL_PROFILE_LOCAL_OLLAMA,
    },
    TemplateSpec {
        name: "cost_model.yaml",
        rel_path: "cost_model.yaml",
        content: TEMPLATE_COST_MODEL,
    },
    TemplateSpec {
        name: "example_taskfile.json",
        rel_path: "tasks/example_taskfile.json",
        content: TEMPLATE_EXAMPLE_TASKFILE,
    },
    TemplateSpec {
        name: "policy_cases.yaml",
        rel_path: "policy_cases.yaml",
        content: TEMPLATE_POLICY_CASES,
    },
];

const INIT_DIRS: &[&str] = &[
    "",
    "runs",
    "sessions",
    "eval/profiles",
    "eval/baselines",
    "tasks",
    "tasks/runs",
];

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub workdir: PathBuf,
    pub state_dir_override: Option<PathBuf>,
    pub force: bool,
    pub print_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub schema_version: String,
    pub version: String,
    pub git_sha: String,
    pub target: String,
    pub build_time_utc: String,
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        schema_version: "openagent.version.v1".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_sha: option_env!("OPENAGENT_GIT_SHA")
            .unwrap_or("unknown")
            .to_string(),
        target: option_env!("OPENAGENT_TARGET")
            .unwrap_or("unknown")
            .to_string(),
        build_time_utc: option_env!("OPENAGENT_BUILD_TIME_UTC")
            .unwrap_or("unknown")
            .to_string(),
    }
}

pub fn list_templates() -> Vec<&'static str> {
    let mut out = TEMPLATES.iter().map(|t| t.name).collect::<Vec<_>>();
    out.sort();
    out
}

pub fn template_content(name: &str) -> Option<&'static str> {
    template_spec(name).map(|t| t.content)
}

pub fn write_template(name: &str, out: &Path, force: bool) -> anyhow::Result<()> {
    let tpl = template_spec(name).ok_or_else(|| anyhow!("unknown template '{}'", name))?;
    if out.exists() && !force {
        return Err(anyhow!(
            "refusing to overwrite existing file: {} (use --force)",
            out.display()
        ));
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, tpl.content.as_bytes())?;
    Ok(())
}

pub fn run_init(opts: &InitOptions) -> anyhow::Result<String> {
    let state_dir = resolved_state_dir(&opts.workdir, opts.state_dir_override.clone());
    let mut out = String::new();
    out.push_str(&format!("STATE_DIR {}\n", state_dir.display()));

    for rel in INIT_DIRS {
        let p = if rel.is_empty() {
            state_dir.clone()
        } else {
            state_dir.join(rel)
        };
        out.push_str(&format!("DIR {}\n", p.display()));
        if !opts.print_only {
            std::fs::create_dir_all(&p)?;
        }
    }

    let approvals_path = state_dir.join("approvals.json");
    out.push_str(&format!(
        "FILE {}\n{}\n",
        approvals_path.display(),
        TEMPLATE_APPROVALS
    ));
    if !opts.print_only {
        maybe_write(&approvals_path, TEMPLATE_APPROVALS, opts.force)?;
    }

    for tpl in TEMPLATES {
        let path = state_dir.join(tpl.rel_path);
        out.push_str(&format!("FILE {}\n{}\n", path.display(), tpl.content));
        if !opts.print_only {
            maybe_write(&path, tpl.content, opts.force)?;
        }
    }

    Ok(out)
}

#[cfg(test)]
pub fn policy_template_sha256() -> String {
    crate::store::sha256_hex(TEMPLATE_POLICY.as_bytes())
}

fn template_spec(name: &str) -> Option<&'static TemplateSpec> {
    TEMPLATES.iter().find(|t| t.name == name)
}

fn maybe_write(path: &Path, content: &str, force: bool) -> anyhow::Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::write(path, content.as_bytes())
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn resolved_state_dir(workdir: &Path, override_state_dir: Option<PathBuf>) -> PathBuf {
    resolve_state_paths(workdir, override_state_dir, None, None, None).state_dir
}

#[cfg(test)]
mod tests {
    use super::{
        list_templates, policy_template_sha256, run_init, template_content, version_info,
        write_template, InitOptions,
    };
    use tempfile::TempDir;

    #[test]
    fn policy_template_hash_is_stable() {
        assert_eq!(
            policy_template_sha256(),
            "4343dbdaf7f670c7f1cdf2fbfed8f11c057951a6d7596a469da67d895fa08bcb"
        );
    }

    #[test]
    fn init_creates_expected_files() {
        let tmp = TempDir::new().expect("tmp");
        let workdir = tmp.path().to_path_buf();
        let out = run_init(&InitOptions {
            workdir: workdir.clone(),
            state_dir_override: None,
            force: false,
            print_only: false,
        })
        .expect("init");
        assert!(out.contains("STATE_DIR"));
        let state_dir = workdir.join(".localagent");
        assert!(state_dir.join("policy.yaml").exists());
        assert!(state_dir.join("approvals.json").exists());
        assert!(state_dir.join("mcp_servers.json").exists());
        assert!(state_dir.join("instructions.yaml").exists());
        assert!(state_dir.join("eval/profiles/local_ollama.yaml").exists());
        assert!(state_dir.join("tasks/example_taskfile.json").exists());
    }

    #[test]
    fn init_respects_force_and_print_only() {
        let tmp = TempDir::new().expect("tmp");
        let state_dir = tmp.path().join(".localagent");
        std::fs::create_dir_all(&state_dir).expect("mkdir");
        let policy = state_dir.join("policy.yaml");
        std::fs::write(&policy, "custom\n").expect("write");

        run_init(&InitOptions {
            workdir: tmp.path().to_path_buf(),
            state_dir_override: Some(state_dir.clone()),
            force: false,
            print_only: false,
        })
        .expect("init");
        assert_eq!(std::fs::read_to_string(&policy).expect("read"), "custom\n");

        run_init(&InitOptions {
            workdir: tmp.path().to_path_buf(),
            state_dir_override: Some(state_dir.clone()),
            force: true,
            print_only: false,
        })
        .expect("init");
        assert_ne!(std::fs::read_to_string(&policy).expect("read"), "custom\n");

        let tmp2 = TempDir::new().expect("tmp2");
        run_init(&InitOptions {
            workdir: tmp2.path().to_path_buf(),
            state_dir_override: None,
            force: false,
            print_only: true,
        })
        .expect("print");
        assert!(!tmp2.path().join(".localagent").exists());
    }

    #[test]
    fn template_write_respects_force() {
        let tmp = TempDir::new().expect("tmp");
        let out = tmp.path().join("policy.yaml");
        write_template("policy.yaml", &out, false).expect("write");
        let first = std::fs::read_to_string(&out).expect("read");
        std::fs::write(&out, "changed").expect("write changed");
        assert!(write_template("policy.yaml", &out, false).is_err());
        write_template("policy.yaml", &out, true).expect("force");
        let second = std::fs::read_to_string(&out).expect("read2");
        assert_eq!(second, first);
    }

    #[test]
    fn version_json_shape_has_required_fields() {
        let v = version_info();
        let j = serde_json::to_value(v).expect("json");
        assert_eq!(
            j.get("schema_version").and_then(|v| v.as_str()),
            Some("openagent.version.v1")
        );
        assert!(j.get("version").is_some());
        assert!(j.get("git_sha").is_some());
        assert!(j.get("target").is_some());
        assert!(j.get("build_time_utc").is_some());
    }

    #[test]
    fn template_catalog_is_available() {
        let names = list_templates();
        assert!(names.contains(&"policy.yaml"));
        assert!(names.contains(&"instructions.yaml"));
        assert!(template_content("policy.yaml").is_some());
        assert!(template_content("instructions.yaml").is_some());
        assert!(template_content("missing").is_none());
    }
}
