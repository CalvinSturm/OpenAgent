use std::path::Path;

use anyhow::{anyhow, Context};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum HooksMode {
    Off,
    Auto,
    On,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStage {
    PreModel,
    ToolResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HooksConfigFile {
    pub version: u32,
    #[serde(default)]
    pub hooks: Vec<HookConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookMatch {
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub name: String,
    pub stages: Vec<HookStage>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub r#match: Option<HookMatch>,
}

#[derive(Debug, Clone)]
pub struct LoadedHook {
    pub cfg: HookConfig,
    exact_tools: Vec<String>,
    tool_globs: Option<GlobSet>,
}

#[derive(Debug, Clone)]
pub struct LoadedHooks {
    pub hooks: Vec<LoadedHook>,
}

impl LoadedHooks {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read hooks config: {}", path.display()))?;
        let mut parsed: HooksConfigFile = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse hooks config: {}", path.display()))?;
        if parsed.version != 1 {
            return Err(anyhow!(
                "unsupported hooks config version: {}",
                parsed.version
            ));
        }
        parsed.hooks.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hooks = Vec::with_capacity(parsed.hooks.len());
        for hook in parsed.hooks {
            validate_hook(&hook)?;
            hooks.push(LoadedHook::from_config(hook)?);
        }
        Ok(Self { hooks })
    }
}

impl LoadedHook {
    fn from_config(cfg: HookConfig) -> anyhow::Result<Self> {
        let mut exact_tools = Vec::new();
        let mut glob_builder = GlobSetBuilder::new();
        let mut has_glob = false;
        if let Some(m) = &cfg.r#match {
            for t in &m.tools {
                if has_glob_meta(t) {
                    glob_builder
                        .add(Glob::new(t).with_context(|| format!("invalid tool glob: {t}"))?);
                    has_glob = true;
                } else {
                    exact_tools.push(t.clone());
                }
            }
        }
        let tool_globs = if has_glob {
            Some(glob_builder.build()?)
        } else {
            None
        };
        Ok(Self {
            cfg,
            exact_tools,
            tool_globs,
        })
    }

    pub fn matches_tool(&self, tool_name: &str) -> bool {
        let Some(m) = &self.cfg.r#match else {
            return true;
        };
        if m.tools.is_empty() {
            return true;
        }
        if self.exact_tools.iter().any(|t| t == tool_name) {
            return true;
        }
        if let Some(globs) = &self.tool_globs {
            return globs.is_match(tool_name);
        }
        false
    }

    pub fn has_stage(&self, stage: HookStage) -> bool {
        self.cfg.stages.contains(&stage)
    }
}

fn validate_hook(hook: &HookConfig) -> anyhow::Result<()> {
    if hook.name.trim().is_empty() {
        return Err(anyhow!("hook name must not be empty"));
    }
    if hook.command.trim().is_empty() {
        return Err(anyhow!("hook command must not be empty"));
    }
    if hook.stages.is_empty() {
        return Err(anyhow!(
            "hook '{}' must declare at least one stage",
            hook.name
        ));
    }
    Ok(())
}

fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

pub fn write_default_template(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let template = r#"version: 1
hooks:
  # - name: "redact"
  #   stages: ["tool_result"]
  #   command: "python3"
  #   args: ["scripts/redact.py"]
  #   timeout_ms: 2000
  #   match:
  #     tools: ["shell", "read_file", "mcp.playwright.*"]
"#;
    std::fs::write(path, template)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{HookStage, LoadedHooks};

    #[test]
    fn loads_and_sorts_hooks_by_name() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("hooks.yaml");
        std::fs::write(
            &path,
            r#"
version: 1
hooks:
  - name: z
    stages: ["pre_model"]
    command: "echo"
  - name: a
    stages: ["tool_result"]
    command: "echo"
"#,
        )
        .expect("write");
        let loaded = LoadedHooks::load(&path).expect("load");
        assert_eq!(loaded.hooks[0].cfg.name, "a");
        assert!(loaded.hooks[0].has_stage(HookStage::ToolResult));
    }
}
