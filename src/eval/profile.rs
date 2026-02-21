use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

use crate::store::sha256_hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalProfile {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub models: Option<Vec<String>>,
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub runs_per_task: Option<usize>,
    #[serde(default)]
    pub caps: Option<String>,
    #[serde(default)]
    pub trust: Option<String>,
    #[serde(default)]
    pub approval_mode: Option<String>,
    #[serde(default)]
    pub auto_approve_scope: Option<String>,
    #[serde(default)]
    pub mcp: Option<Vec<String>>,
    #[serde(default)]
    pub flags: Option<EvalProfileFlags>,
    #[serde(default)]
    pub thresholds: Option<EvalProfileThresholds>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalProfileFlags {
    #[serde(default)]
    pub enable_write_tools: Option<bool>,
    #[serde(default)]
    pub allow_write: Option<bool>,
    #[serde(default)]
    pub allow_shell: Option<bool>,
    #[serde(default)]
    pub stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalProfileThresholds {
    #[serde(default)]
    pub min_pass_rate: Option<f64>,
    #[serde(default)]
    pub fail_on_any: Option<bool>,
    #[serde(default)]
    pub max_avg_steps: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct LoadedProfile {
    pub profile: EvalProfile,
    pub path: PathBuf,
    pub hash_hex: String,
}

pub fn profile_path_from_name(state_dir: &Path, name: &str) -> PathBuf {
    state_dir
        .join("eval")
        .join("profiles")
        .join(format!("{name}.yaml"))
}

pub fn load_profile(
    state_dir: &Path,
    name: Option<&str>,
    explicit: Option<&Path>,
) -> anyhow::Result<LoadedProfile> {
    let path = if let Some(p) = explicit {
        p.to_path_buf()
    } else if let Some(n) = name {
        profile_path_from_name(state_dir, n)
    } else {
        return Err(anyhow!("profile name or --profile-path is required"));
    };
    let bytes =
        fs::read(&path).with_context(|| format!("failed to read profile {}", path.display()))?;
    let profile: EvalProfile = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("failed to parse profile {}", path.display()))?;
    if profile.version != 1 {
        return Err(anyhow!(
            "unsupported profile version {} in {}",
            profile.version,
            path.display()
        ));
    }
    Ok(LoadedProfile {
        profile,
        path,
        hash_hex: sha256_hex(&bytes),
    })
}

pub fn list_profiles(state_dir: &Path) -> anyhow::Result<Vec<String>> {
    let dir = state_dir.join("eval").join("profiles");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

pub fn doctor_profile(profile: &EvalProfile) -> anyhow::Result<Vec<String>> {
    if profile.version != 1 {
        return Err(anyhow!("profile version must be 1"));
    }
    if let Some(models) = &profile.models {
        if models.is_empty() {
            return Err(anyhow!("profile models must not be empty"));
        }
    }
    let mut req = Vec::new();
    if let Some(mcp) = &profile.mcp {
        if mcp.iter().any(|m| m == "playwright") {
            req.push("--mcp playwright".to_string());
        }
    }
    if let Some(flags) = &profile.flags {
        if flags.enable_write_tools.unwrap_or(false) {
            req.push("--enable-write-tools".to_string());
        }
        if flags.allow_write.unwrap_or(false) {
            req.push("--allow-write".to_string());
        }
        if flags.allow_shell.unwrap_or(false) {
            req.push("--allow-shell".to_string());
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{list_profiles, load_profile};

    #[test]
    fn profile_hash_is_deterministic() {
        let td = tempfile::tempdir().expect("tempdir");
        let root = td.path().join("eval").join("profiles");
        fs::create_dir_all(&root).expect("mkdir");
        let p = root.join("ci.yaml");
        fs::write(
            &p,
            "version: 1\nname: ci\nprovider: ollama\nmodels: [\"m\"]\npack: coding\n",
        )
        .expect("write");
        let a = load_profile(td.path(), Some("ci"), None).expect("load");
        let b = load_profile(td.path(), Some("ci"), None).expect("load2");
        assert_eq!(a.hash_hex, b.hash_hex);
    }

    #[test]
    fn profile_listing_sorted() {
        let td = tempfile::tempdir().expect("tempdir");
        let root = td.path().join("eval").join("profiles");
        fs::create_dir_all(&root).expect("mkdir");
        fs::write(root.join("b.yaml"), "version: 1\nname: b\n").expect("write b");
        fs::write(root.join("a.yaml"), "version: 1\nname: a\n").expect("write a");
        let names = list_profiles(td.path()).expect("list");
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
}
