use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub reason: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    default: PolicyDecision,
    rules: Vec<CompiledRule>,
    version: u32,
    includes_resolved: Vec<String>,
    mcp_allow: Option<McpAllowlist>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    tool_pattern: String,
    tool: ToolMatcher,
    decision: PolicyDecision,
    when: Vec<Condition>,
    reason: Option<String>,
    source: RuleSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleSource {
    pub path: String,
}

#[derive(Debug, Clone)]
enum ToolMatcher {
    Exact(String),
    Glob(GlobMatcher),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    pub arg: String,
    pub op: ConditionOp,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    StartsWith,
    Contains,
    Equals,
    Glob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAllowSummary {
    pub allow_servers: Vec<String>,
    pub allow_tools: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct McpAllowlist {
    allow_servers: Vec<String>,
    allow_tools: Vec<String>,
    allow_tool_matchers: Vec<GlobMatcher>,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    version: u32,
    default: RawDecision,
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    includes: Vec<String>,
    mcp: Option<RawMcpAllowlist>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawRule {
    tool: String,
    decision: RawDecision,
    #[serde(default)]
    when: Vec<Condition>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMcpAllowlist {
    #[serde(default)]
    allow_servers: Vec<String>,
    #[serde(default)]
    allow_tools: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RawDecision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicy {
    pub version: u32,
    pub default: PolicyDecision,
    pub rules: Vec<EffectiveRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpAllowSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveRule {
    pub tool: String,
    pub decision: PolicyDecision,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub source: RuleSource,
}

impl Policy {
    #[allow(dead_code)]
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let raw: PolicyFile = serde_yaml::from_str(yaml)?;
        if raw.version != 1 && raw.version != 2 {
            return Err(anyhow!("unsupported policy version: {}", raw.version));
        }
        if !raw.includes.is_empty() {
            return Err(anyhow!(
                "policy includes require file-based loading; use --policy path"
            ));
        }
        compile_policy(
            raw.version,
            map_decision(raw.default),
            compile_rules(raw.rules, "<inline>")?,
            raw.mcp.map(compile_mcp_allowlist).transpose()?,
            Vec::new(),
        )
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let start = normalize_path(path, None);
        let mut visited = HashSet::new();
        let mut chain = Vec::<PathBuf>::new();
        let mut ctx = PolicyLoadContext::default();
        load_policy_recursive(&start, &mut visited, &mut chain, &mut ctx)?;
        let default = ctx
            .default
            .ok_or_else(|| anyhow!("policy missing default decision"))?;
        let version = ctx.version.unwrap_or(1);
        compile_policy(
            version,
            default,
            ctx.rules,
            ctx.mcp_allow,
            ctx.includes_resolved,
        )
    }

    pub fn safe_default() -> Self {
        Self {
            default: PolicyDecision::Deny,
            version: 1,
            includes_resolved: Vec::new(),
            mcp_allow: None,
            rules: vec![
                CompiledRule {
                    tool_pattern: "list_dir".to_string(),
                    tool: ToolMatcher::Exact("list_dir".to_string()),
                    decision: PolicyDecision::Allow,
                    when: Vec::new(),
                    reason: None,
                    source: RuleSource {
                        path: "safe_default".to_string(),
                    },
                },
                CompiledRule {
                    tool_pattern: "read_file".to_string(),
                    tool: ToolMatcher::Exact("read_file".to_string()),
                    decision: PolicyDecision::Allow,
                    when: Vec::new(),
                    reason: None,
                    source: RuleSource {
                        path: "safe_default".to_string(),
                    },
                },
                CompiledRule {
                    tool_pattern: "shell".to_string(),
                    tool: ToolMatcher::Exact("shell".to_string()),
                    decision: PolicyDecision::RequireApproval,
                    when: Vec::new(),
                    reason: None,
                    source: RuleSource {
                        path: "safe_default".to_string(),
                    },
                },
                CompiledRule {
                    tool_pattern: "write_file".to_string(),
                    tool: ToolMatcher::Exact("write_file".to_string()),
                    decision: PolicyDecision::RequireApproval,
                    when: Vec::new(),
                    reason: None,
                    source: RuleSource {
                        path: "safe_default".to_string(),
                    },
                },
                CompiledRule {
                    tool_pattern: "apply_patch".to_string(),
                    tool: ToolMatcher::Exact("apply_patch".to_string()),
                    decision: PolicyDecision::RequireApproval,
                    when: Vec::new(),
                    reason: None,
                    source: RuleSource {
                        path: "safe_default".to_string(),
                    },
                },
            ],
        }
    }

    pub fn evaluate(&self, tool: &str, args: &Value) -> PolicyEvaluation {
        for rule in &self.rules {
            if !rule.matches_tool(tool) {
                continue;
            }
            if rule.matches_conditions(args) {
                return PolicyEvaluation {
                    decision: rule.decision,
                    reason: rule.reason.clone(),
                    source: Some(rule.source.path.clone()),
                };
            }
        }
        PolicyEvaluation {
            decision: self.default,
            reason: None,
            source: Some("default".to_string()),
        }
    }

    pub fn mcp_allowlist_summary(&self) -> Option<McpAllowSummary> {
        self.mcp_allow.as_ref().map(McpAllowlist::summary)
    }

    pub fn mcp_tool_allowed(&self, tool_name: &str) -> Result<(), String> {
        let Some(allow) = &self.mcp_allow else {
            return Ok(());
        };
        if !tool_name.starts_with("mcp.") {
            return Ok(());
        }
        let rest = &tool_name["mcp.".len()..];
        let mut parts = rest.splitn(2, '.');
        let server = parts.next().unwrap_or_default();
        if !allow.allow_servers.is_empty() && !allow.allow_servers.iter().any(|s| s == server) {
            return Err(format!("mcp server not allowlisted: {}", server));
        }
        if !allow.allow_tool_matchers.is_empty()
            && !allow
                .allow_tool_matchers
                .iter()
                .any(|m| m.is_match(tool_name))
        {
            return Err(format!("mcp tool not allowlisted: {}", tool_name));
        }
        Ok(())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn includes_resolved(&self) -> &[String] {
        &self.includes_resolved
    }

    pub fn rules_len(&self) -> usize {
        self.rules.len()
    }

    pub fn to_effective_policy(&self) -> EffectivePolicy {
        EffectivePolicy {
            version: self.version,
            default: self.default,
            rules: self
                .rules
                .iter()
                .map(|r| EffectiveRule {
                    tool: r.tool_pattern.clone(),
                    decision: r.decision,
                    when: r.when.clone(),
                    reason: r.reason.clone(),
                    source: r.source.clone(),
                })
                .collect(),
            mcp: self.mcp_allowlist_summary(),
        }
    }
}

pub fn safe_default_policy_repr() -> &'static str {
    "version:1;default:deny;rules:[allow list_dir,allow read_file,require_approval shell,require_approval write_file,require_approval apply_patch]"
}

#[derive(Default)]
struct PolicyLoadContext {
    version: Option<u32>,
    default: Option<PolicyDecision>,
    rules: Vec<CompiledRule>,
    mcp_allow: Option<McpAllowlist>,
    includes_resolved: Vec<String>,
}

fn load_policy_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    chain: &mut Vec<PathBuf>,
    ctx: &mut PolicyLoadContext,
) -> anyhow::Result<()> {
    let canonical = normalize_path(path, chain.last().map(PathBuf::as_path));
    if chain.iter().any(|p| p == &canonical) {
        let mut cycle = chain
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>();
        cycle.push(canonical.display().to_string());
        return Err(anyhow!(
            "policy include cycle detected: {}",
            cycle.join(" -> ")
        ));
    }
    chain.push(canonical.clone());

    let content = std::fs::read_to_string(&canonical).with_context(|| {
        format!(
            "failed reading policy file '{}' (include chain: {})",
            canonical.display(),
            format_chain(chain)
        )
    })?;
    let raw: PolicyFile = serde_yaml::from_str(&content).with_context(|| {
        format!(
            "failed parsing policy file '{}' (include chain: {})",
            canonical.display(),
            format_chain(chain)
        )
    })?;
    if raw.version != 1 && raw.version != 2 {
        return Err(anyhow!(
            "unsupported policy version {} in '{}' (include chain: {})",
            raw.version,
            canonical.display(),
            format_chain(chain)
        ));
    }
    if ctx.version.is_none() {
        ctx.version = Some(raw.version);
    }

    let this_default = map_decision(raw.default);
    if let Some(root_default) = ctx.default {
        if root_default != this_default {
            return Err(anyhow!(
                "policy default mismatch in '{}' (include chain: {}): expected {:?}, got {:?}",
                canonical.display(),
                format_chain(chain),
                root_default,
                this_default
            ));
        }
    } else {
        ctx.default = Some(this_default);
    }

    if ctx.mcp_allow.is_none() && raw.mcp.is_some() {
        ctx.mcp_allow = raw.mcp.map(compile_mcp_allowlist).transpose()?;
    }

    if !visited.contains(&canonical) {
        ctx.rules.extend(compile_rules(
            raw.rules,
            canonical.to_string_lossy().as_ref(),
        )?);
        visited.insert(canonical.clone());
    }

    let parent_dir = canonical.parent().map(Path::to_path_buf);
    for include in raw.includes {
        let include_path = resolve_include_path(&include, parent_dir.as_deref());
        ctx.includes_resolved
            .push(include_path.display().to_string());
        load_policy_recursive(&include_path, visited, chain, ctx)?;
    }

    chain.pop();
    Ok(())
}

fn compile_rules(raw_rules: Vec<RawRule>, source_path: &str) -> anyhow::Result<Vec<CompiledRule>> {
    let mut rules = Vec::with_capacity(raw_rules.len());
    for rr in raw_rules {
        let matcher = if has_glob_meta(&rr.tool) {
            let glob = Glob::new(&rr.tool)?;
            ToolMatcher::Glob(glob.compile_matcher())
        } else {
            ToolMatcher::Exact(rr.tool.clone())
        };
        rules.push(CompiledRule {
            tool_pattern: rr.tool,
            tool: matcher,
            decision: map_decision(rr.decision),
            when: rr.when,
            reason: rr.reason,
            source: RuleSource {
                path: source_path.to_string(),
            },
        });
    }
    Ok(rules)
}

fn compile_mcp_allowlist(raw: RawMcpAllowlist) -> anyhow::Result<McpAllowlist> {
    let mut matchers = Vec::new();
    for pat in &raw.allow_tools {
        matchers.push(Glob::new(pat)?.compile_matcher());
    }
    Ok(McpAllowlist {
        allow_servers: raw.allow_servers,
        allow_tools: raw.allow_tools,
        allow_tool_matchers: matchers,
    })
}

impl McpAllowlist {
    fn summary(&self) -> McpAllowSummary {
        McpAllowSummary {
            allow_servers: self.allow_servers.clone(),
            allow_tools: self.allow_tools.clone(),
        }
    }
}

fn compile_policy(
    version: u32,
    default: PolicyDecision,
    rules: Vec<CompiledRule>,
    mcp_allow: Option<McpAllowlist>,
    includes_resolved: Vec<String>,
) -> anyhow::Result<Policy> {
    Ok(Policy {
        default,
        rules,
        version,
        includes_resolved,
        mcp_allow,
    })
}

impl CompiledRule {
    fn matches_tool(&self, tool: &str) -> bool {
        match &self.tool {
            ToolMatcher::Exact(name) => name == tool,
            ToolMatcher::Glob(glob) => glob.is_match(tool),
        }
    }

    fn matches_conditions(&self, args: &Value) -> bool {
        self.when.iter().all(|cond| cond.matches(args))
    }
}

impl Condition {
    fn matches(&self, args: &Value) -> bool {
        let Some(arg_val) = args.get(&self.arg).and_then(|v| v.as_str()) else {
            return false;
        };
        match self.op {
            ConditionOp::StartsWith => arg_val.starts_with(&self.value),
            ConditionOp::Contains => arg_val.contains(&self.value),
            ConditionOp::Equals => arg_val == self.value,
            ConditionOp::Glob => Glob::new(&self.value)
                .map(|g| g.compile_matcher().is_match(arg_val))
                .unwrap_or(false),
        }
    }
}

fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

fn map_decision(d: RawDecision) -> PolicyDecision {
    match d {
        RawDecision::Allow => PolicyDecision::Allow,
        RawDecision::Deny => PolicyDecision::Deny,
        RawDecision::RequireApproval => PolicyDecision::RequireApproval,
    }
}

fn resolve_include_path(include: &str, base_dir: Option<&Path>) -> PathBuf {
    let raw = PathBuf::from(include);
    if raw.is_absolute() {
        normalize_path(&raw, None)
    } else {
        normalize_path(&raw, base_dir)
    }
}

fn normalize_path(path: &Path, base_dir: Option<&Path>) -> PathBuf {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(base) = base_dir {
        base.join(path)
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    match std::fs::canonicalize(&candidate) {
        Ok(p) => p,
        Err(_) => candidate,
    }
}

fn format_chain(chain: &[PathBuf]) -> String {
    chain
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" -> ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::{Policy, PolicyDecision};

    #[test]
    fn matches_tool_glob_rule() {
        let policy = Policy::from_yaml(
            r#"
version: 1
default: deny
rules:
  - tool: "read_*"
    decision: allow
"#,
        )
        .expect("policy parse should succeed");
        assert_eq!(
            policy
                .evaluate("read_file", &json!({"path":"a.txt"}))
                .decision,
            PolicyDecision::Allow
        );
    }

    #[test]
    fn reason_field_roundtrip() {
        let policy = Policy::from_yaml(
            r#"
version: 2
default: deny
rules:
  - tool: "shell"
    decision: require_approval
    reason: "dangerous shell"
"#,
        )
        .expect("parse");
        let eval = policy.evaluate("shell", &json!({"cmd":"echo"}));
        assert_eq!(eval.reason.as_deref(), Some("dangerous shell"));
    }

    #[test]
    fn includes_root_first_then_depth_first() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("root.yaml");
        let base = tmp.path().join("base.yaml");
        let deep = tmp.path().join("deep.yaml");
        std::fs::write(
            &root,
            r#"
version: 2
default: deny
rules:
  - tool: "read_file"
    decision: allow
includes:
  - "./base.yaml"
"#,
        )
        .expect("write root");
        std::fs::write(
            &base,
            r#"
version: 2
default: deny
rules:
  - tool: "read_file"
    decision: deny
includes:
  - "./deep.yaml"
"#,
        )
        .expect("write base");
        std::fs::write(
            &deep,
            r#"
version: 2
default: deny
rules:
  - tool: "read_file"
    decision: require_approval
"#,
        )
        .expect("write deep");
        let policy = Policy::from_path(&root).expect("load");
        assert_eq!(
            policy.evaluate("read_file", &json!({"path":"a"})).decision,
            PolicyDecision::Allow
        );
        assert_eq!(policy.includes_resolved().len(), 2);
    }

    #[test]
    fn cycle_detection_reports_chain() {
        let tmp = tempdir().expect("tmp");
        let a = tmp.path().join("a.yaml");
        let b = tmp.path().join("b.yaml");
        std::fs::write(
            &a,
            r#"
version: 2
default: deny
includes: ["./b.yaml"]
"#,
        )
        .expect("a");
        std::fs::write(
            &b,
            r#"
version: 2
default: deny
includes: ["./a.yaml"]
"#,
        )
        .expect("b");
        let err = Policy::from_path(&a).expect_err("must fail");
        assert!(err.to_string().contains("include cycle"));
    }

    #[test]
    fn default_mismatch_errors() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("root.yaml");
        let inc = tmp.path().join("inc.yaml");
        std::fs::write(
            &root,
            r#"
version: 2
default: deny
includes: ["./inc.yaml"]
"#,
        )
        .expect("root");
        std::fs::write(
            &inc,
            r#"
version: 2
default: allow
"#,
        )
        .expect("inc");
        let err = Policy::from_path(&root).expect_err("must fail");
        assert!(err.to_string().contains("default mismatch"));
    }

    #[test]
    fn mcp_allowlist_blocks_non_allowed_tool() {
        let policy = Policy::from_yaml(
            r#"
version: 2
default: deny
mcp:
  allow_servers: ["playwright"]
  allow_tools: ["mcp.playwright.*"]
"#,
        )
        .expect("parse");
        assert!(policy.mcp_tool_allowed("mcp.playwright.click").is_ok());
        let err = policy
            .mcp_tool_allowed("mcp.github.search_repos")
            .expect_err("blocked");
        assert!(err.contains("server not allowlisted"));
    }
}
