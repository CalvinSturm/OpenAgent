use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone)]
pub struct Policy {
    default: PolicyDecision,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    tool: ToolMatcher,
    decision: PolicyDecision,
    when: Vec<Condition>,
}

#[derive(Debug, Clone)]
enum ToolMatcher {
    Exact(String),
    Glob(GlobMatcher),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    pub arg: String,
    pub op: ConditionOp,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOp {
    StartsWith,
    Contains,
    Equals,
    Glob,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    version: u32,
    default: RawDecision,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    tool: String,
    decision: RawDecision,
    #[serde(default)]
    when: Vec<Condition>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawDecision {
    Allow,
    Deny,
    RequireApproval,
}

impl Policy {
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let raw: PolicyFile = serde_yaml::from_str(yaml)?;
        if raw.version != 1 {
            return Err(anyhow::anyhow!(
                "unsupported policy version: {}",
                raw.version
            ));
        }
        let mut rules = Vec::new();
        for rr in raw.rules {
            let matcher = if has_glob_meta(&rr.tool) {
                let glob = Glob::new(&rr.tool)?;
                ToolMatcher::Glob(glob.compile_matcher())
            } else {
                ToolMatcher::Exact(rr.tool)
            };
            rules.push(CompiledRule {
                tool: matcher,
                decision: map_decision(rr.decision),
                when: rr.when,
            });
        }
        Ok(Self {
            default: map_decision(raw.default),
            rules,
        })
    }

    pub fn safe_default() -> Self {
        Self {
            default: PolicyDecision::Deny,
            rules: vec![
                CompiledRule {
                    tool: ToolMatcher::Exact("list_dir".to_string()),
                    decision: PolicyDecision::Allow,
                    when: Vec::new(),
                },
                CompiledRule {
                    tool: ToolMatcher::Exact("read_file".to_string()),
                    decision: PolicyDecision::Allow,
                    when: Vec::new(),
                },
                CompiledRule {
                    tool: ToolMatcher::Exact("shell".to_string()),
                    decision: PolicyDecision::RequireApproval,
                    when: Vec::new(),
                },
                CompiledRule {
                    tool: ToolMatcher::Exact("write_file".to_string()),
                    decision: PolicyDecision::RequireApproval,
                    when: Vec::new(),
                },
                CompiledRule {
                    tool: ToolMatcher::Exact("apply_patch".to_string()),
                    decision: PolicyDecision::RequireApproval,
                    when: Vec::new(),
                },
            ],
        }
    }

    pub fn evaluate(&self, tool: &str, args: &Value) -> PolicyDecision {
        for rule in &self.rules {
            if !rule.matches_tool(tool) {
                continue;
            }
            if rule.matches_conditions(args) {
                return rule.decision;
            }
        }
        self.default
    }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

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
            policy.evaluate("read_file", &json!({"path":"a.txt"})),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn matches_string_conditions() {
        let policy = Policy::from_yaml(
            r#"
version: 1
default: deny
rules:
  - tool: "read_file"
    decision: allow
    when:
      - arg: "path"
        op: starts_with
        value: "src/"
      - arg: "path"
        op: contains
        value: ".rs"
"#,
        )
        .expect("policy parse should succeed");

        assert_eq!(
            policy.evaluate("read_file", &json!({"path":"src/main.rs"})),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate("read_file", &json!({"path":"tests/main.txt"})),
            PolicyDecision::Deny
        );
    }
}
