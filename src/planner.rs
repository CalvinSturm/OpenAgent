use std::collections::BTreeMap;

use anyhow::{anyhow, Context};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PLAN_SCHEMA_VERSION: &str = "openagent.plan.v1";
pub const PLANNER_HANDOFF_HEADER: &str = "PLANNER HANDOFF (openagent.plan.v1)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Single,
    PlannerWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PlannerOutput {
    Json,
    Text,
}

#[derive(Debug, Clone)]
pub struct NormalizedPlan {
    pub plan_json: Value,
    pub plan_hash_hex: String,
    pub used_wrapper: bool,
    pub raw_output: Option<String>,
    pub error: Option<String>,
}

pub fn normalize_planner_output(
    raw_output: &str,
    goal_fallback: &str,
    output: PlannerOutput,
    strict: bool,
) -> anyhow::Result<NormalizedPlan> {
    match output {
        PlannerOutput::Text => {
            let plan_json = wrap_text_plan(goal_fallback, raw_output);
            let plan_hash_hex = hash_canonical_json(&plan_json)?;
            Ok(NormalizedPlan {
                plan_json,
                plan_hash_hex,
                used_wrapper: true,
                raw_output: Some(raw_output.to_string()),
                error: None,
            })
        }
        PlannerOutput::Json => match normalize_plan_json(raw_output) {
            Ok(plan_json) => {
                let plan_hash_hex = hash_canonical_json(&plan_json)?;
                Ok(NormalizedPlan {
                    plan_json,
                    plan_hash_hex,
                    used_wrapper: false,
                    raw_output: None,
                    error: None,
                })
            }
            Err(e) if strict => Err(e),
            Err(e) => {
                let plan_json = wrap_text_plan(goal_fallback, raw_output);
                let plan_hash_hex = hash_canonical_json(&plan_json)?;
                Ok(NormalizedPlan {
                    plan_json,
                    plan_hash_hex,
                    used_wrapper: true,
                    raw_output: Some(raw_output.to_string()),
                    error: Some(e.to_string()),
                })
            }
        },
    }
}

pub fn wrap_text_plan(goal_fallback: &str, raw_text: &str) -> Value {
    let mut obj = Map::new();
    obj.insert(
        "schema_version".to_string(),
        Value::String(PLAN_SCHEMA_VERSION.to_string()),
    );
    obj.insert("goal".to_string(), Value::String(goal_fallback.to_string()));
    obj.insert("assumptions".to_string(), Value::Array(Vec::new()));
    obj.insert("steps".to_string(), Value::Array(Vec::new()));
    obj.insert("risks".to_string(), Value::Array(Vec::new()));
    obj.insert("success_criteria".to_string(), Value::Array(Vec::new()));
    obj.insert("raw_text".to_string(), Value::String(raw_text.to_string()));
    Value::Object(obj)
}

pub fn planner_handoff_content(plan_json: &Value) -> anyhow::Result<String> {
    let body =
        serde_json::to_string_pretty(plan_json).context("failed to encode planner handoff JSON")?;
    Ok(format!("{PLANNER_HANDOFF_HEADER}\n{body}"))
}

pub fn normalize_plan_json(raw: &str) -> anyhow::Result<Value> {
    let value: Value = serde_json::from_str(raw).context("planner output was not valid JSON")?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("planner output must be a JSON object"))?;
    let schema = obj
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("planner output missing schema_version"))?;
    if schema != PLAN_SCHEMA_VERSION {
        return Err(anyhow!(
            "planner schema_version must be {PLAN_SCHEMA_VERSION}, got {schema}"
        ));
    }

    let goal = obj
        .get("goal")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("planner output missing string field goal"))?
        .to_string();

    let assumptions = obj
        .get("assumptions")
        .map(value_string_array)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();

    let success_criteria = obj
        .get("success_criteria")
        .map(value_string_array)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();

    let risks = obj
        .get("risks")
        .map(value_risks_array)
        .transpose()?
        .unwrap_or_default();

    let raw_steps = obj
        .get("steps")
        .map(|v| {
            v.as_array()
                .ok_or_else(|| anyhow!("planner field steps must be an array"))
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();

    let mut steps = Vec::new();
    for (idx, step) in raw_steps.into_iter().enumerate() {
        let step_obj = step
            .as_object()
            .ok_or_else(|| anyhow!("planner step {} must be an object", idx + 1))?;
        let summary = step_obj
            .get("summary")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("planner step {} missing summary", idx + 1))?
            .to_string();
        let intended_tools = step_obj
            .get("intended_tools")
            .map(value_intended_tools_array)
            .transpose()?
            .unwrap_or_default();
        let mut out_step = Map::new();
        out_step.insert("id".to_string(), Value::String(format!("S{}", idx + 1)));
        out_step.insert("summary".to_string(), Value::String(summary));
        out_step.insert("intended_tools".to_string(), Value::Array(intended_tools));
        steps.push(Value::Object(out_step));
    }

    let mut out = Map::new();
    out.insert(
        "schema_version".to_string(),
        Value::String(PLAN_SCHEMA_VERSION.to_string()),
    );
    out.insert("goal".to_string(), Value::String(goal));
    out.insert("assumptions".to_string(), Value::Array(assumptions));
    out.insert("steps".to_string(), Value::Array(steps));
    out.insert("risks".to_string(), Value::Array(risks));
    out.insert(
        "success_criteria".to_string(),
        Value::Array(success_criteria),
    );
    Ok(Value::Object(out))
}

fn value_string_array(value: &Value) -> anyhow::Result<Vec<String>> {
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow!("expected array of strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| anyhow!("expected array of strings"))?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn value_risks_array(value: &Value) -> anyhow::Result<Vec<Value>> {
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow!("planner risks must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item
            .as_object()
            .ok_or_else(|| anyhow!("planner risks entries must be objects"))?;
        let category = obj
            .get("category")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("planner risk missing category"))?;
        let note = obj
            .get("note")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("planner risk missing note"))?;
        let mut risk = Map::new();
        risk.insert("category".to_string(), Value::String(category.to_string()));
        risk.insert("note".to_string(), Value::String(note.to_string()));
        out.push(Value::Object(risk));
    }
    Ok(out)
}

fn value_intended_tools_array(value: &Value) -> anyhow::Result<Vec<Value>> {
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow!("planner intended_tools must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item
            .as_object()
            .ok_or_else(|| anyhow!("planner intended tool entries must be objects"))?;
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("planner intended tool missing name"))?;
        let why = obj
            .get("why")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("planner intended tool missing why"))?;
        let args_hint = obj
            .get("args_hint")
            .cloned()
            .unwrap_or(Value::Object(Map::new()));
        let mut tool = Map::new();
        tool.insert("name".to_string(), Value::String(name.to_string()));
        tool.insert("why".to_string(), Value::String(why.to_string()));
        tool.insert("args_hint".to_string(), args_hint);
        out.push(Value::Object(tool));
    }
    Ok(out)
}

pub fn hash_canonical_json(value: &Value) -> anyhow::Result<String> {
    let canonical = canonical_json_string(value)?;
    Ok(crate::store::sha256_hex(canonical.as_bytes()))
}

fn canonical_json_string(value: &Value) -> anyhow::Result<String> {
    let canonical = canonicalize(value);
    Ok(serde_json::to_string(&canonical)?)
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize(v));
            }
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        hash_canonical_json, normalize_plan_json, normalize_planner_output, PlannerOutput,
    };

    #[test]
    fn strict_json_normalizes_step_ids() {
        let raw = r#"{
          "schema_version":"openagent.plan.v1",
          "goal":"g",
          "assumptions":["a1"],
          "steps":[
            {"id":"X","summary":"s1","intended_tools":[]},
            {"id":"Y","summary":"s2","intended_tools":[]}
          ],
          "risks":[],
          "success_criteria":["ok"]
        }"#;
        let normalized = normalize_plan_json(raw).expect("normalize");
        let steps = normalized
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .expect("steps");
        assert_eq!(steps[0].get("id").and_then(|v| v.as_str()), Some("S1"));
        assert_eq!(steps[1].get("id").and_then(|v| v.as_str()), Some("S2"));
    }

    #[test]
    fn non_strict_json_wraps_invalid() {
        let out = normalize_planner_output("not-json", "goal", PlannerOutput::Json, false)
            .expect("wrapper");
        assert!(out.used_wrapper);
        assert!(out.plan_json.get("raw_text").is_some());
    }

    #[test]
    fn canonical_hash_stable_for_key_order() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":1}}"#).expect("a");
        let b: serde_json::Value = serde_json::from_str(r#"{"a":{"x":1,"y":2},"b":1}"#).expect("b");
        assert_eq!(
            hash_canonical_json(&a).expect("ha"),
            hash_canonical_json(&b).expect("hb")
        );
    }
}
