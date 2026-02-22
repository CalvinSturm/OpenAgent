use std::collections::BTreeMap;

use anyhow::{anyhow, Context};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PLAN_SCHEMA_VERSION: &str = "openagent.plan.v1";
pub const PLANNER_HANDOFF_HEADER: &str = "PLANNER HANDOFF (openagent.plan.v1)";
pub const STEP_RESULT_SCHEMA_VERSION: &str = "openagent.step_result.v1";

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

pub fn planner_worker_contract_content(plan_json: &Value) -> anyhow::Result<String> {
    let step_ids = plan_step_ids(plan_json)?;
    let allow = if step_ids.is_empty() {
        "final".to_string()
    } else {
        format!("{}, final", step_ids.join(", "))
    };
    Ok(format!(
        "WORKER STEP RESULT CONTRACT ({STEP_RESULT_SCHEMA_VERSION})\n\
Return final output as JSON only with fields:\n\
{{\n\
  \"schema_version\": \"{STEP_RESULT_SCHEMA_VERSION}\",\n\
  \"step_id\": \"<one of: {allow}>\",\n\
  \"status\": \"done|retry|replan|fail\",\n\
  \"evidence\": [\"short factual observations\"],\n\
  \"next_step_id\": \"optional next step id\",\n\
  \"notes\": \"optional brief note\"\n\
}}"
    ))
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
        let done_criteria = step_obj
            .get("done_criteria")
            .map(value_string_array)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        let verifier_checks = step_obj
            .get("verifier_checks")
            .map(value_string_array)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        let mut out_step = Map::new();
        out_step.insert("id".to_string(), Value::String(format!("S{}", idx + 1)));
        out_step.insert("summary".to_string(), Value::String(summary));
        out_step.insert("intended_tools".to_string(), Value::Array(intended_tools));
        out_step.insert("done_criteria".to_string(), Value::Array(done_criteria));
        out_step.insert("verifier_checks".to_string(), Value::Array(verifier_checks));
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

pub fn normalize_worker_step_result(raw: &str, plan_json: &Value) -> anyhow::Result<Value> {
    let value = parse_jsonish(raw)?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("worker step result must be a JSON object"))?;
    let schema = obj
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("worker step result missing schema_version"))?;
    if schema != STEP_RESULT_SCHEMA_VERSION {
        return Err(anyhow!(
            "worker step result schema_version must be {STEP_RESULT_SCHEMA_VERSION}, got {schema}"
        ));
    }
    let step_id = obj
        .get("step_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("worker step result missing step_id"))?;
    let allowed_steps = plan_step_ids(plan_json)?;
    if step_id != "final" && !allowed_steps.iter().any(|s| s == step_id) {
        return Err(anyhow!(
            "worker step_id '{step_id}' not present in plan (allowed: {})",
            if allowed_steps.is_empty() {
                "final".to_string()
            } else {
                format!("{}, final", allowed_steps.join(", "))
            }
        ));
    }
    let status = obj
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("worker step result missing status"))?;
    match status {
        "done" | "retry" | "replan" | "fail" => {}
        _ => {
            return Err(anyhow!(
                "worker step result invalid status '{status}' (expected done|retry|replan|fail)"
            ));
        }
    }
    let evidence = obj
        .get("evidence")
        .map(value_string_array)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    let next_step_id = obj
        .get("next_step_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(next) = &next_step_id {
        if next != "final" && !allowed_steps.iter().any(|s| s == next) {
            return Err(anyhow!(
                "worker next_step_id '{next}' not present in plan (allowed: {})",
                if allowed_steps.is_empty() {
                    "final".to_string()
                } else {
                    format!("{}, final", allowed_steps.join(", "))
                }
            ));
        }
    }
    let notes = obj.get("notes").and_then(Value::as_str).map(str::to_string);

    let mut normalized = Map::new();
    normalized.insert(
        "schema_version".to_string(),
        Value::String(STEP_RESULT_SCHEMA_VERSION.to_string()),
    );
    normalized.insert("step_id".to_string(), Value::String(step_id.to_string()));
    normalized.insert("status".to_string(), Value::String(status.to_string()));
    normalized.insert("evidence".to_string(), Value::Array(evidence));
    if let Some(next) = next_step_id {
        normalized.insert("next_step_id".to_string(), Value::String(next));
    }
    if let Some(n) = notes {
        normalized.insert("notes".to_string(), Value::String(n));
    }
    Ok(Value::Object(normalized))
}

fn plan_step_ids(plan_json: &Value) -> anyhow::Result<Vec<String>> {
    let steps = plan_json
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("plan_json missing steps array"))?;
    let mut out = Vec::with_capacity(steps.len());
    for (idx, step) in steps.iter().enumerate() {
        let id = step
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("plan step {} missing id", idx + 1))?;
        out.push(id.to_string());
    }
    Ok(out)
}

fn parse_jsonish(raw: &str) -> anyhow::Result<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty worker step result"));
    }
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return Ok(v);
    }
    if let Some(candidate) = fenced_json_candidate(trimmed) {
        if let Ok(v) = serde_json::from_str::<Value>(&candidate) {
            return Ok(v);
        }
    }
    if let Some((start, end)) = find_json_bounds(trimmed) {
        let candidate = &trimmed[start..=end];
        if let Ok(v) = serde_json::from_str::<Value>(candidate) {
            return Ok(v);
        }
    }
    Err(anyhow!(
        "worker step result must be valid JSON (plain JSON or fenced ```json block)"
    ))
}

fn fenced_json_candidate(s: &str) -> Option<String> {
    if !s.starts_with("```") {
        return None;
    }
    let lines = s.lines().collect::<Vec<_>>();
    if lines.len() < 3 {
        return None;
    }
    if !lines.first()?.starts_with("```") || !lines.last()?.starts_with("```") {
        return None;
    }
    Some(lines[1..lines.len() - 1].join("\n"))
}

fn find_json_bounds(s: &str) -> Option<(usize, usize)> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end <= start {
        return None;
    }
    Some((start, end))
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
        hash_canonical_json, normalize_plan_json, normalize_planner_output,
        normalize_worker_step_result, PlannerOutput, STEP_RESULT_SCHEMA_VERSION,
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

    #[test]
    fn worker_step_result_validates_against_plan_step_ids() {
        let plan = serde_json::json!({
            "schema_version":"openagent.plan.v1",
            "goal":"g",
            "assumptions":[],
            "steps":[{"id":"S1","summary":"s1","intended_tools":[],"done_criteria":[],"verifier_checks":[]}],
            "risks":[],
            "success_criteria":[]
        });
        let raw = format!(
            r#"{{"schema_version":"{}","step_id":"S1","status":"done","evidence":["ok"]}}"#,
            STEP_RESULT_SCHEMA_VERSION
        );
        let normalized = normalize_worker_step_result(&raw, &plan).expect("valid");
        assert_eq!(
            normalized.get("step_id").and_then(|v| v.as_str()),
            Some("S1")
        );
        assert_eq!(
            normalized.get("status").and_then(|v| v.as_str()),
            Some("done")
        );
    }
}
