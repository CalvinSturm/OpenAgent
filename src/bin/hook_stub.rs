use std::io::{Read, Write};

use serde_json::json;

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }

    let parsed = serde_json::from_str::<serde_json::Value>(&input).ok();
    if parsed
        .as_ref()
        .and_then(|v| v.get("payload"))
        .and_then(|p| p.get("force_invalid_json"))
        .and_then(|x| x.as_bool())
        == Some(true)
    {
        print!("not-json");
        return;
    }

    let stage = parsed
        .as_ref()
        .and_then(|v| {
            v.get("stage")
                .and_then(|s| s.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "pre_model".to_string());

    let mode = parsed
        .as_ref()
        .and_then(|v| v.get("payload"))
        .and_then(|p| p.get("force_mode"))
        .and_then(|x| x.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("HOOK_STUB_MODE").ok())
        .unwrap_or_else(|| "auto".to_string());
    let auto_mode = if mode == "auto" {
        if stage == "tool_result" {
            "modify"
        } else {
            "pass"
        }
    } else {
        mode.as_str()
    };
    let out = match (stage.as_str(), auto_mode) {
        (_, "abort") => json!({
            "schema_version":"openagent.hook_output.v1",
            "action":"abort",
            "message":"stub abort"
        }),
        ("pre_model", "modify_many") => json!({
            "schema_version":"openagent.hook_output.v1",
            "action":"modify",
            "payload":{"append_messages":[
                {"role":"system","content":"a"},
                {"role":"system","content":"b"},
                {"role":"system","content":"c"}
            ]}
        }),
        ("pre_model", "modify") => json!({
            "schema_version":"openagent.hook_output.v1",
            "action":"modify",
            "payload":{"append_messages":[{"role":"system","content":"stub appended"}]}
        }),
        ("tool_result", "modify") => json!({
            "schema_version":"openagent.hook_output.v1",
            "action":"modify",
            "payload":{"content":"stub redacted","truncated":false}
        }),
        _ => json!({
            "schema_version":"openagent.hook_output.v1",
            "action":"pass"
        }),
    };

    let _ = std::io::stdout().write_all(out.to_string().as_bytes());
}
