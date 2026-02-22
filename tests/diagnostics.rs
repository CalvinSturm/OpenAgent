use std::path::PathBuf;

use openagent::diagnostics::{
    render_json, render_text, sort_diagnostics, Diagnostic, Severity, DIAGNOSTIC_SCHEMA_VERSION,
};
use serde_json::json;

fn diag(
    code: &str,
    severity: Severity,
    path: Option<&str>,
    line: Option<u32>,
    col: Option<u32>,
    message: &str,
) -> Diagnostic {
    Diagnostic {
        schema_version: DIAGNOSTIC_SCHEMA_VERSION.to_string(),
        code: code.to_string(),
        severity,
        message: message.to_string(),
        path: path.map(PathBuf::from),
        line,
        col,
        hint: None,
        details: None,
    }
}

#[test]
fn sort_diagnostics_is_predictable_and_stable() {
    let mut diags = vec![
        diag(
            "Z_LAST",
            Severity::Info,
            Some("b/file.txt"),
            Some(3),
            Some(1),
            "info later",
        ),
        diag(
            "E_SAME",
            Severity::Error,
            Some("a/file.txt"),
            Some(10),
            Some(2),
            "same-key",
        ),
        diag("W_MID", Severity::Warning, None, None, None, "warning"),
        diag(
            "E_FIRST",
            Severity::Error,
            Some("a/file.txt"),
            Some(1),
            Some(1),
            "earlier line",
        ),
        diag(
            "E_SAME",
            Severity::Error,
            Some("a/file.txt"),
            Some(10),
            Some(2),
            "same-key",
        ),
    ];

    diags[1].hint = Some("first duplicate".to_string());
    diags[4].hint = Some("second duplicate".to_string());

    sort_diagnostics(&mut diags);

    let ordered: Vec<(
        &str,
        Severity,
        Option<&str>,
        Option<u32>,
        Option<u32>,
        Option<&str>,
    )> = diags
        .iter()
        .map(|d| {
            (
                d.code.as_str(),
                d.severity,
                d.path.as_deref().and_then(|p| p.to_str()),
                d.line,
                d.col,
                d.hint.as_deref(),
            )
        })
        .collect();

    assert_eq!(
        ordered,
        vec![
            (
                "E_FIRST",
                Severity::Error,
                Some("a/file.txt"),
                Some(1),
                Some(1),
                None
            ),
            (
                "E_SAME",
                Severity::Error,
                Some("a/file.txt"),
                Some(10),
                Some(2),
                Some("first duplicate")
            ),
            (
                "E_SAME",
                Severity::Error,
                Some("a/file.txt"),
                Some(10),
                Some(2),
                Some("second duplicate")
            ),
            ("W_MID", Severity::Warning, None, None, None, None),
            (
                "Z_LAST",
                Severity::Info,
                Some("b/file.txt"),
                Some(3),
                Some(1),
                None
            ),
        ]
    );

    let text_a = render_text(&diags);
    let text_b = render_text(&diags);
    assert_eq!(text_a, text_b);
}

#[test]
fn json_roundtrip_preserves_schema_version() {
    let mut d = diag(
        "OA1001",
        Severity::Warning,
        Some("config/openagent.yaml"),
        Some(7),
        Some(12),
        "unknown field",
    );
    d.hint = Some("remove the field or update the schema".to_string());
    d.details = Some(json!({ "field": "legacy_mode", "allowed": false }));

    let value = render_json(&[d.clone()]);
    let parsed: Vec<Diagnostic> = serde_json::from_value(value).expect("roundtrip diagnostics");

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].schema_version, DIAGNOSTIC_SCHEMA_VERSION);
    assert_eq!(parsed[0], d);
}
