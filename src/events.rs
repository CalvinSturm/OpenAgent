use std::io::Write;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    RunStart,
    RunEnd,
    ModelRequestStart,
    ModelDelta,
    ModelResponseEnd,
    ToolCallDetected,
    ToolDecision,
    ToolExecTarget,
    ToolExecStart,
    ToolExecEnd,
    CompactionPerformed,
    PolicyLoaded,
    PlannerStart,
    PlannerEnd,
    WorkerStart,
    TaskgraphStart,
    TaskgraphNodeStart,
    TaskgraphNodeEnd,
    TaskgraphEnd,
    HookStart,
    HookEnd,
    HookError,
    ProviderRetry,
    ProviderError,
    McpServerStart,
    McpServerStop,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    pub run_id: String,
    pub step: u32,
    pub kind: EventKind,
    pub data: Value,
}

impl Event {
    pub fn new(run_id: String, step: u32, kind: EventKind, data: Value) -> Self {
        Self {
            ts: crate::trust::now_rfc3339(),
            run_id,
            step,
            kind,
            data,
        }
    }
}

pub trait EventSink: Send {
    fn emit(&mut self, event: Event) -> anyhow::Result<()>;
}

pub struct StdoutSink;

impl StdoutSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for StdoutSink {
    fn emit(&mut self, event: Event) -> anyhow::Result<()> {
        if matches!(event.kind, EventKind::ModelDelta) {
            if let Some(delta) = event.data.get("delta").and_then(|v| v.as_str()) {
                print!("{delta}");
                std::io::stdout().flush().ok();
            }
        }
        Ok(())
    }
}

pub struct JsonlFileSink {
    file: std::fs::File,
}

impl JsonlFileSink {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open events file {}", path.display()))?;
        Ok(Self { file })
    }
}

impl EventSink for JsonlFileSink {
    fn emit(&mut self, event: Event) -> anyhow::Result<()> {
        let line = serde_json::to_string(&event)?;
        writeln!(self.file, "{line}")?;
        Ok(())
    }
}

pub struct MultiSink {
    sinks: Vec<Box<dyn EventSink>>,
}

impl MultiSink {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn push(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl Default for MultiSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for MultiSink {
    fn emit(&mut self, event: Event) -> anyhow::Result<()> {
        for sink in &mut self.sinks {
            sink.emit(event.clone())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{Event, EventKind, EventSink, JsonlFileSink};

    #[test]
    fn event_serializes() {
        let ev = Event::new(
            "run1".to_string(),
            0,
            EventKind::RunStart,
            serde_json::json!({"x":1}),
        );
        let s = serde_json::to_string(&ev).expect("serialize");
        assert!(s.contains("\"run_start\""));
        assert!(s.contains("\"run1\""));
    }

    #[test]
    fn jsonl_appends() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("events.jsonl");
        let mut sink = JsonlFileSink::new(&path).expect("sink");
        sink.emit(Event::new(
            "r".to_string(),
            0,
            EventKind::RunStart,
            serde_json::json!({}),
        ))
        .expect("emit1");
        sink.emit(Event::new(
            "r".to_string(),
            1,
            EventKind::RunEnd,
            serde_json::json!({}),
        ))
        .expect("emit2");
        let content = std::fs::read_to_string(path).expect("read");
        assert_eq!(content.lines().count(), 2);
    }
}
