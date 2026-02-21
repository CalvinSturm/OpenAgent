use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::hooks::config::{HookStage, HooksMode, LoadedHook, LoadedHooks};
use crate::hooks::protocol::{
    HookAction, HookInput, HookInvocationReport, HookOutput, HookStageWire, PreModelModifyPayload,
    ToolResultModifyPayload,
};
use crate::types::{Message, Role};

#[derive(Debug, Clone)]
pub struct HookRuntimeConfig {
    pub mode: HooksMode,
    pub config_path: PathBuf,
    pub strict: bool,
    pub timeout_ms: u64,
    pub max_stdout_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct HookManager {
    pub mode: HooksMode,
    pub strict: bool,
    pub timeout_ms: u64,
    pub max_stdout_bytes: usize,
    pub config_path: PathBuf,
    pub hooks: Vec<LoadedHook>,
}

#[derive(Debug, Clone)]
pub struct HookExecError {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PreModelHookResult {
    pub append_messages: Vec<Message>,
    pub abort_reason: Option<String>,
    pub invocations: Vec<HookInvocationReport>,
}

#[derive(Debug, Clone)]
pub struct ToolResultHookResult {
    pub content: String,
    pub truncated: bool,
    pub abort_reason: Option<String>,
    pub invocations: Vec<HookInvocationReport>,
    pub input_digest: String,
    pub output_digest: String,
    pub input_len: usize,
    pub output_len: usize,
}

impl HookManager {
    pub fn build(cfg: HookRuntimeConfig) -> anyhow::Result<Self> {
        let hooks = match cfg.mode {
            HooksMode::Off => Vec::new(),
            HooksMode::Auto => {
                if cfg.config_path.exists() {
                    LoadedHooks::load(&cfg.config_path)?.hooks
                } else {
                    Vec::new()
                }
            }
            HooksMode::On => {
                if cfg.config_path.exists() {
                    LoadedHooks::load(&cfg.config_path)?.hooks
                } else {
                    crate::hooks::config::write_default_template(&cfg.config_path).ok();
                    Vec::new()
                }
            }
        };
        Ok(Self {
            mode: cfg.mode,
            strict: cfg.strict,
            timeout_ms: cfg.timeout_ms,
            max_stdout_bytes: cfg.max_stdout_bytes,
            config_path: cfg.config_path,
            hooks,
        })
    }

    pub fn enabled(&self) -> bool {
        !matches!(self.mode, HooksMode::Off)
    }

    pub fn list(&self) -> &[LoadedHook] {
        &self.hooks
    }

    pub async fn run_pre_model_hooks(
        &self,
        base_input: HookInput,
    ) -> Result<PreModelHookResult, HookExecError> {
        let mut appended = Vec::<Message>::new();
        let mut invocations = Vec::new();

        for hook in self
            .hooks
            .iter()
            .filter(|h| h.has_stage(HookStage::PreModel))
        {
            let started = Instant::now();
            let out = self.invoke_hook(hook, &base_input).await;
            match out {
                Ok(output) => {
                    let mut report = HookInvocationReport {
                        ts: crate::trust::now_rfc3339(),
                        step: base_input.step,
                        stage: "pre_model".to_string(),
                        hook_name: hook.cfg.name.clone(),
                        action: format!("{:?}", output.action).to_lowercase(),
                        message: output.message.clone(),
                        modified: false,
                        duration_ms: started.elapsed().as_millis(),
                        input_digest: None,
                        output_digest: None,
                        appended_message_count: None,
                        appended_digests: None,
                    };
                    match output.action {
                        HookAction::Pass => {}
                        HookAction::Abort => {
                            invocations.push(report);
                            return Ok(PreModelHookResult {
                                append_messages: appended,
                                abort_reason: Some(output.message.unwrap_or_else(|| {
                                    format!("hook '{}' aborted run", hook.cfg.name)
                                })),
                                invocations,
                            });
                        }
                        HookAction::Modify => {
                            let payload_val = output.payload.ok_or_else(|| HookExecError {
                                message: format!(
                                    "hook '{}' returned modify without payload",
                                    hook.cfg.name
                                ),
                            })?;
                            let payload: PreModelModifyPayload =
                                serde_json::from_value(payload_val).map_err(|e| HookExecError {
                                    message: format!(
                                        "hook '{}' invalid pre_model payload: {}",
                                        hook.cfg.name, e
                                    ),
                                })?;
                            if payload.append_messages.len() > 2 {
                                let msg = format!(
                                    "hook '{}' append_messages exceeds max 2 entries",
                                    hook.cfg.name
                                );
                                if self.strict {
                                    return Err(HookExecError { message: msg });
                                }
                                eprintln!("WARN: hook failed: {}", msg);
                                continue;
                            }
                            let mut digests = Vec::new();
                            let mut count = 0usize;
                            for m in payload.append_messages {
                                let Some(role) = parse_append_role(&m.role) else {
                                    let msg = format!(
                                        "hook '{}' may only append system/developer messages",
                                        hook.cfg.name
                                    );
                                    if self.strict {
                                        return Err(HookExecError { message: msg });
                                    }
                                    eprintln!("WARN: hook failed: {}", msg);
                                    continue;
                                };
                                if m.content.chars().count() > 4000 {
                                    let msg = format!(
                                        "hook '{}' append content exceeds 4000 chars",
                                        hook.cfg.name
                                    );
                                    if self.strict {
                                        return Err(HookExecError { message: msg });
                                    }
                                    eprintln!("WARN: hook failed: {}", msg);
                                    continue;
                                }
                                digests.push(sha256_hex(m.content.as_bytes()));
                                appended.push(Message {
                                    role,
                                    content: Some(m.content),
                                    tool_call_id: None,
                                    tool_name: None,
                                    tool_calls: None,
                                });
                                count += 1;
                            }
                            report.modified = count > 0;
                            report.appended_message_count = Some(count);
                            report.appended_digests = Some(digests);
                        }
                    }
                    invocations.push(report);
                }
                Err(e) => {
                    if self.strict {
                        return Err(e);
                    }
                    eprintln!("WARN: hook failed: {}", e.message);
                    invocations.push(HookInvocationReport {
                        ts: crate::trust::now_rfc3339(),
                        step: base_input.step,
                        stage: "pre_model".to_string(),
                        hook_name: hook.cfg.name.clone(),
                        action: "pass".to_string(),
                        message: Some(e.message),
                        modified: false,
                        duration_ms: started.elapsed().as_millis(),
                        input_digest: None,
                        output_digest: None,
                        appended_message_count: None,
                        appended_digests: None,
                    });
                }
            }
        }

        Ok(PreModelHookResult {
            append_messages: appended,
            abort_reason: None,
            invocations,
        })
    }

    pub async fn run_tool_result_hooks(
        &self,
        base_input: HookInput,
        tool_name: &str,
        content: &str,
        truncated: bool,
    ) -> Result<ToolResultHookResult, HookExecError> {
        let input_digest = sha256_hex(content.as_bytes());
        let input_len = content.chars().count();
        let mut current = content.to_string();
        let mut current_truncated = truncated;
        let mut invocations = Vec::new();

        for hook in self
            .hooks
            .iter()
            .filter(|h| h.has_stage(HookStage::ToolResult) && h.matches_tool(tool_name))
        {
            let started = Instant::now();
            let output = self.invoke_hook(hook, &base_input).await;
            match output {
                Ok(out) => {
                    let mut report = HookInvocationReport {
                        ts: crate::trust::now_rfc3339(),
                        step: base_input.step,
                        stage: "tool_result".to_string(),
                        hook_name: hook.cfg.name.clone(),
                        action: format!("{:?}", out.action).to_lowercase(),
                        message: out.message.clone(),
                        modified: false,
                        duration_ms: started.elapsed().as_millis(),
                        input_digest: Some(sha256_hex(current.as_bytes())),
                        output_digest: None,
                        appended_message_count: None,
                        appended_digests: None,
                    };
                    match out.action {
                        HookAction::Pass => {}
                        HookAction::Abort => {
                            invocations.push(report);
                            return Ok(ToolResultHookResult {
                                content: current,
                                truncated: current_truncated,
                                abort_reason: Some(out.message.unwrap_or_else(|| {
                                    format!("hook '{}' aborted run", hook.cfg.name)
                                })),
                                invocations,
                                input_digest,
                                output_digest: sha256_hex(content.as_bytes()),
                                input_len,
                                output_len: content.chars().count(),
                            });
                        }
                        HookAction::Modify => {
                            let payload_val = out.payload.ok_or_else(|| HookExecError {
                                message: format!(
                                    "hook '{}' returned modify without payload",
                                    hook.cfg.name
                                ),
                            })?;
                            let payload: ToolResultModifyPayload =
                                serde_json::from_value(payload_val).map_err(|e| HookExecError {
                                    message: format!(
                                        "hook '{}' invalid tool_result payload: {}",
                                        hook.cfg.name, e
                                    ),
                                })?;
                            if payload.content.len() > self.max_stdout_bytes {
                                let msg = format!(
                                    "hook '{}' tool_result content exceeds hooks max stdout bytes",
                                    hook.cfg.name
                                );
                                if self.strict {
                                    return Err(HookExecError { message: msg });
                                }
                                eprintln!("WARN: hook failed: {}", msg);
                                continue;
                            }
                            current = payload.content;
                            if let Some(v) = payload.truncated {
                                current_truncated = v;
                            }
                            report.modified = true;
                            report.output_digest = Some(sha256_hex(current.as_bytes()));
                        }
                    }
                    if report.output_digest.is_none() {
                        report.output_digest = Some(sha256_hex(current.as_bytes()));
                    }
                    invocations.push(report);
                }
                Err(e) => {
                    if self.strict {
                        return Err(e);
                    }
                    eprintln!("WARN: hook failed: {}", e.message);
                    invocations.push(HookInvocationReport {
                        ts: crate::trust::now_rfc3339(),
                        step: base_input.step,
                        stage: "tool_result".to_string(),
                        hook_name: hook.cfg.name.clone(),
                        action: "pass".to_string(),
                        message: Some(e.message),
                        modified: false,
                        duration_ms: started.elapsed().as_millis(),
                        input_digest: Some(sha256_hex(current.as_bytes())),
                        output_digest: Some(sha256_hex(current.as_bytes())),
                        appended_message_count: None,
                        appended_digests: None,
                    });
                }
            }
        }

        let output_digest = sha256_hex(current.as_bytes());
        let output_len = current.chars().count();
        Ok(ToolResultHookResult {
            content: current,
            truncated: current_truncated,
            abort_reason: None,
            invocations,
            input_digest,
            output_digest,
            input_len,
            output_len,
        })
    }
    async fn invoke_hook(
        &self,
        hook: &LoadedHook,
        input: &HookInput,
    ) -> Result<HookOutput, HookExecError> {
        let timeout_ms = hook.cfg.timeout_ms.unwrap_or(self.timeout_ms);
        let mut command = Command::new(&hook.cfg.command);
        command.args(&hook.cfg.args);
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let mut child = command.spawn().map_err(|e| HookExecError {
            message: format!("failed spawning hook '{}': {}", hook.cfg.name, e),
        })?;

        let input_bytes = serde_json::to_vec(input).map_err(|e| HookExecError {
            message: format!("failed encoding hook input '{}': {}", hook.cfg.name, e),
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(&input_bytes)
                .await
                .map_err(|e| HookExecError {
                    message: format!("failed writing stdin for hook '{}': {}", hook.cfg.name, e),
                })?;
        }

        let output = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| HookExecError {
            message: format!("hook '{}' timed out after {}ms", hook.cfg.name, timeout_ms),
        })?
        .map_err(|e| HookExecError {
            message: format!("hook '{}' failed to complete: {}", hook.cfg.name, e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect::<String>();
            return Err(HookExecError {
                message: format!(
                    "hook '{}' exited with {}: {}",
                    hook.cfg.name, output.status, stderr
                ),
            });
        }

        if output.stdout.len() > self.max_stdout_bytes {
            return Err(HookExecError {
                message: format!(
                    "hook '{}' stdout exceeded max {} bytes",
                    hook.cfg.name, self.max_stdout_bytes
                ),
            });
        }
        let parsed: HookOutput =
            serde_json::from_slice(&output.stdout).map_err(|e| HookExecError {
                message: format!("hook '{}' returned invalid JSON: {}", hook.cfg.name, e),
            })?;
        if parsed.schema_version != "openagent.hook_output.v1" {
            return Err(HookExecError {
                message: format!(
                    "hook '{}' returned unsupported schema_version",
                    hook.cfg.name
                ),
            });
        }
        Ok(parsed)
    }
}

fn parse_append_role(role: &str) -> Option<Role> {
    match role {
        "system" => Some(Role::System),
        "developer" => Some(Role::Developer),
        _ => None,
    }
}

pub fn make_pre_model_input(
    run_id: &str,
    step: u32,
    provider: &str,
    model: &str,
    workdir: &Path,
    payload: serde_json::Value,
) -> HookInput {
    HookInput {
        schema_version: "openagent.hook_input.v1".to_string(),
        stage: HookStageWire::PreModel,
        run_id: run_id.to_string(),
        step,
        provider: provider.to_string(),
        model: model.to_string(),
        workdir: stable_workdir(workdir),
        caps: None,
        payload,
    }
}

pub fn make_tool_result_input(
    run_id: &str,
    step: u32,
    provider: &str,
    model: &str,
    workdir: &Path,
    payload: serde_json::Value,
) -> HookInput {
    HookInput {
        schema_version: "openagent.hook_input.v1".to_string(),
        stage: HookStageWire::ToolResult,
        run_id: run_id.to_string(),
        step,
        provider: provider.to_string(),
        model: model.to_string(),
        workdir: stable_workdir(workdir),
        caps: None,
        payload,
    }
}

fn stable_workdir(path: &Path) -> String {
    match std::fs::canonicalize(path) {
        Ok(p) => p.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{HookManager, HookRuntimeConfig};
    use crate::hooks::config::HooksMode;

    #[test]
    fn invalid_config_is_error() {
        let tmp = tempdir().expect("tmp");
        let cfg = tmp.path().join("hooks.yaml");
        std::fs::write(&cfg, "bad:").expect("write");
        let res = HookManager::build(HookRuntimeConfig {
            mode: HooksMode::Auto,
            config_path: cfg,
            strict: false,
            timeout_ms: 1000,
            max_stdout_bytes: 1000,
        });
        assert!(res.is_err());
    }
}
