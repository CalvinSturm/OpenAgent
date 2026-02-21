# LLM Provider Setup (LocalAgent)

This guide covers practical setup for local model providers used by LocalAgent:

- LM Studio (`--provider lmstudio`)
- Ollama (`--provider ollama`)
- llama.cpp server (`--provider llamacpp`)

## 1) LM Studio Setup

### Steps

1. Install LM Studio.
2. Download at least one chat-capable model.
3. Start LM Studio local server mode.
4. Confirm endpoint is active.

Default endpoint used by LocalAgent:

```text
http://localhost:1234/v1
```

### Verify

```bash
localagent doctor --provider lmstudio
```

Expected:

```text
OK: lmstudio reachable at http://localhost:1234/v1
```

### Run

```bash
localagent --provider lmstudio --model <model-id> --prompt "Say hi." run
```

TUI:

```bash
localagent --provider lmstudio --model <model-id> chat --tui true
```

## 2) Ollama Setup

### Install

Install Ollama from official distribution for your OS.

### Pull a model

```bash
ollama pull qwen3:8b
```

### Verify server

Default endpoint:

```text
http://localhost:11434
```

Health check:

```bash
localagent doctor --provider ollama
```

### Run

```bash
localagent --provider ollama --model qwen3:8b --prompt "Say hi." run
```

TUI:

```bash
localagent --provider ollama --model qwen3:8b chat --tui true
```

## 3) llama.cpp Server Setup

Start `llama-server` with your model.

Typical example:

```bash
llama-server -m /path/to/model.gguf --host 127.0.0.1 --port 8080 --jinja
```

Default endpoint used by LocalAgent:

```text
http://localhost:8080/v1
```

Verify:

```bash
localagent doctor --provider llamacpp
```

Run:

```bash
localagent --provider llamacpp --model <model-id> --prompt "Say hi." run
```

### Important for tool calling

For llama.cpp tool-calling flows, start with `--jinja`.

## 4) Common LocalAgent Safety Flags

Defaults are safe and restrictive.

- `--trust off`
- `--allow-shell false`
- `--enable-write-tools false`
- `--allow-write false`

Enable intentionally when needed:

```bash
localagent \
  --provider lmstudio \
  --model <model-id> \
  --allow-shell \
  --enable-write-tools \
  --allow-write \
  --prompt "..." run
```

## 5) Fast Dev Preset

For speed-oriented local testing:

```bash
localagent --provider lmstudio --model <model-id> --caps off --trust off --hooks off --no-session --max-steps 8 chat --tui true
```

## 6) Troubleshooting

### `localagent: command not recognized`

Use Cargo directly:

```bash
cargo run -- --help
```

Or install globally:

```bash
cargo install --path . --force
```

### `unexpected argument` errors

Put global flags before subcommands.

Correct:

```bash
localagent --provider lmstudio --model <model> --prompt "hi" run
```

### Provider connection refused/timeouts

Run doctor:

```bash
localagent doctor --provider lmstudio
localagent doctor --provider ollama
localagent doctor --provider llamacpp
```

### Wrong model name

Make sure `--model` exactly matches provider model identifier.

### Tool-calling not working on llama.cpp

Restart with:

```bash
--jinja
```

## 7) Optional: MCP Playwright for Browser Tasks

Ensure `.localagent/mcp_servers.json` exists (`localagent init` creates it), then:

```bash
localagent mcp list
localagent mcp doctor playwright
```

Use in run/chat:

```bash
localagent --provider lmstudio --model <model> --mcp playwright chat --tui true
```

## 8) Recommended First Validation Flow

```bash
localagent init
localagent doctor --provider lmstudio
localagent --provider lmstudio --model <model> --prompt "Say hi in one sentence." run
localagent --provider lmstudio --model <model> chat --tui true
```
