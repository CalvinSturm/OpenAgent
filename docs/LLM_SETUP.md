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
localagent --provider lmstudio --model <model-id> chat --tui
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
localagent --provider ollama --model qwen3:8b chat --tui
```

### Model Recommendations by VRAM (Tool Calling + Reasoning)

These are practical starting points for local agent use. Exact memory needs depend on quantization, context length, and runtime settings.

#### 8 GB VRAM

Good starting points:

- `qwen3:4b`
- `deepseek-r1:1.5b`
- `deepseek-r1:7b` (lower context / tighter memory settings)

Tradeoffs:

- More likely to need per-model prompt tuning for reliable tool-call formatting
- Weaker multi-step planning than larger models

#### 12 GB VRAM

Good starting points:

- `qwen3:8b` (strong default local-agent pick)
- `deepseek-r1:8b`
- `deepseek-r1:14b` (depending on quantization/context)

#### 16 GB VRAM

Good starting points:

- `qwen3:14b`
- `deepseek-r1:14b`
- `qwen3:8b` with more headroom for context

#### 24 GB VRAM

Good starting points:

- `qwen3:30b`
- `qwen3:32b`
- `deepseek-r1:32b`

#### 48 GB+ VRAM / Multi-GPU

Good starting points:

- `deepseek-r1:70b`
- `qwen3-coder-next` (coding-focused agent workflows)

### Quick Recommendations

- General local agent default: `qwen3:8b`
- Reasoning/planning focus: `deepseek-r1:8b` or `deepseek-r1:14b`
- 24 GB class GPU: `qwen3:30b` or `deepseek-r1:32b`
- Coding-focused agent: `qwen3-coder-next`
- Small-footprint tool-calling pick: `nanbeige4.1-3b@bf16`

### Known-Good Small Tool-Calling Profile

If you have this model in LM Studio:

- `nanbeige4.1-3b@bf16`

Recommended quick run:

```bash
localagent --provider lmstudio --model nanbeige4.1-3b@bf16 chat --tui
```

Recommended smoke flow:

```bash
localagent --provider lmstudio --model nanbeige4.1-3b@bf16 --prompt "Say hi." run
localagent --provider lmstudio --model nanbeige4.1-3b@bf16 learn list
```

PowerShell helper (repo script) now applies a tuned preset for this model:

```powershell
.\scripts\run-localagent.ps1 -Provider lmstudio -Model "nanbeige4.1-3b@bf16" -Command chat -Mode coding
```

### Important Notes for Local Agent Reliability

- Models trained for both tool calling and reasoning usually perform better in MCP-heavy workflows.
- Smaller models often need model-specific instruction tuning to format tool calls consistently.
- See `docs/INSTRUCTION_PROFILES.md` for per-model tuning guidance and examples.

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
localagent --provider lmstudio --model <model-id> --caps off --trust off --hooks off --no-session --max-steps 8 chat --tui
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

When upgrading LocalAgent, re-run the same command from the repo root.

Windows note: if `cargo install` fails with a `failed to move ... localagent.exe` error, close any running `localagent` process/TUI and retry.

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

For slow CPUs / first-token delays, increase timeouts and disable retries while testing:

```bash
localagent --provider llamacpp --base-url http://localhost:5001/v1 --model default --http-timeout-ms 300000 --http-stream-idle-timeout-ms 120000 --http-max-retries 0 --prompt "..." run
```

### Wrong model name

Make sure `--model` exactly matches provider model identifier.

### Tool-calling not working on llama.cpp

Restart with:

```bash
--jinja
```

### Tool calls are inconsistent on smaller local models

This is common and usually improvable.

What to do:

1. Add a per-model profile in `.localagent/instructions.yaml`
2. Keep instructions short and explicit (tool JSON format, one call at a time, ask before guessing)
3. Test the same prompt repeatedly and keep only changes that improve consistency

See `docs/INSTRUCTION_PROFILES.md` for examples and a recommended workflow.

## 7) Optional: MCP Playwright for Browser Tasks

Ensure `.localagent/mcp_servers.json` exists (`localagent` auto-init or `localagent init` creates it), then:

```bash
localagent mcp list
localagent mcp doctor playwright
```

Use in run/chat:

```bash
localagent --provider lmstudio --model <model> --mcp playwright chat --tui
```

## 8) Recommended First Validation Flow

```bash
localagent doctor --provider lmstudio
localagent --provider lmstudio --model <model> --prompt "Say hi in one sentence." run
localagent --provider lmstudio --model <model> chat --tui
```
