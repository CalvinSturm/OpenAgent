# LocalAgent Install

## From Source

```bash
cargo install --path .
```

Then bootstrap state/config:

```bash
localagent init
```

Primary command is `localagent`.

## From GitHub Releases

1. Download the archive for your OS from the Releases page.
2. Extract the binary and place it on your `PATH`.
3. Run:

```bash
localagent version
localagent init
```

## Verify

```bash
localagent --help
localagent doctor --provider ollama
localagent --provider ollama --model llama3.2 --prompt "hello" run
```

## Command Pattern

Global flags come before subcommands:

```bash
localagent --provider lmstudio --model essentialai/rnj-1 --prompt "hello" run
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui
```
