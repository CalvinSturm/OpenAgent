# LocalAgent Templates

Use `localagent template list` to see all embedded templates.

## Available Names

- `policy.yaml`
- `instructions.yaml`
- `hooks.yaml`
- `mcp_servers.json`
- `eval_profile_local_ollama.yaml`
- `cost_model.yaml`
- `example_taskfile.json`
- `policy_cases.yaml`

## Commands

Show a template:

```bash
localagent template show policy.yaml
```

Write a template to disk:

```bash
localagent template write policy_cases.yaml --out .localagent/policy_cases.yaml
```

Overwrite existing file:

```bash
localagent template write policy.yaml --out .localagent/policy.yaml --force
```

## Init Relationship

`localagent init` uses the same embedded bytes for generated files.  
That keeps template output deterministic across `init`, `show`, and `write`.
