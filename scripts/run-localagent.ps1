param(
    [Parameter(Mandatory = $true)]
    [string]$Model,

    [ValidateSet("lmstudio", "ollama", "llamacpp", "mock")]
    [string]$Provider = "lmstudio",

    [ValidateSet("chat", "run", "exec")]
    [string]$Command = "chat",

    [ValidateSet("safe", "coding", "web", "custom")]
    [string]$Mode = "coding",

    [string]$Prompt = "",

    [switch]$PlainTui,
    [switch]$NoTaskProfile,
    [switch]$DryRun,

    [string[]]$ExtraArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ModelPreset {
    param([string]$Name)

    $preset = @{
        InstructionModelProfile = $null
        InstructionTaskProfile = "coding_orchestrator_v1"
        MaxContextChars = "20000"
        MaxSessionMessages = "20"
        CompactionMode = "summary"
    }

    if ($Name -like "orchestrator-8b-claude-4.5-opus-distill*") {
        $preset.InstructionModelProfile = "orchestrator_8b_opus_distill_v1"
        $preset.MaxContextChars = "20000"
        return $preset
    }

    if ($Name -like "qwen*") {
        $preset.MaxContextChars = "16000"
        return $preset
    }

    if ($Name -like "nanbeige4.1-3b*") {
        # Known-good low-footprint tool-calling model preset.
        $preset.MaxContextChars = "12000"
        $preset.MaxSessionMessages = "16"
        return $preset
    }

    if ($Name -like "llama*") {
        $preset.MaxContextChars = "12000"
        return $preset
    }

    return $preset
}

function Add-ModeFlags {
    param(
        [string]$SelectedMode,
        [System.Collections.Generic.List[string]]$ArgsList
    )

    switch ($SelectedMode) {
        "safe" { }
        "coding" {
            $ArgsList.Add("--enable-write-tools")
            $ArgsList.Add("--allow-write")
            $ArgsList.Add("--allow-shell")
        }
        "web" {
            $ArgsList.Add("--mcp")
            $ArgsList.Add("playwright")
        }
        "custom" {
            $ArgsList.Add("--enable-write-tools")
            $ArgsList.Add("--allow-write")
            $ArgsList.Add("--allow-shell")
            $ArgsList.Add("--mcp")
            $ArgsList.Add("playwright")
        }
    }
}

$localagentCmd = Get-Command "localagent" -ErrorAction SilentlyContinue
if (-not $localagentCmd) {
    throw "localagent binary not found on PATH. Install first with 'cargo install --path . --force'."
}

$workdir = (Get-Location).Path
$stateDir = Join-Path $workdir ".localagent"
$instructionsPath = Join-Path $stateDir "instructions.yaml"
$preset = Resolve-ModelPreset -Name $Model

$argsList = [System.Collections.Generic.List[string]]::new()
$argsList.Add("--provider")
$argsList.Add($Provider)
$argsList.Add("--model")
$argsList.Add($Model)
$argsList.Add("--caps")
$argsList.Add("strict")
$argsList.Add("--trust")
$argsList.Add("on")
$argsList.Add("--max-context-chars")
$argsList.Add($preset.MaxContextChars)
$argsList.Add("--compaction-mode")
$argsList.Add($preset.CompactionMode)
$argsList.Add("--max-session-messages")
$argsList.Add($preset.MaxSessionMessages)

if (Test-Path $instructionsPath) {
    $argsList.Add("--instructions-config")
    $argsList.Add($instructionsPath)
}

if ($preset.InstructionModelProfile) {
    $argsList.Add("--instruction-model-profile")
    $argsList.Add($preset.InstructionModelProfile)
}

if ((-not $NoTaskProfile) -and $preset.InstructionTaskProfile) {
    $argsList.Add("--instruction-task-profile")
    $argsList.Add($preset.InstructionTaskProfile)
}

Add-ModeFlags -SelectedMode $Mode -ArgsList $argsList

switch ($Command) {
    "chat" {
        $argsList.Add("chat")
        if ($PlainTui) {
            $argsList.Add("--plain-tui")
        }
        else {
            $argsList.Add("--tui")
        }
    }
    "run" {
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw 'Prompt is required for ''run''. Pass -Prompt "<text>".'
        }
        $argsList.Add("--prompt")
        $argsList.Add($Prompt)
        $argsList.Add("run")
    }
    "exec" {
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw 'Prompt is required for ''exec''. Pass -Prompt "<text>".'
        }
        $argsList.Add("--prompt")
        $argsList.Add($Prompt)
        $argsList.Add("exec")
    }
}

if ($ExtraArgs) {
    foreach ($arg in $ExtraArgs) {
        $argsList.Add($arg)
    }
}

$preview = "localagent " + ($argsList -join " ")
Write-Host $preview

if ($DryRun) {
    return
}

& localagent @argsList
$exit = $LASTEXITCODE
if ($null -ne $exit -and $exit -ne 0) {
    exit $exit
}
