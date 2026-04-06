<#
.SYNOPSIS
    PAS -- Practical Attack Simulation

.DESCRIPTION
    A detection engineering platform for validating detections, mapping coverage
    gaps, generating threat hunting artifacts, and building blue team capability.

    PAS executes MITRE ATT&CK-mapped behaviors on a controlled host and guides
    the analyst through validating whether their SIEM and EDR produced the
    expected telemetry and detections. It does not evaluate itself.

    USE CASES:
      - Detection validation   : confirm an existing rule fires on real behavior
      - Coverage mapping       : discover what techniques you have no detection for
      - Threat hunt support    : generate artifacts to hunt against in your SIEM
      - Blue team training     : structured, repeatable lab exercises

.PARAMETER Scenario
    Path to a single scenario YAML file.

.PARAMETER Suite
    Path to a suite YAML file (runs multiple scenarios in order).

.PARAMETER Tactic
    Run all scenarios found under scenarios\<tactic>\ directory.

.PARAMETER Out
    Output directory for result JSON files. Defaults to .\results\

.PARAMETER DryRun
    Print all steps without executing anything. Safe to run anywhere.

.PARAMETER Quiet
    Suppress all non-essential output. Only errors and final verdict shown.

.PARAMETER Verbose
    Show step-level debug output including exact commands executed.

.PARAMETER Validate
    Validate scenario YAML(s) against the schema without running anything.
    Omit -Scenario to validate all scenarios in the scenarios\ directory.

.PARAMETER Report
    Generate an HTML coverage report from all result JSONs in -Out directory.

.PARAMETER HuntMode
    Skip the analyst verdict prompt. Run steps and save result as HUNT_ARTIFACT.
    Use when generating telemetry for threat hunting rather than detection validation.

.EXAMPLE
    .\pas_runner.ps1 -Scenario scenarios\persistence\T1053.005_scheduled_task.yml

.EXAMPLE
    .\pas_runner.ps1 -Tactic persistence -Out results\persistence\

.EXAMPLE
    .\pas_runner.ps1 -Suite scenarios\suites\ransomware_precursor.yml

.EXAMPLE
    .\pas_runner.ps1 -Scenario scenarios\discovery\T1082_system_info.yml -HuntMode

.EXAMPLE
    .\pas_runner.ps1 -DryRun -Scenario scenarios\persistence\T1053.005_scheduled_task.yml

.EXAMPLE
    .\pas_runner.ps1 -Validate

.EXAMPLE
    .\pas_runner.ps1 -Report -Out results\

.NOTES
    Run as Administrator for scenarios requiring elevated privileges.
    Always run in an isolated lab VM -- never on production systems.
    GitHub: https://github.com/stanleytobias/PracticalAttackSim-Runner
#>

[CmdletBinding(DefaultParameterSetName = 'Scenario')]
param(
    [Parameter(ParameterSetName = 'Scenario', Position = 0)]
    [string]$Scenario,

    [Parameter(ParameterSetName = 'Suite')]
    [string]$Suite,

    [Parameter(ParameterSetName = 'Tactic')]
    [string]$Tactic,

    [Parameter(ParameterSetName = 'Report')]
    [switch]$Report,

    [Parameter(ParameterSetName = 'Validate')]
    [switch]$Validate,

    [string]$Out = '.\results',
    [switch]$DryRun,
    [switch]$Quiet,
    [switch]$HuntMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve root ──────────────────────────────────────────────────────────────
$PAS_ROOT = $PSScriptRoot

# ── Import modules ────────────────────────────────────────────────────────────
$modules = @(
    'lib\PAS.Logging.psm1',
    'lib\PAS.Yaml.psm1',
    'lib\PAS.Schema.psm1',
    'lib\PAS.Executor.psm1',
    'lib\PAS.Results.psm1',
    'lib\PAS.Sigma.psm1',
    'lib\PAS.Report.psm1'
)

foreach ($mod in $modules) {
    $modPath = Join-Path $PAS_ROOT $mod
    if (-not (Test-Path $modPath)) {
        Write-Error "Required module not found: $modPath"
        exit 1
    }
    Import-Module $modPath -Force
}

Set-PASLogging -Quiet:$Quiet -Verbose:($PSBoundParameters.ContainsKey('Verbose'))

if (-not (Test-Path $Out)) {
    New-Item -ItemType Directory -Path $Out -Force | Out-Null
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
switch ($PSCmdlet.ParameterSetName) {

    'Scenario' {
        if (-not $Scenario) { Write-PASError "Specify -Scenario <path>"; exit 1 }
        if (-not (Test-Path $Scenario)) { Write-PASError "Scenario not found: $Scenario"; exit 1 }

        $s = Import-PASYaml -Path $Scenario
        $v = Test-PASSchema -Scenario $s
        if (-not $v.Valid) {
            Write-PASError "Schema validation failed:"
            $v.Errors | ForEach-Object { Write-PASError "  - $_" }
            exit 1
        }

        Invoke-PASScenario -Scenario $s `
                           -ScenarioPath $Scenario `
                           -Out $Out `
                           -DryRun:$DryRun `
                           -Quiet:$Quiet `
                           -HuntMode:$HuntMode
    }

    'Suite' {
        if (-not (Test-Path $Suite)) { Write-PASError "Suite not found: $Suite"; exit 1 }
        $suiteObj = Import-PASYaml -Path $Suite
        Invoke-PASSuite -Suite $suiteObj `
                        -SuitePath $Suite `
                        -Out $Out `
                        -DryRun:$DryRun `
                        -Quiet:$Quiet `
                        -HuntMode:$HuntMode
    }

    'Tactic' {
        $tacticDir = Join-Path $PAS_ROOT "scenarios\$Tactic"
        if (-not (Test-Path $tacticDir)) {
            Write-PASError "No scenario directory found for tactic: $Tactic"
            Write-PASInfo  "Expected path: $tacticDir"
            exit 1
        }

        $files = Get-ChildItem $tacticDir -Filter '*.yml' | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-PASError "No scenario YAMLs found in: $tacticDir"
            exit 1
        }

        Write-PASBanner "TACTIC RUN -- $($Tactic.ToUpper()) ($($files.Count) scenarios)"

        foreach ($file in $files) {
            $s = Import-PASYaml -Path $file.FullName
            $v = Test-PASSchema -Scenario $s
            if (-not $v.Valid) {
                Write-PASWarn "Skipping $($file.Name) -- schema errors: $($v.Errors -join '; ')"
                continue
            }
            Invoke-PASScenario -Scenario $s `
                               -ScenarioPath $file.FullName `
                               -Out $Out `
                               -DryRun:$DryRun `
                               -Quiet:$Quiet `
                               -HuntMode:$HuntMode
        }
    }

    'Validate' {
        $target = if ($Scenario) { $Scenario } else { $null }

        if ($target) {
            # Single file
            $s = Import-PASYaml -Path $target
            $v = Test-PASSchema -Scenario $s
            if ($v.Valid) {
                Write-PASOk "PASS: $target"
            } else {
                Write-PASError "FAIL: $target"
                $v.Errors | ForEach-Object { Write-PASError "  - $_" }
                exit 1
            }
        } else {
            # All scenarios
            $allFiles = Get-ChildItem (Join-Path $PAS_ROOT 'scenarios') -Recurse -Filter '*.yml' |
                        Where-Object { $_.DirectoryName -notlike '*suites*' }
            $pass = 0; $fail = 0

            foreach ($f in $allFiles | Sort-Object FullName) {
                try {
                    $s = Import-PASYaml -Path $f.FullName
                    $v = Test-PASSchema -Scenario $s
                    if ($v.Valid) {
                        Write-PASOk  "  PASS  $($f.Name)"
                        $pass++
                    } else {
                        Write-PASError "  FAIL  $($f.Name)"
                        $v.Errors | ForEach-Object { Write-PASError "        - $_" }
                        $fail++
                    }
                } catch {
                    Write-PASError "  ERR   $($f.Name) -- $_"
                    $fail++
                }
            }

            Write-PASInfo ""
            Write-PASInfo "Validation complete: $pass passed, $fail failed"
            if ($fail -gt 0) { exit 1 }
        }
    }

    'Report' {
        Write-PASInfo "Generating HTML report from: $Out"
        $reportPath = New-PASReport -ResultsDir $Out
        Write-PASOk  "Report written: $reportPath"
    }
}
