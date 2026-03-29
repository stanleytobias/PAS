# PAS.Executor.psm1
# Core scenario and suite execution engine.
# No vendor/EDR framing — this is a detection engineering platform.

function Invoke-PASScenario {
    param(
        [Parameter(Mandatory)] [object]$Scenario,
        [Parameter(Mandatory)] [string]$ScenarioPath,
        [string]$Out       = '.\results',
        [switch]$DryRun,
        [switch]$Quiet,
        [switch]$HuntMode
    )

    $runId    = "pas-$(Get-Date -Format 'yyyyMMdd')-$(Get-Random -Minimum 100 -Maximum 999)"
    $runStart = Get-Date
    $mode     = if ($HuntMode) { 'HUNT' } elseif ($DryRun) { 'DRY-RUN' } else { 'VALIDATE' }

    Write-PASBanner "$($Scenario['name'])  [$mode]"
    Write-PASInfo "Run ID    : $runId"
    Write-PASInfo "Technique : $($Scenario['mitre_technique'])"
    Write-PASInfo "Tactic    : $($Scenario['mitre_tactic'])"
    Write-PASInfo "Platform  : $($Scenario['platform'])"
    Write-PASInfo "Mode      : $mode"
    Write-PASInfo ""

    $stepsExecuted = @()
    $cleanupErrors = @()
    $scenarioError = $null

    # ── Execute steps ─────────────────────────────────────────────────────────
    foreach ($step in @($Scenario['steps'])) {
        $num  = $step['step']
        $type = $step['type']
        $desc = $step['description']

        Write-PASStep "[$num] $type — $desc"

        $stepResult = [ordered]@{
            step        = $num
            type        = $type
            description = $desc
            command     = $null
            exit_code   = $null
            error       = $null
            timestamp   = (Get-Date -Format 'o')
            skipped     = $DryRun.IsPresent
        }

        if (-not $DryRun) {
            try {
                $r = Invoke-PASStep -Step $step
                $stepResult['command']   = $r.Command
                $stepResult['exit_code'] = $r.ExitCode
                Write-PASDebug "    exit_code: $($r.ExitCode)"
            } catch {
                $stepResult['error'] = $_.ToString()
                $scenarioError       = "Step $num failed: $_"
                Write-PASWarn "    Step $num error: $_"
            }
        } else {
            Write-PASDebug "    [DRY-RUN] skipped"
        }

        $stepsExecuted += $stepResult
    }

    # ── Cleanup ───────────────────────────────────────────────────────────────
    Write-PASInfo ""
    Write-PASInfo "Running cleanup..."
    $cleanupOk = $true

    foreach ($step in @($Scenario['cleanup'])) {
        Write-PASDebug "  cleanup [$($step['step'])] $($step['description'])"
        if ($DryRun) { continue }
        try {
            Invoke-PASStep -Step $step | Out-Null
        } catch {
            $cleanupOk = $false
            $cleanupErrors += "Cleanup step $($step['step']) failed: $_"
            Write-PASWarn "  Cleanup step $($step['step']) failed: $_"
        }
    }

    if ($cleanupOk) { Write-PASOk "Cleanup complete." }
    else            { Write-PASWarn "Cleanup had errors — review artifacts manually." }

    # ── Analyst interaction ───────────────────────────────────────────────────
    $outcome = $null

    if (-not $DryRun -and -not $Quiet) {
        if ($HuntMode) {
            Write-PASBanner "HUNT ARTIFACT GENERATED" Magenta
            Write-PASInfo "Artifacts generated for: $($Scenario['mitre_technique']) — $($Scenario['name'])"
            Write-PASInfo "Go hunt in your SIEM. Suggested queries from the analyst checklist:"
            Write-PASInfo ""
            @($Scenario['analyst_checklist']) | ForEach-Object { Write-PASInfo "  - $_" }
            Write-PASInfo ""
        } else {
            $outcome = Read-PASOutcome -Scenario $Scenario
        }
    }

    # ── Result object ─────────────────────────────────────────────────────────
    $duration = [int]((Get-Date) - $runStart).TotalSeconds

    $resultObj = [ordered]@{
        run_id           = $runId
        timestamp        = $runStart.ToString('o')
        duration_seconds = $duration
        mode             = $mode
        scenario_id      = $Scenario['id']
        scenario_name    = $Scenario['name']
        mitre_technique  = $Scenario['mitre_technique']
        mitre_tactic     = $Scenario['mitre_tactic']
        platform         = $Scenario['platform']
        dry_run          = $DryRun.IsPresent
        hunt_mode        = $HuntMode.IsPresent
        scenario_error   = $scenarioError
        steps_executed   = $stepsExecuted
        cleanup_ok       = $cleanupOk
        cleanup_errors   = $cleanupErrors
        outcome          = [ordered]@{
            verdict                    = if ($HuntMode)  { 'HUNT_ARTIFACT' }
                                         elseif ($outcome) { $outcome.Verdict }
                                         else              { 'PENDING' }
            telemetry_visible          = if ($outcome) { $outcome.TelemetryVisible } else { $null }
            detection_fired            = if ($outcome) { $outcome.DetectionFired }   else { $null }
            detection_name             = if ($outcome) { $outcome.DetectionName }    else { $null }
            detection_fidelity         = if ($outcome) { $outcome.Fidelity }         else { $null }
            gap_type                   = if ($outcome) { $outcome.GapType }          else { $null }
            notes                      = if ($outcome) { $outcome.Notes }            else { '' }
        }
        sigma_rule_generated = $false
        sigma_rule_path      = $null
    }

    # ── Auto Sigma on gap ─────────────────────────────────────────────────────
    if (-not $DryRun -and -not $HuntMode -and $outcome) {
        if ($outcome.Verdict -in @('GAP', 'BLIND_SPOT', 'PARTIAL')) {
            Write-PASInfo "Verdict is $($outcome.Verdict) — generating Sigma scaffold..."
            $sigmaOut  = Join-Path $Out 'sigma'
            $sigmaPath = New-PASSigmaScaffold -Result $resultObj `
                             -StepTypes ($stepsExecuted | ForEach-Object { $_['type'] }) `
                             -Out $sigmaOut
            if ($sigmaPath) {
                $resultObj['sigma_rule_generated'] = $true
                $resultObj['sigma_rule_path']      = $sigmaPath
                Write-PASOk "Sigma scaffold: $sigmaPath"
            }
        }
    }

    # ── Save + print verdict ──────────────────────────────────────────────────
    $resultFile = Save-PASResult -Result $resultObj -Out $Out

    $verdict = $resultObj['outcome']['verdict']
    $color   = switch ($verdict) {
        'COVERED'       { 'Green'      }
        'PARTIAL'       { 'Yellow'     }
        'GAP'           { 'DarkYellow' }
        'BLIND_SPOT'    { 'Red'        }
        'HUNT_ARTIFACT' { 'Cyan'       }
        default         { 'Gray'       }
    }
    Write-Host ""
    Write-Host "  RESULT: $verdict" -ForegroundColor $color
    Write-PASOk "Saved: $resultFile"
    Write-PASInfo ""

    return $resultObj
}

function Invoke-PASSuite {
    param(
        [Parameter(Mandatory)] [object]$Suite,
        [Parameter(Mandatory)] [string]$SuitePath,
        [string]$Out    = '.\results',
        [switch]$DryRun,
        [switch]$Quiet,
        [switch]$HuntMode
    )

    $suiteDir  = Split-Path $SuitePath -Parent
    $scenarios = @($Suite['scenarios'])

    Write-PASBanner "SUITE — $($Suite['name'])"
    Write-PASInfo "Total scenarios : $($scenarios.Count)"
    Write-PASInfo ""

    $results = @()
    $idx     = 0

    foreach ($entry in $scenarios) {
        $idx++
        $path = if ([System.IO.Path]::IsPathRooted($entry)) { $entry }
                else { Join-Path $suiteDir $entry }

        Write-PASInfo "[$idx/$($scenarios.Count)] $([System.IO.Path]::GetFileName($path))"

        if (-not (Test-Path $path)) {
            Write-PASWarn "  File not found — skipping: $path"
            continue
        }

        $s = Import-PASYaml -Path $path
        $v = Test-PASSchema -Scenario $s
        if (-not $v.Valid) {
            Write-PASWarn "  Schema invalid — skipping: $($v.Errors -join '; ')"
            continue
        }

        $r = Invoke-PASScenario -Scenario $s `
                                -ScenarioPath $path `
                                -Out $Out `
                                -DryRun:$DryRun `
                                -Quiet:$Quiet `
                                -HuntMode:$HuntMode
        $results += $r
    }

    # Suite summary
    $tally = $results | Group-Object { $_['outcome']['verdict'] }
    Write-PASBanner "SUITE COMPLETE — $($Suite['name'])"
    foreach ($g in $tally | Sort-Object Name) {
        $col = switch ($g.Name) {
            'COVERED'       { 'Green'      }
            'PARTIAL'       { 'Yellow'     }
            'GAP'           { 'DarkYellow' }
            'BLIND_SPOT'    { 'Red'        }
            'HUNT_ARTIFACT' { 'Cyan'       }
            default         { 'Gray'       }
        }
        Write-Host "  $($g.Name.PadRight(15)) : $($g.Count)" -ForegroundColor $col
    }
    Write-PASInfo ""
}

function Invoke-PASStep {
    param([Parameter(Mandatory)][object]$Step)

    switch ($Step['type']) {

        'exec' {
            $bin  = $Step['binary']
            $args = if ($Step['args']) { $Step['args'] } else { '' }
            $proc = Start-Process -FilePath $bin -ArgumentList $args `
                                  -PassThru -Wait -NoNewWindow -ErrorAction SilentlyContinue
            return [PSCustomObject]@{ Command = "$bin $args"; ExitCode = $proc.ExitCode }
        }

        'exec_powershell' {
            $cmd     = $Step['command']
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
            $proc    = Start-Process powershell.exe `
                           -ArgumentList "-NonInteractive -NoProfile -EncodedCommand $encoded" `
                           -PassThru -Wait -NoNewWindow -ErrorAction SilentlyContinue
            return [PSCustomObject]@{ Command = "powershell.exe [encoded]"; ExitCode = $proc.ExitCode }
        }

        'exec_wmi' {
            $class  = $Step['wmi_class']
            $method = $Step['method']
            $wArgs  = $Step['wmi_args']
            $obj    = [wmiclass]$class
            $obj.InvokeMethod($method, $wArgs) | Out-Null
            return [PSCustomObject]@{ Command = "$class.$method"; ExitCode = 0 }
        }

        'exec_com' {
            $progId = $Step['com_progid']
            $method = $Step['method']
            $cArgs  = $Step['com_args']
            $com    = New-Object -ComObject $progId
            $com.$method($cArgs) | Out-Null
            return [PSCustomObject]@{ Command = "$progId.$method"; ExitCode = 0 }
        }

        'sleep' {
            Start-Sleep -Seconds $Step['seconds']
            return [PSCustomObject]@{ Command = "sleep $($Step['seconds'])s"; ExitCode = 0 }
        }

        'marker' {
            Write-PASInfo "  >>> $($Step['message'])"
            return [PSCustomObject]@{ Command = "MARKER"; ExitCode = 0 }
        }

        'file_write' {
            $path = $Step['path']
            $dir  = Split-Path $path -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Set-Content -Path $path -Value $Step['content'] -Encoding UTF8 -Force
            return [PSCustomObject]@{ Command = "file_write: $path"; ExitCode = 0 }
        }

        'file_delete' {
            Remove-Item -Path $Step['path'] -Force -ErrorAction SilentlyContinue
            return [PSCustomObject]@{ Command = "file_delete: $($Step['path'])"; ExitCode = 0 }
        }

        'reg_write' {
            $p = "$($Step['hive']):\$($Step['key'])"
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            $t = if ($Step['value_type']) { $Step['value_type'] } else { 'String' }
            Set-ItemProperty -Path $p -Name $Step['value_name'] -Value $Step['value_data'] -Type $t -Force
            return [PSCustomObject]@{ Command = "reg_write: $p\$($Step['value_name'])"; ExitCode = 0 }
        }

        'reg_delete' {
            $p = "$($Step['hive']):\$($Step['key'])"
            if ($Step['value_name']) {
                Remove-ItemProperty -Path $p -Name $Step['value_name'] -ErrorAction SilentlyContinue
            } else {
                Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
            }
            return [PSCustomObject]@{ Command = "reg_delete: $p"; ExitCode = 0 }
        }

        default { throw "Unknown step type: $($Step['type'])" }
    }
}

function Read-PASOutcome {
    param([object]$Scenario)

    $checklist = @($Scenario['analyst_checklist'])

    $line = '=' * 60
    Write-Host ""
    Write-Host $line                                             -ForegroundColor Magenta
    Write-Host "  ANALYST CHECKLIST — $($Scenario['id'])"       -ForegroundColor Magenta
    Write-Host "  $($Scenario['mitre_technique']) | $($Scenario['mitre_tactic'])" -ForegroundColor Magenta
    Write-Host $line                                             -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Check your SIEM and EDR for the following:" -ForegroundColor White
    Write-Host ""
    foreach ($item in $checklist) {
        Write-Host "  [ ] $item" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  VERDICT:" -ForegroundColor Yellow
    Write-Host "    [1] COVERED     — detection fired, correct technique context"    -ForegroundColor Green
    Write-Host "    [2] PARTIAL     — detection fired but low fidelity or missing context" -ForegroundColor Yellow
    Write-Host "    [3] GAP         — no detection, but telemetry is present in SIEM"     -ForegroundColor DarkYellow
    Write-Host "    [4] BLIND_SPOT  — no detection and no telemetry at all"               -ForegroundColor Red
    Write-Host "    [5] PENDING     — skip for now, revisit later"                        -ForegroundColor DarkGray
    Write-Host ""

    # Verdict
    $verdictMap = @{ '1'='COVERED'; '2'='PARTIAL'; '3'='GAP'; '4'='BLIND_SPOT'; '5'='PENDING' }
    $verdict    = 'PENDING'
    while ($true) {
        $c = Read-Host "  Verdict [1-5]"
        if ($verdictMap.ContainsKey($c)) { $verdict = $verdictMap[$c]; break }
        Write-PASWarn "  Enter 1–5"
    }

    if ($verdict -eq 'PENDING') { return [PSCustomObject]@{ Verdict='PENDING'; TelemetryVisible=$null; DetectionFired=$null; DetectionName=$null; Fidelity=$null; GapType=$null; Notes='' } }

    # Telemetry visible?
    $telemetry = $null
    if ($verdict -in @('GAP','PARTIAL','COVERED')) {
        $t = Read-Host "  Telemetry visible in SIEM/EDR? [y/n]"
        $telemetry = ($t -eq 'y')
    }

    # Detection details
    $detectionFired = $null
    $detectionName  = ''
    $fidelity       = $null
    if ($verdict -in @('COVERED','PARTIAL')) {
        $detectionFired = $true
        $detectionName  = Read-Host "  Detection/alert name (optional)"
        $f = Read-Host "  Fidelity [h=high / m=medium / l=low]"
        $fidelity = switch ($f) { 'h'{'high'} 'm'{'medium'} 'l'{'low'} default{$null} }
    }

    # Gap type
    $gapType = $null
    if ($verdict -in @('GAP','BLIND_SPOT')) {
        Write-Host "  Gap type:"                                           -ForegroundColor Yellow
        Write-Host "    [1] No detection rule exists for this technique"   -ForegroundColor Gray
        Write-Host "    [2] Rule exists but did not fire"                  -ForegroundColor Gray
        Write-Host "    [3] Telemetry missing — log source not configured" -ForegroundColor Gray
        Write-Host "    [4] Telemetry missing — sensor not deployed"       -ForegroundColor Gray
        $g = Read-Host "  Gap type [1-4]"
        $gapType = switch ($g) {
            '1' { 'no_rule' }
            '2' { 'rule_did_not_fire' }
            '3' { 'missing_log_source' }
            '4' { 'missing_sensor' }
            default { 'unknown' }
        }
    }

    $notes = Read-Host "  Notes (optional)"

    return [PSCustomObject]@{
        Verdict         = $verdict
        TelemetryVisible = $telemetry
        DetectionFired  = $detectionFired
        DetectionName   = $detectionName
        Fidelity        = $fidelity
        GapType         = $gapType
        Notes           = $notes
    }
}

Export-ModuleMember -Function Invoke-PASScenario, Invoke-PASSuite, Invoke-PASStep, Read-PASOutcome
