# PAS.Sigma.psm1
# Auto-generates Sigma rule scaffolds from PAS result objects.

$script:LOGSOURCE_MAP = @{
    'exec'            = 'process_creation'
    'exec_powershell' = 'process_creation'
    'exec_wmi'        = 'process_creation'
    'exec_com'        = 'process_creation'
    'reg_write'       = 'registry_set'
    'reg_delete'      = 'registry_delete'
    'file_write'      = 'file_event'
    'file_delete'     = 'file_delete'
    'marker'          = 'process_creation'
    'sleep'           = 'process_creation'
}

$script:FP_HINTS = @{
    'T1053' = 'Legitimate scheduled task creation by administrators or software installers'
    'T1059' = 'Legitimate administrative PowerShell or scripting activity'
    'T1547' = 'Software installer modifying startup registry keys'
    'T1546' = 'Legitimate WMI event subscriptions by management tooling'
    'T1070' = 'Legitimate forensic or backup tooling modifying file timestamps'
    'T1562' = 'Security tooling testing or authorised red team activity'
    'T1003' = 'Legitimate credential management tooling with LSASS access'
    'T1082' = 'IT asset inventory or endpoint management tooling'
    'T1021' = 'Legitimate remote service creation by administrators'
    'T1115' = 'Legitimate productivity software accessing clipboard'
    'T1074' = 'Legitimate backup or data management activity'
    'T1048' = 'Legitimate data transfer tools or cloud sync'
    'T1071' = 'Legitimate DNS activity from managed software'
    'T1055' = 'Legitimate AV or EDR using process injection techniques'
    'T1218' = 'Legitimate signed binary usage by software installers'
    'T1110' = 'Legitimate authentication testing or password auditing tools'
    'T1087' = 'Legitimate IT administration or identity management tools'
    'T1057' = 'Legitimate process monitoring or endpoint management software'
    'T1135' = 'Legitimate IT administration tools enumerating network shares'
    'T1016' = 'Legitimate network diagnostic or monitoring tools'
    'T1083' = 'Legitimate file management or backup software'
    'T1595' = 'Legitimate vulnerability scanning by authorised security teams'
}

function New-PASSigmaScaffold {
    param(
        [Parameter(Mandatory)] [object]$Result,
        [string[]]$StepTypes,
        [string]$Out = '.\results\sigma'
    )

    if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path $Out -Force | Out-Null }

    $technique  = $Result['mitre_technique']
    $tactic     = $Result['mitre_tactic']
    $scenarioId = $Result['scenario_id']
    $runId      = $Result['run_id']
    $verdict    = $Result['outcome']['verdict']
    $gapType    = $Result['outcome']['gap_type']
    $dateOnly   = ([datetime]$Result['timestamp']).ToString('yyyy-MM-dd')
    $uuid       = [System.Guid]::NewGuid().ToString()

    # Logsource -- prefer non-process types if present
    $logsource = 'process_creation'
    foreach ($t in $StepTypes) {
        if ($script:LOGSOURCE_MAP.ContainsKey($t) -and $script:LOGSOURCE_MAP[$t] -ne 'process_creation') {
            $logsource = $script:LOGSOURCE_MAP[$t]; break
        }
    }

    $tacticTag    = 'attack.' + $tactic.Replace('-', '_')
    $techniqueTag = 'attack.' + $technique.ToLower()

    $base   = $technique -replace '\.\d+$', ''
    $fpHint = if ($script:FP_HINTS[$technique]) { $script:FP_HINTS[$technique] }
              elseif ($script:FP_HINTS[$base])  { $script:FP_HINTS[$base] }
              else { 'Legitimate administrative activity -- review environment baseline' }

    $level = switch ($verdict) {
        'BLIND_SPOT' { 'high'   }
        'GAP'        { 'high'   }
        'PARTIAL'    { 'medium' }
        default      { 'medium' }
    }

    $gapNote = if ($gapType) { "# Gap type recorded: $gapType" } else { '' }

    $sigma = @"
title: <FILL IN: Descriptive detection name>
id: $uuid
status: experimental
description: >
  <FILL IN: What this rule detects and why it is suspicious.>
  Validated by PAS scenario '$scenarioId' (run: $runId) on $dateOnly.
  PAS verdict: $verdict. $gapNote
references:
  - https://attack.mitre.org/techniques/$($technique -replace '\.', '/')/ 
  - https://github.com/stanleytobias/PracticalAttackSim-Runner
author: stanleytobias
date: $dateOnly
tags:
  - $tacticTag
  - $techniqueTag
logsource:
  category: $logsource
  product: windows
detection:
  selection:
    # FILL IN: Field conditions based on observed telemetry.
    #
    # process_creation:
    #   Image|endswith: '\<binary>.exe'
    #   CommandLine|contains: '<argument>'
    #   ParentImage|endswith: '\<parent>.exe'
    #
    # registry_set:
    #   TargetObject|contains: '<registry path>'
    #   Details|contains: '<value>'
    #
    # file_event:
    #   TargetFilename|endswith: '.<ext>'
    #   TargetFilename|contains: '<path pattern>'
    #
    # network_connection:
    #   DestinationPort: <port>
    #   Initiated: 'true'
    #
    <PLACEHOLDER>: '<PLACEHOLDER>'
  condition: selection
falsepositives:
  - $fpHint
  - <FILL IN: Environment-specific false positives>
level: $level

# ── PAS Metadata ──────────────────────────────────────────────────────────────
# run_id      : $runId
# scenario    : $scenarioId
# verdict     : $verdict
# gap_type    : $gapType
# date        : $dateOnly
# logsource   : $logsource (inferred from: $($StepTypes -join ', '))
#
# Conversion:
#   sigma convert -t microsoft365defender -p windows <this_file>
#   OR use https://uncoder.io
#
# After deployment:
#   Re-run: .\pas_runner.ps1 -Scenario scenarios\...\$scenarioId.yml
#   Confirm verdict changes to COVERED
#   Commit to SIEM-UseCases repo
"@

    $outFile = Join-Path $Out "$scenarioId`_pas.yml"
    $sigma | Set-Content -Path $outFile -Encoding UTF8
    return $outFile
}

Export-ModuleMember -Function New-PASSigmaScaffold
