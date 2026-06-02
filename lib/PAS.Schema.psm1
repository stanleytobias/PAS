# PAS.Schema.psm1
# Validates a parsed scenario object against the PAS scenario schema.
# Returns a result object with Valid (bool) and Errors (string[]).

$VALID_TACTICS = @(
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact'
)

$VALID_PLATFORMS = @('windows', 'linux', 'macos', 'cloud', 'containers')

$VALID_STEP_TYPES = @(
    'exec', 'exec_powershell', 'exec_wmi', 'exec_com',
    'sleep', 'marker', 'file_write', 'file_delete',
    'reg_write', 'reg_delete'
)

function Test-PASSchema {
    param(
        [Parameter(Mandatory)]
        [object]$Scenario
    )

    $errors = @()

    # ── Required top-level fields ─────────────────────────────────────────────
    $required = @('id', 'name', 'mitre_technique', 'mitre_tactic',
                  'description', 'author', 'created', 'platform',
                  'steps', 'cleanup', 'analyst_checklist')

    foreach ($field in $required) {
        if (-not $Scenario.Contains($field) -or $null -eq $Scenario[$field]) {
            $errors += "Missing required field: '$field'"
        }
    }

    # ── Field format validation ───────────────────────────────────────────────
    if ($Scenario['id'] -and $Scenario['id'] -notmatch '^T\d{4}(\.\d{3})?_.+$') {
        $errors += "Field 'id' must match pattern T####[.###]_name -- got: '$($Scenario['id'])'"
    }

    if ($Scenario['mitre_technique'] -and $Scenario['mitre_technique'] -notmatch '^T\d{4}(\.\d{3})?$') {
        $errors += "Field 'mitre_technique' must match T#### or T####.### -- got: '$($Scenario['mitre_technique'])'"
    }

    $tacticNorm = ($Scenario['mitre_tactic'] -replace '_', '-')
    if ($Scenario['mitre_tactic'] -and $tacticNorm -notin $VALID_TACTICS) {
        $errors += "Field 'mitre_tactic' must be one of: $($VALID_TACTICS -join ', ') -- got: '$($Scenario['mitre_tactic'])'"
    }

    if ($Scenario['platform'] -and $Scenario['platform'] -notin $VALID_PLATFORMS) {
        $errors += "Field 'platform' must be one of: $($VALID_PLATFORMS -join ', ') -- got: '$($Scenario['platform'])'"
    }

    # ── Steps validation ──────────────────────────────────────────────────────
    if ($Scenario['steps']) {
        $steps = @($Scenario['steps'])
        if ($steps.Count -eq 0) {
            $errors += "Field 'steps' must contain at least one step"
        }
        foreach ($step in $steps) {
            $errors += Test-PASStep -Step $step -Context 'steps'
        }
    }

    # ── Cleanup validation ────────────────────────────────────────────────────
    if ($Scenario['cleanup']) {
        $cleanup = @($Scenario['cleanup'])
        if ($cleanup.Count -eq 0) {
            $errors += "Field 'cleanup' must contain at least one step"
        }
        foreach ($step in $cleanup) {
            $errors += Test-PASStep -Step $step -Context 'cleanup'
        }
    }

    # ── Checklist validation ──────────────────────────────────────────────────
    if ($Scenario['analyst_checklist']) {
        $cl = @($Scenario['analyst_checklist'])
        if ($cl.Count -eq 0) {
            $errors += "Field 'analyst_checklist' must contain at least one item"
        }
    }

    $errors = $errors | Where-Object { $_ -ne $null -and $_ -ne '' }

    return [PSCustomObject]@{
        Valid  = ($errors.Count -eq 0)
        Errors = $errors
    }
}

function Test-PASStep {
    param([object]$Step, [string]$Context)
    $errs = @()

    if (-not $Step) { return }

    if (-not $Step.Contains('step') -or $null -eq $Step['step']) {
        $errs += "[$Context] Step missing required field 'step' (integer)"
    }
    if (-not $Step['type']) {
        $errs += "[$Context] Step $($Step['step']) missing required field 'type'"
    } elseif ($Step['type'] -notin $VALID_STEP_TYPES) {
        $errs += "[$Context] Step $($Step['step']) has invalid type '$($Step['type'])'. Valid: $($VALID_STEP_TYPES -join ', ')"
    }
    if (-not $Step['description']) {
        $errs += "[$Context] Step $($Step['step']) missing required field 'description'"
    }

    # Type-specific required fields
    switch ($Step['type']) {
        'exec' {
            if (-not $Step['binary']) {
                $errs += "[$Context] Step $($Step['step']) (exec) missing required field 'binary'"
            }
        }
        'exec_powershell' {
            if (-not $Step['command']) {
                $errs += "[$Context] Step $($Step['step']) (exec_powershell) missing required field 'command'"
            }
        }
        'exec_wmi' {
            if (-not $Step['wmi_class']) { $errs += "[$Context] Step $($Step['step']) (exec_wmi) missing 'wmi_class'" }
            if (-not $Step['method'])    { $errs += "[$Context] Step $($Step['step']) (exec_wmi) missing 'method'" }
        }
        'exec_com' {
            if (-not $Step['com_progid']) { $errs += "[$Context] Step $($Step['step']) (exec_com) missing 'com_progid'" }
            if (-not $Step['method'])     { $errs += "[$Context] Step $($Step['step']) (exec_com) missing 'method'" }
        }
        'sleep' {
            if (-not $Step.Contains('seconds') -or $null -eq $Step['seconds']) {
                $errs += "[$Context] Step $($Step['step']) (sleep) missing required field 'seconds'"
            }
        }
        'marker' {
            if (-not $Step['message']) {
                $errs += "[$Context] Step $($Step['step']) (marker) missing required field 'message'"
            }
        }
        'file_write' {
            if (-not $Step['path'])    { $errs += "[$Context] Step $($Step['step']) (file_write) missing 'path'" }
            if (-not $Step['content']) { $errs += "[$Context] Step $($Step['step']) (file_write) missing 'content'" }
        }
        'file_delete' {
            if (-not $Step['path']) { $errs += "[$Context] Step $($Step['step']) (file_delete) missing 'path'" }
        }
        'reg_write' {
            if (-not $Step['hive'])       { $errs += "[$Context] Step $($Step['step']) (reg_write) missing 'hive'" }
            if (-not $Step['key'])        { $errs += "[$Context] Step $($Step['step']) (reg_write) missing 'key'" }
            if (-not $Step['value_name']) { $errs += "[$Context] Step $($Step['step']) (reg_write) missing 'value_name'" }
            if (-not $Step.Contains('value_data') -or $null -eq $Step['value_data']) { $errs += "[$Context] Step $($Step['step']) (reg_write) missing 'value_data'" }
        }
        'reg_delete' {
            if (-not $Step['hive']) { $errs += "[$Context] Step $($Step['step']) (reg_delete) missing 'hive'" }
            if (-not $Step['key'])  { $errs += "[$Context] Step $($Step['step']) (reg_delete) missing 'key'" }
        }
    }

    return $errs
}

# Validates a suite object: required fields + that every referenced scenario file exists.
# Mirrors the path-resolution rules in Invoke-PASSuite (string entries are relative to the
# suite's own dir; object entries' scenario_file is relative to the scenarios/ root).
function Test-PASSuiteSchema {
    param(
        [Parameter(Mandatory)] [object]$Suite,
        [Parameter(Mandatory)] [string]$SuitePath
    )

    $errors = @()
    if (-not $Suite['name']) { $errors += "Suite missing required field: 'name'" }

    $entries = @()
    if ($Suite['scenarios']) { $entries = @($Suite['scenarios']) }
    else { $errors += "Suite missing required field: 'scenarios'" }

    $suiteDir     = Split-Path $SuitePath -Parent
    $scenarioRoot = Split-Path $suiteDir  -Parent

    $i = 0
    foreach ($entry in $entries) {
        $i++
        if ($entry -is [string]) { $rel = $entry;                  $base = $suiteDir }
        else                     { $rel = $entry['scenario_file']; $base = $scenarioRoot }

        if (-not $rel) {
            $errors += "Suite entry $i has no scenario path ('scenario_file')"
            continue
        }
        $path = if ([System.IO.Path]::IsPathRooted($rel)) { $rel } else { Join-Path $base $rel }
        if (-not (Test-Path $path)) {
            $errors += "Suite entry $i references missing scenario: $rel"
        }
    }

    return [PSCustomObject]@{
        Valid  = ($errors.Count -eq 0)
        Errors = $errors
    }
}

Export-ModuleMember -Function Test-PASSchema, Test-PASSuiteSchema
