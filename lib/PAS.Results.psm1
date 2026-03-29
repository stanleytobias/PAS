# PAS.Results.psm1
# Save, load, and summarise PAS run result JSON files.

function Save-PASResult {
    param(
        [Parameter(Mandatory)] [object]$Result,
        [Parameter(Mandatory)] [string]$Out
    )
    if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path $Out -Force | Out-Null }
    $path = Join-Path $Out "$($Result['run_id']).json"
    $Result | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding UTF8
    return $path
}

function Get-PASResults {
    param(
        [Parameter(Mandatory)] [string]$ResultsDir,
        [string]$Tactic    = $null,
        [string]$Technique = $null,
        [string]$Verdict   = $null,
        [string]$Mode      = $null
    )
    if (-not (Test-Path $ResultsDir)) { return @() }

    $results = Get-ChildItem $ResultsDir -Filter '*.json' -Recurse |
               Sort-Object LastWriteTime -Descending |
               ForEach-Object {
                   try { Get-Content $_.FullName -Raw | ConvertFrom-Json }
                   catch { Write-PASWarn "Could not parse: $($_.Name)" }
               } | Where-Object { $_ }

    if ($Tactic)    { $results = $results | Where-Object { $_.mitre_tactic    -eq $Tactic    } }
    if ($Technique) { $results = $results | Where-Object { $_.mitre_technique -eq $Technique } }
    if ($Verdict)   { $results = $results | Where-Object { $_.outcome.verdict -eq $Verdict   } }
    if ($Mode)      { $results = $results | Where-Object { $_.mode            -eq $Mode      } }

    return $results
}

function Get-PASCoverageSummary {
    param([string]$ResultsDir)

    $results = Get-PASResults -ResultsDir $ResultsDir
    if (-not $results -or @($results).Count -eq 0) {
        return [PSCustomObject]@{
            Total      = 0; Covered = 0; Partial = 0
            Gap        = 0; BlindSpot = 0; Pending = 0
            HuntRuns   = 0; ByTactic = @()
        }
    }

    $all = @($results)

    $byTactic = $all | Group-Object mitre_tactic | ForEach-Object {
        $g = $_.Group
        [PSCustomObject]@{
            Tactic    = $_.Name
            Total     = $g.Count
            Covered   = @($g | Where-Object { $_.outcome.verdict -eq 'COVERED'       }).Count
            Partial   = @($g | Where-Object { $_.outcome.verdict -eq 'PARTIAL'       }).Count
            Gap       = @($g | Where-Object { $_.outcome.verdict -eq 'GAP'           }).Count
            BlindSpot = @($g | Where-Object { $_.outcome.verdict -eq 'BLIND_SPOT'    }).Count
            Pending   = @($g | Where-Object { $_.outcome.verdict -eq 'PENDING'       }).Count
            HuntRuns  = @($g | Where-Object { $_.outcome.verdict -eq 'HUNT_ARTIFACT' }).Count
        }
    } | Sort-Object Tactic

    return [PSCustomObject]@{
        Total     = $all.Count
        Covered   = @($all | Where-Object { $_.outcome.verdict -eq 'COVERED'       }).Count
        Partial   = @($all | Where-Object { $_.outcome.verdict -eq 'PARTIAL'       }).Count
        Gap       = @($all | Where-Object { $_.outcome.verdict -eq 'GAP'           }).Count
        BlindSpot = @($all | Where-Object { $_.outcome.verdict -eq 'BLIND_SPOT'    }).Count
        Pending   = @($all | Where-Object { $_.outcome.verdict -eq 'PENDING'       }).Count
        HuntRuns  = @($all | Where-Object { $_.outcome.verdict -eq 'HUNT_ARTIFACT' }).Count
        ByTactic  = $byTactic
    }
}

Export-ModuleMember -Function Save-PASResult, Get-PASResults, Get-PASCoverageSummary
