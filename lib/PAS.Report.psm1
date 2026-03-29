# PAS.Report.psm1
# Generates an HTML detection coverage report from PAS result JSON files.

function New-PASReport {
    param(
        [Parameter(Mandatory)] [string]$ResultsDir,
        [string]$OutputFile = $null
    )

    $results = @(Get-PASResults -ResultsDir $ResultsDir)
    $summary = Get-PASCoverageSummary -ResultsDir $ResultsDir

    if (-not $OutputFile) {
        $OutputFile = Join-Path $ResultsDir "pas_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    }

    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $valRuns     = @($results | Where-Object { $_.mode -ne 'HUNT' })
    $coveragePct = if ($summary.Total -gt 0) {
        [Math]::Round(($summary.Covered + $summary.Partial * 0.5) / [Math]::Max(1, ($summary.Total - $summary.HuntRuns)) * 100, 1)
    } else { 0 }

    # ── Table rows ────────────────────────────────────────────────────────────
    $rows = foreach ($r in ($results | Sort-Object mitre_tactic, mitre_technique)) {
        $v = $r.outcome.verdict
        $bc = switch ($v) {
            'COVERED'       { 'badge-covered' }
            'PARTIAL'       { 'badge-partial' }
            'GAP'           { 'badge-gap'     }
            'BLIND_SPOT'    { 'badge-blind'   }
            'HUNT_ARTIFACT' { 'badge-hunt'    }
            default         { 'badge-pending' }
        }
        $sigma    = if ($r.sigma_rule_path) { "<span class='sigma-tag'>Sigma</span>" } else { '' }
        $gapType  = if ($r.outcome.gap_type)        { "<span class='gap-type'>$($r.outcome.gap_type)</span>" } else { '' }
        $detName  = if ($r.outcome.detection_name)  { $r.outcome.detection_name } else { '—' }
        $notes    = if ($r.outcome.notes)            { $r.outcome.notes }           else { '' }
        $modeTag  = if ($r.mode -eq 'HUNT')     { "<span class='mode-tag hunt'>HUNT</span>" }
                    elseif ($r.mode -eq 'DRY-RUN') { "<span class='mode-tag dry'>DRY</span>" }
                    else { '' }
        $techUrl  = "https://attack.mitre.org/techniques/$($r.mitre_technique -replace '\.','/')/"
        $date     = if ($r.timestamp) { $r.timestamp.Substring(0,10) } else { '' }

        @"
        <tr>
          <td class="tactic">$($r.mitre_tactic)</td>
          <td class="technique"><a href="$techUrl" target="_blank">$($r.mitre_technique)</a></td>
          <td>$($r.scenario_name) $modeTag</td>
          <td><span class="badge $bc">$v</span> $gapType</td>
          <td>$detName</td>
          <td class="notes">$notes</td>
          <td>$sigma</td>
          <td class="ts">$date</td>
        </tr>
"@
    }

    # ── Tactic cards ──────────────────────────────────────────────────────────
    $tacticCards = foreach ($t in @($summary.ByTactic)) {
        $denom  = [Math]::Max(1, $t.Total - $t.HuntRuns)
        $tacPct = [Math]::Round(($t.Covered + $t.Partial * 0.5) / $denom * 100)
        @"
        <div class="tactic-card">
          <div class="tactic-name">$($t.Tactic)</div>
          <div class="tactic-stats">
            <span class="badge badge-covered">$($t.Covered)</span>
            <span class="badge badge-partial">$($t.Partial)</span>
            <span class="badge badge-gap">$($t.Gap)</span>
            <span class="badge badge-blind">$($t.BlindSpot)</span>
            $(if ($t.HuntRuns -gt 0) { "<span class='badge badge-hunt'>$($t.HuntRuns) hunts</span>" })
          </div>
          <div class="progress-bar"><div class="progress-fill" style="width:${tacPct}%"></div></div>
          <div class="tactic-pct">${tacPct}%</div>
        </div>
"@
    }

    $tacticOptions = ($results | Select-Object -ExpandProperty mitre_tactic -Unique | Sort-Object |
        ForEach-Object { "<option value='$_'>$_</option>" }) -join "`n    "

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PAS — Detection Coverage</title>
<style>
:root {
  --bg:       #0d1117; --surface:  #161b22; --border:   #30363d;
  --text:     #c9d1d9; --muted:    #8b949e;
  --green:    #3fb950; --yellow:   #d29922; --orange:   #f0883e;
  --red:      #f85149; --blue:     #58a6ff; --purple:   #bc8cff;
  --cyan:     #39c5cf;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; background: var(--bg); color: var(--text); padding: 2rem; font-size: 13px; }
h1 { font-size: 1.4rem; color: var(--blue); margin-bottom: 0.2rem; }
.sub { color: var(--muted); font-size: 11px; margin-bottom: 2rem; }

.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem 1.5rem; text-align: center; min-width: 110px; }
.stat-val { font-size: 1.8rem; font-weight: 700; }
.stat-lbl { color: var(--muted); font-size: 10px; margin-top: 2px; text-transform: uppercase; }
.stat.total   .stat-val { color: var(--blue);   }
.stat.pct     .stat-val { color: var(--purple); }
.stat.covered .stat-val { color: var(--green);  }
.stat.partial .stat-val { color: var(--yellow); }
.stat.gap     .stat-val { color: var(--orange); }
.stat.blind   .stat-val { color: var(--red);    }
.stat.hunt    .stat-val { color: var(--cyan);   }

.tactic-grid { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 2rem; }
.tactic-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; min-width: 190px; flex: 1; }
.tactic-name { font-size: 10px; font-weight: 700; color: var(--blue); text-transform: uppercase; margin-bottom: 6px; }
.tactic-stats { display: flex; flex-wrap: wrap; gap: 3px; margin-bottom: 6px; }
.progress-bar { background: var(--border); border-radius: 3px; height: 3px; }
.progress-fill { background: var(--green); height: 3px; border-radius: 3px; transition: width 0.3s; }
.tactic-pct { font-size: 10px; color: var(--muted); text-align: right; margin-top: 2px; }

.filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center; }
.filter-bar input, .filter-bar select { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 5px 10px; border-radius: 4px; font-size: 12px; }

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
thead th { background: var(--surface); color: var(--muted); font-size: 10px; text-transform: uppercase; padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
tbody tr:hover { background: #1c2128; }
td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
td.tactic { color: var(--muted); font-size: 10px; text-transform: uppercase; }
td.technique a { color: var(--blue); text-decoration: none; font-family: monospace; }
td.technique a:hover { text-decoration: underline; }
td.notes { color: var(--muted); font-size: 11px; max-width: 180px; }
td.ts { color: var(--muted); font-size: 10px; white-space: nowrap; }

.badge { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase; white-space: nowrap; }
.badge-covered { background:#1a3a1a; color:var(--green);  border:1px solid var(--green);  }
.badge-partial { background:#3a2e0a; color:var(--yellow); border:1px solid var(--yellow); }
.badge-gap     { background:#3a1e0a; color:var(--orange); border:1px solid var(--orange); }
.badge-blind   { background:#3a0a0a; color:var(--red);    border:1px solid var(--red);    }
.badge-hunt    { background:#0a2e30; color:var(--cyan);   border:1px solid var(--cyan);   }
.badge-pending { background:#1e1e1e; color:var(--muted);  border:1px solid var(--border); }

.gap-type   { font-size: 10px; color: var(--orange); margin-left: 4px; }
.sigma-tag  { font-size: 10px; color: var(--purple); border: 1px solid var(--purple); padding: 1px 5px; border-radius: 3px; }
.mode-tag   { font-size: 10px; padding: 1px 5px; border-radius: 3px; margin-left: 4px; }
.mode-tag.hunt { background: #0a2e30; color: var(--cyan); }
.mode-tag.dry  { background: #1e1e1e; color: var(--muted); }
</style>
</head>
<body>

<h1>PAS — Detection Coverage Report</h1>
<div class="sub">Generated: $generatedAt &nbsp;·&nbsp; $ResultsDir</div>

<div class="summary">
  <div class="stat total">  <div class="stat-val">$($summary.Total)</div>    <div class="stat-lbl">Total Runs</div></div>
  <div class="stat pct">    <div class="stat-val">${coveragePct}%</div>       <div class="stat-lbl">Coverage</div></div>
  <div class="stat covered"><div class="stat-val">$($summary.Covered)</div>   <div class="stat-lbl">Covered</div></div>
  <div class="stat partial"><div class="stat-val">$($summary.Partial)</div>   <div class="stat-lbl">Partial</div></div>
  <div class="stat gap">    <div class="stat-val">$($summary.Gap)</div>       <div class="stat-lbl">Gap</div></div>
  <div class="stat blind">  <div class="stat-val">$($summary.BlindSpot)</div> <div class="stat-lbl">Blind Spot</div></div>
  <div class="stat hunt">   <div class="stat-val">$($summary.HuntRuns)</div>  <div class="stat-lbl">Hunt Runs</div></div>
</div>

<div class="tactic-grid">
$($tacticCards -join "`n")
</div>

<div class="filter-bar">
  <input type="text" id="searchInput" placeholder="Search technique, name..." oninput="filter()">
  <select id="verdictSel" onchange="filter()">
    <option value="">All verdicts</option>
    <option>COVERED</option><option>PARTIAL</option>
    <option>GAP</option><option>BLIND_SPOT</option>
    <option>HUNT_ARTIFACT</option><option>PENDING</option>
  </select>
  <select id="tacticSel" onchange="filter()">
    <option value="">All tactics</option>
    $tacticOptions
  </select>
</div>

<div class="table-wrap">
<table id="t">
  <thead><tr>
    <th>Tactic</th><th>Technique</th><th>Scenario</th>
    <th>Verdict</th><th>Detection</th><th>Notes</th><th>Sigma</th><th>Date</th>
  </tr></thead>
  <tbody>
$($rows -join "`n")
  </tbody>
</table>
</div>

<script>
function filter() {
  const s = document.getElementById('searchInput').value.toLowerCase();
  const v = document.getElementById('verdictSel').value.toLowerCase();
  const t = document.getElementById('tacticSel').value.toLowerCase();
  document.querySelectorAll('#t tbody tr').forEach(r => {
    const txt = r.textContent.toLowerCase();
    r.style.display = (!s||txt.includes(s)) && (!v||txt.includes(v)) && (!t||txt.includes(t)) ? '' : 'none';
  });
}
</script>
</body>
</html>
"@

    $html | Set-Content -Path $OutputFile -Encoding UTF8
    return $OutputFile
}

Export-ModuleMember -Function New-PASReport
