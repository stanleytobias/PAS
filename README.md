# PAS — Practical Attack Simulation

**An attack simulation framework for detection engineering.**

PAS executes MITRE ATT&CK-mapped behaviors on a controlled Windows host and
guides analysts through validating whether their SIEM and EDR produced the
expected telemetry and detections. It generates the artifact. Detection is your job.

---

## Use Cases

| Use Case | Description |
|---|---|
| **Detection validation** | Run a scenario, confirm an existing rule fires on real behavior |
| **Coverage mapping** | Run a full tactic, discover which techniques have no detection |
| **Threat hunt support** | Generate real artifacts in your environment to hunt against |
| **Blue team training** | Structured, repeatable, lab-safe exercises with guided checklists |

---

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- Run as **Administrator** for scenarios requiring elevated privileges
- **Isolated lab VM only** — never run on production systems

---

## Quick Start

```powershell
# Clone
git clone https://github.com/stanleytobias/PAS
cd PAS

# Validate all scenario YAMLs
.\pas_runner.ps1 -Validate

# Run a single scenario
.\pas_runner.ps1 -Scenario scenarios\persistence\T1053.005_scheduled_task.yml

# Run all scenarios for a tactic
.\pas_runner.ps1 -Tactic persistence -Out results\persistence\

# Run a pre-built suite
.\pas_runner.ps1 -Suite scenarios\suites\detection_coverage_v1.yml

# Hunt mode — generate artifacts, skip verdict prompt
.\pas_runner.ps1 -Scenario scenarios\discovery\T1082_system_info.yml -HuntMode

# Generate HTML coverage report
.\pas_runner.ps1 -Report -Out results\
```

---

## How It Works

```
1. Pick a scenario (or tactic batch, or suite)
2. PAS executes each step — process spawns, registry writes, network probes
3. PAS runs cleanup — removes all artifacts it created
4. You check your SIEM and EDR for the expected telemetry
5. You enter a verdict at the interactive prompt
6. PAS saves a result JSON
7. On GAP or BLIND_SPOT — PAS auto-generates a Sigma rule scaffold
8. Edit the scaffold, convert to KQL, deploy to Sentinel, re-run to confirm
9. Run -Report to see your full coverage matrix as HTML
```

---

## Verdicts

| Verdict | Meaning |
|---|---|
| `COVERED` | Detection fired with correct ATT&CK technique context |
| `PARTIAL` | Detection fired but low fidelity or missing context |
| `GAP` | No detection — but telemetry is visible in SIEM/EDR |
| `BLIND_SPOT` | No detection and no telemetry — complete coverage gap |
| `HUNT_ARTIFACT` | Hunt mode run — artifacts generated, no verdict captured |
| `PENDING` | Skipped for now, saved for later review |

When you record `GAP` or `BLIND_SPOT`, you also classify the gap type:

| Gap Type | Meaning |
|---|---|
| `no_rule` | No detection rule exists for this technique |
| `rule_did_not_fire` | A rule exists but did not trigger |
| `missing_log_source` | Telemetry absent — log source not configured |
| `missing_sensor` | Telemetry absent — sensor not deployed |

---

## Repo Structure

```
PAS/
  pas_runner.ps1              # Entry point
  lib/
    PAS.Logging.psm1          # Output and verbosity
    PAS.Yaml.psm1             # Pure-PowerShell YAML parser
    PAS.Schema.psm1           # Scenario validation
    PAS.Executor.psm1         # Step engine and analyst prompt
    PAS.Results.psm1          # Result persistence and querying
    PAS.Sigma.psm1            # Sigma scaffold auto-generation
    PAS.Report.psm1           # HTML coverage report
  scenarios/
    suites/                   # Multi-scenario suite definitions
    reconnaissance/
    execution/
    persistence/
    privilege_escalation/
    defense_evasion/
    credential_access/
    discovery/
    lateral_movement/
    collection/
    exfiltration/
    impact/
    command_and_control/
  docs/
    getting_started.md
    workflow.md
    hunt_mode.md
    writing_scenarios.md
    sigma_workflow.md
  SCENARIO_SCHEMA.md          # Full scenario YAML field reference
  results/                    # Created on first run — gitignored
```

---

## What PAS Does NOT Do

- Connect to external infrastructure
- Exfiltrate data
- Persist itself between runs
- Disable or modify security products
- Evaluate its own detection

---

## Related

- [SIEM-UseCases](https://github.com/stanleytobias/SIEM-UseCases) — KQL detection rules validated using PAS
