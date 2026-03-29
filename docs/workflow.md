# Detection Engineering Workflow with PAS

## The Core Loop

```
Pick a technique gap
        │
        ▼
Run PAS scenario
        │
        ▼
Check SIEM + EDR
        │
   ┌────┴────┐
   │         │
COVERED    GAP / BLIND_SPOT
   │         │
Document   Classify gap type
coverage        │
           ┌────┴──────────────────────┐
           │                           │
       no_rule /              missing_log_source /
    rule_did_not_fire           missing_sensor
           │                           │
      Edit Sigma scaffold         Fix telemetry
      Convert to KQL              (connector,
      Deploy to Sentinel           Sysmon, MDE
           │                       sensor policy)
           ▼                           │
     Re-run scenario ◄────────────────┘
           │
           ▼
      COVERED ✓
           │
           ▼
    Commit rule to
    SIEM-UseCases repo
```

## Step by Step

### 1. Choose What to Test

Pick a starting point based on what matters to you:

- **Known gap** — you suspect you have no coverage for a specific technique
- **Threat intel driven** — a recent report mentions a specific TTP, validate you can see it
- **Tactic sweep** — run an entire tactic to map coverage across all its techniques
- **Suite** — run a pre-built scenario group that represents a threat scenario

### 2. Run the Scenario

```powershell
# Single technique
.\pas_runner.ps1 -Scenario scenarios\persistence\T1053.005_scheduled_task.yml

# Full tactic
.\pas_runner.ps1 -Tactic persistence -Out results\persistence\

# Pre-built threat scenario
.\pas_runner.ps1 -Suite scenarios\suites\detection_coverage_v1.yml
```

### 3. Check Your SIEM and EDR

While the analyst checklist is on screen, open your SIEM and EDR.
Each checklist item tells you what to look for and where.

For MDE + Sentinel, typical queries:

```kql
// Was the process created?
DeviceProcessEvents
| where Timestamp > ago(10m)
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"

// Was there a registry event?
DeviceRegistryEvents
| where Timestamp > ago(10m)
| where RegistryKey contains "Schedule\\TaskCache"
```

### 4. Enter Your Verdict

```
[1] COVERED     — detection fired, correct technique context
[2] PARTIAL     — detection fired but low fidelity or missing context
[3] GAP         — no detection, but telemetry is present
[4] BLIND_SPOT  — no detection and no telemetry
[5] PENDING     — skip for now
```

For GAP and BLIND_SPOT, PAS also asks for a gap type:

```
[1] no_rule             — technique has no detection rule
[2] rule_did_not_fire   — rule exists but didn't trigger
[3] missing_log_source  — log source not configured
[4] missing_sensor      — sensor not deployed on this host class
```

This classification is the most important output — it tells you what action to take next.

### 5. Act on the Gap

| Gap Type | Next Action |
|---|---|
| `no_rule` | Write a Sigma rule from the auto-generated scaffold |
| `rule_did_not_fire` | Review and tune the existing rule's conditions |
| `missing_log_source` | Configure the log source (Sysmon, MDE policy, connector) |
| `missing_sensor` | Deploy the sensor to this host class |

### 6. Close the Loop

After fixing a gap, re-run the same scenario:

```powershell
.\pas_runner.ps1 -Scenario scenarios\persistence\T1053.005_scheduled_task.yml
```

The new result file will record the updated verdict. Your coverage report improves.

### 7. Review Coverage

```powershell
.\pas_runner.ps1 -Report -Out results\
```

Opens an HTML report showing your coverage across all tactics and techniques.

## Tactic Sweep Pattern

The most efficient way to map coverage for an entire tactic:

```powershell
# Run all persistence scenarios
.\pas_runner.ps1 -Tactic persistence -Out results\persistence\

# Generate report
.\pas_runner.ps1 -Report -Out results\persistence\
```

Work through tactics in priority order based on your threat profile.
Recommended starting order for most environments:

1. Execution
2. Persistence
3. Defense Evasion
4. Credential Access
5. Discovery
6. Lateral Movement
7. Collection + Exfiltration
