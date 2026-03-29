# Writing PAS Scenarios

## Principles

**Safe by design.** Every scenario must clean up after itself. Leave no persistent
artifacts. Use loopback addresses for network tests. Never connect to external
infrastructure.

**One technique per file.** Keep scenarios focused. If a sub-technique has
meaningfully different behavior, give it its own file.

**Real behavior, not just presence.** The goal is to trigger the telemetry an
adversary would actually generate — not just to create a file or registry key
that happens to share a name. Think about what MDE or Sysmon would actually log.

**Honest checklists.** The analyst checklist should tell the analyst exactly where
to look and what to query. Vague checklist items produce useless verdicts.

## File Naming

```
T<technique_id>_<short_name>.yml

T1053.005_scheduled_task.yml
T1059.001_powershell_encoded.yml
T1003.001_lsass_handle.yml
```

## Folder Placement

Place the file in `scenarios/<tactic>/`. Use the primary tactic from ATT&CK.
For techniques that appear under multiple tactics (e.g. T1078 Valid Accounts),
use the tactic that best describes the simulation's intent.

## Step Design Guidelines

### Prefer exec_powershell for flexibility

```yaml
- step: 1
  type: exec_powershell
  description: "Enumerate scheduled tasks"
  command: |
    Get-ScheduledTask | Where-Object { $_.TaskPath -eq '\' } |
        Select-Object TaskName, State | Format-Table
```

### Always follow execution with a sleep

Give telemetry time to flush to your SIEM before the checklist appears.
3–5 seconds is usually sufficient. Use longer sleeps for network events.

```yaml
- step: 3
  type: sleep
  description: "Allow telemetry to flush"
  seconds: 5
```

### Use markers to guide the analyst

Place markers before steps where the analyst should be watching, and after
execution to prompt them to check their console.

```yaml
- step: 4
  type: marker
  description: "Post-execution prompt"
  message: "Check EDR console — schtasks.exe creation event should be visible now"
```

### Cleanup must be complete

Every artifact you create must be removed in the cleanup block:
- Scheduled tasks → `schtasks /delete`
- Registry keys → `reg_delete`
- Files → `file_delete`
- Processes you launched → `Stop-Process`
- Services you created → `sc delete`

If cleanup fails, PAS will warn the analyst and record the error in the result JSON.

### Marker-only for unsafe or passive techniques

For pre-compromise techniques (recon, resource development) or techniques with
no safe simulation (firmware corruption, disk wipe), use marker steps to
document the technique and provide control validation guidance instead.

```yaml
steps:
  - step: 1
    type: marker
    description: "Technique context"
    message: "T1542.001 — System Firmware modification has no safe simulation"

  - step: 2
    type: marker
    description: "Control validation"
    message: "CONTROL CHECK: Verify UEFI Secure Boot is enabled in BIOS settings"

cleanup:
  - step: 1
    type: marker
    description: "No cleanup required"
    message: "Marker-only scenario — no artifacts created"
```

## Checklist Writing

Each item should be independently actionable. Write it so an analyst can copy
it directly into a SIEM search or know exactly where to click in their EDR.

```yaml
analyst_checklist:
  # Bad — too vague
  - "Check if something happened in the SIEM"

  # Good — specific and actionable
  - "Process event: schtasks.exe with CommandLine containing '/create' and '/tn PASTest'"
  - "Parent process: powershell.exe or cmd.exe spawning schtasks.exe"
  - "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache modified"
  - "Sentinel: DeviceProcessEvents | where FileName == 'schtasks.exe' and ProcessCommandLine contains '/create'"
  - "MDE alert: 'Suspicious scheduled task' or persistence category alert"
```

## Validate Before Committing

```powershell
.\pas_runner.ps1 -Validate -Scenario scenarios\<tactic>\<your_scenario>.yml
```

Fix all schema errors before submitting. The full field reference is in
[SCENARIO_SCHEMA.md](../SCENARIO_SCHEMA.md).

## Testing Your Scenario

```powershell
# Dry run first — verify step order and types look right
.\pas_runner.ps1 -DryRun -Scenario scenarios\<tactic>\<your_scenario>.yml

# Live run in your lab VM
.\pas_runner.ps1 -Scenario scenarios\<tactic>\<your_scenario>.yml
```

Check that:
- All steps execute without errors
- Cleanup removes everything it should
- The checklist items are findable in your SIEM
- The scenario generates a useful result JSON
