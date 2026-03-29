# Hunt Mode

Hunt mode lets you use PAS to generate real telemetry in your environment that
you can then hunt against in your SIEM — without entering a verdict or being
interrupted by the analyst checklist prompt.

## When to Use Hunt Mode

- You want to verify a new hunting hypothesis against real artifacts
- You're developing a KQL query and need live data to test against
- You're running training exercises where analysts hunt without knowing what ran
- You want to pre-populate your SIEM with a technique's artifact signature

## Usage

```powershell
# Single scenario in hunt mode
.\pas_runner.ps1 -Scenario scenarios\lateral_movement\T1021.002_smb_admin_shares.yml -HuntMode

# Full tactic in hunt mode
.\pas_runner.ps1 -Tactic discovery -HuntMode -Out results\hunts\

# Suite in hunt mode
.\pas_runner.ps1 -Suite scenarios\suites\detection_coverage_v1.yml -HuntMode -Out results\hunts\
```

## What Happens

1. PAS executes all steps normally
2. PAS runs cleanup normally
3. Instead of the verdict prompt, PAS prints the checklist as **suggested SIEM queries**
4. Result is saved with verdict `HUNT_ARTIFACT`
5. You go hunt in your SIEM using the printed suggestions

## Hunt Mode Output

```
============================================================
  HUNT ARTIFACT GENERATED
  T1021.002 — SMB/Windows Admin Shares
============================================================

Artifacts generated. Go hunt in your SIEM.
Suggested queries from analyst checklist:

  - Process event: net.exe or net1.exe with 'use' and admin share (C$, ADMIN$, IPC$)
  - Process event: cmd.exe or powershell.exe spawning net.exe
  - Network event: outbound SMB (TCP 445) from workstation to workstation
  - Sentinel: DeviceNetworkEvents | where RemotePort == 445 and...
  - MDE alert: 'Lateral movement via SMB' or 'Admin share access'
```

## Blind Hunt Exercise

A useful training pattern: run scenarios in hunt mode without telling analysts
what you ran, then have them identify the techniques from the SIEM data alone.

```powershell
# Operator runs this (analysts don't see the command)
.\pas_runner.ps1 -Tactic lateral_movement -HuntMode -Quiet -Out results\exercise\

# Analysts hunt in SIEM for 30-60 minutes
# Debrief: compare findings to result JSONs in results\exercise\
```

## Hunt Runs in Coverage Reports

Hunt runs appear in the HTML report with a `HUNT` badge and are excluded from
the coverage percentage calculation — they don't count as validated coverage.
They do appear in the per-tactic breakdown so you can see where you've generated
hunt data vs where you've validated detections.
