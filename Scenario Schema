# PAS Scenario Schema Reference

Every scenario in `scenarios/` must be a valid YAML file conforming to this schema.
Run `.\pas_runner.ps1 -Validate` at any time to check all scenarios.

---

## Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | ✅ | Unique identifier. Format: `T####[.###]_short_name` |
| `name` | string | ✅ | Human-readable scenario name |
| `mitre_technique` | string | ✅ | ATT&CK technique ID. Format: `T####` or `T####.###` |
| `mitre_tactic` | string | ✅ | ATT&CK tactic. See valid values below |
| `description` | string | ✅ | What this scenario simulates and why |
| `author` | string | ✅ | Author handle or name |
| `created` | string | ✅ | Creation date. Format: `YYYY-MM-DD` |
| `platform` | string | ✅ | Target platform. See valid values below |
| `references` | list | — | URLs (ATT&CK page, blog posts, etc.) |
| `steps` | list | ✅ | Ordered execution steps. Minimum 1 |
| `cleanup` | list | ✅ | Steps to undo all artifacts. Minimum 1 |
| `analyst_checklist` | list | ✅ | Items analyst validates in SIEM/EDR. Minimum 1 |

---

## Valid `mitre_tactic` Values

```
reconnaissance       resource-development    initial-access
execution            persistence             privilege-escalation
defense-evasion      credential-access       discovery
lateral-movement     collection              command-and-control
exfiltration         impact
```

---

## Valid `platform` Values

```
windows    linux    macos    cloud    containers
```

---

## Step Object Fields

Every entry in `steps` and `cleanup` is a step object.

| Field | Type | Required | Description |
|---|---|---|---|
| `step` | integer | ✅ | Step number. Must be unique within the list |
| `type` | string | ✅ | Step type. See valid values below |
| `description` | string | ✅ | What this step does |
| + type-specific fields | | | See per-type reference below |

---

## Step Types

### `exec`
Run a binary with arguments.

```yaml
- step: 1
  type: exec
  description: "Create scheduled task"
  binary: schtasks.exe
  args: "/create /tn PASTest /tr calc.exe /sc onlogon /f"
```

| Field | Required | Description |
|---|---|---|
| `binary` | ✅ | Executable name or full path |
| `args` | — | Arguments string |

---

### `exec_powershell`
Run a PowerShell command or script block. Auto-encoded as Base64 before execution.

```yaml
- step: 2
  type: exec_powershell
  description: "Enumerate local users"
  command: |
    Get-LocalUser | Select-Object Name, Enabled | Format-Table
```

| Field | Required | Description |
|---|---|---|
| `command` | ✅ | PowerShell command string (multi-line supported) |

---

### `exec_wmi`
Invoke a WMI method.

```yaml
- step: 3
  type: exec_wmi
  description: "Execute process via WMI"
  wmi_class: "Win32_Process"
  method: "Create"
  wmi_args: "calc.exe"
```

| Field | Required | Description |
|---|---|---|
| `wmi_class` | ✅ | WMI class name |
| `method` | ✅ | Method to invoke |
| `wmi_args` | — | Arguments passed to the method |

---

### `exec_com`
Invoke a method on a COM object.

```yaml
- step: 4
  type: exec_com
  description: "Execute via WScript.Shell"
  com_progid: "WScript.Shell"
  method: "Run"
  com_args: "calc.exe"
```

| Field | Required | Description |
|---|---|---|
| `com_progid` | ✅ | COM ProgID |
| `method` | ✅ | Method to call |
| `com_args` | — | Arguments |

---

### `sleep`
Wait N seconds. Use to allow telemetry to flush before the analyst checklist prompt.

```yaml
- step: 5
  type: sleep
  description: "Allow telemetry to flush"
  seconds: 3
```

| Field | Required | Description |
|---|---|---|
| `seconds` | ✅ | Integer sleep duration |

---

### `marker`
Print a message. No execution — used to prompt analyst attention at a specific point.

```yaml
- step: 6
  type: marker
  description: "Analyst prompt"
  message: "Check your SIEM now — schtasks.exe creation event should be visible"
```

| Field | Required | Description |
|---|---|---|
| `message` | ✅ | Message to display |

---

### `file_write`
Write a text file to disk.

```yaml
- step: 7
  type: file_write
  description: "Write dummy payload"
  path: "C:\\Windows\\Temp\\pas_test.txt"
  content: "PAS_TEST_PAYLOAD"
```

| Field | Required | Description |
|---|---|---|
| `path` | ✅ | Full file path |
| `content` | ✅ | File content (string) |

---

### `file_delete`
Delete a file.

```yaml
- step: 8
  type: file_delete
  description: "Remove test file"
  path: "C:\\Windows\\Temp\\pas_test.txt"
```

| Field | Required | Description |
|---|---|---|
| `path` | ✅ | Full file path |

---

### `reg_write`
Write a registry value.

```yaml
- step: 9
  type: reg_write
  description: "Write run key"
  hive: HKCU
  key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  value_name: PASTest
  value_data: "C:\\Windows\\Temp\\pas_test.exe"
  value_type: REG_SZ
```

| Field | Required | Description |
|---|---|---|
| `hive` | ✅ | `HKLM` \| `HKCU` \| `HKCR` \| `HKU` \| `HKCC` |
| `key` | ✅ | Registry key path (no hive prefix) |
| `value_name` | ✅ | Value name |
| `value_data` | ✅ | Value data |
| `value_type` | — | `REG_SZ` (default) \| `REG_DWORD` \| `REG_BINARY` \| `REG_EXPAND_SZ` \| `REG_MULTI_SZ` |

---

### `reg_delete`
Delete a registry value or key.

```yaml
- step: 10
  type: reg_delete
  description: "Remove run key"
  hive: HKCU
  key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  value_name: PASTest
```

| Field | Required | Description |
|---|---|---|
| `hive` | ✅ | Registry hive |
| `key` | ✅ | Registry key path |
| `value_name` | — | Omit to delete the entire key |

---

## Analyst Checklist Guidelines

Each checklist item should be a specific, actionable observation the analyst can
look for in their SIEM or EDR. Be precise about:

- Which table or log source to query
- Which process, file, registry path, or network event to look for
- What the expected parent-child process relationship is

**Good:**
```yaml
analyst_checklist:
  - "Process event: schtasks.exe with /create in CommandLine, parent is powershell.exe"
  - "Registry event: HKLM\\...\\TaskCache key written"
  - "Sentinel: DeviceProcessEvents | where FileName == 'schtasks.exe' and ProcessCommandLine contains '/create'"
```

**Too vague:**
```yaml
analyst_checklist:
  - "Check if task was created"
  - "Look in SIEM"
```

---

## Complete Example

```yaml
id: T1053.005_scheduled_task
name: "Scheduled Task Creation via schtasks.exe"
mitre_technique: "T1053.005"
mitre_tactic: "persistence"
description: >
  Creates a scheduled task using schtasks.exe to simulate adversary persistence.
  The task is created with /SC ONLOGON to trigger at user logon.
  Tests detection of schtasks.exe spawned from a non-standard parent process.
author: stanleytobias
created: "2026-01-01"
platform: windows
references:
  - https://attack.mitre.org/techniques/T1053/005/

steps:
  - step: 1
    type: marker
    description: "Pre-execution prompt"
    message: "Starting T1053.005 — Scheduled Task creation simulation"

  - step: 2
    type: exec
    description: "Create scheduled task via schtasks.exe"
    binary: schtasks.exe
    args: "/create /tn PASTest /tr C:\\Windows\\System32\\calc.exe /sc onlogon /f"

  - step: 3
    type: sleep
    description: "Allow telemetry to flush to SIEM"
    seconds: 5

  - step: 4
    type: marker
    description: "Analyst prompt"
    message: "Check your SIEM and EDR — schtasks.exe /create event should now be visible"

cleanup:
  - step: 1
    type: exec
    description: "Remove PAS test scheduled task"
    binary: schtasks.exe
    args: "/delete /tn PASTest /f"

analyst_checklist:
  - "Process event: schtasks.exe with CommandLine containing /create and /tn PASTest"
  - "Parent process: powershell.exe or cmd.exe spawning schtasks.exe"
  - "Registry event: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache key modified"
  - "File event: XML task definition written to C:\\Windows\\System32\\Tasks\\PASTest"
  - "Sentinel: DeviceProcessEvents | where FileName == 'schtasks.exe' and ProcessCommandLine contains '/create'"
  - "MDE alert: 'Suspicious scheduled task creation' or similar persistence alert"
```

---

## Validation

```powershell
# Validate all scenarios
.\pas_runner.ps1 -Validate

# Validate one file
.\pas_runner.ps1 -Validate -Scenario scenarios\persistence\T1053.005_scheduled_task.yml
```

Schema errors are reported per-field with clear messages before any execution occurs.
