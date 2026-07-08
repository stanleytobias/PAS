# Testing Microsoft Defender ASR Rules with PAS

PAS's normal loop validates **detections** (did a SIEM/EDR rule fire on real
behavior). ASR rules are a **preventive control** — the question is different:
*did Defender block or audit the behavior, and did it emit the ASR event my
pipeline can see?* This guide explains how to test ASR rules safely through PAS
without changing the runner, and ships three ready-to-run scenarios in
`scenarios/asr/`.

---

## The one thing that's different: a blocked step is success

In a detection scenario, a step that fails to execute is a problem. In an **ASR
Block-mode** test, a step that fails to execute is the *win* — the control did
its job. PAS's executor already tolerates this: every step runs inside a
try/catch and the scenario proceeds to cleanup and the analyst prompt regardless
(`lib/PAS.Executor.psm1`). So a blocked `exec`/`exec_wmi`/`exec_powershell` step
records an error in the result JSON **and that error is the evidence**, not a
bug.

Because of that inversion, interpret ASR verdicts like this:

| PAS verdict | Meaning for an ASR test |
|---|---|
| `COVERED` | ASR event fired (1121 block / 1122 audit) **and** it reached your SIEM/MDE with the right rule context |
| `PARTIAL` | ASR fired locally but the event isn't in your SIEM, or lacks rule/GUID context |
| `GAP` | Behavior ran, no ASR event — but the rule *was* configured (rule failed to match) |
| `BLIND_SPOT` | No ASR event and the rule wasn't configured / Defender is passive (nothing could have fired) |

---

## Test in Audit mode first, always

Run every ASR rule through this progression. Never start in Block on a machine
you care about.

1. **Audit** the target rule. Behavior completes normally, Defender logs
   **Event ID 1122**. This proves the rule *matches* the behavior and that your
   SIEM/MDE ingests ASR events — with zero disruption.
2. **Review** the audit events (see verification below). Confirm no legitimate
   software also trips the rule (LSASS and PsExec/WMI rules are notoriously
   noisy).
3. **Warn** or **Block** in rings. Block logs **Event ID 1121** and stops the
   behavior. Re-run the same PAS scenario to confirm the block.

The shipped scenarios are mode-agnostic: each one prints the rule's *currently
configured* action in a preflight step, performs the behavior, then tails the
Defender log for 1121/1122 in a postflight step. Run the same file in audit and
in block; only the event ID changes.

---

## Preconditions (surfaced by every scenario's preflight step)

- **Defender must be the active AV.** `Get-MpComputerStatus | Select AMRunningMode`
  must be `Normal`. In `Passive`/`SxS Passive` (a third-party AV is primary), ASR
  rules do **not** enforce.
- **Real-time protection on.** `RealTimeProtectionEnabled = True`.
- **Cloud-delivered protection** is required for two rules: *Block executable
  files unless prevalence/age/trusted-list* (`01443614…`) and *Use advanced
  protection against ransomware* (`c1db55ab…`). The LSASS, PsExec/WMI, and
  WMI-persistence rules work fully offline.

---

## Setting a rule's mode

```powershell
# Read current state (GUIDs and their actions run in parallel arrays)
$p = Get-MpPreference
0..($p.AttackSurfaceReductionRules_Ids.Count-1) | ForEach-Object {
    [pscustomobject]@{ Id = $p.AttackSurfaceReductionRules_Ids[$_]
                       Action = $p.AttackSurfaceReductionRules_Actions[$_] }
}
# Action codes: 0 Disabled | 1 Block | 2 Audit | 6 Warn

# Put ONE rule into Audit (use Add-, not Set-, so you don't wipe other rules)
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c `
                 -AttackSurfaceReductionRules_Actions AuditMode

# Promote the same rule to Block after review
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c `
                 -AttackSurfaceReductionRules_Actions Enabled

# Turn it back off
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c `
                 -AttackSurfaceReductionRules_Actions Disabled
```

> In a managed environment ASR is usually pushed by Intune/GPO and a local
> `Add-MpPreference` may be overridden or refused (merge behavior). Do mode
> changes the same way your fleet does, so the test reflects production.

---

## Verifying an ASR rule fired

Two authoritative signals. Prefer them over exact MDE ActionType spelling.

**1. Local event log (ground truth, no cloud needed).** The scenarios do this
for you, but to check by hand:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id      = 1121,1122          # 1121 = Blocked, 1122 = Audited
    StartTime = (Get-Date).AddMinutes(-5)
} | Where-Object { $_.Message -match '<rule-guid>' } |
    Format-List TimeCreated, Id, Message
```

The event message carries the rule **GUID** (`ID:` field), the offending
**process/path**, and the **parent** — filter on the GUID to isolate one rule.

**2. Microsoft Defender for Endpoint — Advanced Hunting.** The robust query
matches the family, so it survives any naming drift:

```kql
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType startswith "Asr"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, AdditionalFields
```

Each rule has a paired `…Blocked` / `…Audited` ActionType (see the table). Filter
to a specific one only after you've confirmed the exact string in your tenant.

---

## How an ASR scenario is laid out

Every scenario in `scenarios/asr/` follows the same five-beat shape so results
are self-explaining:

1. `marker` — rule name, GUID, safety note (benign payload, lab VM only).
2. `exec_powershell` **preflight** — Defender running mode + RTP, and this rule's
   *configured* action. If the rule is Not Configured it says so loudly, because
   a "no block" result then means nothing.
3. `exec_powershell` / `exec_wmi` **trigger** — the benign behavior that matches
   the rule (spawns `calc`/`cmd /c exit`, opens-and-closes a handle, etc.).
4. `exec_powershell` **postflight** — tails 1121/1122 for this GUID and prints
   hits, so you get local confirmation before the analyst prompt.
5. `analyst_checklist` — the SIEM/MDE queries and the expected event.

Run one:

```powershell
.\pas_runner.ps1 -DryRun  -Scenario scenarios\asr\T1047_asr_block_psexec_wmi_child_process.yml
.\pas_runner.ps1          -Scenario scenarios\asr\T1047_asr_block_psexec_wmi_child_process.yml
.\pas_runner.ps1 -Suite   scenarios\suites\asr_validation.yml
```

---

## Rule → behavior → verification map

Shipped scenarios are marked ✅. The rest use the exact same pattern — copy a
shipped file, swap the GUID in the preflight/postflight, and replace the trigger
step. Rules marked **env** need a specific app/hardware present (Office, Adobe,
Outlook, a USB device, a vulnerable driver) so they can't be triggered with a
pure PowerShell payload.

| ASR rule | GUID | Safe benign trigger | MDE ActionType (Blocked/Audited) | Shipped |
|---|---|---|---|---|
| Block process creations from PsExec and WMI | `d1e49aac-8f56-4280-b9ba-993a6d77406c` | `Win32_Process.Create("cmd /c exit")` | `AsrPsexecWmiChildProcess…` | ✅ |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` | `OpenProcess(VM_READ)` on lsass, close immediately — **no dump** | `AsrLsassCredentialTheft…` | ✅ |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` | Create `__EventFilter`+`CommandLineEventConsumer`+binding, remove at once | `AsrPersistenceThroughWmi…` | ✅ |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Run a heavily obfuscated but benign `.ps1`/`.vbs` (heuristic — may not fire every time) | `AsrObfuscatedScript…` | — |
| Block JS/VBScript from launching downloaded exe | `d3e037e1-3eb8-44c8-a917-57927947596d` | `.js` via `WScript.Shell.Run` of a MOTW-tagged benign `.exe` | `AsrScriptExecutableDownload…` | — |
| Block executable files unless prevalence/age/trusted-list | `01443614-cd74-433a-b99e-2ecdc07bfc25` | Compile+run a brand-new benign exe (needs cloud protection) | `AsrUntrustedExecutable…` | — |
| Block use of copied or impersonated system tools *(preview)* | `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb` | Copy `calc.exe` → `svchost.exe`, run it | `AsrAbusedSystemTool…` | — |
| Block all Office apps from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` | Word/Excel macro spawns `calc` | `AsrOfficeChildProcess…` | env |
| Block Office apps from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` | Office macro writes an `.exe` | `AsrExecutableOfficeContent…` | env |
| Block Office apps from injecting into other processes | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` | Office macro injects into another process | `AsrOfficeProcessInjection…` | env |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4ddddc7b` | VBA `Declare`/`VirtualAlloc` from a macro | `AsrOfficeMacroWin32ApiCalls…` | env |
| Block Office communication app child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` | Outlook spawns `calc` | `AsrOfficeCommAppChildProcess…` | env |
| Block executable content from email/webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Launch a benign exe saved from Outlook/webmail | `AsrExecutableEmailContent…` | env |
| Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` | Adobe Reader spawns `calc` | `AsrAdobeReaderChildProcess…` | env |
| Block untrusted/unsigned processes from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` | Run an unsigned exe from removable media | `AsrUntrustedUsbProcess…` | env |
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce9` | Load a known-vulnerable signed driver | `AsrVulnerableSignedDriver…` | env |
| Use advanced protection against ransomware | `c1db55ab-c21a-4637-bb3f-a12568109d35` | ML/cloud — no clean benign trigger | `AsrRansomware…` | env |
| Block Webshell creation for Servers | `a8f5898e-1dc8-49a9-9878-85004b8a61e6` | Exchange/IIS server only | `AsrWebshellCreation…` | env |
| Block rebooting machine in Safe Mode *(preview)* | `33ddedf1-c6e0-47cb-833e-de6133960387` | `bcdedit /set safeboot` (disruptive) | confirm in tenant | env |

Confirm exact ActionType strings against your own tenant with the
`startswith "Asr"` query — Microsoft occasionally renames them, and the local
1121/1122 + GUID check is always authoritative.

---

## Safety

Everything here follows PAS's rules: benign payloads only (`calc`, `cmd /c
exit`, echo), full cleanup, isolated lab VM. Specifically, the LSASS scenario
**opens and immediately closes a handle and never reads or dumps memory**; the
WMI-persistence scenario creates the subscription and tears it down before it can
ever fire. The trigger is the *request* Defender inspects — you do not need to
complete the malicious action to test the rule.
