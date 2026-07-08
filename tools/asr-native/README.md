# PAS ASR native test kit (PowerShell-free)

PowerShell-free triggers for the three PAS ASR scenarios, for hosts where
PowerShell is locked down by **Constrained Language Mode (CLM)**. CLM restricts
the PowerShell *engine* (`Add-Type`, P/Invoke, arbitrary .NET) but does **not**
constrain VBScript run by `cscript`, native `.exe` files, or the on-box .NET
compiler — so these tests use exactly those. Nothing here touches PowerShell.

> If your hardening is full application control (WDAC/AppLocker enforce) rather
> than CLM, a freshly built `.exe` is blocked too — this kit assumes CLM, where
> native binaries still run. See `../../docs/asr_testing.md`.

## Why this works when the PowerShell scenarios don't

| Trigger | Mechanism | CLM-safe? |
|---|---|---|
| WMI child process (`d1e49aac`) | `cscript` → `Win32_Process.Create` | Yes — cscript isn't the PS engine |
| WMI persistence (`e6db77e5`) | `cscript` → `__EventFilter`/`CommandLineEventConsumer`/binding | Yes |
| LSASS theft (`9e6c4e1f`) | native `.exe` → `OpenProcess(PROCESS_VM_READ)` | Yes — CLM doesn't constrain native exes |
| Obfuscated script (`5beb7efe`) | `cscript` → obfuscated JScript (AMSI-scored) | Yes (heuristic — may not fire) |
| Script launches downloaded exe (`d3e037e1`) | `cscript` → `.js` runs a MOTW-tagged exe | Yes |
| Copied system tool (`c0033c00`) | `cmd` copies `hostname.exe` → `svchost.exe`, runs it | Yes |
| Untrusted/low-prevalence exe (`01443614`) | `csc.exe` compiles a novel exe, runs it (needs cloud) | Yes |

The LSASS and low-prevalence tests need native executables, so they compile on-box
with the .NET Framework compiler
(`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) — no Visual Studio, no
internet, no smuggled binary. `run_asr_tests.cmd` builds them automatically.

These 7 are the ASR rules triggerable without an external app; the other 12
(Office/Adobe/Outlook/USB/server, and the ransomware/driver/Safe-Mode rules) need
software or hardware this kit can't stand in for — see the YAML scenarios and map
in `../../docs/asr_testing.md`.

## Files

| File | Purpose |
|---|---|
| `run_asr_tests.cmd` | Orchestrator: preflight → trigger → postflight, all native |
| `asr_wmi_child.vbs` | Trigger: WMI process creation (child of WmiPrvSE.exe) |
| `asr_wmi_persist.vbs` | Trigger: register a benign, non-firing WMI subscription |
| `asr_wmi_persist_cleanup.vbs` | Remove the subscription created above |
| `asr_lsass.cs` | Source: opens+closes an lsass handle with `PROCESS_VM_READ` (no dump) |
| `asr_obfuscated_script.js` | Trigger: obfuscated JScript (AMSI-scored) |
| `asr_script_downloaded_exe.js` | Trigger: launch a MOTW-tagged exe (staged by the runner) |

## Usage (elevated, isolated lab VM)

```bat
REM All seven tests
run_asr_tests.cmd

REM One at a time
run_asr_tests.cmd wmi
run_asr_tests.cmd lsass
run_asr_tests.cmd persist
run_asr_tests.cmd obfus
run_asr_tests.cmd scriptexe
run_asr_tests.cmd copytool
run_asr_tests.cmd untrusted
```

Each test prints whether the behavior was allowed (audit/disabled) or blocked,
then the runner tails the last Defender ASR events. Set the target rule to Audit
first, confirm **Event 1122**, then Block and confirm **Event 1121** — same as the
PowerShell scenarios (`../../docs/asr_testing.md`).

## GPO blocks the scripts? Use the exe

If Group Policy blocks Windows Script Host or `.cmd`/`.vbs`/`.js` (AppLocker script
rules), compile `asr_trigger.cs` to a single self-contained exe — no script engine
involved:

```bat
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo ^
  /out:asr_trigger.exe /r:System.Management.dll asr_trigger.cs
asr_trigger.exe [wmi|lsass|persist|copytool|untrusted|all]
```

It covers the 5 rules a native process can trigger (`wmi`, `lsass`, `persist`,
`copytool`, `untrusted`). The two script-engine rules (`obfus` 5beb7efe, `scriptexe`
d3e037e1) can't be exercised without a script host, so they're out on a
script-blocked box. Rename a copy to `asr_<rule>.exe` (e.g. `asr_wmi.exe`) to
double-click a single rule — the exe reads its own filename. Output goes to the
console and `%TEMP%\pas_asr_trigger.log`. If the exe is *also* blocked, your policy
is application control (WDAC/AppLocker exe rules), not just scripts, and you'd need
a signed or allow-listed binary.

Prebuilt copies are committed under [`bin/`](bin/) — `asr_trigger.exe` plus the
per-rule `asr_<rule>.exe` files — for target machines without a compiler. They are
unsigned; some AV/EDR may flag them since they exercise attack behaviors. Rebuild
from `asr_trigger.cs` if you'd rather not trust the committed binaries.

## Verification (also PowerShell-free)

```bat
REM Block (1121) / audit (1122) events
wevtutil qe "Microsoft-Windows-Windows Defender/Operational" ^
  /q:"*[System[(EventID=1121 or EventID=1122)]]" /c:10 /rd:true /f:text

REM GPO/Intune-configured ASR rule modes (empty if set locally)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
```

## Safety

Benign payloads only (`cmd /c exit`, a never-firing `calc.exe` consumer, an
open+close handle with no read/dump). The persistence test cleans up after itself.
Same guarantees as the YAML scenarios — run only on an isolated lab VM.

## Relation to the YAML scenarios

These 7 mirror their `scenarios/asr/*.yml` counterparts (the automatable tier of
the full 19-rule matrix). Use the YAML scenarios where PowerShell runs in Full
Language Mode (you get PAS's verdict prompt, result JSON, and Sigma scaffolding);
use this kit where PowerShell is constrained.
