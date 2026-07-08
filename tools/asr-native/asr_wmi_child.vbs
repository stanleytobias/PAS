' PAS ASR native test - Block process creations from PsExec and WMI (d1e49aac)
'
' Benign: asks WMI to create cmd.exe /c exit. The child parents to WmiPrvSE.exe,
' which is exactly the behavior the rule targets. Runs under Constrained Language
' Mode because cscript/VBScript is not a PowerShell-engine feature.
'
' Usage:  cscript //nologo asr_wmi_child.vbs

Option Explicit
Dim svc, proc, pid, rv

WScript.Echo "[PAS][ASR] Block PsExec/WMI child process (d1e49aac)"
WScript.Echo "[PAS][ASR] WMI Win32_Process.Create -> cmd.exe /c exit (child parents to WmiPrvSE.exe)"

On Error Resume Next
Set svc  = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set proc = svc.Get("Win32_Process")
rv = proc.Create("cmd.exe /c exit", Null, Null, pid)
If Err.Number <> 0 Then
    WScript.Echo "[PAS][ASR] Create raised error " & Err.Number & " (0x" & Hex(Err.Number) & ") -> consistent with a BLOCK (Event 1121)."
    WScript.Quit 1
End If
On Error GoTo 0

If rv = 0 Then
    WScript.Echo "[PAS][ASR] Create OK (ReturnValue=0, PID=" & pid & ") -> expected in AUDIT/Disabled (Event 1122)."
Else
    WScript.Echo "[PAS][ASR] Create ReturnValue=" & rv & " (non-zero) -> consistent with a BLOCK (Event 1121)."
End If
