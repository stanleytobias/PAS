' PAS ASR native test - cleanup for asr_wmi_persist.vbs
' Removes the PAS_ASR filter, consumer, and binding from root\subscription.
' Requires Administrator.
'
' Usage:  cscript //nologo asr_wmi_persist_cleanup.vbs

Option Explicit
Dim svc, o

On Error Resume Next
Set svc = GetObject("winmgmts:{impersonationLevel=impersonate,authenticationLevel=pktPrivacy}!\\.\root\subscription")
If Err.Number <> 0 Then
    WScript.Echo "[PAS][ASR][Cleanup] Could not bind root\subscription (err " & Err.Number & ") -> run elevated."
    WScript.Quit 1
End If

For Each o In svc.ExecQuery("SELECT * FROM __FilterToConsumerBinding")
    If InStr(o.Consumer, "PAS_ASR_Consumer") > 0 Or InStr(o.Filter, "PAS_ASR_Filter") > 0 Then o.Delete_
Next
For Each o In svc.ExecQuery("SELECT * FROM CommandLineEventConsumer WHERE Name = 'PAS_ASR_Consumer'")
    o.Delete_
Next
For Each o In svc.ExecQuery("SELECT * FROM __EventFilter WHERE Name = 'PAS_ASR_Filter'")
    o.Delete_
Next
On Error GoTo 0

WScript.Echo "[PAS][ASR][Cleanup] Removed PAS_ASR filter, consumer, and binding (if present)."
