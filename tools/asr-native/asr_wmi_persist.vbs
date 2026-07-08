' PAS ASR native test - Block persistence through WMI event subscription (e6db77e5)
'
' Benign: registers a permanent WMI event subscription (__EventFilter +
' CommandLineEventConsumer + __FilterToConsumerBinding) in root\subscription.
' The consumer is calc.exe but the trigger condition (Hour = 99) can never occur,
' so it NEVER fires. Run asr_wmi_persist_cleanup.vbs afterward to remove it.
' Requires Administrator. Runs under Constrained Language Mode (cscript, not PS).
'
' Usage:  cscript //nologo asr_wmi_persist.vbs

Option Explicit
Dim svc, filter, consumer, binding

WScript.Echo "[PAS][ASR] Block persistence through WMI event subscription (e6db77e5)"
WScript.Echo "[PAS][ASR] Registering benign, non-firing subscription (consumer=calc.exe, trigger Hour=99 never occurs)."

On Error Resume Next
Set svc = GetObject("winmgmts:{impersonationLevel=impersonate,authenticationLevel=pktPrivacy}!\\.\root\subscription")
If Err.Number <> 0 Then
    WScript.Echo "[PAS][ASR] Could not bind root\subscription (err " & Err.Number & ") -> run elevated."
    WScript.Quit 1
End If

Set filter = svc.Get("__EventFilter").SpawnInstance_
filter.Name          = "PAS_ASR_Filter"
filter.EventNamespace = "root\cimv2"
filter.QueryLanguage  = "WQL"
filter.Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 99"
filter.Put_
If Err.Number <> 0 Then
    Report "__EventFilter"
    WScript.Quit 1
End If

Set consumer = svc.Get("CommandLineEventConsumer").SpawnInstance_
consumer.Name                = "PAS_ASR_Consumer"
consumer.CommandLineTemplate = "calc.exe"
consumer.Put_
If Err.Number <> 0 Then
    Report "CommandLineEventConsumer"
    WScript.Quit 1
End If

Set binding = svc.Get("__FilterToConsumerBinding").SpawnInstance_
binding.Filter   = "__EventFilter.Name=""PAS_ASR_Filter"""
binding.Consumer = "CommandLineEventConsumer.Name=""PAS_ASR_Consumer"""
binding.Put_
If Err.Number <> 0 Then
    Report "__FilterToConsumerBinding"
    WScript.Quit 1
End If
On Error GoTo 0

WScript.Echo "[PAS][ASR] Subscription registered -> expect Event 1122 if audited. Now run asr_wmi_persist_cleanup.vbs."

Sub Report(cls)
    WScript.Echo "[PAS][ASR] Creating " & cls & " raised error " & Err.Number & " (0x" & Hex(Err.Number) & ") -> consistent with a BLOCK (Event 1121) or missing elevation."
End Sub
