@echo off
REM ============================================================================
REM  PAS ASR native test kit - PowerShell-free, runs under Constrained Language Mode
REM  Drives ASR rule triggers with cscript (VBScript) and a native exe, and reads
REM  results with wevtutil/reg/sc. No PowerShell engine involved.
REM
REM  Usage:  run_asr_tests.cmd [all|wmi|lsass|persist]   (default: all)
REM  Run elevated for the persistence test. Isolated lab VM only.
REM ============================================================================
setlocal EnableExtensions
set "HERE=%~dp0"
set "GUID_WMI=d1e49aac-8f56-4280-b9ba-993a6d77406c"
set "GUID_LSASS=9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
set "GUID_PERSIST=e6db77e5-3df2-4cf1-b95a-636979351e5b"
set "GUID_OBFUS=5beb7efe-fd9a-4556-801d-275e5ffc04cc"
set "GUID_SCREXE=d3e037e1-3eb8-44c8-a917-57927947596d"
set "GUID_COPYTOOL=c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"
set "GUID_UNTRUSTED=01443614-cd74-433a-b99e-2ecdc07bfc25"

set "WHICH=%~1"
if /I "%WHICH%"=="" set "WHICH=all"

echo ============================================================
echo   PAS ASR native test kit  (PowerShell-free / CLM-safe)
echo ============================================================
call :preflight

if /I "%WHICH%"=="all" (
    call :test_wmi
    call :test_lsass
    call :test_persist
    call :test_obfuscated
    call :test_scriptexe
    call :test_copiedtool
    call :test_untrustedexe
    goto :end
)
if /I "%WHICH%"=="wmi"       ( call :test_wmi         & goto :end )
if /I "%WHICH%"=="lsass"     ( call :test_lsass       & goto :end )
if /I "%WHICH%"=="persist"   ( call :test_persist     & goto :end )
if /I "%WHICH%"=="obfus"     ( call :test_obfuscated  & goto :end )
if /I "%WHICH%"=="scriptexe" ( call :test_scriptexe   & goto :end )
if /I "%WHICH%"=="copytool"  ( call :test_copiedtool  & goto :end )
if /I "%WHICH%"=="untrusted" ( call :test_untrustedexe & goto :end )
echo Unknown test "%WHICH%". Use: run_asr_tests.cmd [all^|wmi^|lsass^|persist^|obfus^|scriptexe^|copytool^|untrusted]

:end
echo.
echo Done. Match each postflight event's rule GUID / target path to the test you ran.
endlocal
goto :eof

REM ---------------------------------------------------------------------------
:preflight
echo.
echo --- Preflight ---
echo Defender service (WinDefend):
sc query WinDefend | findstr /I "STATE"
echo   (If not RUNNING, or Defender is in passive mode, ASR will NOT enforce.)
echo GPO/Intune-configured ASR rules (empty if rules were set locally):
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" 2>nul || echo   (no GPO ASR key found - rules may be set locally via Set-MpPreference)
net session >nul 2>&1 && (echo Elevation: Administrator) || (echo Elevation: NOT admin - the persistence test needs admin)
goto :eof

REM ---------------------------------------------------------------------------
:sleep5
timeout /t 5 /nobreak >nul 2>&1 || ping -n 6 127.0.0.1 >nul
goto :eof

REM ---------------------------------------------------------------------------
:postflight
echo --- Postflight: last 5 Defender ASR events (1121=block, 1122=audit) ---
wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /q:"*[System[(EventID=1121 or EventID=1122)]]" /c:5 /rd:true /f:text 2>nul || echo   (no ASR events found, or channel unavailable)
goto :eof

REM ---------------------------------------------------------------------------
:test_wmi
echo.
echo === Test 1: PsExec/WMI child process  (%GUID_WMI%) ===
cscript //nologo "%HERE%asr_wmi_child.vbs"
call :sleep5
call :postflight
goto :eof

REM ---------------------------------------------------------------------------
:test_lsass
echo.
echo === Test 2: LSASS credential theft  (%GUID_LSASS%) ===
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%HERE%asr_lsass.exe" (
    if exist "%CSC%" (
        echo Compiling asr_lsass.exe with on-box csc.exe ...
        "%CSC%" /nologo /out:"%HERE%asr_lsass.exe" "%HERE%asr_lsass.cs"
    ) else (
        echo csc.exe not found - cannot build asr_lsass.exe. Install .NET Framework 4.x or precompile it elsewhere.
        goto :eof
    )
)
"%HERE%asr_lsass.exe"
call :sleep5
call :postflight
goto :eof

REM ---------------------------------------------------------------------------
:test_persist
echo.
echo === Test 3: WMI event subscription persistence  (%GUID_PERSIST%) ===
cscript //nologo "%HERE%asr_wmi_persist.vbs"
call :sleep5
call :postflight
echo Cleaning up subscription ...
cscript //nologo "%HERE%asr_wmi_persist_cleanup.vbs"
goto :eof

REM ---------------------------------------------------------------------------
:test_obfuscated
echo.
echo === Test 4: Obfuscated script  (%GUID_OBFUS%) ===
echo   (heuristic/AMSI-scored - may not fire on every payload)
cscript //nologo "%HERE%asr_obfuscated_script.js"
call :sleep5
call :postflight
goto :eof

REM ---------------------------------------------------------------------------
:test_scriptexe
echo.
echo === Test 5: Script launches downloaded exe  (%GUID_SCREXE%) ===
copy /Y "%WINDIR%\System32\hostname.exe" "%TEMP%\pas_dl.exe" >nul
REM Apply Mark-of-the-Web (Zone.Identifier = 3 = Internet) via an alternate data stream
> "%TEMP%\pas_dl.exe:Zone.Identifier" echo [ZoneTransfer]
>> "%TEMP%\pas_dl.exe:Zone.Identifier" echo ZoneId=3
cscript //nologo "%HERE%asr_script_downloaded_exe.js"
call :sleep5
call :postflight
del "%TEMP%\pas_dl.exe" >nul 2>&1
goto :eof

REM ---------------------------------------------------------------------------
:test_copiedtool
echo.
echo === Test 6: Copied/impersonated system tool  (%GUID_COPYTOOL%) ===
copy /Y "%WINDIR%\System32\hostname.exe" "%TEMP%\svchost.exe" >nul
"%TEMP%\svchost.exe"
call :sleep5
call :postflight
del "%TEMP%\svchost.exe" >nul 2>&1
goto :eof

REM ---------------------------------------------------------------------------
:test_untrustedexe
echo.
echo === Test 7: Untrusted/low-prevalence executable  (%GUID_UNTRUSTED%) ===
echo   (requires cloud-delivered protection to enforce)
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" ( echo   csc.exe not found - skipping & goto :eof )
REM Generate a unique source each run so the compiled PE has a novel hash (low prevalence)
set "UCS=%TEMP%\pas_unique_%RANDOM%%RANDOM%.cs"
set "UEXE=%TEMP%\pas_unique_%RANDOM%%RANDOM%.exe"
> "%UCS%" echo class P{static void Main(){System.Console.WriteLine("PAS low-prevalence exe %TIME% %RANDOM%");}}
"%CSC%" /nologo /out:"%UEXE%" "%UCS%" >nul
"%UEXE%"
call :sleep5
call :postflight
del "%UCS%" "%UEXE%" >nul 2>&1
goto :eof
