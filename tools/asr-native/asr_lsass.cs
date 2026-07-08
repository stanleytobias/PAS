// PAS ASR native test - Block credential stealing from LSASS (9e6c4e1f)
//
// Benign: opens a handle to lsass.exe requesting PROCESS_VM_READ (the access mask
// credential dumpers use and the ASR rule inspects), then Closes it immediately.
// It performs NO memory read and NO MiniDump. The handle *request* is the trigger.
//
// Why a native exe: Constrained Language Mode blocks Add-Type / P-Invoke in
// PowerShell, but does not constrain native executables. Build on-box with the
// .NET Framework compiler (no Visual Studio, no internet):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:asr_lsass.exe asr_lsass.cs
// run_asr_tests.cmd does this for you.
//
// Exit codes: 0 = handle granted (audit/disabled, expect Event 1122)
//             1 = handle denied  (block,           expect Event 1121)
//             2 = lsass not found

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class PasAsrLsass
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;

    static int Main()
    {
        Console.WriteLine("[PAS][ASR] LSASS credential-theft rule test (9e6c4e1f). Benign: OpenProcess + CloseHandle, NO dump.");

        Process[] ps = Process.GetProcessesByName("lsass");
        if (ps.Length == 0)
        {
            Console.WriteLine("[PAS][ASR] lsass.exe not found.");
            return 2;
        }

        uint pid = (uint)ps[0].Id;
        uint access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
        Console.WriteLine("[PAS][ASR] Requesting handle to lsass PID " + pid +
                          " access=0x" + access.ToString("X") + " (VM_READ|QUERY_INFORMATION).");

        IntPtr h = OpenProcess(access, false, pid);
        if (h != IntPtr.Zero)
        {
            Console.WriteLine("[PAS][ASR] Handle GRANTED -> consistent with AUDIT/Disabled (expect Event 1122). Closing now; no read, no dump.");
            CloseHandle(h);
            return 0;
        }

        int err = Marshal.GetLastWin32Error();
        Console.WriteLine("[PAS][ASR] Handle DENIED (Win32Error=" + err + ") -> consistent with a BLOCK (expect Event 1121).");
        return 1;
    }
}
