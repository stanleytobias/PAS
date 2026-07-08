// PAS ASR native trigger - single self-contained executable
//
// For hosts where GPO blocks scripts (Windows Script Host disabled, or AppLocker
// script rules) but still allows executables. Covers the 5 ASR rules that can be
// triggered by a native process. The other 2 rules (obfuscated scripts 5beb7efe,
// JS/VBScript launching downloaded exe d3e037e1) detect a script running through a
// script engine, so they cannot be exercised by an exe on a script-blocked host.
//
// Build (any machine with .NET Framework, no Visual Studio):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo ^
//     /out:asr_trigger.exe /r:System.Management.dll asr_trigger.cs
//
// Usage (isolated lab VM; elevated for lsass/persist):
//   asr_trigger.exe [wmi|lsass|persist|copytool|untrusted|all]   (default: all)
// Or rename/copy the exe to asr_<rule>.exe and double-click it: a copy named
//   asr_wmi.exe runs "wmi", asr_lsass.exe runs "lsass", etc. (filename = command).
//
// Output goes to the console AND %TEMP%\pas_asr_trigger.log so double-click users
// keep the results after the window closes. It only TRIGGERS behaviors and reads
// events; it does not enable ASR rules (that needs admin/Intune - see docs).

using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;

class AsrTrigger
{
    const string G_WMI       = "d1e49aac-8f56-4280-b9ba-993a6d77406c";
    const string G_LSASS     = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";
    const string G_PERSIST   = "e6db77e5-3df2-4cf1-b95a-636979351e5b";
    const string G_COPYTOOL  = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb";
    const string G_UNTRUSTED = "01443614-cd74-433a-b99e-2ecdc07bfc25";

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    static string _log;

    static int Main(string[] args)
    {
        string cmd;
        if (args.Length > 0)
        {
            cmd = args[0].ToLowerInvariant();
        }
        else
        {
            // No args (e.g. double-clicked): derive the command from the exe's own
            // filename, so a renamed copy asr_wmi.exe runs "wmi", asr_lsass.exe runs
            // "lsass", etc. asr_trigger.exe (or any unrecognized name) runs "all".
            string me = Path.GetFileNameWithoutExtension(
                Process.GetCurrentProcess().MainModule.FileName).ToLowerInvariant();
            if (me.StartsWith("asr_")) me = me.Substring(4);
            string[] known = { "wmi", "lsass", "persist", "copytool", "untrusted", "all" };
            cmd = Array.IndexOf(known, me) >= 0 ? me : "all";
        }
        if (cmd == "noop") return 0;   // used by the untrusted-exe child; must exit fast

        _log = Path.Combine(Path.GetTempPath(), "pas_asr_trigger.log");
        try { File.WriteAllText(_log, "PAS ASR trigger " + DateTime.Now + Environment.NewLine); } catch { }

        Out("=== PAS ASR native trigger (exe) ===");
        Out("Log: " + _log);
        Preflight();

        switch (cmd)
        {
            case "wmi":       Wmi();       break;
            case "lsass":     Lsass();     break;
            case "persist":   Persist();   break;
            case "copytool":  CopyTool();  break;
            case "untrusted": Untrusted(); break;
            case "all":       Wmi(); Lsass(); Persist(); CopyTool(); Untrusted(); break;
            default:
                Out("usage: asr_trigger.exe [wmi|lsass|persist|copytool|untrusted|all]");
                return 2;
        }

        System.Threading.Thread.Sleep(3000);
        Postflight();

        if (!Console.IsOutputRedirected)
        {
            Console.Write("\nPress Enter to exit...");
            Console.ReadLine();
        }
        return 0;
    }

    static void Out(string s)
    {
        Console.WriteLine(s);
        try { File.AppendAllText(_log, s + Environment.NewLine); } catch { }
    }

    static string ActName(object a)
    {
        if (a == null) return "?";
        try
        {
            switch (Convert.ToInt32(a))
            {
                case 0: return "Disabled";
                case 1: return "Block";
                case 2: return "Audit";
                case 6: return "Warn";
                default: return a.ToString();
            }
        }
        catch { return a.ToString(); }
    }

    static void Preflight()
    {
        Out("\n--- preflight (Defender + ASR config) ---");
        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
            scope.Connect();

            foreach (ManagementObject o in new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT AMRunningMode,RealTimeProtectionEnabled FROM MSFT_MpComputerStatus")).Get())
            {
                Out("[preflight] AMRunningMode=" + o["AMRunningMode"] + " RTP=" + o["RealTimeProtectionEnabled"]
                    + "  (must be Normal + True for ASR to enforce)");
            }

            foreach (ManagementObject o in new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference")).Get())
            {
                var ids  = o["AttackSurfaceReductionRules_Ids"] as string[];
                var acts = o["AttackSurfaceReductionRules_Actions"] as Array;
                if (ids == null || ids.Length == 0)
                {
                    Out("[preflight] No ASR rules configured -> nothing will fire. Enable a rule first (admin/Intune).");
                }
                else
                {
                    for (int i = 0; i < ids.Length; i++)
                    {
                        object a = (acts != null && i < acts.Length) ? acts.GetValue(i) : null;
                        Out("[preflight] " + ids[i] + " = " + ActName(a));
                    }
                }
            }
        }
        catch (Exception e) { Out("[preflight] could not read Defender config: " + e.Message); }
    }

    static void Wmi()
    {
        Out("\n=== [wmi] " + G_WMI + " (PsExec/WMI child process) ===");
        try
        {
            var mc = new ManagementClass("Win32_Process");
            var inParams = mc.GetMethodParameters("Create");
            inParams["CommandLine"] = "cmd.exe /c exit";
            var outParams = mc.InvokeMethod("Create", inParams, null);
            uint rv = Convert.ToUInt32(outParams["ReturnValue"]);
            Out(rv == 0
                ? "[wmi] Create OK (ReturnValue=0) -> ran; Audit/Disabled => Event 1122"
                : "[wmi] Create ReturnValue=" + rv + " (non-zero) -> consistent with a BLOCK (Event 1121)");
        }
        catch (Exception e) { Out("[wmi] threw: " + e.Message + "  (a block can surface as an exception)"); }
    }

    static void Lsass()
    {
        Out("\n=== [lsass] " + G_LSASS + " (credential theft) ===");
        var ps = Process.GetProcessesByName("lsass");
        if (ps.Length == 0) { Out("[lsass] lsass not found"); return; }
        uint access = 0x0010 | 0x0400;   // PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        IntPtr h = OpenProcess(access, false, (uint)ps[0].Id);
        if (h != IntPtr.Zero)
        {
            Out("[lsass] handle GRANTED -> Audit/Disabled => Event 1122. Closing now (no read, no dump).");
            CloseHandle(h);
        }
        else
        {
            Out("[lsass] handle DENIED (Win32Error=" + Marshal.GetLastWin32Error()
                + ") -> a BLOCK (Event 1121), OR you are not elevated (the OS ACL denies lsass to non-admins).");
        }
    }

    static void Persist()
    {
        Out("\n=== [persist] " + G_PERSIST + " (WMI event subscription; needs admin) ===");
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            var filter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null).CreateInstance();
            filter["Name"] = "PAS_ASR_Filter";
            filter["EventNamespace"] = @"root\cimv2";
            filter["QueryLanguage"] = "WQL";
            filter["Query"] = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 99";
            filter.Put();

            var cons = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null).CreateInstance();
            cons["Name"] = "PAS_ASR_Consumer";
            cons["CommandLineTemplate"] = "calc.exe";
            cons.Put();

            var bind = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();
            bind["Filter"] = "__EventFilter.Name=\"PAS_ASR_Filter\"";
            bind["Consumer"] = "CommandLineEventConsumer.Name=\"PAS_ASR_Consumer\"";
            bind.Put();

            Out("[persist] subscription registered (non-firing) -> Audit => Event 1122. Cleaning up.");
        }
        catch (Exception e) { Out("[persist] threw: " + e.Message + "  (a BLOCK => Event 1121, or you are not elevated)"); }
        finally { PersistCleanup(); }
    }

    static void PersistCleanup()
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            string[] queries = {
                "SELECT * FROM __FilterToConsumerBinding",
                "SELECT * FROM CommandLineEventConsumer WHERE Name='PAS_ASR_Consumer'",
                "SELECT * FROM __EventFilter WHERE Name='PAS_ASR_Filter'"
            };
            foreach (string q in queries)
            {
                foreach (ManagementObject o in new ManagementObjectSearcher(scope, new ObjectQuery(q)).Get())
                {
                    try
                    {
                        if (q.IndexOf("Binding", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            string c = o["Consumer"] as string, f = o["Filter"] as string;
                            if ((c != null && c.IndexOf("PAS_ASR_Consumer") >= 0) ||
                                (f != null && f.IndexOf("PAS_ASR_Filter") >= 0)) o.Delete();
                        }
                        else o.Delete();
                    }
                    catch { }
                }
            }
            Out("[persist] cleanup done (filter/consumer/binding removed if present).");
        }
        catch { }
    }

    static void CopyTool()
    {
        Out("\n=== [copytool] " + G_COPYTOOL + " (copied/impersonated system tool) ===");
        string dst = Path.Combine(Path.GetTempPath(), "svchost.exe");
        try
        {
            File.Copy(Path.Combine(Environment.SystemDirectory, "hostname.exe"), dst, true);
            var p = Process.Start(new ProcessStartInfo { FileName = dst, UseShellExecute = false, CreateNoWindow = true });
            if (p != null) p.WaitForExit(5000);
            Out("[copytool] ran hostname.exe as svchost.exe from TEMP -> Audit/Disabled => Event 1122.");
        }
        catch (Exception e) { Out("[copytool] blocked/threw: " + e.Message + " -> possible BLOCK (Event 1121)"); }
        finally { try { File.Delete(dst); } catch { } }
    }

    static void Untrusted()
    {
        Out("\n=== [untrusted] " + G_UNTRUSTED + " (low-prevalence exe; needs cloud protection) ===");
        string self = Process.GetCurrentProcess().MainModule.FileName;
        string dst = Path.Combine(Path.GetTempPath(),
            "pas_novel_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".exe");
        try
        {
            File.Copy(self, dst, true);
            // Append random bytes as a PE overlay: unique hash (novel/low-prevalence), still runs.
            byte[] rnd = new byte[512];
            new Random().NextBytes(rnd);
            using (var fs = new FileStream(dst, FileMode.Append)) fs.Write(rnd, 0, rnd.Length);

            var p = Process.Start(new ProcessStartInfo { FileName = dst, Arguments = "noop", UseShellExecute = false, CreateNoWindow = true });
            if (p != null) p.WaitForExit(5000);
            Out("[untrusted] ran a novel-hash exe -> Audit => Event 1122 / Block => Event 1121 (only with cloud protection on).");
        }
        catch (Exception e) { Out("[untrusted] blocked/threw: " + e.Message + " -> possible BLOCK (Event 1121)"); }
        finally { try { File.Delete(dst); } catch { } }
    }

    static void Postflight()
    {
        Out("\n--- postflight: Defender ASR events (1121=block, 1122=audit), last 5 min ---");
        try
        {
            string xpath = "*[System[(EventID=1121 or EventID=1122) and TimeCreated[timediff(@SystemTime)<=300000]]]";
            var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, xpath);
            query.ReverseDirection = true;
            int n = 0;
            using (var reader = new EventLogReader(query))
            {
                EventRecord rec;
                while ((rec = reader.ReadEvent()) != null && n < 10)
                {
                    string kind = rec.Id == 1121 ? "BLOCKED 1121" : "AUDITED 1122";
                    Out("[" + kind + "] " + rec.TimeCreated + " : " + FirstLine(rec.FormatDescription()));
                    n++;
                }
            }
            if (n == 0)
                Out("[postflight] no 1121/1122 in last 5 min (rule off, behavior did not match, or not yet flushed).");
        }
        catch (UnauthorizedAccessException)
        {
            Out("[postflight] access denied reading the Defender log (run elevated), OR verify in MDE: DeviceEvents | where ActionType startswith 'Asr'");
        }
        catch (EventLogException e)
        {
            Out("[postflight] can't read the Defender log (" + e.Message + "). Verify in MDE: DeviceEvents | where ActionType startswith 'Asr'");
        }
        catch (Exception e) { Out("[postflight] " + e.Message); }
    }

    static string FirstLine(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        int i = s.IndexOfAny(new[] { '\r', '\n' });
        return i < 0 ? s : s.Substring(0, i);
    }
}
