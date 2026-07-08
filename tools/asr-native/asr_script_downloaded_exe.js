// PAS ASR native test - Block JS/VBScript from launching downloaded executable content (d3e037e1)
//
// A .js that uses WScript.Shell.Run to launch an executable that carries a
// Mark-of-the-Web (Zone.Identifier = 3, "Internet"). run_asr_tests.cmd stages a
// benign MOTW-tagged copy of hostname.exe at %TEMP%\pas_dl.exe before calling this.
//
// Usage (staged by run_asr_tests.cmd):  cscript //nologo asr_script_downloaded_exe.js

var sh  = new ActiveXObject("WScript.Shell");
var tmp = sh.Environment("Process")("TEMP");
var exe = tmp + "\\pas_dl.exe";

WScript.Echo("[PAS][ASR] JScript launching downloaded (MOTW) executable: " + exe);
try {
    var rc = sh.Run('"' + exe + '"', 0, true);
    WScript.Echo("[PAS][ASR] Launch returned " + rc + " -> it ran (Audit/Disabled, expect Event 1122).");
} catch (e) {
    WScript.Echo("[PAS][ASR] Launch raised error 0x" + (e.number >>> 0).toString(16) + " -> consistent with a BLOCK (expect Event 1121).");
}
