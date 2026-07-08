// PAS ASR native test - Block execution of potentially obfuscated scripts (5beb7efe)
//
// Benign but heavily obfuscated JScript. Windows Script Host is AMSI-integrated,
// so an obfuscated .js run by cscript is scanned by the same engine that backs
// this ASR rule. Deobfuscates to a harmless WScript.Echo.
//
// NOTE: this rule is heuristic (AMSI scores obfuscation), so it may not fire on
// every payload or build. A "no event" here is not proof the rule is off.
//
// Usage:  cscript //nologo asr_obfuscated_script.js

var _p = ["\x57\x53\x63\x72\x69\x70\x74", "\x45\x63\x68\x6f"];   // "WScript","Echo"
var _c = [80, 65, 83, 45, 79, 66, 70, 85, 83, 67, 45, 74, 83];   // "PAS-OBFUSC-JS"
var _s = "";
for (var _i = 0; _i < _c.length; _i++) { _s += String["fromCharCode"](_c[_i]); }
var _f = this[_p[0]][_p[1]];
_f("[PAS][ASR] Obfuscated JScript executed (5beb7efe) -> decoded marker: " + _s);
_f("[PAS][ASR] If this ran, the rule is Audit/Disabled (expect Event 1122). A block prevents execution (Event 1121).");
