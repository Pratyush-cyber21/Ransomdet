/*
===============================================================================
YARA RULES: RANSOMWARE SIGNATURES & CVE-2017-0144 ETERNALBLUE PATTERNS
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).
===============================================================================
*/

rule WannaCry_Ransom_Note_Artifacts
{
    meta:
        description = "Detects WannaCry ransom note text, payment demands, and threat actor identifiers"
        author = "Antigravity DFIR Lab"
        cve = "CVE-2017-0144"
        threat_actor = "Lazarus Group / APT38"

    strings:
        $note_header_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note_header_2 = "Lazarus Group / WannaCry Simulation" ascii wide nocase
        $btc_wallet    = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii wide
        $killswitch    = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii wide
        $cve_ref       = "CVE-2017-0144" ascii wide

    condition:
        2 of them
}

rule Suspicious_High_Entropy_Ciphertext
{
    meta:
        description = "Detects Fernet AES-CBC ciphertext headers and .locked extensions"
        author = "Antigravity DFIR Lab"

    strings:
        $fernet_magic = "gAAAAA" ascii wide
        $locked_ext   = ".locked" ascii wide

    condition:
        any of them
}

rule EternalBlue_Exploit_Markers
{
    meta:
        description = "Detects SMBv1 EternalBlue CVE-2017-0144 exploit payload artifacts and buffer patterns"
        reference = "MS17-010 / Shadow Brokers EternalBlue"

    strings:
        $smb_trans2 = "TRANSACTION2-OVERFLOW-SIMULATION" ascii wide
        $cve_tag    = "CVE-2017-0144-ETERNALBLUE" ascii wide
        $smb_magic  = "\xffSMB\x33"

    condition:
        any of them
}

rule In_Memory_Volatile_Artifacts
{
    meta:
        description = "Detects in-memory malware artifacts, mutexes, and volatile process keys"

    strings:
        $mutex_marker = "Global\\MsWinZonesCacheCounterMutexA" ascii wide
        $dropper_proc = "mssecsvc.exe" ascii wide
        $enc_key_tag  = "LIVE_ENCRYPTION_KEY=" ascii wide

    condition:
        any of them
}
