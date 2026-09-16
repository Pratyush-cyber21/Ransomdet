rule Educational_Ransomware_Simulator_Artifacts
{
    meta:
        description = "Detects harmless educational ransomware simulator artifacts and ransom notes"
        author = "Antigravity Forensic Framework"
        date = "2024-09-16"
        reference = "Base Paper: Patil et al. (2024)"

    strings:
        $ransom_note_title = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide
        $threat_id = "SIM-RANSOM-2024-CVE-MOCK" ascii wide
        $attribution_id = "MOCK_LOCKBIT_SIM_v1" ascii wide
        $c2_beacon_str = "127.0.0.1:4444" ascii wide
        $key_file_ref = "decryption_key.log" ascii wide

    condition:
        any of ($ransom_note_title, $threat_id, $attribution_id, $c2_beacon_str, $key_file_ref)
}

rule Suspicious_Locked_Extension
{
    meta:
        description = "Detects files with .locked extension or Fernet crypto header patterns"

    strings:
        $locked_ext = ".locked" ascii wide
        $fernet_hdr = "gAAAAA" ascii wide  // Common Fernet token base64 prefix

    condition:
        any of ($locked_ext, $fernet_hdr)
}
