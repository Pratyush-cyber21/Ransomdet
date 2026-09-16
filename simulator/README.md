# Harmless Ransomware Simulator (`simulator/`)

## Educational Scope & Safety Disclaimer
This directory contains a harmless, non-malicious educational simulator designed exclusively for digital forensics and incident response training. It replicates the behavior of ransomware attacks at a safe, self-contained scale to allow forensic layer analysis (Detection, Acquisition, Analysis, Correlation, and Reporting).

### Safety Controls & Hard Constraints
1. **Directory Isolation**: The script enforces a hard path validation step. It will ONLY execute against files inside the designated `sandbox/` directory within the project folder.
2. **Safe Encryption**: The encryption uses standard AES-Fernet cryptography, and the decryption key is immediately written in **plaintext** to `sandbox/decryption_key.log`.
3. **Synthetic Targets**: The script populates its own dummy files (`.csv`, `.docx`, `.json`, `.txt`) inside `sandbox/` prior to encryption. It does not access or modify any personal or system files.
4. **Loopback-Only Network Beacon**: C2 communication attempts are hardcoded to `127.0.0.1:4444` (IPv4 loopback). No external IPs or hostnames are ever contacted.
5. **No Exploits / No Persistence**: Contains zero exploit code (no EternalBlue, SMB RCE, etc.), no authority escalation, and no persistence mechanisms (registry keys, crons, systemd services).

## Execution Instructions

```bash
python3 simulator/ransomware_sim.py
```

### Artifacts Produced in `sandbox/`:
- `financial_q4.csv.locked`
- `project_roadmap.docx.locked`
- `confidential_keys.json.locked`
- `employee_roster.txt.locked`
- `decryption_key.log` (Plaintext recovery key)
- `READ_ME_RANSOM.txt` (Harmless ransom note)
