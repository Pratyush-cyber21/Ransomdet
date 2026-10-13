#!/usr/bin/env python3
"""
===============================================================================
EDUCATIONAL RANSOMWARE SIMULATOR (CVE-2017-0144 & WANNACRY REPLICATION)
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

SAFETY & HARD CONSTRAINTS DISCLAIMER:
- This script is an educational simulation for digital forensics coursework.
- It operates strictly inside the designated local `sandbox/` directory.
- It generates synthetic dummy files and encrypts ONLY those dummy files.
- The symmetric encryption key is saved in PLAINTEXT to `sandbox/decryption_key.log`.
- Creates a volatile memory image buffer in `sandbox/volatile_memory.raw`.
- Simulates CVE-2017-0144 EternalBlue SMBv1 probe on loopback (127.0.0.1:445).
- Simulates WannaCry killswitch domain resolution attempt.
- Beacons exclusively to loopback C2 listener (127.0.0.1:4444).
- NO real exploit code, NO weaponized payloads, NO cross-contamination.
===============================================================================
"""

import os
import sys
import time
import math
import socket
import logging
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (SIMULATOR) %(message)s"
)
logger = logging.getLogger("RansomwareSimulator")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_DIR = PROJECT_ROOT / "sandbox"

MOCK_C2_HOST = "127.0.0.1"
MOCK_C2_PORT = 4444
SMB_PROBE_HOST = "127.0.0.1"
SMB_PROBE_PORT = 445
WANNACRY_KILLSWITCH_DOMAIN = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"

RANSOM_NOTE_NAME = "READ_ME_RANSOM.txt"
WANNACRY_NOTE_NAME = "@Please_Read_Me@.txt"

RANSOM_NOTE_CONTENT = f"""
===============================================================================
!!! YOUR FILES HAVE BEEN ENCRYPTED (SIMULATED RANSOMWARE INCIDENT) !!!
===============================================================================
Threat Actor Attribution: Lazarus Group / WannaCry Simulation (Patil et al. 2024)
Exploitation Vector: CVE-2017-0144 (EternalBlue / SMBv1 Remote Code Execution)
Kill-Switch Query: {WANNACRY_KILLSWITCH_DOMAIN}

All critical corporate and hospital files in this environment have been locked
using AES-Fernet cryptography. To restore your data, contact the operators.

Simulated Payment Target: 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
Demanded Amount: $300 in Bitcoin (BTC)

SAFETY NOTICE (FORENSICS LAB):
- Decryption Key is safely preserved in: sandbox/decryption_key.log
- Volatile memory buffer is saved in: sandbox/volatile_memory.raw
- No external systems or production data were affected.
===============================================================================
"""

DUMMY_FILES = {
    "financial_q4.csv": "Quarter,Revenue,Expenses,NetProfit\nQ1,120000,75000,45000\nQ2,135000,80000,55000\nQ3,160000,92000,68000\nQ4,210000,105000,105000\nTotal,625000,352000,273000",
    "project_roadmap.docx": "Ransomdet Engineering Specification\nPhase 1: Detection & EDR\nPhase 2: Acquisition & PCAP\nPhase 3: Analysis & YARA\nPhase 4: CTI Correlation\nPhase 5: Reporting",
    "confidential_keys.json": '{\n  "environment": "production",\n  "api_token": "mock-sec-tok-9841-f8a12",\n  "db_auth": "internal_vault_secret",\n  "compliance": "GDPR-Article-33"\n}',
    "employee_roster.txt": "EMP_ID,FULL_NAME,DEPARTMENT,CLEARANCE\n101,Alice Smith,Digital Forensics,Level-3\n102,Bob Jones,SOC Analyst,Level-2\n103,Dr. Patil,Chief Investigator,Level-5",
    "patient_records.xml": '<?xml version="1.0"?>\n<hospital_db>\n  <patient id="701"><name>John Doe</name><diagnosis>Cardiovascular Monitoring</diagnosis><ward>ICU-B</ward></patient>\n  <patient id="702"><name>Jane Roe</name><diagnosis>Endovascular Screening</diagnosis><ward>Ward-4</ward></patient>\n</hospital_db>',
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy of given byte stream (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def verify_safety_sandbox():
    """Verify target sandbox directory is strictly inside project root."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    resolved_sandbox = SANDBOX_DIR.resolve()
    resolved_root = PROJECT_ROOT.resolve()
    if not str(resolved_sandbox).startswith(str(resolved_root)) or "sandbox" not in resolved_sandbox.name:
        logger.error(f"SAFETY VIOLATION: Sandbox path {resolved_sandbox} is invalid or outside project root!")
        sys.exit(1)
    logger.info(f"Safety check verified. Sandbox environment: {resolved_sandbox}")

def populate_dummy_files():
    """Create initial dummy test files inside sandbox directory."""
    logger.info("Populating initial baseline dummy files into sandbox...")
    for filename, content in DUMMY_FILES.items():
        filepath = SANDBOX_DIR / filename
        data = content.encode("utf-8")
        entropy = calculate_shannon_entropy(data)
        with open(filepath, "wb") as f:
            f.write(data)
        logger.info(f"  + Created baseline file: {filename} (Size: {len(data)} B, Plaintext Entropy: {entropy:.2f})")

def perform_harmless_encryption():
    """Generate key, encrypt dummy files, log key, drop ransom note, create RAM buffer."""
    key = Fernet.generate_key()
    key_log_path = SANDBOX_DIR / "decryption_key.log"
    with open(key_log_path, "wb") as kf:
        kf.write(key)
    logger.info(f"Generated encryption key: {key.decode()} (Logged to {key_log_path.name})")

    cipher = Fernet(key)

    # Encrypt each dummy file
    for filename in DUMMY_FILES.keys():
        filepath = SANDBOX_DIR / filename
        if filepath.exists():
            with open(filepath, "rb") as f:
                data = f.read()
            pre_entropy = calculate_shannon_entropy(data)
            encrypted_data = cipher.encrypt(data)
            post_entropy = calculate_shannon_entropy(encrypted_data)

            locked_filepath = SANDBOX_DIR / f"{filename}.locked"
            with open(locked_filepath, "wb") as lf:
                lf.write(encrypted_data)
            os.remove(filepath)
            logger.info(f"  * Encrypted {filename} -> {locked_filepath.name} (Entropy: {pre_entropy:.2f} -> {post_entropy:.2f})")

    # Drop primary and WannaCry alias ransom notes
    for note_name in [RANSOM_NOTE_NAME, WANNACRY_NOTE_NAME]:
        note_path = SANDBOX_DIR / note_name
        with open(note_path, "w", encoding="utf-8") as nf:
            nf.write(RANSOM_NOTE_CONTENT)
        logger.info(f"  ! Dropped ransom note: {note_name}")

    # Generate volatile process memory buffer (simulating RAM state before scrubbing)
    mem_path = SANDBOX_DIR / "volatile_memory.raw"
    mem_header = b"\x50\x45\x00\x00\x4c\x01\x03\x00" # Simulated PE header
    mem_strings = (
        f"PID=2384 PROCESS=mssecsvc.exe PARENT_PID=1024\n"
        f"MUTEX=Global\\MsWinZonesCacheCounterMutexA\n"
        f"EXPLOIT=CVE-2017-0144 EternalBlue SMBv1 Buffer\n"
        f"KILLSWITCH={WANNACRY_KILLSWITCH_DOMAIN}\n"
        f"LIVE_ENCRYPTION_KEY={key.decode()}\n"
        f"CIPHER_ALGORITHM=AES-CBC-256/Fernet\n"
        f"TARGET_DIR={SANDBOX_DIR.resolve()}\n"
    ).encode("utf-8")
    padding = b"\x00" * 4096
    with open(mem_path, "wb") as mf:
        mf.write(mem_header + mem_strings + padding)
    logger.info(f"Created simulated volatile memory dump: {mem_path.name} (Contains in-memory key schedule)")

def attempt_smb_and_killswitch_probes():
    """Simulate CVE-2017-0144 SMBv1 probe and killswitch domain lookup."""
    # 1. Kill-switch domain resolution attempt (expected to fail / NXDOMAIN in offline lab)
    logger.info(f"Querying simulated kill-switch domain: {WANNACRY_KILLSWITCH_DOMAIN}")
    try:
        socket.gethostbyname(WANNACRY_KILLSWITCH_DOMAIN)
        logger.info("  > Killswitch resolved (Sinkhole detected).")
    except socket.gaierror:
        logger.info("  > Killswitch query failed (Domain unregistered -> Infection proceeds).")
    except Exception as e:
        logger.info(f"  > Killswitch resolution exception: {e}")

    # 2. SMBv1 Port 445 probe (EternalBlue lateral spread simulation)
    logger.info(f"Attempting simulated SMBv1 probe to {SMB_PROBE_HOST}:{SMB_PROBE_PORT} (CVE-2017-0144)...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((SMB_PROBE_HOST, SMB_PROBE_PORT))
        # Simulated SMB Negotiate Protocol request packet
        smb_negotiate = b"\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x18\x01\x28\x00\x00"
        s.sendall(smb_negotiate)
        s.close()
        logger.info("  > SMBv1 probe packet sent successfully.")
    except Exception as e:
        logger.info(f"  > SMBv1 probe attempted (Loopback port 445 offline, normal in lab): {e}")

def attempt_mock_c2_beacon():
    """Attempt a harmless TCP beacon connection to local loopback (127.0.0.1:4444)."""
    logger.info(f"Initiating mock C2 beacon to loopback ({MOCK_C2_HOST}:{MOCK_C2_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((MOCK_C2_HOST, MOCK_C2_PORT))
        beacon_msg = b"HELO C2_MOCK_BEACON_BEHAVIOR_RANSOM_SIM\n"
        s.sendall(beacon_msg)
        logger.info("  > Mock C2 connection established and beacon sent successfully.")
        s.close()
    except Exception as e:
        logger.info(f"  > Mock C2 beacon attempted ({MOCK_C2_HOST}:{MOCK_C2_PORT}): {e}")

def run_simulation():
    """Main execution flow for harmless ransomware simulator."""
    logger.info("=========================================================")
    logger.info("STARTING HARMLESS EDUCATIONAL RANSOMWARE SIMULATOR")
    logger.info("Replicating: CVE-2017-0144 EternalBlue & WannaCry Flow")
    logger.info("=========================================================")
    verify_safety_sandbox()
    populate_dummy_files()
    time.sleep(0.5)
    perform_harmless_encryption()
    time.sleep(0.5)
    attempt_smb_and_killswitch_probes()
    attempt_mock_c2_beacon()
    logger.info("=========================================================")
    logger.info("SIMULATION COMPLETE - ALL ARTIFACTS CONTAINED IN SANDBOX")
    logger.info("=========================================================")

if __name__ == "__main__":
    run_simulation()
