#!/usr/bin/env python3
"""
===============================================================================
EDUCATIONAL RANSOMWARE SIMULATOR (HARMLESS DEMONSTRATION)
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

SAFETY & HARD CONSTRAINTS DISCLAIMER:
- This script is purely an educational simulation for digital forensics labs.
- It is strictly restricted to operating inside the designated local `sandbox/` directory.
- It generates synthetic dummy files and encrypts ONLY those dummy files.
- The symmetric encryption key is saved in PLAINTEXT to `sandbox/decryption_key.log`.
- Network activity is strictly limited to a single TCP beacon to loopback (127.0.0.1:4444).
- NO real exploit code, NO persistence, NO privilege escalation, NO external network calls.
===============================================================================
"""

import os
import sys
import time
import socket
import logging
from pathlib import Path
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (SIMULATOR) %(message)s"
)
logger = logging.getLogger("RansomwareSimulator")

# Enforce strict safety boundary check
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_DIR = PROJECT_ROOT / "sandbox"

MOCK_C2_HOST = "127.0.0.1"
MOCK_C2_PORT = 4444
RANSOM_NOTE_NAME = "READ_ME_RANSOM.txt"

RANSOM_NOTE_CONTENT = f"""
===============================================================================
!!! YOUR FILES HAVE BEEN ENCRYPTED (SIMULATED RANSOMWARE) !!!
===============================================================================
Threat ID: SIM-RANSOM-2024-CVE-MOCK
Attribution ID: MOCK_LOCKBIT_SIM_v1

This is a harmless educational simulation conducted for coursework forensics analysis.
All files in this sandbox folder have been encrypted using AES-Fernet symmetric encryption.

Recovery Information:
- Decryption Key is safely logged in plaintext at: sandbox/decryption_key.log
- C2 Communication Target: {MOCK_C2_HOST}:{MOCK_C2_PORT} (Loopback Only)

DO NOT PANIC: No external systems were harmed, and no data left your machine.
===============================================================================
"""

DUMMY_FILES = {
    "financial_q4.csv": "Quarter,Revenue,Expenses\nQ1,10000,5000\nQ2,12000,5500\nQ3,15000,6000\nQ4,20000,7000",
    "project_roadmap.docx": "Project Title: NextGen Forensics Lab\nMilestone 1: Detection\nMilestone 2: Acquisition\nMilestone 3: Analysis",
    "confidential_keys.json": '{"service": "api_gateway", "status": "active", "access": "internal_only"}',
    "employee_roster.txt": "ID,Name,Role\n101,Alice Smith,DFIR Analyst\n102,Bob Jones,SOC Lead",
}

def verify_safety_sandbox():
    """Verify target sandbox directory is strictly inside project root and safe."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    resolved_sandbox = SANDBOX_DIR.resolve()
    resolved_root = PROJECT_ROOT.resolve()
    
    if not str(resolved_sandbox).startswith(str(resolved_root)) or "sandbox" not in resolved_sandbox.name:
        logger.error(f"SAFETY VIOLATION: Sandbox path {resolved_sandbox} is invalid or outside project root!")
        sys.exit(1)
        
    logger.info(f"Safety check passed. Operating strictly inside sandbox: {resolved_sandbox}")

def populate_dummy_files():
    """Create initial dummy test files inside sandbox directory."""
    logger.info("Populating dummy test files into sandbox...")
    for filename, content in DUMMY_FILES.items():
        filepath = SANDBOX_DIR / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"  + Created dummy file: {filepath.name}")

def perform_harmless_encryption():
    """Generate key, encrypt dummy files, log key in plaintext, drop ransom note."""
    key = Fernet.generate_key()
    key_log_path = SANDBOX_DIR / "decryption_key.log"
    
    with open(key_log_path, "wb") as kf:
        kf.write(key)
    logger.info(f"Symmetric encryption key generated & logged in plaintext: {key_log_path.name}")
    
    cipher = Fernet(key)
    
    # Encrypt dummy files
    for filename in DUMMY_FILES.keys():
        filepath = SANDBOX_DIR / filename
        if filepath.exists():
            with open(filepath, "rb") as f:
                data = f.read()
            
            encrypted_data = cipher.encrypt(data)
            locked_filepath = SANDBOX_DIR / f"{filename}.locked"
            
            with open(locked_filepath, "wb") as lf:
                lf.write(encrypted_data)
                
            os.remove(filepath)
            logger.info(f"  * Encrypted {filename} -> {locked_filepath.name}")
            
    # Drop ransom note
    note_path = SANDBOX_DIR / RANSOM_NOTE_NAME
    with open(note_path, "w", encoding="utf-8") as nf:
        nf.write(RANSOM_NOTE_CONTENT)
    logger.info(f"  ! Dropped ransom note: {note_path.name}")

def attempt_mock_c2_beacon():
    """Attempt a harmless TCP beacon connection to local loopback (127.0.0.1:4444)."""
    logger.info(f"Initiating mock C2 beacon to loopback ({MOCK_C2_HOST}:{MOCK_C2_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((MOCK_C2_HOST, MOCK_C2_PORT))
        beacon_msg = b"HELO C2_MOCK_BEACON_BEHAVIOR_RANSOM_SIM\n"
        s.sendall(beacon_msg)
        logger.info("  > Mock C2 connection established and beacon sent successfully.")
        s.close()
    except Exception as e:
        logger.info(f"  > Mock C2 connection attempt completed (No listener active on {MOCK_C2_HOST}:{MOCK_C2_PORT}): {e}")

def run_simulation():
    """Main execution flow for harmless ransomware simulator."""
    logger.info("=========================================================")
    logger.info("STARTING HARMLESS EDUCATIONAL RANSOMWARE SIMULATOR")
    logger.info("=========================================================")
    
    verify_safety_sandbox()
    populate_dummy_files()
    time.sleep(1) # Short delay to mimic operational sequence
    perform_harmless_encryption()
    time.sleep(1)
    attempt_mock_c2_beacon()
    
    logger.info("=========================================================")
    logger.info("SIMULATION COMPLETE - ALL ARTIFACTS CONTAINED IN SANDBOX")
    logger.info("=========================================================")

if __name__ == "__main__":
    run_simulation()
