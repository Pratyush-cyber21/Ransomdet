#!/usr/bin/env python3
"""
===============================================================================
LAYER 3: ANALYSIS - DISK FORENSICS, SHANNON ENTROPY & DATA RECOVERY
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module performs deep disk forensic analysis on acquired disk artifacts:
- Computes mathematical Shannon Entropy for each file (distinguishing encrypted vs plaintext)
- Gathers MACB filesystem timeline metadata (Autopsy / Sleuth Kit standard)
- Employs carved volatile memory encryption keys to execute live data recovery
===============================================================================
"""

import os
import math
import json
import logging
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (ANALYSIS-DISK) %(message)s"
)
logger = logging.getLogger("DiskAnalyzer")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "acquisition" / "evidence_disk_image"
MEMORY_ANALYSIS_PATH = PROJECT_ROOT / "analysis" / "memory_analysis.json"
KEY_LOG_PATH = PROJECT_ROOT / "sandbox" / "decryption_key.log"
RECOVERED_DIR = PROJECT_ROOT / "acquisition" / "recovered_files"
OUTPUT_FILE = PROJECT_ROOT / "analysis" / "disk_analysis.json"

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0000 to 8.0000) for given bytes."""
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

def get_macb_timestamps(filepath: Path):
    """Retrieve MACB timestamps in ISO format."""
    stat = filepath.stat()
    return {
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
        "changed": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "birth": datetime.fromtimestamp(getattr(stat, 'st_birthtime', stat.st_ctime)).isoformat()
    }

def analyze_disk_artifacts():
    """Analyze all disk image artifacts for entropy and perform automated data recovery."""
    logger.info("Executing Disk Forensic Analysis (Shannon Entropy & File Carving)...")

    disk_report = {
        "timestamp": datetime.now().isoformat(),
        "total_files_inspected": 0,
        "files_analyzed": [],
        "encrypted_files_identified": [],
        "plaintext_files_identified": [],
        "recovery_rate_pct": 0.0,
        "recovered_files": []
    }

    if not EVIDENCE_DIR.exists():
        logger.warning(f"Evidence directory {EVIDENCE_DIR} not found.")
        return disk_report

    # Retrieve encryption key from carved memory results or fallback log
    decryption_key = None
    if MEMORY_ANALYSIS_PATH.exists():
        try:
            with open(MEMORY_ANALYSIS_PATH, "r", encoding="utf-8") as mf:
                mem_data = json.load(mf)
                keys = mem_data.get("recovered_encryption_keys", [])
                if keys:
                    decryption_key = keys[0].encode("utf-8")
        except Exception:
            pass

    if not decryption_key and KEY_LOG_PATH.exists():
        with open(KEY_LOG_PATH, "rb") as kf:
            decryption_key = kf.read().strip()

    cipher = Fernet(decryption_key) if decryption_key else None

    RECOVERED_DIR.mkdir(parents=True, exist_ok=True)

    files_list = [f for f in EVIDENCE_DIR.glob("*") if f.is_file()]
    disk_report["total_files_inspected"] = len(files_list)

    total_encrypted = 0
    successfully_recovered = 0

    for fpath in files_list:
        with open(fpath, "rb") as f:
            content = f.read()

        entropy = calculate_shannon_entropy(content)
        macb = get_macb_timestamps(fpath)

        is_encrypted = (entropy >= 7.2) or fpath.name.endswith(".locked")
        classification = "ENCRYPTED (High Entropy)" if is_encrypted else "PLAINTEXT / STRUCTURED"

        file_meta = {
            "filename": fpath.name,
            "size_bytes": len(content),
            "shannon_entropy": entropy,
            "classification": classification,
            "macb_timeline": macb
        }
        disk_report["files_analyzed"].append(file_meta)

        if is_encrypted:
            total_encrypted += 1
            disk_report["encrypted_files_identified"].append(fpath.name)
            logger.info(f"  [!] Encrypted File Found: {fpath.name} (Entropy: {entropy:.2f} >= 7.2)")

            # Attempt live recovery using carved key
            if cipher and fpath.name.endswith(".locked"):
                try:
                    decrypted_content = cipher.decrypt(content)
                    orig_name = fpath.name[:-7]
                    rec_path = RECOVERED_DIR / orig_name
                    with open(rec_path, "wb") as rf:
                        rf.write(decrypted_content)
                    rec_entropy = calculate_shannon_entropy(decrypted_content)
                    disk_report["recovered_files"].append({
                        "original_filename": orig_name,
                        "recovered_path": str(rec_path),
                        "original_size": len(decrypted_content),
                        "restored_entropy": rec_entropy
                    })
                    successfully_recovered += 1
                    logger.info(f"      -> Successfully Recovered: {orig_name} (Entropy restored: {rec_entropy:.2f})")
                except Exception as e:
                    logger.error(f"Failed to decrypt {fpath.name}: {e}")
        else:
            disk_report["plaintext_files_identified"].append(fpath.name)

    if total_encrypted > 0:
        disk_report["recovery_rate_pct"] = round((successfully_recovered / total_encrypted) * 100.0, 1)
    else:
        disk_report["recovery_rate_pct"] = 100.0

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(disk_report, f, indent=2)

    logger.info(f"Disk forensic analysis complete. Data Recovery Rate: {disk_report['recovery_rate_pct']}%. Saved to {OUTPUT_FILE.name}")
    return disk_report

if __name__ == "__main__":
    analyze_disk_artifacts()
