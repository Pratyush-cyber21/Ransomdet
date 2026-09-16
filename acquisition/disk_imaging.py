#!/usr/bin/env python3
"""
===============================================================================
LAYER 2: ACQUISITION - FORENSIC DISK IMAGING & EVIDENCE PRESERVATION
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module creates a SHA-256 hash-preserved forensic image of the `sandbox/` folder.
===============================================================================
"""

import os
import shutil
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (ACQUISITION) %(message)s"
)
logger = logging.getLogger("DiskImaging")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_DIR = PROJECT_ROOT / "sandbox"
EVIDENCE_DIR = PROJECT_ROOT / "acquisition" / "evidence_disk_image"
MANIFEST_FILE = PROJECT_ROOT / "acquisition" / "disk_manifest.json"

def calculate_sha256(filepath):
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def acquire_forensic_disk_image():
    """Copy sandbox files to evidence folder and compute cryptographic hashes."""
    logger.info("Starting forensic disk imaging & evidence acquisition...")
    
    if EVIDENCE_DIR.exists():
        shutil.rmtree(EVIDENCE_DIR)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "source_directory": str(SANDBOX_DIR),
        "target_image_directory": str(EVIDENCE_DIR),
        "total_files_acquired": 0,
        "files": []
    }

    if not SANDBOX_DIR.exists():
        logger.warning("Sandbox directory empty or missing during acquisition.")
        return manifest

    acquired_count = 0
    for src_file in SANDBOX_DIR.glob("*"):
        if src_file.is_file():
            dst_file = EVIDENCE_DIR / src_file.name
            shutil.copy2(src_file, dst_file)
            
            file_hash = calculate_sha256(dst_file)
            file_entry = {
                "filename": src_file.name,
                "size_bytes": src_file.stat().st_size,
                "sha256": file_hash,
                "acquisition_time": datetime.now().isoformat()
            }
            manifest["files"].append(file_entry)
            acquired_count += 1
            logger.info(f"  + Imaged {src_file.name} | SHA-256: {file_hash[:16]}...")

    manifest["total_files_acquired"] = acquired_count

    with open(MANIFEST_FILE, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    logger.info(f"Forensic imaging complete. {acquired_count} files acquired. Manifest saved to {MANIFEST_FILE.name}")
    return manifest

if __name__ == "__main__":
    acquire_forensic_disk_image()
