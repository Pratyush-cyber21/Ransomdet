#!/usr/bin/env python3
"""
===============================================================================
LAYER 3: ANALYSIS - YARA SCANNING & ARTIFACT STATIC ANALYSIS
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module scans acquired evidence disk artifacts against YARA signature rules.
===============================================================================
"""

import json
import logging
from pathlib import Path
from datetime import datetime

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (ANALYSIS) %(message)s"
)
logger = logging.getLogger("ForensicAnalysis")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
YARA_RULES_PATH = PROJECT_ROOT / "analysis" / "ransomware_rules.yar"
EVIDENCE_DIR = PROJECT_ROOT / "acquisition" / "evidence_disk_image"
OUTPUT_FILE = PROJECT_ROOT / "analysis" / "analysis_results.json"

def scan_evidence():
    """Scan acquired disk image files using YARA rules."""
    logger.info("Executing YARA malware signature & artifact analysis...")
    
    analysis_report = {
        "timestamp": datetime.now().isoformat(),
        "rules_file": str(YARA_RULES_PATH),
        "target_directory": str(EVIDENCE_DIR),
        "total_files_scanned": 0,
        "matched_artifacts": [],
        "extracted_iocs": {
            "hashes": [],
            "c2_addresses": ["127.0.0.1:4444"],
            "ransom_note_signatures": [],
            "threat_actor_attribution": "MOCK_LOCKBIT_SIM_v1"
        }
    }

    if not EVIDENCE_DIR.exists():
        logger.warning("Evidence directory missing during analysis step.")
        return analysis_report

    compiled_rules = None
    if HAVE_YARA and YARA_RULES_PATH.exists():
        try:
            compiled_rules = yara.compile(filepath=str(YARA_RULES_PATH))
            logger.info(f"YARA rules compiled successfully from {YARA_RULES_PATH.name}")
        except Exception as e:
            logger.error(f"YARA compilation error: {e}")

    scanned_count = 0
    for target_file in EVIDENCE_DIR.glob("*"):
        if target_file.is_file():
            scanned_count += 1
            matches_found = []
            
            if compiled_rules:
                try:
                    matches = compiled_rules.match(str(target_file))
                    matches_found = [m.rule for m in matches]
                except Exception as e:
                    logger.error(f"Error scanning {target_file.name}: {e}")
            else:
                # String fallback scanner
                with open(target_file, "rb") as tf:
                    content = tf.read().decode("latin1", errors="ignore")
                    if "YOUR FILES HAVE BEEN ENCRYPTED" in content or "MOCK_LOCKBIT_SIM" in content:
                        matches_found.append("Educational_Ransomware_Simulator_Artifacts")
                    if target_file.name.endswith(".locked") or "gAAAAA" in content:
                        matches_found.append("Suspicious_Locked_Extension")

            if matches_found:
                matched_entry = {
                    "filename": target_file.name,
                    "matched_yara_rules": matches_found,
                    "file_size": target_file.stat().st_size
                }
                analysis_report["matched_artifacts"].append(matched_entry)
                logger.info(f"  ! MATCH DETECTED [{target_file.name}]: {matches_found}")

                if "READ_ME_RANSOM" in target_file.name:
                    analysis_report["extracted_iocs"]["ransom_note_signatures"].append(target_file.name)

    analysis_report["total_files_scanned"] = scanned_count

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(analysis_report, f, indent=2)

    logger.info(f"Artifact analysis complete. Results saved to {OUTPUT_FILE.name}")
    return analysis_report

if __name__ == "__main__":
    scan_evidence()
