#!/usr/bin/env python3
"""
===============================================================================
LAYER 1: DETECTION - SANDBOX ANOMALY MONITOR
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module monitors the `sandbox/` folder for typical ransomware behaviors:
- Burst file modification / creation / deletion events
- Detection of suspicious file extensions (e.g. `.locked`)
- Detection of ransom note creation (e.g. `READ_ME_RANSOM.txt`)
===============================================================================
"""

import os
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime

# Import watchdog if available, otherwise use polling watcher fallback
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except ImportError:
    HAVE_WATCHDOG = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (DETECTION) %(message)s"
)
logger = logging.getLogger("ForensicDetection")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_DIR = PROJECT_ROOT / "sandbox"
ALERT_OUTPUT_PATH = PROJECT_ROOT / "detection" / "detection_alert.json"

SUSPICIOUS_EXTENSIONS = {".locked", ".crypto", ".enc", ".ransom"}
KNOWN_RANSOM_NOTES = {"READ_ME_RANSOM.txt", "DECRYPT_FILES.txt", "RANSOM_NOTE.txt"}
BURST_THRESHOLD_FILES = 3

class DetectionEngine:
    def __init__(self, sandbox_path=SANDBOX_DIR):
        self.sandbox_path = Path(sandbox_path)
        self.alerts = []
        self.detected_anomalies = {
            "burst_activity_detected": False,
            "suspicious_extensions_found": [],
            "ransom_notes_found": [],
            "detection_timestamp": None,
            "total_events_logged": 0,
            "status": "CLEAN"
        }

    def scan_sandbox(self):
        """Perform a comprehensive state scan of the sandbox directory."""
        logger.info(f"Scanning directory for ransomware indicators: {self.sandbox_path}")
        if not self.sandbox_path.exists():
            logger.warning("Sandbox directory does not exist yet.")
            return self.detected_anomalies

        files = list(self.sandbox_path.glob("*"))
        locked_files = []
        ransom_notes = []
        modified_recently_count = 0
        now = time.time()

        for f in files:
            if f.is_file():
                # Check for suspicious extensions
                if f.suffix in SUSPICIOUS_EXTENSIONS:
                    locked_files.append(f.name)
                
                # Check for ransom notes
                if f.name in KNOWN_RANSOM_NOTES:
                    ransom_notes.append(f.name)
                    
                # Check recent modifications (within last 60 seconds)
                mtime = f.stat().st_mtime
                if (now - mtime) < 60:
                    modified_recently_count += 1

        is_burst = modified_recently_count >= BURST_THRESHOLD_FILES
        
        if locked_files or ransom_notes or is_burst:
            self.detected_anomalies["status"] = "ALERT_RANSOMWARE_BEHAVIOR_DETECTED"
            self.detected_anomalies["burst_activity_detected"] = is_burst
            self.detected_anomalies["suspicious_extensions_found"] = locked_files
            self.detected_anomalies["ransom_notes_found"] = ransom_notes
            self.detected_anomalies["detection_timestamp"] = datetime.now().isoformat()
            self.detected_anomalies["total_events_logged"] = len(files)

            logger.warning("!!! DETECTION ALERT TRIGGERED !!!")
            logger.warning(f"  - Status: {self.detected_anomalies['status']}")
            logger.warning(f"  - Burst modification detected: {is_burst} ({modified_recently_count} files)")
            logger.warning(f"  - Encrypted files detected: {locked_files}")
            logger.warning(f"  - Ransom notes detected: {ransom_notes}")
        else:
            logger.info("Sandbox state clean. No ransomware indicators detected.")

        # Save alert output JSON
        ALERT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ALERT_OUTPUT_PATH, "w", encoding="utf-8") as af:
            json.dump(self.detected_anomalies, af, indent=2)
            
        return self.detected_anomalies

def run_detection():
    engine = DetectionEngine()
    return engine.scan_sandbox()

if __name__ == "__main__":
    run_detection()
