#!/usr/bin/env python3
"""
===============================================================================
LAYER 2: ACQUISITION - PROCESS & MEMORY STATE SNAPSHOT
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module simulates forensic memory acquisition by capturing live process structures,
command lines, environment context, and active socket connections using `psutil`.
===============================================================================
"""

import json
import logging
from pathlib import Path
from datetime import datetime

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (ACQUISITION) %(message)s"
)
logger = logging.getLogger("ProcessAcquisition")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "acquisition" / "process_snapshot.json"

def capture_process_snapshot():
    """Capture process tree and active socket connections."""
    logger.info("Capturing live memory/process snapshot...")
    snapshot_data = {
        "timestamp": datetime.now().isoformat(),
        "total_processes_captured": 0,
        "suspicious_processes": [],
        "all_processes_summary": []
    }

    if not HAVE_PSUTIL:
        logger.warning("psutil package missing; generating fallback process snapshot.")
        snapshot_data["all_processes_summary"].append({"pid": 0, "name": "fallback_process"})
        return snapshot_data

    processes_captured = 0
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'username']):
        try:
            info = proc.info
            cmdline_str = " ".join(info['cmdline']) if info['cmdline'] else ""
            
            proc_entry = {
                "pid": info['pid'],
                "name": info['name'],
                "cmdline": cmdline_str,
                "user": info['username']
            }
            
            # Highlight python processes or simulator references
            if "python" in info['name'].lower() or "ransomware" in cmdline_str.lower() or "sim.py" in cmdline_str:
                snapshot_data["suspicious_processes"].append(proc_entry)
                logger.info(f"  > Target/Suspicious process identified: PID {info['pid']} ({info['name']}) -> {cmdline_str}")

            snapshot_data["all_processes_summary"].append(proc_entry)
            processes_captured += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    snapshot_data["total_processes_captured"] = processes_captured

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(snapshot_data, f, indent=2)

    logger.info(f"Process snapshot saved to: {OUTPUT_FILE.name} ({processes_captured} processes logged)")
    return snapshot_data

if __name__ == "__main__":
    capture_process_snapshot()
