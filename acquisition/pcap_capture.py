#!/usr/bin/env python3
"""
===============================================================================
LAYER 2: ACQUISITION - LOOPBACK PACKET & C2 NETWORK CAPTURE
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module simulates local packet capture of C2 beacon attempts on loopback port 4444.
===============================================================================
"""

import json
import socket
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (ACQUISITION) %(message)s"
)
logger = logging.getLogger("NetworkAcquisition")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "acquisition" / "network_capture.json"
PCAP_LOG_FILE = PROJECT_ROOT / "acquisition" / "loopback_beacon.pcap.log"

def capture_network_activity():
    """Simulate loopback network acquisition by checking local socket logs / C2 indicators."""
    logger.info("Capturing loopback network telemetry for port 4444 (C2 Beacon target)...")

    network_evidence = {
        "timestamp": datetime.now().isoformat(),
        "target_interface": "lo0 / 127.0.0.1",
        "captured_flows": [
            {
                "src_ip": "127.0.0.1",
                "src_port": 51234,
                "dst_ip": "127.0.0.1",
                "dst_port": 4444,
                "protocol": "TCP",
                "payload_snippet": "HELO C2_MOCK_BEACON_BEHAVIOR_RANSOM_SIM",
                "status": "BEACON_DETECTED"
            }
        ],
        "total_flows": 1
    }

    # Save structured network capture JSON
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(network_evidence, f, indent=2)

    # Save mock PCAP log representation
    with open(PCAP_LOG_FILE, "w", encoding="utf-8") as pf:
        pf.write(f"=== LOOPBACK PACKET CAPTURE LOG ({datetime.now().isoformat()}) ===\n")
        pf.write("127.0.0.1:51234 -> 127.0.0.1:4444 [SYN] Seq=0\n")
        pf.write("127.0.0.1:51234 -> 127.0.0.1:4444 [PSH, ACK] Payload='HELO C2_MOCK_BEACON_BEHAVIOR_RANSOM_SIM'\n")

    logger.info(f"Network telemetry acquired. Flow evidence written to {OUTPUT_FILE.name} and {PCAP_LOG_FILE.name}")
    return network_evidence

if __name__ == "__main__":
    capture_network_activity()
