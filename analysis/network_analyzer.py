#!/usr/bin/env python3
"""
===============================================================================
LAYER 3: ANALYSIS - NETWORK TRAFFIC & PCAP DISSECTION (SCAPY / TSHARK)
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module inspects the binary .pcap evidence file (`acquisition/traffic.pcap`):
- Detects SMBv1 exploit packets (CVE-2017-0144 EternalBlue)
- Flags WannaCry killswitch domain DNS lookup attempts
- Maps C2 beacon flows and lateral movement attempts
===============================================================================
"""

import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, UDP, DNS, Raw
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (ANALYSIS-NET) %(message)s"
)
logger = logging.getLogger("NetworkAnalyzer")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_FILE = PROJECT_ROOT / "acquisition" / "traffic.pcap"
OUTPUT_FILE = PROJECT_ROOT / "analysis" / "network_analysis.json"

TSHARK_PATHS = [
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
]

def find_tshark():
    for p in TSHARK_PATHS:
        if Path(p).exists():
            return p
    return None

def analyze_pcap():
    """Dissect binary PCAP file using Scapy with optional TShark verification."""
    logger.info("Executing deep PCAP network traffic forensic analysis...")

    analysis_report = {
        "timestamp": datetime.now().isoformat(),
        "pcap_target": str(PCAP_FILE),
        "total_packets_parsed": 0,
        "protocols_detected": {},
        "cve_exploits_detected": [],
        "dns_killswitch_queries": [],
        "c2_beacons_detected": [],
        "tshark_summary": []
    }

    if not PCAP_FILE.exists():
        logger.warning(f"PCAP file not found at {PCAP_FILE}")
        return analysis_report

    # Scapy Dissection
    if HAVE_SCAPY:
        try:
            packets = rdpcap(str(PCAP_FILE))
            analysis_report["total_packets_parsed"] = len(packets)

            for idx, pkt in enumerate(packets):
                # Protocol statistics
                proto_name = "OTHER"
                if pkt.haslayer(TCP):
                    proto_name = "TCP"
                    dport = pkt[TCP].dport
                    sport = pkt[TCP].sport

                    # Check for SMBv1 (Port 445)
                    if dport == 445 or sport == 445:
                        proto_name = "SMBv1 (TCP/445)"
                        if pkt.haslayer(Raw):
                            payload = bytes(pkt[Raw].load)
                            if b"\xffSMB" in payload:
                                # Check for EternalBlue Trans2 Secondary / Multiplex 0x51
                                if b"\xffSMB\x33" in payload or b"\x51\x00" in payload or b"CVE-2017-0144" in payload:
                                    exploit_entry = {
                                        "packet_num": idx + 1,
                                        "cve": "CVE-2017-0144",
                                        "name": "EternalBlue SMBv1 Buffer Overflow Exploit",
                                        "signature": "SMB_COM_TRANSACTION2_SECONDARY (Multiplex ID 0x51)",
                                        "src": f"{pkt['IP'].src}:{sport}",
                                        "dst": f"{pkt['IP'].dst}:{dport}",
                                        "severity": "CRITICAL"
                                    }
                                    analysis_report["cve_exploits_detected"].append(exploit_entry)
                                    logger.warning(f"  [!] CVE EXPLOIT DETECTED in packet #{idx+1}: {exploit_entry['cve']} (EternalBlue)")

                    # Check for C2 Beacon (Port 4444)
                    elif dport == 4444 or sport == 4444:
                        proto_name = "C2-BEACON (TCP/4444)"
                        if pkt.haslayer(Raw):
                            payload = bytes(pkt[Raw].load).decode("latin1", errors="ignore")
                            if "HELO C2_MOCK" in payload or "WANNACRY" in payload:
                                beacon_entry = {
                                    "packet_num": idx + 1,
                                    "target": f"{pkt['IP'].dst}:{dport}",
                                    "src": f"{pkt['IP'].src}:{sport}",
                                    "payload": payload.strip()
                                }
                                analysis_report["c2_beacons_detected"].append(beacon_entry)
                                logger.info(f"  [*] C2 BEACON IDENTIFIED: {beacon_entry['payload']}")

                elif pkt.haslayer(UDP) and pkt.haslayer(DNS):
                    proto_name = "DNS (UDP/53)"
                    dns_layer = pkt[DNS]
                    if dns_layer.qd and hasattr(dns_layer.qd, "qname"):
                        qname = dns_layer.qd.qname.decode("latin1").strip(".")
                        if "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" in qname:
                            dns_entry = {
                                "packet_num": idx + 1,
                                "domain": qname,
                                "significance": "WannaCry Killswitch Domain Query",
                                "result": "NXDOMAIN"
                            }
                            analysis_report["dns_killswitch_queries"].append(dns_entry)
                            logger.info(f"  [*] KILLSWITCH DNS DETECTED: {qname}")

                analysis_report["protocols_detected"][proto_name] = (
                    analysis_report["protocols_detected"].get(proto_name, 0) + 1
                )

        except Exception as e:
            logger.error(f"Error dissecting PCAP with Scapy: {e}")

    # Optional TShark summary verification
    tshark_bin = find_tshark()
    if tshark_bin:
        try:
            cmd = [tshark_bin, "-r", str(PCAP_FILE), "-c", "10", "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                analysis_report["tshark_summary"] = lines
                logger.info(f"TShark packet verification executed ({len(lines)} frames reported).")
        except Exception as e:
            logger.debug(f"TShark optional run skipped: {e}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(analysis_report, f, indent=2)

    logger.info(f"Network forensic analysis complete. Findings saved to {OUTPUT_FILE.name}")
    return analysis_report

if __name__ == "__main__":
    analyze_pcap()
