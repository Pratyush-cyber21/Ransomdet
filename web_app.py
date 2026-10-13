#!/usr/bin/env python3
"""
===============================================================================
WEB DASHBOARD SERVER: RANSOMDET LIVE FORENSIC SIMULATOR & WORKBENCH
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module runs a lightweight Python web server serving an interactive dashboard
at http://localhost:8080 to visualize live ransomware attack simulation, 5-layer
forensic pipeline steps, binary PCAP packet inspection, volatile RAM key carving,
Shannon entropy file charts, YARA signature matches, chain of custody logs, and metrics.
===============================================================================
"""

import sys
import os
import json
import io
import contextlib
import logging
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, HTTPServer

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator import run_end_to_end_pipeline

PORT = 8080
WEB_DIR = PROJECT_ROOT / "web"
SANDBOX_DIR = PROJECT_ROOT / "sandbox"
PCAP_FILE = PROJECT_ROOT / "acquisition" / "traffic.pcap"
CUSTODY_FILE = PROJECT_ROOT / "reporting" / "chain_of_custody.json"
REPORT_FILE = PROJECT_ROOT / "reporting" / "forensic_report.md"
NET_ANALYSIS_FILE = PROJECT_ROOT / "analysis" / "network_analysis.json"
MEM_ANALYSIS_FILE = PROJECT_ROOT / "analysis" / "memory_analysis.json"
DISK_ANALYSIS_FILE = PROJECT_ROOT / "analysis" / "disk_analysis.json"
YARA_ANALYSIS_FILE = PROJECT_ROOT / "analysis" / "analysis_results.json"
CORRELATION_FILE = PROJECT_ROOT / "correlation" / "correlation_results.json"

class ForensicWebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url_path = self.path.split('?')[0]

        if url_path == "/api/run":
            self.handle_api_run()
        elif url_path == "/api/sandbox":
            self.handle_api_sandbox()
        elif url_path == "/api/custody":
            self.handle_api_custody()
        elif url_path == "/api/report":
            self.handle_api_report()
        elif url_path == "/api/network":
            self.handle_api_file_json(NET_ANALYSIS_FILE)
        elif url_path == "/api/memory":
            self.handle_api_file_json(MEM_ANALYSIS_FILE)
        elif url_path == "/api/disk":
            self.handle_api_file_json(DISK_ANALYSIS_FILE)
        elif url_path == "/api/yara":
            self.handle_api_file_json(YARA_ANALYSIS_FILE)
        elif url_path == "/api/correlation":
            self.handle_api_file_json(CORRELATION_FILE)
        elif url_path == "/api/download/pcap":
            self.handle_download_pcap()
        elif url_path == "/api/download/report":
            self.handle_download_report()
        else:
            if url_path == "/" or url_path == "":
                self.path = "/index.html"
            return super().do_GET()

    def handle_api_run(self):
        """Execute orchestrator pipeline and capture log stream."""
        log_stream = io.StringIO()
        metrics = {}

        with contextlib.redirect_stdout(log_stream):
            try:
                metrics = run_end_to_end_pipeline()
            except Exception as e:
                print(f"[ERROR] Pipeline execution failed: {e}")

        logs_raw = log_stream.getvalue()
        log_lines = [line.strip() for line in logs_raw.splitlines() if line.strip()]

        response_data = {
            "status": "SUCCESS",
            "metrics": metrics,
            "logs": log_lines
        }
        self.send_json_response(response_data)

    def handle_api_sandbox(self):
        """Return file listing in sandbox directory."""
        files = []
        if SANDBOX_DIR.exists():
            for f in sorted(SANDBOX_DIR.glob("*")):
                if f.is_file():
                    files.append({
                        "name": f.name,
                        "size": f.stat().st_size,
                        "is_locked": f.name.endswith(".locked"),
                        "is_note": ("READ_ME" in f.name or "Please_Read" in f.name),
                        "is_key": ("key" in f.name.lower() or "memory" in f.name.lower())
                    })
        self.send_json_response(files)

    def handle_api_custody(self):
        """Return chain of custody ledger JSON."""
        custody_data = []
        if CUSTODY_FILE.exists():
            with open(CUSTODY_FILE, "r", encoding="utf-8") as f:
                custody_data = json.load(f)
        self.send_json_response(custody_data)

    def handle_api_report(self):
        """Return Markdown forensic report content."""
        report_text = "No report generated yet."
        if REPORT_FILE.exists():
            with open(REPORT_FILE, "r", encoding="utf-8") as f:
                report_text = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(report_text.encode("utf-8"))

    def handle_api_file_json(self, filepath):
        data = {}
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        self.send_json_response(data)

    def handle_download_pcap(self):
        """Serve binary PCAP file for Wireshark download."""
        if PCAP_FILE.exists():
            with open(PCAP_FILE, "rb") as pf:
                pcap_bytes = pf.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Disposition", 'attachment; filename="traffic.pcap"')
            self.send_header("Content-Length", str(len(pcap_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(pcap_bytes)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"PCAP file not yet generated. Run the pipeline first.")

    def handle_download_report(self):
        if REPORT_FILE.exists():
            with open(REPORT_FILE, "rb") as rf:
                report_bytes = rf.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="forensic_report.md"')
            self.send_header("Content-Length", str(len(report_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(report_bytes)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Report not yet generated.")

    def send_json_response(self, data):
        json_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json_bytes)

def start_server():
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, ForensicWebHandler)
    print("=" * 70)
    print(f" RANSOMDET LIVE FORENSIC WEB DASHBOARD READY")
    print(f" Access URL: http://localhost:{PORT}")
    print("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down web dashboard server.")

if __name__ == "__main__":
    start_server()
