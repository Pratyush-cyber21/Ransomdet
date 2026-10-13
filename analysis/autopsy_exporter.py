#!/usr/bin/env python3
"""
===============================================================================
AUTOPSY & THE SLEUTH KIT (TSK) INTEGRATION MODULE
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module bridges the gap between our automated Python forensic pipeline and
the Autopsy Digital Forensics Desktop Application (Basis Technology / Sleuth Kit):
- Generates an authentic Autopsy Case configuration file (`.aut`)
- Constructs a Sleuth Kit timeline `bodyfile.txt` for Autopsy's Mactime Ingest Module
- Compiles an Autopsy-compliant HTML/XML Case Ingest Report
- Enables direct importation into Autopsy GUI on Windows or Kali Linux VMs
===============================================================================
"""

import os
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (AUTOPSY-EXPORT) %(message)s"
)
logger = logging.getLogger("AutopsyExporter")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "acquisition" / "evidence_disk_image"
AUTOPSY_CASE_DIR = PROJECT_ROOT / "acquisition" / "autopsy_case"
BODYFILE_PATH = AUTOPSY_CASE_DIR / "tsk_bodyfile.txt"
AUT_FILE_PATH = AUTOPSY_CASE_DIR / "Ransomdet_Forensic_Case.aut"
REPORT_HTML_PATH = AUTOPSY_CASE_DIR / "Autopsy_Forensic_Report.html"

def compute_md5(filepath):
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()

def export_autopsy_case():
    """Generate complete Autopsy case folder, .aut case file, and TSK bodyfile."""
    logger.info("Generating Autopsy Digital Forensics Case & Sleuth Kit (TSK) files...")

    AUTOPSY_CASE_DIR.mkdir(parents=True, exist_ok=True)

    if not EVIDENCE_DIR.exists():
        logger.warning("Evidence directory not found for Autopsy export.")
        return False

    now_iso = datetime.now().strftime("%Y/%m/%d %H:%M:%S (UTC)")
    files = [f for f in EVIDENCE_DIR.glob("*") if f.is_file()]

    # 1. Generate Sleuth Kit Bodyfile (Format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime)
    bodyfile_lines = []
    evidence_items = []

    for idx, fpath in enumerate(files):
        stat = fpath.stat()
        md5_hash = compute_md5(fpath)
        inode = getattr(stat, 'st_ino', 1000 + idx)
        size = stat.st_size
        atime = int(stat.st_atime)
        mtime = int(stat.st_mtime)
        ctime = int(stat.st_ctime)
        crtime = int(getattr(stat, 'st_birthtime', stat.st_ctime))

        # Sleuth Kit Bodyfile standard format line
        line = f"{md5_hash}|/evidence_disk_image/{fpath.name}|{inode}|r/rrwxrwxrwx|0|0|{size}|{atime}|{mtime}|{ctime}|{crtime}"
        bodyfile_lines.append(line)

        evidence_items.append({
            "filename": fpath.name,
            "md5": md5_hash,
            "size": size,
            "is_encrypted": fpath.name.endswith(".locked"),
            "modified": datetime.fromtimestamp(mtime).isoformat()
        })

    with open(BODYFILE_PATH, "w", encoding="utf-8") as bf:
        bf.write("\n".join(bodyfile_lines) + "\n")
    logger.info(f"  + Generated Sleuth Kit bodyfile: {BODYFILE_PATH.name} ({len(bodyfile_lines)} file entries)")

    # 2. Generate Autopsy Case XML (.aut)
    aut_content = f"""<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<AutopsyCase>
  <SchemaVersion>5.0</SchemaVersion>
  <CreatedDate>{now_iso}</CreatedDate>
  <ModifiedDate>{now_iso}</ModifiedDate>
  <CreatedBy>Antigravity DFIR Automated Orchestrator</CreatedBy>
  <Case>
    <Name>Ransomdet_Forensic_Case</Name>
    <Number>CASE-2024-WANNACRY-001</Number>
    <Examiner>Lead DFIR Investigator</Examiner>
    <CaseType>Single-user case</CaseType>
    <Database>autopsy.db</Database>
    <CaseRootImageDir>{str(EVIDENCE_DIR.resolve())}</CaseRootImageDir>
  </Case>
  <DataSources>
    <DataSource>
      <Name>evidence_disk_image</Name>
      <Type>Logical Directory</Type>
      <Path>{str(EVIDENCE_DIR.resolve())}</Path>
      <DeviceID>DEV_001</DeviceID>
      <Timezone>UTC</Timezone>
    </DataSource>
  </DataSources>
</AutopsyCase>
"""
    with open(AUT_FILE_PATH, "w", encoding="utf-8") as af:
        af.write(aut_content)
    logger.info(f"  + Generated Autopsy Case file: {AUT_FILE_PATH.name}")

    # 3. Generate Autopsy HTML Ingest Report
    html_rows = []
    for item in evidence_items:
        badge = '<span style="color: #EF4444; font-weight: bold;">[ENCRYPTED]</span>' if item['is_encrypted'] else '<span style="color: #10B981;">[CLEAN/NOTE]</span>'
        html_rows.append(f"""
        <tr>
            <td><code>{item['filename']}</code></td>
            <td>{badge}</td>
            <td><code>{item['md5']}</code></td>
            <td>{item['size']} B</td>
            <td>{item['modified']}</td>
        </tr>
        """)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Autopsy Forensic Ingest Report - Ransomdet Case</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B0F19; color: #E2E8F0; padding: 2rem; }}
        h1 {{ color: #00F2FE; border-bottom: 2px solid #1E293B; padding-bottom: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; background: #131B2E; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #1E293B; font-size: 0.85rem; }}
        th {{ background: #1E293B; color: #94A3B8; text-transform: uppercase; font-size: 0.75rem; }}
        code {{ font-family: monospace; color: #38BDF8; }}
        .box {{ background: #1E293B; padding: 1rem; border-radius: 8px; margin-top: 1rem; border-left: 4px solid #00F2FE; }}
    </style>
</head>
<body>
    <h1>Autopsy Digital Forensics Ingest Report</h1>
    <div class="box">
        <p><strong>Case Name:</strong> Ransomdet_Forensic_Case | <strong>Case Number:</strong> CASE-2024-WANNACRY-001</p>
        <p><strong>Examiner:</strong> Lead DFIR Investigator | <strong>Generated:</strong> {now_iso}</p>
        <p><strong>Data Source:</strong> Logical Files (evidence_disk_image/) | <strong>TSK Bodyfile:</strong> tsk_bodyfile.txt</p>
    </div>

    <h2>Identified Evidence Artifacts</h2>
    <table>
        <thead>
            <tr>
                <th>Artifact File Name</th>
                <th>Classification</th>
                <th>MD5 Hash</th>
                <th>File Size</th>
                <th>Last Modified (UTC)</th>
            </tr>
        </thead>
        <tbody>
            {"".join(html_rows)}
        </tbody>
    </table>

    <div class="box" style="margin-top: 2rem;">
        <h3>How to Load in Autopsy GUI:</h3>
        <ol>
            <li>Launch <strong>Autopsy</strong> on Windows or Kali Linux.</li>
            <li>Click <strong>Open Case</strong> and select <code>Ransomdet_Forensic_Case.aut</code> (or <strong>Add Data Source</strong> -> <strong>Logical Files</strong> -> select <code>evidence_disk_image/</code>).</li>
            <li>Enable Ingest Modules: <em>File Type Identification, Encryption Detection, Keyword Search</em>.</li>
        </ol>
    </div>
</body>
</html>
"""
    with open(REPORT_HTML_PATH, "w", encoding="utf-8") as rf:
        rf.write(html_content)
    logger.info(f"  + Generated Autopsy HTML Report: {REPORT_HTML_PATH.name}")

    return {
        "status": "SUCCESS",
        "case_file": str(AUT_FILE_PATH),
        "bodyfile": str(BODYFILE_PATH),
        "html_report": str(REPORT_HTML_PATH),
        "artifacts_count": len(files)
    }

if __name__ == "__main__":
    export_autopsy_case()
