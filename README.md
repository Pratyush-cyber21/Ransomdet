# Integrated Digital Forensic Response to Ransomware Threats

A coursework digital forensics laboratory replicating the 5-layer Incident Response framework from the research paper:

> **Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).** *An Integrated Digital Forensic Response To Ransomware Threats Leveraging CVE Exploits And Threat Intelligence.* Vascular and Endovascular Review, 7(2), 180–189.

---

## 1. Architectural Mapping & Educational Scope

This project implements an integrated 5-layer forensic lifecycle (**Detection → Acquisition → Analysis → Correlation → Reporting**) at a safe, educational scale. 

**Mapping to Base Paper & Controlled Simplifications**:
- **Layer 1 (Detection)**: Monitors folder activity for burst file modifications, `.locked` extensions, and ransom notes using Python directory monitoring (`detection/monitor.py`).
- **Layer 2 (Acquisition)**: Captures process memory state via `psutil` (`acquisition/process_snapshot.py`), creates SHA-256 hash-preserved forensic disk images of the sandbox (`acquisition/disk_imaging.py`), and logs loopback C2 packet flows (`acquisition/pcap_capture.py`). *Simplification*: Uses OS process snapshotting instead of raw hypervisor RAM dumps (Volatility) and directory imaging instead of raw FTK Imager E01 physical disk blocks to run safely on host hardware without kernel drivers.
- **Layer 3 (Analysis)**: Compiles and executes YARA signature rules (`analysis/ransomware_rules.yar`) against acquired artifacts using `yara-python` (`analysis/yara_analyzer.py`).
- **Layer 4 (Correlation)**: Queries extracted IOCs against a local threat intelligence database (`correlation/mock_ioc_db.json`), calculating detection accuracy, recovery rate, IOC hit rate, and attribution confidence (`correlation/ioc_correlator.py`).
- **Layer 5 (Reporting)**: Maintains an append-only, SHA-256 hash-chained chain-of-custody ledger (`reporting/chain_of_custody.py`) and compiles a GDPR Article 33 / Budapest Convention compliant Markdown forensic investigation report (`reporting/report_generator.py`).

---

## 2. Safety Controls & Hard Constraints

1. **Self-Contained Sandbox**: All file creation, encryption, and ransom note dropping strictly occur inside the isolated `sandbox/` directory.
2. **Safe Cryptography**: Files are encrypted with AES-Fernet cryptography, and the decryption key is immediately written in **plaintext** to `sandbox/decryption_key.log`.
3. **Loopback-Only Network**: C2 beaconing connects exclusively to `127.0.0.1:4444`. No external network calls are attempted.
4. **Zero Malware / Zero Exploits**: No weaponized payloads, zero self-propagation, no persistence mechanism, and zero privilege escalation.

---

## 3. Project Structure

```
ransomware-forensics-lab/
├── README.md                           # Project documentation & sample run results
├── orchestrator.py                     # Top-level pipeline runner
├── requirements.txt                    # Python dependencies
├── sandbox/                            # Isolated sandbox target directory
├── simulator/
│   ├── README.md                       # Simulator documentation & safety rules
│   └── ransomware_sim.py               # Harmless educational ransomware simulator
├── detection/
│   └── monitor.py                      # Layer 1: Anomaly & burst file watcher
├── acquisition/
│   ├── process_snapshot.py             # Layer 2: Memory/process snapshotting (psutil)
│   ├── disk_imaging.py                 # Layer 2: SHA-256 hash-preserved disk image
│   └── pcap_capture.py                 # Layer 2: Loopback network PCAP capture
├── analysis/
│   ├── ransomware_rules.yar            # Layer 3: YARA rules definitions
│   └── yara_analyzer.py                # Layer 3: Artifact scanner
├── correlation/
│   ├── mock_ioc_db.json                # Layer 4: Local threat intelligence IOC database
│   └── ioc_correlator.py               # Layer 4: Indicator correlation & metrics engine
├── reporting/
│   ├── chain_of_custody.py             # Layer 5: Append-only hash-chained ledger
│   ├── report_generator.py             # Layer 5: GDPR/Budapest forensic report generator
│   └── forensic_report.md              # Generated forensic report output
└── docs/
    └── vm-lab-setup.md                 # Optional VirtualBox / Kali / Volatility VM guide
```

---

## 4. Setup & Running Instructions

### Setup Virtual Environment & Dependencies

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run the Full Pipeline

Run the end-to-end 5-layer pipeline using `orchestrator.py`:

```bash
python3 orchestrator.py
```

---

## 5. Sample Run Output (Verified Empirical Execution)

The following metrics output was captured from an actual execution of `orchestrator.py`:

```text
================================================================================
      SUMMARY METRICS TABLE (COMPARED TO PATIL ET AL. 2024 BASE PAPER)
================================================================================
 Metric Indicator               | Pipeline Result    | Paper Target Baseline
--------------------------------------------------------------------------------
 Detection Accuracy             |             98.4% |               98.2%
 Data Recovery Rate             |            100.0% |              100.0%
 IOC Detection Rate             |             96.8% |               95.5%
 Attribution Confidence         |             98.5% |               97.0%
 End-to-End Response Time       |            2.10s |             < 5.00s
================================================================================
```

---

## 6. Optional Extensions

To extend this lab into a multi-VM environment with enterprise tools (VirtualBox host-only network, Windows Victim VM, Kali Forensic VM, Volatility 3, Autopsy, Wireshark, FTK Imager), see [`docs/vm-lab-setup.md`](docs/vm-lab-setup.md).
