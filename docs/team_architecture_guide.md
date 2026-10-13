# Ransomdet: Integrated Digital Forensic Response Framework
## Complete Architectural Working & Team Technical Guide

> **Reference Paper:**  
> Patil, S.P., Kamalesh, V.N., & Bamane, K.D. (2024).  
> *An Integrated Digital Forensic Response To Ransomware Threats Leveraging CVE Exploits And Threat Intelligence.*  
> *Vascular and Endovascular Review*, 7(2), 180–189.

---

## 1. Project Overview & Problem Statement

### Why this project exists
When ransomware strikes an organization, traditional incident response teams usually act **reactively and in silos**:
1. **Siloed Evidence:** Memory, disk, and network evidence are investigated by separate teams using disconnected tools, leading to missing correlations and delayed containment.
2. **Loss of Volatile Artifacts:** Encryption keys often exist only in volatile RAM. If a system is rebooted or powered down without forensically sound memory dumping, the keys are permanently lost, rendering data unrecoverable.
3. **Exploitation of Known Vulnerabilities (CVEs):** Modern ransomware behaves like a worm (e.g., WannaCry, NotPetya) by leveraging unpatched network flaws such as **CVE-2017-0144 (EternalBlue / SMBv1)** to spread across subnets in minutes without user interaction.
4. **Legal & Regulatory Inadmissibility:** Without a cryptographically verified chain of custody ($I_C = 100\%$), evidence collected during an incident cannot be used in court or submitted to regulators under **GDPR Article 33** (which mandates 72-hour reporting) or the **Budapest Convention on Cybercrime**.

### The Solution: Ransomdet
**Ransomdet** builds an integrated, automated **5-layer digital forensic investigation framework** that detects attacks in real-time, captures memory, disk, and network evidence without alteration, performs multi-modal forensic analysis (Memory + Disk + Network + YARA signatures), correlates findings against Cyber Threat Intelligence (CTI) databases, and generates a legally compliant forensic report with an immutable chain-of-custody ledger.

```
+-----------------------------------------------------------------------------------+
|                        5-LAYER DIGITAL FORENSIC FRAMEWORK                         |
+-----------------------------------------------------------------------------------+
|  [L1] DETECTION     -> Anomaly Monitor (.locked burst, ransom note, high entropy) |
|  [L2] ACQUISITION   -> Memory (psutil/RAM), Disk (SHA-256), Network (PCAP/Flows)  |
|  [L3] ANALYSIS      -> YARA signatures, Shannon entropy, Volatile key carving     |
|  [L4] CORRELATION   -> CTI Threat DB (MISP/VirusTotal), Attribution Score (Score) |
|  [L5] REPORTING     -> Hash-chained Ledger (Ic=100%), GDPR Art 33 / Budapest Rep  |
+-----------------------------------------------------------------------------------+
```

---

## 2. End-to-End System Workflow (The 5 Layers)

### Layer 0: Controlled Ransomware Simulator (`simulator/`)
To test digital forensic tools safely without risking real malware execution, the simulator executes strictly inside an isolated `sandbox/` directory under **strict safety constraints**:
* **Target Files:** Populates dummy business files (`confidential_keys.json`, `financial_q4.csv`, `project_roadmap.docx`, `employee_roster.txt`).
* **Cryptographic Operation:** Encrypts files using AES-Fernet cryptography, renaming them with `.locked` extensions.
* **Key Preservation:** Automatically writes the plaintext decryption key to `sandbox/decryption_key.log` so data is always 100% recoverable.
* **Network Emulation:** Emulates an SMBv1 scan (port 445) simulating CVE-2017-0144 EternalBlue worm propagation, queries a simulated kill-switch domain, and beacons to a loopback C2 listener (`127.0.0.1:4444`).

---

### Layer 1: Detection Layer (`detection/monitor.py`)
* **Role:** Acts as an Endpoint Detection and Response (EDR) and SIEM sensor.
* **Mechanism:** 
  1. Continuously tracks file creation, modification, and deletion events in monitored directories.
  2. Calculates the burst modification rate (detecting rapid encryption attempts within seconds).
  3. Scans for known ransomware artifacts (e.g., extensions like `.locked`, `.wnry`, and dropped ransom notes like `README_RESTORE_FILES.txt` or `@Please_Read_Me@.txt`).
* **Output:** Emits a structured `detection_alert.json` containing the incident timestamp, detected compromised paths, burst count, and severity level (`CRITICAL`), immediately triggering automated acquisition.

---

### Layer 2: Acquisition Layer (`acquisition/`)
Forensic acquisition must follow strict standards of evidence preservation:
1. **Volatile Memory Snapshot (`process_snapshot.py`):**
   * Captures runtime memory details before reboot: PID, process name, command line arguments, parent-child relationships, CPU/memory percentage, and active network connections.
   * Exports snapshot to `process_snapshot.json`.
2. **Forensic Disk Imaging (`disk_imaging.py`):**
   * Replicates target disk evidence into `evidence_disk_image/`.
   * Calculates cryptographic **SHA-256 hashes** for every acquired file.
   * Generates `disk_manifest.json` ensuring no bytes were altered during collection.
3. **Network Telemetry Capture (`pcap_capture.py`):**
   * Captures network traffic (SMBv1 probes on port 445, DNS queries, and TCP 4444 C2 beacons).
   * Generates a packet trace log and PCAP evidence record in `network_capture.json`.

---

### Layer 3: Analysis Layer (`analysis/`)
* **YARA Signature Matching (`yara_analyzer.py`):**
  * Compiles custom rule sets in `ransomware_rules.yar`.
  * Scans acquired evidence for:
    * `Ransomware_Note_Indicator`: Flags strings such as *"All your files have been locked"*, *"Bitcoins"*, and decryption instructions.
    * `Fernet_Encrypted_Header`: Identifies encrypted ciphertext magic headers (`gAAAAA`).
    * `WannaCry_Network_Beacon`: Identifies port 4444 C2 strings and SMB exploit markers.
* **Shannon File Entropy Analysis:**
  * Computes entropy ($H(X) = -\sum P(x) \log_2 P(x)$) across all files. Plaintext files range between 3.5–5.0; encrypted files score $\ge 7.5$ (near maximum theoretical entropy 8.0), scientifically confirming cryptographic locking.
* **Output:** Generates `analysis_results.json` mapping all matched rules, offsets, and affected artifacts.

---

### Layer 4: Correlation Layer (`correlation/ioc_correlator.py`)
* **Role:** Connects technical artifacts to strategic Cyber Threat Intelligence (CTI).
* **Mechanism:**
  1. Aggregates all extracted Indicators of Compromise (IOCs): SHA-256 hashes, file extensions (`.locked`), ransom note headers, C2 ports (`4444`), and SMBv1 exploit patterns (`CVE-2017-0144`).
  2. Queries the Threat Intelligence Database (`mock_ioc_db.json`, based on MISP / VirusTotal formats).
  3. Computes the paper's **Threat Correlation Score**:
     $$\text{Score} = \sum_{i=1}^{n} \delta(f_i, \text{TDB})$$
     Where $\delta = 1$ if an indicator matches a known threat actor catalog entry, and $0$ otherwise.
  4. If $\text{Score} \ge \theta$, the incident is attributed to a specific ransomware family (e.g., `WannaCry.A` or `WannaCry-Variant-2024`).
  5. Computes forensic performance metrics: Detection Accuracy, Recovery Rate, IOC Detection Rate, and Attribution Confidence.
* **Output:** Produces `correlation_results.json`.

---

### Layer 5: Reporting & Legal Compliance (`reporting/`)
* **Chain of Custody Ledger (`chain_of_custody.py`):**
  * Every forensic action (detection, acquisition, analysis, report generation) is logged into an append-only JSON ledger (`chain_of_custody.json`).
  * Each record contains: timestamp, action, target artifact, current SHA-256 hash, and previous entry hash (forming a cryptographic hash chain similar to a tamper-proof blockchain).
  * Automatically calculates the paper's **Integrity Score ($I_C = 100\%$)**.
* **Automated Forensic Investigation Report (`report_generator.py`):**
  * Generates a comprehensive report in `forensic_report.md`.
  * Structured for international regulatory bodies:
    * **GDPR Article 33:** 72-hour breach notification dossier, assessment of compromised data types, and containment timestamps.
    * **Budapest Convention on Cybercrime (ETS No. 185):** Verifiable electronic evidence, hash preservation, and examiner details.
    * **Remediation & Patch Validation:** Explicitly checks whether CVE-2017-0144 / MS17-010 has been patched ($C_P \ge 95\%$).

---

## 3. Mathematical Framework from the Paper

The research paper provides exact formulas to evaluate whether a forensic response is scientifically and legally sound:

| Metric | Formula | Target Threshold | Meaning & Application in Ransomdet |
| :--- | :--- | :--- | :--- |
| **Log Completeness ($C_L$)** | $C_L = \frac{\|L_{\text{captured}}\|}{\|L_{\text{expected}}\|} \times 100\%$ | $\ge 95\%$ | Verifies that all expected event logs across memory, disk, and network were collected without data drop. |
| **Evidence Integrity Score ($I_C$)** | $I_C = \frac{\sum_{i=1}^{n-1} \mathbb{1}(H_i = H_{i+1})}{n-1} \times 100\%$ | $= 100\%$ | Verifies that evidence hashes remain unchanged across all investigative phases (Chain of Custody). |
| **Sandbox Isolation** | $E_s \cap E_h = \emptyset$ | $\emptyset$ | Guarantees zero cross-contamination between the sandbox testing directory and the host system. |
| **Execution Similarity ($S_{sim}$)** | $S_{sim} = \frac{\|T_s \cap T_r\|}{\|T\|} \times 100\%$ | $\ge 85\%$ | Measures how closely the simulated execution matches real-world ransomware attack traces. |
| **Threat Correlation Score** | $\text{Score} = \sum_{i=1}^n \delta(f_i, \text{TDB})$ | $\ge \theta$ | Sum of matching IOCs against CTI databases used to mathematically attribute the attack. |
| **Patch Compliance Rate ($C_P$)** | $C_P = \frac{\|P_a\|}{\|P\|} \times 100\%$ | $\ge 95\%$ | Verifies that required security updates (e.g., MS17-010 for EternalBlue) are applied to prevent re-infection. |

---

## 4. Current State of the Codebase (`Ransomdet`)

### Repository Structure
```
ransomware-forensics-lab/
├── orchestrator.py           # Master execution script running all 5 layers sequentially
├── requirements.txt          # Python packages (yara-python, psutil, cryptography)
├── web_app.py                # Local web server on port 8080 serving the UI & REST API
├── web/
│   └── index.html            # Complete dark-mode forensic dashboard UI
├── sandbox/                  # Isolated execution environment for encrypted files
├── simulator/
│   └── ransomware_sim.py     # Safe AES-Fernet encryption & simulated C2 beaconing
├── detection/
│   └── monitor.py            # Watches sandbox for burst modifications & .locked files
├── acquisition/
│   ├── process_snapshot.py   # Dumps process memory table via psutil
│   ├── disk_imaging.py       # Copies sandbox files to evidence folder with SHA-256 hashes
│   └── pcap_capture.py       # Simulates network packet logging
├── analysis/
│   ├── ransomware_rules.yar  # YARA rules for ransom note & ciphertext headers
│   └── yara_analyzer.py      # Scans acquired files using yara-python
├── correlation/
│   ├── mock_ioc_db.json      # Threat catalog for WannaCry, REvil, DarkSide
│   └── ioc_correlator.py     # Matches IOCs and calculates paper metrics
└── reporting/
    ├── chain_of_custody.py   # Hash-chained immutable custody ledger
    └── report_generator.py   # Generates GDPR & Budapest compliant Markdown report
```

---

## 5. How to Run and Demonstrate the System Today

### Method 1: Command Line Interface (CLI)
From inside the project directory:
```bash
# 1. Activate the Python virtual environment
source .venv/bin/activate

# 2. Run the full 5-layer pipeline
python3 orchestrator.py
```
**Console Output:** Displays step-by-step execution across Layers 0–5 and outputs the final benchmark table comparing results to the Patil et al. (2024) paper baseline.

### Method 2: Interactive Web Dashboard
```bash
python3 web_app.py
```
Open a browser and navigate to: **`http://localhost:8080`**

**Dashboard Features:**
1. **Interactive Control:** Click **"Execute 5-Layer Forensic Pipeline"** to trigger live simulation and response.
2. **Real-Time Execution Logs:** Streamed live in the console window.
3. **Live Metrics Cards:** Displays Detection Accuracy, Recovery Rate, IOC Detection Rate, Attribution Confidence, and Response Time.
4. **Sandbox File Viewer:** View raw files before and after encryption (`.locked`).
5. **Chain of Custody Ledger:** Visualizes the SHA-256 hash-chained evidentiary record.
6. **Forensic Report Preview:** Renders the GDPR Article 33 and Budapest Convention compliant investigation report.

---

## 6. Implementation Upgrade Plan (Integrating Real Forensic Tools)

To elevate this project from an educational prototype to an advanced, industry-grade digital forensics platform aligned with the paper's complete toolchain, here is the detailed technical upgrade roadmap:

### Upgrade Modules:
1. **Real Binary PCAP Generation & TShark Dissector (`Wireshark / Scapy`):**
   * Upgrade `pcap_capture.py` from flat text logging to writing standard binary `.pcap` files using `scapy`.
   * Include real SMBv1 Negotiate / Trans2 exploit packets (`CVE-2017-0144`), simulated WannaCry killswitch DNS query (`www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`), and TCP 4444 beacons.
   * Provide automated packet dissection and Wireshark-compatible export.

2. **Memory Analysis & Volatile Key Carving (Volatility Emulation):**
   * Upgrade `acquisition/process_snapshot.py` and `analysis/` to simulate volatile RAM dump carving.
   * Carve the plaintext AES key directly from simulated memory buffers and correlate process trees (`mssecsvc.exe` spawning `tasksche.exe`).

3. **Shannon Entropy Engine (Autopsy / SleuthKit Disk Forensics):**
   * Add a file entropy calculation module in `analysis/`.
   * Automatically generate byte-frequency charts distinguishing unencrypted plaintexts from encrypted high-entropy ciphertexts.

4. **Live & Offline Threat Intelligence Hybrid Engine:**
   * Support live lookups against the VirusTotal API v3 (when an API key is provided) with automatic fallback to the local offline threat catalog.

5. **Enhanced Interactive Web Dashboard:**
   * Add interactive packet inspection tabs, hex-view memory carvers, and one-click PDF/Markdown export for the legal report.
