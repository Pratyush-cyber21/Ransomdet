# Optional Multi-VM Lab Setup Guide: Enterprise Forensic Architecture

This guide provides step-by-step instructions for extending the safe Python-based ransomware simulation into a full isolated multi-virtual-machine forensic environment using VirtualBox, Windows 10/11 Target VM, Kali Linux Forensic Analyst VM, Volatility 3, Autopsy, Wireshark, and FTK Imager.

---

## 1. Environment Architecture & Isolation Setup

```
                     +-----------------------------------+
                     |  Host Machine (VirtualBox Engine) |
                     +-----------------+-----------------+
                                       |
                +----------------------+----------------------+
                | VirtualBox Host-Only Network (vboxnet0)     |
                | Subnet: 192.168.56.0/24                     |
                | DHCP: DISABLED (Static IP Assignments)      |
                +----------------------+----------------------+
                                       |
             +-------------------------+-------------------------+
             |                                                   |
+------------v------------+                         +------------v------------+
|  Windows Victim VM      |                         |  Kali Forensic Analyst  |
|  IP: 192.168.56.10      |                         |  IP: 192.168.56.20      |
|  Target Endpoint        |                         |  Forensic Workstation   |
+-------------------------+                         +-------------------------+
```

### Step 1.1: Create Isolated Host-Only Network in VirtualBox
1. Open **VirtualBox** -> **Tools** -> **Network Manager**.
2. Click **Create** to create a new Host-Only Network (`vboxnet0` or `VirtualBox Host-Only Ethernet Adapter`).
3. Set IPv4 Address: `192.168.56.1` / Subnet Mask: `255.255.255.0`.
4. **Disable DHCP Server** to prevent rogue DHCP leases or internet routing leaks.

---

## 2. VM Provisioning & Tool Installation

### Step 2.1: Windows Victim VM Setup
1. Create a Windows 10/11 VM attached to `vboxnet0` (Static IP: `192.168.56.10`).
2. Disable Windows Defender / Real-Time Protection (for lab execution).
3. Install **FTK Imager** (for memory & disk acquisition).
4. Create a system restore point or VirtualBox snapshot named `Clean_Baseline`.

### Step 2.2: Kali Linux Forensic Workstation Setup
1. Create a Kali Linux VM attached to `vboxnet0` (Static IP: `192.168.56.20`).
2. Install primary forensic tools:

```bash
sudo apt update && sudo apt install -y \
  yara \
  wireshark \
  tshark \
  autopsy \
  python3-pip \
  git \
  pypy3

# Install Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
python3 setup.py build
sudo python3 setup.py install
```

---

## 3. 5-Layer Forensic Execution Lifecycle in Multi-VM Setup

### Layer 1: Detection
- On Windows Victim VM: Configure **Sysmon** (System Monitor) with SwiftOnSecurity config to monitor event ID 11 (FileCreate) for `.locked` extensions and event ID 1 (ProcessCreate).
- Export Sysmon EVTX logs for analysis.

### Layer 2: Acquisition
1. **Memory Dump**: Use **FTK Imager** or `winpmem` on Windows Victim VM to capture RAM into `memdump.raw`:
   ```cmd
   winpmem.exe -o C:\Forensics\memdump.raw
   ```
2. **Disk Image**: Use FTK Imager to acquire an E01 or DD bit-stream image of the victim volume into `victim_disk.E01`.
3. **Network Packet Capture**: Run `tshark` on Kali Forensic VM monitoring host-only interface `eth0`:
   ```bash
   sudo tshark -i eth0 -w /forensics/c2_capture.pcap -f "tcp port 4444"
   ```

### Layer 3: Analysis
1. **Memory Forensic Analysis with Volatility 3**:
   ```bash
   # List active processes at incident time
   vol -f memdump.raw windows.pslist

   # Scan for injected code or orphaned sockets
   vol -f memdump.raw windows.malfind
   vol -f memdump.raw windows.netscan
   ```
2. **YARA Signature Scanning**:
   ```bash
   yara -r ransomware_rules.yar /forensics/extracted_files/
   ```
3. **Disk Forensic Analysis with Autopsy**:
   - Create new case in Autopsy -> Add Data Source (`victim_disk.E01`).
   - Run ingest modules: Keyword Search, File Extension Mismatch, Recent Activity.

### Layer 4: Correlation
- Deploy a local **MISP** (Malware Information Sharing Platform) Docker container on Kali VM.
- Import extracted file hashes, mutex strings, and C2 IP (`192.168.56.10:4444`) into MISP to query threat actor profiles.

### Layer 5: Reporting
- Document memory structures (offset tables, PID lineage, socket endpoints).
- Hash all acquired evidence (`memdump.raw`, `victim_disk.E01`, `c2_capture.pcap`) with SHA-256 immediately upon acquisition.
- Maintain chain-of-custody documentation log.
