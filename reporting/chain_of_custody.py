#!/usr/bin/env python3
"""
===============================================================================
LAYER 5: REPORTING - APPEND-ONLY HASH-CHAINED CHAIN OF CUSTODY LOG
===============================================================================
Coursework Project: Integrated Digital Forensic Response to Ransomware Threats
Base Paper: Patil, S.P., Kamalesh, V.N., Bamane, K.D. (2024).

This module manages an append-only, SHA-256 hash-chained log to ensure strict chain of custody
integrity for all digital evidence acquired during the forensic lifecycle.
===============================================================================
"""

import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (CUSTODY) %(message)s"
)
logger = logging.getLogger("ChainOfCustody")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CUSTODY_LOG_PATH = PROJECT_ROOT / "reporting" / "chain_of_custody.json"

class ChainOfCustodyManager:
    def __init__(self, log_path=CUSTODY_LOG_PATH):
        self.log_path = Path(log_path)
        self.entries = self._load_or_init_log()

    def _load_or_init_log(self):
        if self.log_path.exists():
            with open(self.log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            genesis_entry = {
                "sequence_id": 0,
                "timestamp": datetime.now().isoformat(),
                "action": "GENESIS_LOG_INITIALIZED",
                "evidence_item": "CHAIN_OF_CUSTODY_ROOT",
                "handled_by": "DFIR_Lead_Analyst",
                "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "entry_hash": ""
            }
            genesis_entry["entry_hash"] = self._compute_entry_hash(genesis_entry)
            return [genesis_entry]

    def _compute_entry_hash(self, entry):
        hash_str = f"{entry['sequence_id']}|{entry['timestamp']}|{entry['action']}|{entry['evidence_item']}|{entry['handled_by']}|{entry['prev_hash']}"
        return hashlib.sha256(hash_str.encode("utf-8")).hexdigest()

    def add_evidence_record(self, action, evidence_item, handled_by="DFIR_Analyst_01", notes=""):
        prev_entry = self.entries[-1]
        new_seq = len(self.entries)
        
        entry = {
            "sequence_id": new_seq,
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "evidence_item": evidence_item,
            "handled_by": handled_by,
            "notes": notes,
            "prev_hash": prev_entry["entry_hash"],
            "entry_hash": ""
        }
        entry["entry_hash"] = self._compute_entry_hash(entry)
        self.entries.append(entry)
        self._save_log()
        logger.info(f"Chain of Custody Record Added #{new_seq}: {action} -> {evidence_item}")
        return entry

    def _save_log(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, indent=2)

    def verify_integrity(self):
        """Verify the cryptographic hash-chain integrity of all custody records."""
        for i in range(1, len(self.entries)):
            curr = self.entries[i]
            prev = self.entries[i-1]
            
            if curr["prev_hash"] != prev["entry_hash"]:
                logger.error(f"INTEGRITY FAILURE at record sequence #{i}: Hash link broken!")
                return False
                
            recomputed = self._compute_entry_hash(curr)
            if curr["entry_hash"] != recomputed:
                logger.error(f"INTEGRITY FAILURE at record sequence #{i}: Data tampered!")
                return False
                
        logger.info("Chain of Custody cryptographic hash-chain integrity VERIFIED successfully.")
        return True

if __name__ == "__main__":
    coc = ChainOfCustodyManager()
    coc.add_evidence_record("EVIDENCE_ACQUIRED", "sandbox_disk_image.img")
    coc.verify_integrity()
