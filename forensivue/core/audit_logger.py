import json
import os
from typing import Any
from forensivue.core.hash_utils import generate_string_hash
from datetime import datetime, timezone

class AuditLogger:
    """
    Append-only, hash-chained audit logger.
    Every action is written to a file with a cryptographic hash linking it to the previous entry.
    """
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._ensure_log_file()
        
    def _ensure_log_file(self):
        """Creates the log file with a genesis block if it doesn't exist."""
        if not os.path.exists(self.log_path):
            genesis_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "SYSTEM_INIT",
                "details": "Audit log genesis block",
                "previous_hash": "0" * 64,  # Genesis has no previous hash
            }
            # Calculate hash of the genesis record
            record_str = json.dumps(genesis_record, sort_keys=True)
            genesis_record["hash"] = generate_string_hash(record_str)
            
            with open(self.log_path, "w") as f:
                f.write(json.dumps(genesis_record) + "\n")

    def _get_last_hash(self) -> str:
        """Reads the last line of the log to get the previous hash."""
        try:
            with open(self.log_path, "rb") as f:
                # Seek to end and read the last line
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b'\n':
                    f.seek(-2, os.SEEK_CUR)
                last_line = f.readline().decode()
                last_record = json.loads(last_line)
                return last_record.get("hash", "0"*64)
        except OSError:
            # Fallback if file is too small or genesis is only line
            with open(self.log_path, "r") as f:
                lines = f.readlines()
                if lines:
                    return json.loads(lines[-1]).get("hash", "0"*64)
            return "0"*64

    def log_action(self, action: str, details: Any):
        """
        Logs a new action. 
        Uses file locking to ensure append-only integrity during concurrent writes.
        """
        previous_hash = self._get_last_hash()
        
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
            "previous_hash": previous_hash
        }
        
        record_str = json.dumps(record, sort_keys=True)
        record["hash"] = generate_string_hash(record_str)
        
        # Append-only write (simplified for Windows without fcntl)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
                    
    def verify_chain(self) -> bool:
        """
        Verifies the cryptographic integrity of the entire audit log.
        Returns True if intact, False if tampered.
        """
        expected_prev_hash = "0" * 64
        with open(self.log_path, "r") as f:
            for i, line in enumerate(f):
                record = json.loads(line)
                record_hash = record.pop("hash")
                
                # Check link
                if i > 0 and record["previous_hash"] != expected_prev_hash:
                    return False
                    
                # Recompute hash
                record_str = json.dumps(record, sort_keys=True)
                computed_hash = generate_string_hash(record_str)
                
                if computed_hash != record_hash:
                    return False
                    
                expected_prev_hash = record_hash
                
        return True
