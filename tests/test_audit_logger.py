import os
import json
from forensivue.core.audit_logger import AuditLogger

def test_audit_logger_genesis(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    
    assert os.path.exists(str(log_file))
    
    with open(log_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 1
        genesis = json.loads(lines[0])
        assert genesis["action"] == "SYSTEM_INIT"
        assert genesis["previous_hash"] == "0" * 64

def test_audit_logger_chaining(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    
    logger.log_action("EXTRACT_FILE", {"file": "video1.mp4", "md5": "abc"})
    logger.log_action("VERIFY_HASH", {"file": "video1.mp4"})
    
    assert logger.verify_chain() is True

def test_audit_logger_tampering(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    
    logger.log_action("EXTRACT_FILE", {"file": "video1.mp4"})
    
    # Tamper with the file
    with open(log_file, "r") as f:
        lines = f.readlines()
    
    # Modify the last record
    tampered_record = json.loads(lines[-1])
    tampered_record["details"] = {"file": "malicious.mp4"}
    
    # We must write the tampered record back WITH the original hash to simulate a naive modification
    lines[-1] = json.dumps(tampered_record) + "\n"
    
    with open(log_file, "w") as f:
        f.writelines(lines)
        
    assert logger.verify_chain() is False
