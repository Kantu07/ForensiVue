import pytest
import os
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.acquisition import AcquisitionManager
from forensivue.core.hash_utils import generate_file_hashes

@pytest.fixture
def manager(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    return AcquisitionManager(AuditLogger(str(log_file)))

def test_acquisition_success(manager, tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"TESTDATA" * 1024)  # 8KB
    
    dest = tmp_path / "dest.dd"
    record = manager.acquire_image(
        source_path=str(source), 
        dest_path=str(dest), 
        case_id="CASE-001", 
        examiner="Alice"
    )
    
    assert os.path.exists(str(dest))
    assert os.path.exists(f"{str(dest)}.json")
    
    hashes = generate_file_hashes(str(dest))
    assert record["hashes"]["md5"] == hashes["md5"]
    assert record["hashes"]["sha256"] == hashes["sha256"]
    
def test_acquisition_verification_failure(manager, tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"TESTDATA" * 1024)
    
    dest = tmp_path / "dest.dd"
    
    # We monkeypatch generate_file_hashes to simulate tampering during the verification phase
    def fake_generate(path):
        return {"md5": "wrong", "sha256": "wrong"}
        
    monkeypatch.setattr("forensivue.core.acquisition.generate_file_hashes", fake_generate)
    
    with pytest.raises(ValueError, match="Verification failed"):
        manager.acquire_image(
            source_path=str(source), 
            dest_path=str(dest), 
            case_id="CASE-001", 
            examiner="Alice"
        )
