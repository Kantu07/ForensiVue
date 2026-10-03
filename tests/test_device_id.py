import pytest
import os
import binascii
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.device_id import DeviceIdentifier

@pytest.fixture
def device_id_module(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    sig_file = os.path.join(os.path.dirname(__file__), "..", "forensivue", "config", "signatures.yaml")
    return DeviceIdentifier(sig_file, AuditLogger(str(log_file)))

def test_identify_hikvision_magic_bytes(device_id_module, tmp_path):
    img = tmp_path / "hik.dd"
    # Create 2048 bytes of zeroes
    data = bytearray(2048)
    
    # Hikvision magic hex: 48494B564953494F4E at offset 512
    hik_magic = binascii.unhexlify("48494B564953494F4E")
    data[512:512+len(hik_magic)] = hik_magic
    img.write_bytes(data)
    
    results = device_id_module.identify(str(img))
    
    assert results[0]["vendor"] == "Hikvision"
    assert results[0]["confidence"] > 0.0
    assert any(e["type"] == "magic_bytes" for e in results[0]["evidence"])

def test_identify_dahua_string_and_magic(device_id_module, tmp_path):
    img = tmp_path / "dahua.dd"
    data = bytearray(2048)
    
    # Dahua magic DHAV at 1024
    dhav_magic = binascii.unhexlify("44484156")
    data[1024:1024+len(dhav_magic)] = dhav_magic
    
    # Dahua string at 50
    dahua_str = b"dahua"
    data[50:50+len(dahua_str)] = dahua_str
    
    img.write_bytes(data)
    
    results = device_id_module.identify(str(img))
    
    assert results[0]["vendor"] == "Dahua"
    assert results[0]["confidence"] == 1.0 # Both matched
    assert len(results[0]["evidence"]) == 2

def test_identify_unknown(device_id_module, tmp_path):
    img = tmp_path / "random.dd"
    img.write_bytes(b"RANDOM DATA" * 1024)
    
    results = device_id_module.identify(str(img))
    
    assert len(results) == 1
    assert results[0]["vendor"] == "unknown"
    assert results[0]["confidence"] == 1.0
