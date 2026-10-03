import pytest
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.plugin_registry import PluginRegistry
from forensivue.core.models import EvidenceItem

@pytest.fixture
def registry(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    reg = PluginRegistry(logger)
    reg.load_plugins()
    return reg

def test_plugin_discovery(registry):
    parsers = registry.get_parsers()
    assert "GenericStubParser" in parsers

def test_identify_and_parse_success(registry, tmp_path):
    evidence = EvidenceItem(
        id="EV-001",
        path="/path/to/evidence.generic_dvr",
        acquisition_hash_md5="abc",
        acquisition_hash_sha256="def"
    )
    
    result = registry.parse_evidence(evidence)
    
    assert result["status"] == "success"
    assert result["parser"] == "GenericStubParser"
    assert result["filesystem_info"]["layout"] == "generic_fat32_stub"

def test_identify_and_parse_unrecognized(registry):
    evidence = EvidenceItem(
        id="EV-002",
        path="/path/to/unknown.bin",
        acquisition_hash_md5="123",
        acquisition_hash_sha256="456"
    )
    
    result = registry.parse_evidence(evidence)
    
    assert result["status"] == "error"
    assert result["reason"] == "unrecognized"
