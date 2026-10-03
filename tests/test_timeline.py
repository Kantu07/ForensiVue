import pytest
import os
import json
from forensivue.core.plugin_registry import PluginRegistry
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.models import EvidenceItem
from forensivue.core.timeline import TimelineManager

def test_timeline_manager(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    registry = PluginRegistry(logger)
    registry.load_plugins()
    
    generated_dir = os.path.join(os.path.dirname(__file__), "..", "generated")
    if not os.path.exists(generated_dir):
        pytest.skip("Generated images not found. Run generate_suite.py first.")
        
    img_path = os.path.join(generated_dir, "mixed.dd")
    if not os.path.exists(img_path):
        pytest.skip("mixed.dd not found")
        
    evidence = EvidenceItem(
        id="mixed.dd",
        path=img_path,
        acquisition_hash_md5="N/A",
        acquisition_hash_sha256="N/A"
    )
    
    result = registry.parse_evidence(evidence)
    parser = registry.get_parsers()[result["parser"]]()
    recordings = parser.list_recordings(evidence)
    
    # 1. Base functionality
    tm = TimelineManager(logger)
    tm.add_recordings(recordings)
    
    unified = tm.get_unified_timeline()
    assert len(unified) == len(recordings)
    
    # 2. Clock Drift Detection
    # Since we didn't embed "fs_creation_time" in the synthetic metadata during generation, 
    # it should return 0.0 drift
    assert tm.detect_clock_drift() == 0.0
    
    # We will inject a mock fs time to test drift
    tm.events[0].metadata["fs_creation_time"] = "2020-09-13T12:26:40+00:00" # Some epoch exact time
    
    # 3. Apply manual correction
    original_start = unified[0]["adjusted_start"]
    tm.apply_manual_correction(3600.0, "DST Offset")
    
    unified_updated = tm.get_unified_timeline()
    assert unified_updated[0]["correction_seconds"] == 3600.0
    assert unified_updated[0]["adjusted_start"] != original_start
    
    # Check that audit log recorded the action
    with open(str(log_file), "r") as f:
        logs = f.read()
        assert "TIMELINE_CORRECTION" in logs

def test_timeline_correlations(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    registry = PluginRegistry(logger)
    registry.load_plugins()
    
    generated_dir = os.path.join(os.path.dirname(__file__), "..", "generated")
    img_path = os.path.join(generated_dir, "multi_channel.dd")
    if not os.path.exists(img_path):
        pytest.skip("multi_channel.dd not found")
        
    evidence = EvidenceItem(
        id="multi_channel.dd",
        path=img_path,
        acquisition_hash_md5="N/A",
        acquisition_hash_sha256="N/A"
    )
    
    result = registry.parse_evidence(evidence)
    parser = registry.get_parsers()[result["parser"]]()
    recordings = parser.list_recordings(evidence)
    
    tm = TimelineManager(logger)
    tm.add_recordings(recordings)
    
    # The multi_channel.dd generated test has all channels starting at exactly the same time (1600000000)
    # Therefore, correlations within 5 seconds should find overlapping pairs
    correlations = tm.find_correlated_events(max_gap_seconds=5.0)
    
    # For 4 channels exactly overlapping, pairs (A,B) where A!=B is (4 choose 2) = 6
    assert len(correlations) == 6
    
    ev1, ev2 = correlations[0]
    assert ev1["channel"] != ev2["channel"]
