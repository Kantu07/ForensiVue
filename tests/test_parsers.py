import pytest
import os
import glob
import json
from forensivue.core.plugin_registry import PluginRegistry
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.models import EvidenceItem

def test_parsers_against_ground_truth(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    registry = PluginRegistry(logger)
    registry.load_plugins()
    
    generated_dir = os.path.join(os.path.dirname(__file__), "..", "generated")
    if not os.path.exists(generated_dir):
        pytest.skip("Generated images not found. Run generate_suite.py first.")
        
    dd_files = glob.glob(os.path.join(generated_dir, "*.dd"))
    
    print("\n\n--- PARSER vs GROUND TRUTH EVALUATION ---")
    
    for dd_file in dd_files:
        json_file = f"{dd_file}.json"
        if not os.path.exists(json_file):
            continue
            
        with open(json_file, "r") as f:
            truth = json.load(f)
            
        evidence = EvidenceItem(
            id=os.path.basename(dd_file),
            path=dd_file,
            acquisition_hash_md5="N/A",
            acquisition_hash_sha256="N/A"
        )
        
        # Parse filesystem
        result = registry.parse_evidence(evidence)
        assert result["status"] == "success"
        parser_name = result["parser"]
        
        # Instaniate the parser to list recordings
        parser_class = registry.get_parsers()[parser_name]
        parser = parser_class()
        
        recordings = parser.list_recordings(evidence)
        
        # Compare
        expected_count = len(truth["recordings"])
        found_count = len(recordings)
        
        print(f"\nImage: {os.path.basename(dd_file)}")
        print(f"Vendor Matched: {parser_name} | Expected Vendor: {truth['vendor']}")
        print(f"Recordings Found: {found_count} | Expected: {expected_count}")
        
        assert found_count == expected_count, f"Count mismatch in {dd_file}"
        
        # Test extract on first recording
        if recordings:
            out_path = str(tmp_path / f"extracted_{recordings[0].recording_id}.mp4")
            parser.extract_video(evidence, recordings[0], out_path)
            assert os.path.exists(out_path)
            assert os.path.exists(f"{out_path}.raw.h264")
            
    print("-----------------------------------------\n")
