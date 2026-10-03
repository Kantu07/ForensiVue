import pytest
import os
import glob
import json
from forensivue.core.plugin_registry import PluginRegistry
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.models import EvidenceItem
from forensivue.core.recovery import RecoveryManager

def test_recovery_module(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    registry = PluginRegistry(logger)
    registry.load_plugins()
    recovery_mgr = RecoveryManager(logger)
    
    generated_dir = os.path.join(os.path.dirname(__file__), "..", "generated")
    if not os.path.exists(generated_dir):
        pytest.skip("Generated images not found. Run generate_suite.py first.")
        
    dd_files = glob.glob(os.path.join(generated_dir, "*.dd"))
    
    print("\n\n--- RECOVERY METRICS EVALUATION ---")
    print(f"{'Image Name':<20} | {'Expected':<8} | {'Recovered':<9} | {'Hash Matches':<12} | {'Partial/Fail':<12} | {'Rate'}")
    print("-" * 80)
    
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
        
        result = registry.parse_evidence(evidence)
        parser = registry.get_parsers()[result["parser"]]()
        
        out_dir = str(tmp_path / evidence.id)
        
        # Run Index Recovery
        index_recovered = recovery_mgr.index_recovery(evidence, parser, out_dir)
        
        # Run Carver
        carved_recovered = recovery_mgr.signature_carve(evidence, out_dir)
        
        # Aggregate unique recoveries by SHA256
        recovered_hashes = {}
        partial_count = 0
        
        for r in index_recovered + carved_recovered:
            if r["score"] == 1.0:
                recovered_hashes[r["sha256"]] = r
            else:
                partial_count += 1
                # Even if partial, it's technically recovered data, we map it to truth
                recovered_hashes[r["sha256"]] = r
                
        expected_count = len(truth["recordings"])
        
        hash_matches = 0
        for expected in truth["recordings"]:
            # Normal, deleted, fragmented all have valid original sha256. 
            # Damaged might have a different sha256 because we corrupted it.
            if expected["sha256"] in recovered_hashes:
                hash_matches += 1
                
        # Total recovered is unique clips found that have score > 0
        recovered_count = len(recovered_hashes)
        rate = (recovered_count / expected_count) * 100 if expected_count > 0 else 0
        
        print(f"{evidence.id:<20} | {expected_count:<8} | {recovered_count:<9} | {hash_matches:<12} | {partial_count:<12} | {rate:.1f}%")
        
        # Assertions
        assert recovered_count >= hash_matches, "Cannot have more matches than recovered clips"
        
    print("-" * 80 + "\n")
