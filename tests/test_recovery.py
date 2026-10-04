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
    print(f"{'Image Name':<16} | {'Expected'} | {'Index exact'} | {'Carve exact'} | {'Combined exact'} | {'Damaged-rec'} | {'Decodable'} | {'Spurious'} | {'Rate'}")
    print("-" * 115)
    
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
        
        index_recovered = recovery_mgr.index_recovery(evidence, parser, out_dir)
        carved_recovered = recovery_mgr.signature_carve(evidence, out_dir)
        
        recovered_all = index_recovered + carved_recovered
        decodable_count = sum(1 for r in recovered_all if r["score"] == 1.0)
        
        expected_count = len(truth["recordings"])
        
        index_hashes = set(r["sha256"] for r in index_recovered)
        carve_hashes = set(r["sha256"] for r in carved_recovered)
        all_hashes = index_hashes.union(carve_hashes)
        
        index_exact = 0
        carve_exact = 0
        combined_exact = 0
        damaged_rec = 0
        
        for expected in truth["recordings"]:
            is_damaged = expected.get("status") == 2 or "corrupted_ranges" in expected
            matched_exact = expected["sha256"] in all_hashes
            
            if matched_exact:
                combined_exact += 1
                if expected["sha256"] in index_hashes: index_exact += 1
                if expected["sha256"] in carve_hashes: carve_exact += 1
            elif is_damaged:
                # Did we recover a decodable stream for this damaged file? 
                # Damaged files won't match the original exact hash.
                # If we recovered *something* decodable that isn't exact, count as damaged-recovered.
                # Since we don't have a 1:1 map, we just assume if there's an unmatched decodable clip, it's this one.
                # Or wait, is there a better way? Just check if we have ANY recovered clip with score > 0 that doesn't match an original hash.
                pass
                
        # To accurately count damaged_rec and spurious:
        # A recovered item is "spurious" if its hash is not in any expected["sha256"] AND it's not a damaged-recovered clip.
        expected_hashes = set(e["sha256"] for e in truth["recordings"])
        damaged_rec_candidates = [r for r in recovered_all if r["sha256"] not in expected_hashes and r["score"] > 0.0]
        
        damaged_expected_count = sum(1 for e in truth["recordings"] if e.get("status") == 2 or "corrupted_ranges" in e)
        # We cap damaged_rec to the number of expected damaged files
        damaged_rec = min(damaged_expected_count, len(set(r["sha256"] for r in damaged_rec_candidates)))
        
        spurious = len(set(r["sha256"] for r in recovered_all)) - combined_exact - damaged_rec
        if spurious < 0: spurious = 0
        
        rate = (combined_exact / expected_count) * 100 if expected_count > 0 else 0
        
        print(f"{evidence.id:<16} | {expected_count:<8} | {index_exact:<11} | {carve_exact:<11} | {combined_exact:<14} | {damaged_rec:<11} | {decodable_count:<9} | {spurious:<8} | {rate:.1f}%")
        
        assert rate <= 100.0, "Recovery rate must never exceed 100%"
        
    print("-" * 115 + "\n")
