import pytest
import os
import json
import hashlib
from forensivue.testing.synthetic_generator import SyntheticImageBuilder

def verify_image_consistency(img_path):
    assert os.path.exists(str(img_path))
    json_path = f"{img_path}.json"
    assert os.path.exists(json_path)
    
    with open(json_path, "r") as f:
        meta = json.load(f)
        
    with open(str(img_path), "rb") as f:
        for rec in meta["recordings"]:
            full_data = bytearray()
            for b in rec["blocks"]:
                f.seek(b["offset"])
                full_data.extend(f.read(b["length"]))
                
            actual_hash = hashlib.sha256(full_data).hexdigest()
            if rec.get("status") == 2:  # FLAG_DAMAGED
                # Damaged files have physically altered bytes, so hash won't match the original
                pass
            else:
                assert actual_hash == rec["sha256"], f"Hash mismatch for rec {rec['id']}"
    return meta

def test_synthetic_generator_normal(tmp_path):
    img = tmp_path / "normal.dd"
    builder = SyntheticImageBuilder("Hikvision", 2)
    builder.add_recording(1, 100, 200)
    builder.build(str(img))
    meta = verify_image_consistency(img)
    assert meta["vendor"] == "Hikvision"
    assert len(meta["recordings"]) == 1

def test_synthetic_generator_fragmented(tmp_path):
    img = tmp_path / "fragmented.dd"
    builder = SyntheticImageBuilder("Dahua", 2)
    builder.add_recording(1, 100, 200, fragmented=True)
    builder.build(str(img))
    meta = verify_image_consistency(img)
    assert len(meta["recordings"][0]["blocks"]) == 2

def test_synthetic_generator_deleted(tmp_path):
    img = tmp_path / "deleted.dd"
    builder = SyntheticImageBuilder("Hikvision", 2)
    rec1 = builder.add_recording(1, 100, 200)
    builder.mark_deleted(rec1)
    builder.build(str(img))
    meta = verify_image_consistency(img)
    assert meta["recordings"][0]["status"] == 0 # FLAG_DELETED

def test_synthetic_generator_damaged(tmp_path):
    img = tmp_path / "damaged.dd"
    builder = SyntheticImageBuilder("Dahua", 2)
    rec1 = builder.add_recording(1, 100, 200)
    builder.corrupt_block(rec1)
    builder.build(str(img))
    meta = verify_image_consistency(img)
    assert meta["recordings"][0]["status"] == 2 # FLAG_DAMAGED

def test_synthetic_generator_multichannel(tmp_path):
    img = tmp_path / "multi_channel.dd"
    builder = SyntheticImageBuilder("Hikvision", 4)
    builder.add_recording(1, 100, 200)
    builder.add_recording(2, 100, 200)
    builder.add_recording(3, 100, 200)
    builder.build(str(img))
    meta = verify_image_consistency(img)
    assert len(meta["recordings"]) == 3
    assert meta["recordings"][1]["channel"] == 2

def test_synthetic_generator_mixed(tmp_path):
    img = tmp_path / "mixed.dd"
    builder = SyntheticImageBuilder("Dahua", 5)
    r1 = builder.add_recording(1, 100, 200)
    r2 = builder.add_recording(2, 200, 300, fragmented=True)
    r3 = builder.add_recording(1, 300, 400)
    builder.mark_deleted(r1)
    builder.corrupt_block(r3)
    builder.build(str(img))
    meta = verify_image_consistency(img)
    assert meta["recordings"][0]["status"] == 0
    assert len(meta["recordings"][1]["blocks"]) == 2
    assert meta["recordings"][2]["status"] == 2
