import os
import pytest
from forensivue.core.hash_utils import generate_file_hashes, generate_string_hash

def test_generate_string_hash():
    # Known SHA-256 for "test"
    assert generate_string_hash("test") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

def test_generate_file_hashes(tmp_path):
    test_file = tmp_path / "evidence.bin"
    test_file.write_text("forensic_data")
    
    hashes = generate_file_hashes(str(test_file))
    
    # "forensic_data" hashes
    assert hashes["md5"] == "76e27889b92339526a419c266f44f38d"
    assert hashes["sha256"] == "ddb0783bce8129748ec82cc16e1bf378bebf4679367ddd1ded4f0ad4589e912a"

def test_missing_file():
    with pytest.raises(FileNotFoundError):
        generate_file_hashes("non_existent_file.bin")
