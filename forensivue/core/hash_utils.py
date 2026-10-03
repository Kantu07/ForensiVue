import hashlib
import os

def generate_file_hashes(file_path: str) -> dict[str, str]:
    """
    Generates MD5 and SHA-256 hashes for a given file.
    Reads in chunks to handle large files efficiently.
    """
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
        
    return {
        "md5": md5_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest()
    }

def generate_string_hash(data: str) -> str:
    """
    Generates a SHA-256 hash for a given string (used for audit chaining).
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
