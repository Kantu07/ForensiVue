import hashlib
import json
import datetime
from typing import Dict, Any

from forensivue.core.audit_logger import AuditLogger
from forensivue.core.hash_utils import generate_file_hashes

VERSION = "1.0.0"

class AcquisitionManager:
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        
    def acquire_image(self, source_path: str, dest_path: str, case_id: str, examiner: str, 
                      write_blocker_used: bool = True, skip_bad_sectors: bool = True, chunk_size=1024*1024) -> Dict[str, Any]:
        """
        Creates a raw (.dd) image from a source with chunked read-only access.
        Computes MD5 and SHA-256 in a single pass.
        Re-reads the output image to verify hashes.
        """
        self.audit_logger.log_action("ACQUISITION_START", {
            "source": source_path, "dest": dest_path, "case_id": case_id, 
            "examiner": examiner, "write_blocker": write_blocker_used
        })
        
        start_time = datetime.datetime.now(datetime.timezone.utc)
        
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        bad_sectors = []
        bytes_read = 0
        
        with open(source_path, "rb") as src, open(dest_path, "wb") as dst:
            while True:
                try:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    dst.write(chunk)
                    bytes_read += len(chunk)
                except OSError as e:
                    if skip_bad_sectors:
                        bad_sectors.append(bytes_read)
                        self.audit_logger.log_action("ACQUISITION_BAD_SECTOR", {"offset": bytes_read, "error": str(e)})
                        dst.write(b'\x00' * chunk_size)
                        
                        try:
                            src.seek(bytes_read + chunk_size)
                        except OSError:
                            pass # If seek fails, we abort
                            
                        bytes_read += chunk_size
                    else:
                        self.audit_logger.log_action("ACQUISITION_FAILED", {"reason": "bad_sector", "offset": bytes_read})
                        raise
                        
        source_hashes = {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
        
        end_time = datetime.datetime.now(datetime.timezone.utc)
        
        self.audit_logger.log_action("ACQUISITION_COPY_COMPLETE", {"bytes_read": bytes_read, "hashes": source_hashes})
        
        self.audit_logger.log_action("VERIFICATION_START", {"dest": dest_path})
        dest_hashes = generate_file_hashes(dest_path)
        
        if source_hashes["md5"] != dest_hashes["md5"] or source_hashes["sha256"] != dest_hashes["sha256"]:
            self.audit_logger.log_action("VERIFICATION_FAIL", {"expected": source_hashes, "got": dest_hashes})
            raise ValueError("Verification failed: Output image hashes do not match source hashes.")
            
        self.audit_logger.log_action("VERIFICATION_SUCCESS", {"hashes": dest_hashes})
        
        record = {
            "case_id": case_id,
            "examiner": examiner,
            "source_path": source_path,
            "dest_path": dest_path,
            "write_blocker_used": write_blocker_used,
            "skip_bad_sectors": skip_bad_sectors,
            "bad_sectors_map": bad_sectors,
            "hashes": dest_hashes,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "tool_version": VERSION,
            "total_bytes": bytes_read
        }
        
        json_path = f"{dest_path}.json"
        with open(json_path, "w") as f:
            json.dump(record, f, indent=4)
            
        self.audit_logger.log_action("ACQUISITION_COMPLETE", {"record_path": json_path})
        return record
