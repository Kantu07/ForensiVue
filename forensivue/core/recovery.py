import os
import subprocess
import hashlib
import tempfile
from typing import List, Dict, Any
from forensivue.core.models import EvidenceItem, Recording
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.interfaces import BaseVendorParser

class RecoveryManager:
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger

    def _validate_clip_data(self, data: bytes) -> float:
        """
        Validates raw H.264 data using ffmpeg decoding.
        Returns 1.0 for perfect decode, 0.5 for partial/damaged, 0.0 for failed.
        """
        if not data or b'\x00\x00\x00\x01' not in data:
            return 0.0
            
        with tempfile.NamedTemporaryFile(suffix=".h264", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
            
        try:
            cmd = ["ffmpeg", "-v", "error", "-i", tmp_path, "-f", "null", "-"]
            result = subprocess.run(cmd, stderr=subprocess.PIPE, text=True)
            
            # If no errors reported, it's perfect
            if result.returncode == 0 and not result.stderr.strip():
                return 1.0
                
            # If it failed entirely or has massive errors
            err = result.stderr.lower()
            if "invalid data found" in err and "moov atom not found" in err:
                return 0.0
                
            # Partial decodes (e.g. damaged blocks but still playable)
            if "error" in err or "corrupt" in err or "missing picture in access unit" in err:
                # Check if it decoded at least some frames
                cmd_probe = ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", tmp_path]
                probe_res = subprocess.run(cmd_probe, capture_output=True, text=True)
                if probe_res.stdout.strip():
                    return 0.5
                return 0.0
                
            return 1.0
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def index_recovery(self, evidence: EvidenceItem, parser: BaseVendorParser, output_dir: str) -> List[Dict]:
        """
        Recovers recordings marked as deleted/free in the index table.
        """
        self.audit_logger.log_action("INDEX_RECOVERY_START", {"evidence": evidence.id})
        os.makedirs(output_dir, exist_ok=True)
        
        recovered = []
        recordings = parser.list_recordings(evidence)
        
        with open(evidence.path, "rb") as f:
            for rec in recordings:
                offset = rec.metadata.get("synthetic_offset")
                length = rec.metadata.get("synthetic_length")
                
                if offset is not None and length is not None:
                    f.seek(offset)
                    data = f.read(length)
                    
                    score = self._validate_clip_data(data)
                    if score > 0:
                        # We can recover this
                        out_path = os.path.join(output_dir, f"recovered_index_{rec.recording_id}.h264")
                        with open(out_path, "wb") as out_f:
                            out_f.write(data)
                            
                        md5_val = hashlib.md5(data).hexdigest()
                        sha256_val = hashlib.sha256(data).hexdigest()
                        
                        res = {
                            "method": "index",
                            "original_id": rec.recording_id,
                            "path": out_path,
                            "score": score,
                            "md5": md5_val,
                            "sha256": sha256_val,
                            "offset": offset,
                            "length": length
                        }
                        recovered.append(res)
                        self.audit_logger.log_action("INDEX_RECOVERY_SUCCESS", res)
                            
        self.audit_logger.log_action("INDEX_RECOVERY_COMPLETE", {"recovered_count": len(recovered)})
        return recovered

    def signature_carve(self, evidence: EvidenceItem, output_dir: str) -> List[Dict]:
        """
        Scans raw image for H.264 NAL starts. Groups them into valid video segments.
        Handles fragmentation by checking sequence continuity via ffmpeg validation.
        """
        self.audit_logger.log_action("CARVE_START", {"evidence": evidence.id})
        os.makedirs(output_dir, exist_ok=True)
        
        with open(evidence.path, "rb") as f:
            data = f.read()
            
        chunks = []
        zero_pad = b'\x00' * 4096
        start = 0
        
        # 1. Identify dense data chunks separated by large zero padding
        while start < len(data):
            zero_start = start
            while start < len(data) and data[start] == 0:
                start += 1
            if start >= len(data):
                break
                
            # Backtrack to preserve H264 NAL start codes (00 00 00 01)
            # Only backtrack if the first non-zero byte is 0x01
            if start < len(data) and data[start] == 1:
                backtrack = min(3, start - zero_start)
                start -= backtrack
                
            end = data.find(zero_pad, start)
            if end == -1:
                end = len(data)
                
            chunk_data = data[start:end]
            if b'\x00\x00\x00\x01' in chunk_data:
                # To avoid prepending disk headers, start at the first SPS NAL unit if present
                sps_idx = chunk_data.find(b'\x00\x00\x00\x01\x67')
                if sps_idx != -1:
                    chunk_data = chunk_data[sps_idx:]
                    start += sps_idx
                chunks.append({"offset": start, "length": len(chunk_data), "data": chunk_data})
                
            # If we adjusted start for SPS, end was still based on the original start.
            # Next start should be end + padding length.
            start = end + len(zero_pad)
            
        # 2. Reconstruct and Validate
        recovered = []
        i = 0
        while i < len(chunks):
            candidate_data = chunks[i]["data"]
            offsets_used = [chunks[i]["offset"]]
            lengths_used = [chunks[i]["length"]]
            
            # Check if this chunk is part of a fragmented file by stitching with the next
            if i + 1 < len(chunks):
                stitched_data = candidate_data + chunks[i+1]["data"]
                # If stitching produces a perfect validation, we assume they belong together
                if self._validate_clip_data(stitched_data) == 1.0:
                    candidate_data = stitched_data
                    offsets_used.append(chunks[i+1]["offset"])
                    lengths_used.append(chunks[i+1]["length"])
                    i += 1 # consume the next chunk
                    
            score = self._validate_clip_data(candidate_data)
            if score > 0:
                out_path = os.path.join(output_dir, f"recovered_carve_{offsets_used[0]}.h264")
                with open(out_path, "wb") as out_f:
                    out_f.write(candidate_data)
                    
                md5_val = hashlib.md5(candidate_data).hexdigest()
                sha256_val = hashlib.sha256(candidate_data).hexdigest()
                
                res = {
                    "method": "carve",
                    "path": out_path,
                    "score": score,
                    "md5": md5_val,
                    "sha256": sha256_val,
                    "offsets": offsets_used,
                    "lengths": lengths_used
                }
                recovered.append(res)
                self.audit_logger.log_action("CARVE_SUCCESS", res)
                
            i += 1
            
        self.audit_logger.log_action("CARVE_COMPLETE", {"recovered_count": len(recovered)})
        return recovered
