import struct
import os
import subprocess
import tempfile
import hashlib
from typing import List, Dict, Any
from forensivue.core.interfaces import BaseVendorParser
from forensivue.core.models import EvidenceItem, Recording
from forensivue.core.time_utils import parse_unix_epoch

class SyntheticLayoutParserMixin:
    """
    Provides shared parsing logic for our SYNTHETIC testing layouts.
    Real vendor plugins will NOT use this, as proprietary formats are closed-source.
    """
    
    def _parse_synthetic_index(self, evidence: EvidenceItem) -> List[Recording]:
        recordings = []
        index_offset = 4096
        struct_fmt = "<IIIIIH"
        struct_size = 64
        
        with open(evidence.path, "rb") as f:
            f.seek(index_offset)
            while True:
                data = f.read(struct_size)
                if len(data) < struct_size:
                    break
                    
                # If first byte is 0, we assume end of index
                if data[0:4] == b'\x00\x00\x00\x00':
                    break
                    
                channel, start, end, offset, length, flags = struct.unpack(struct_fmt, data[:22])
                
                status_str = "active"
                if flags == 0:
                    status_str = "deleted"
                elif flags == 2:
                    status_str = "damaged"
                    
                rec = Recording(
                    recording_id=f"CH{channel}_{start}",
                    channel_id=channel,
                    start_time=parse_unix_epoch(start),
                    end_time=parse_unix_epoch(end),
                    file_path=evidence.path,
                    metadata={"synthetic_offset": offset, "synthetic_length": length, "flags": flags},
                    status=status_str
                )
                recordings.append(rec)
                
        return recordings

    def _extract_synthetic_video(self, evidence: EvidenceItem, recording: Recording, output_path: str) -> str:
        """Extracts the raw H.264 stream and converts it to MP4."""
        offset = recording.metadata["synthetic_offset"]
        length = recording.metadata["synthetic_length"]
        
        raw_path = f"{output_path}.raw.h264"
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(evidence.path, "rb") as src, open(raw_path, "wb") as dst:
            src.seek(offset)
            # Simplistic chunking (fragmented blocks aren't fully resolved in this basic parser 
            # for synthetic sake, we just read the length from the offset)
            bytes_left = length
            while bytes_left > 0:
                chunk = src.read(min(4096, bytes_left))
                if not chunk:
                    break
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                dst.write(chunk)
                bytes_left -= len(chunk)
                
        # Record the hashes in metadata (or log them)
        recording.metadata["md5"] = md5_hash.hexdigest()
        recording.metadata["sha256"] = sha256_hash.hexdigest()
        
        # Convert to MP4
        cmd = ["ffmpeg", "-y", "-i", raw_path, "-c", "copy", output_path]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return output_path
