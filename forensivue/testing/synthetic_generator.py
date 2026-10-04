import os
import subprocess
import tempfile
import struct
import hashlib
import json
import time

FLAG_VALID = 1
FLAG_DELETED = 0
FLAG_DAMAGED = 2

class SyntheticImageBuilder:
    def __init__(self, vendor_style="Hikvision", image_size_mb=10):
        self.vendor_style = vendor_style
        self.image_size = image_size_mb * 1024 * 1024
        self.data = bytearray(self.image_size)
        self.recordings = []
        self.next_offset = 1024 * 1024  # Start data at 1MB
        
        self._write_header()
        
    def _write_header(self):
        # Disclaimer
        disclaimer = b"WARNING: SYNTHETIC IMAGE MODELED ON ASSUMED LAYOUTS. NOT A REAL VENDOR FORMAT."
        self.data[0:len(disclaimer)] = disclaimer
        
        # Magic bytes
        if self.vendor_style == "Hikvision":
            magic = bytes.fromhex("48494B564953494F4E")
            self.data[512:512+len(magic)] = magic
        elif self.vendor_style == "Dahua":
            magic = bytes.fromhex("44484156")
            self.data[1024:1024+len(magic)] = magic
            
    def _generate_video_chunk(self) -> bytes:
        """Generates a raw H.264 video stream using ffmpeg lavfi testsrc."""
        with tempfile.NamedTemporaryFile(suffix=".h264", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            cmd = [
                "ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=duration=1:size=320x240:rate=10",
                "-c:v", "libx264", "-f", "h264", tmp_path
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            with open(tmp_path, "rb") as f:
                return f.read()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def add_recording(self, channel: int, start_ts: int, end_ts: int, fragmented: bool = False):
        video_bytes = self._generate_video_chunk()
        length = len(video_bytes)
        
        video_hash = hashlib.sha256(video_bytes).hexdigest()
        
        blocks = []
        
        if not fragmented:
            # Contiguous
            offset = self.next_offset
            self.data[offset:offset+length] = video_bytes
            self.next_offset += length
            blocks = [{"offset": offset, "length": length}]
        else:
            # Split into two pieces separated by a 100KB gap
            part1_len = length // 2
            part2_len = length - part1_len
            
            offset1 = self.next_offset
            self.data[offset1:offset1+part1_len] = video_bytes[:part1_len]
            
            offset2 = offset1 + part1_len + 102400 # 100KB gap
            self.data[offset2:offset2+part2_len] = video_bytes[part1_len:]
            
            self.next_offset = offset2 + part2_len
            
            blocks = [
                {"offset": offset1, "length": part1_len},
                {"offset": offset2, "length": part2_len}
            ]
            
        rec_id = len(self.recordings)
        self.recordings.append({
            "id": rec_id,
            "channel": channel,
            "start": start_ts,
            "end": end_ts,
            "blocks": blocks,
            "total_length": length,
            "sha256": video_hash,
            "status": FLAG_VALID
        })
        
        # Round up offset for neatness
        self.next_offset = ((self.next_offset // 4096) + 1) * 4096
        
        return rec_id

    def mark_deleted(self, rec_id: int):
        self.recordings[rec_id]["status"] = FLAG_DELETED

    def corrupt_block(self, rec_id: int, block_index: int = 0):
        rec = self.recordings[rec_id]
        rec["status"] = FLAG_DAMAGED
        offset = rec["blocks"][block_index]["offset"]
        length = rec["blocks"][block_index]["length"]
        
        # Corrupt the middle 100 bytes
        corrupt_start = offset + (length // 2)
        corrupt_end = min(corrupt_start + 100, offset + length)
        
        self.data[corrupt_start:corrupt_end] = b'\xFF' * (corrupt_end - corrupt_start)
        
        # Store original pre-corruption hash as 'sha256' is already done in add_recording
        # We just add a corrupted_ranges list to mark where the damage is
        rec["corrupted_ranges"] = [{"offset": corrupt_start, "length": corrupt_end - corrupt_start}]

    def _write_index(self):
        # Index table starts at 4096
        index_offset = 4096
        for rec in self.recordings:
            # We assume for simple index that we only store the first block in the main index
            # Real filesystems use inodes or linked lists, we just store block 0 for simplicity.
            # Format: <I I I I I H 42s
            first_block = rec["blocks"][0]
            struct_data = struct.pack(
                "<IIIIIH",
                rec["channel"],
                rec["start"],
                rec["end"],
                first_block["offset"],
                rec["total_length"],
                rec["status"]
            )
            # Pad to 64 bytes
            struct_data = struct_data.ljust(64, b'\x00')
            self.data[index_offset:index_offset+64] = struct_data
            index_offset += 64

    def build(self, output_path: str):
        self._write_index()
        with open(output_path, "wb") as f:
            f.write(self.data)
            
        json_path = output_path + ".json"
        with open(json_path, "w") as f:
            json.dump({"vendor": self.vendor_style, "recordings": self.recordings}, f, indent=4)
