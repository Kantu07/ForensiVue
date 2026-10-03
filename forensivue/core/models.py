from dataclasses import dataclass
from typing import Optional, Dict, Any
from forensivue.core.time_utils import ForensicTime

@dataclass
class EvidenceItem:
    """Represents a piece of digital evidence (e.g., a forensic image or raw disk)."""
    id: str
    path: str
    acquisition_hash_md5: str
    acquisition_hash_sha256: str
    notes: Optional[str] = None

@dataclass
class Channel:
    """Represents a camera channel in the DVR/NVR."""
    channel_id: int
    name: str
    resolution: Optional[str] = None

@dataclass
class Recording:
    """Represents an extracted or identified video recording."""
    recording_id: str
    channel_id: int
    start_time: ForensicTime
    end_time: ForensicTime
    file_path: str
    metadata: Dict[str, Any]
