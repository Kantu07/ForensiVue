import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
from forensivue.core.models import Recording
from forensivue.core.audit_logger import AuditLogger

class TimelineEvent:
    def __init__(self, rec: Recording, source_method: str = "index"):
        self.recording_id = rec.recording_id
        self.channel_id = rec.channel_id
        self.original_start = rec.start_time.utc_iso8601
        self.original_end = rec.end_time.utc_iso8601
        
        self.adjusted_start = self.original_start
        self.adjusted_end = self.original_end
        self.correction_seconds = 0.0
        
        self.status = rec.status
        self.source_method = source_method
        
        # Keep original raw values just in case
        self.raw_start = rec.start_time.raw_value
        self.raw_end = rec.end_time.raw_value
        self.metadata = rec.metadata

    def _iso_to_epoch(self, iso_str: str) -> float:
        try:
            dt = datetime.fromisoformat(iso_str)
            return dt.timestamp()
        except ValueError:
            return 0.0

    def get_start_epoch(self) -> float:
        return self._iso_to_epoch(self.adjusted_start)

    def get_end_epoch(self) -> float:
        return self._iso_to_epoch(self.adjusted_end)

    def apply_offset(self, seconds: float):
        if not self.original_start or not self.original_end:
            return
            
        self.correction_seconds += seconds
        
        try:
            start_dt = datetime.fromisoformat(self.original_start) + timedelta(seconds=self.correction_seconds)
            end_dt = datetime.fromisoformat(self.original_end) + timedelta(seconds=self.correction_seconds)
            
            self.adjusted_start = start_dt.isoformat()
            self.adjusted_end = end_dt.isoformat()
        except Exception:
            self.adjusted_start = "unknown"
            self.adjusted_end = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recording_id": self.recording_id,
            "channel": self.channel_id,
            "adjusted_start": self.adjusted_start,
            "adjusted_end": self.adjusted_end,
            "original_start": self.original_start,
            "original_end": self.original_end,
            "correction_seconds": self.correction_seconds,
            "status": self.status,
            "source": self.source_method
        }

class TimelineManager:
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.events: List[TimelineEvent] = []

    def add_recordings(self, recordings: List[Recording], source_method: str = "index"):
        for rec in recordings:
            self.events.append(TimelineEvent(rec, source_method))
            
    def detect_clock_drift(self) -> float:
        """
        Detects clock drift by comparing index time with an embedded filesystem time 
        if available in the metadata. Returns the average drift in seconds.
        """
        drifts = []
        for ev in self.events:
            fs_time_str = ev.metadata.get("fs_creation_time")
            if fs_time_str and ev.original_start != "unknown":
                try:
                    fs_epoch = datetime.fromisoformat(fs_time_str).timestamp()
                    idx_epoch = ev._iso_to_epoch(ev.original_start)
                    drifts.append(fs_epoch - idx_epoch)
                except ValueError:
                    pass
                    
        if not drifts:
            return 0.0
        return sum(drifts) / len(drifts)

    def apply_manual_correction(self, offset_seconds: float, reason: str):
        self.audit_logger.log_action("TIMELINE_CORRECTION", {
            "offset_seconds": offset_seconds,
            "reason": reason,
            "event_count": len(self.events)
        })
        
        for ev in self.events:
            ev.apply_offset(offset_seconds)

    def get_unified_timeline(self) -> List[Dict[str, Any]]:
        # Sort by adjusted start time
        self.events.sort(key=lambda e: e.get_start_epoch())
        return [e.to_dict() for e in self.events]
        
    def find_correlated_events(self, max_gap_seconds: float) -> List[Tuple[Dict, Dict]]:
        """
        Finds events on different channels that occur within max_gap_seconds of each other.
        """
        correlations = []
        # Ensure sorted
        self.events.sort(key=lambda e: e.get_start_epoch())
        
        for i in range(len(self.events)):
            for j in range(i + 1, len(self.events)):
                ev1 = self.events[i]
                ev2 = self.events[j]
                
                if ev1.channel_id == ev2.channel_id:
                    continue
                    
                # Since sorted by start time, ev2.start >= ev1.start
                # The gap is distance between ev1.end and ev2.start if ev2 starts after ev1 ends
                # Otherwise they overlap (gap = 0)
                if ev2.get_start_epoch() > ev1.get_end_epoch():
                    gap = ev2.get_start_epoch() - ev1.get_end_epoch()
                else:
                    gap = 0.0
                    
                if gap <= max_gap_seconds:
                    correlations.append((ev1.to_dict(), ev2.to_dict()))
                else:
                    # Because they are sorted by start time, eventually the gap will always be larger
                    # Wait, ev2.start could be far ahead. But we can't completely break here because 
                    # there might be long events overlapping. 
                    # Just a simple break if start gap > max_gap_seconds + max_duration
                    # To be safe and simple, we can just compute all pairs if the list is small.
                    if (ev2.get_start_epoch() - ev1.get_start_epoch()) > max_gap_seconds + 86400:
                        break
                        
        return correlations
