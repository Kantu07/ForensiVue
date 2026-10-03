from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

@dataclass
class ForensicTime:
    """
    Represents a timestamp with forensic integrity.
    Maintains the raw value parsed from the DVR and the UTC standard time.
    """
    raw_value: str
    detected_offset: str
    utc_iso8601: str

def parse_dvr_time(raw_time_str: str, time_format: str = "%Y-%m-%d %H:%M:%S", offset_hours: int = 0) -> ForensicTime:
    """
    Parses a DVR timestamp into a ForensicTime object.
    Requires an explicit offset to calculate true UTC time.
    
    If the parse fails, it raises ValueError to ensure no fabrication.
    """
    try:
        dt_naive = datetime.strptime(raw_time_str, time_format)
    except ValueError as e:
        raise ValueError(f"Unrecognized time format '{raw_time_str}' for format '{time_format}'") from e
    
    # Calculate UTC time based on the provided offset
    offset_seconds = offset_hours * 3600
    tz = timezone(timedelta(seconds=offset_seconds))
    dt_aware = dt_naive.replace(tzinfo=tz)
    
    # Convert to UTC
    dt_utc = dt_aware.astimezone(timezone.utc)
    
    offset_str = f"{offset_hours:+} hours"
    
    return ForensicTime(
        raw_value=raw_time_str,
        detected_offset=offset_str,
        utc_iso8601=dt_utc.isoformat()
    )

def parse_unix_epoch(epoch: int, offset_hours: int = 0) -> ForensicTime:
    """Parses a UNIX epoch timestamp into a ForensicTime object."""
    # Convert epoch to naive UTC datetime, then treat as UTC
    dt_utc = datetime.fromtimestamp(epoch, tz=timezone.utc)
    
    # DVRs often store local time in epoch or real epoch.
    # Assuming the epoch is true UTC epoch for our synthetic layout.
    dt_local = dt_utc + timedelta(hours=offset_hours)
    
    raw_val = dt_local.strftime("%Y-%m-%d %H:%M:%S")
    offset_str = f"{offset_hours:+} hours"
    
    return ForensicTime(
        raw_value=raw_val,
        detected_offset=offset_str,
        utc_iso8601=dt_utc.isoformat()
    )
