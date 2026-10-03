import pytest
from forensivue.core.time_utils import parse_dvr_time

def test_parse_dvr_time_valid():
    # 2026-10-03 10:00:00 in +05:30 offset
    ft = parse_dvr_time("2026-10-03 10:00:00", offset_hours=5.5)
    assert ft.raw_value == "2026-10-03 10:00:00"
    assert ft.detected_offset == "+5.5 hours"
    assert ft.utc_iso8601 == "2026-10-03T04:30:00+00:00"

def test_parse_dvr_time_invalid_format():
    with pytest.raises(ValueError, match="Unrecognized time format"):
        parse_dvr_time("10:00 2026/10/03")
