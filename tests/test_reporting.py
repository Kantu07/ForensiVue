import pytest
import os
from forensivue.core.reporting import ReportGenerator

def test_report_generator(tmp_path):
    report_data = {
        "case_info": {"case_id": "TEST-123", "examiner": "Jane Doe"},
        "date": "2023-10-01 12:00:00 UTC",
        "tool_version": "v1.0",
        "acquisition": {"source": "fake.dd", "md5": "abc", "sha256": "def"},
        "identification": {"vendor": "Hikvision", "confidence": "100.0%"},
        "recordings": [
            {"recording_id": "1", "channel": 1, "start": "2023-01-01", "end": "2023-01-02", "status": "active", "confidence": "1.0"},
            {"recording_id": "2", "channel": 2, "start": "2023-01-02", "end": "2023-01-03", "status": "deleted", "confidence": "0.5"}
        ],
        "timeline": [
            {"channel": 1, "adjusted_start": "2023-01-01", "adjusted_end": "2023-01-02", "status": "active"}
        ],
        "verification": {"result": "VALID", "log_excerpt": "log line 1\nlog line 2"}
    }
    
    out_dir = str(tmp_path / "reports")
    rg = ReportGenerator(out_dir)
    
    html_out = os.path.join(out_dir, "test_report.html")
    pdf_out = os.path.join(out_dir, "test_report.pdf")
    
    rg.generate_html(report_data, html_out)
    rg.generate_pdf(report_data, pdf_out)
    
    assert os.path.exists(html_out)
    assert os.path.exists(pdf_out)
    
    # Check HTML content
    with open(html_out, "r", encoding="utf-8") as f:
        html = f.read()
        assert "TEST-123" in html
        assert "Hikvision" in html
        assert "Jane Doe" in html
        assert "LIMITATIONS NOTICE" in html
