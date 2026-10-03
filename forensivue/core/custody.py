import csv
import json
from fpdf import FPDF
from typing import List, Dict, Any

class CustodyExporter:
    """Exports the chain of custody audit log to standard formats."""
    def __init__(self, audit_log_path: str):
        self.audit_log_path = audit_log_path
        
    def _read_logs(self) -> List[Dict[str, Any]]:
        logs = []
        try:
            with open(self.audit_log_path, "r") as f:
                for line in f:
                    if line.strip():
                        logs.append(json.loads(line))
        except FileNotFoundError:
            pass
        return logs

    def export_csv(self, output_path: str):
        logs = self._read_logs()
        if not logs:
            return
            
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Action", "Details", "Hash"])
            for log in logs:
                details_str = json.dumps(log.get("details", {}))
                writer.writerow([log.get("timestamp"), log.get("action"), details_str, log.get("hash")])

    def export_pdf(self, output_path: str):
        logs = self._read_logs()
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=10)
        
        pdf.cell(0, 10, text="ForensiVue - Chain of Custody Audit Log", new_y="NEXT", new_x="LMARGIN", align="C")
        
        for log in logs:
            action = log.get('action', '')
            ts = log.get('timestamp', '')
            details = json.dumps(log.get('details', {}))
            
            line = f"[{ts}] {action}: {details}"
            pdf.multi_cell(0, 6, text=line)
            
        pdf.output(output_path)
