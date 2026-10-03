import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ReportGenerator:
    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)
        
    def generate_html(self, report_data: dict, output_path: str):
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ForensiVue Report - Case {report_data['case_info']['case_id']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }}
                h1, h2, h3 {{ color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .alert {{ background-color: #ffdddd; border-left: 6px solid #f44336; padding: 10px; margin-bottom: 15px; }}
            </style>
        </head>
        <body>
            <h1>ForensiVue - Forensic Analysis Report</h1>
            <div class="alert">
                <strong>LIMITATIONS NOTICE:</strong> Testing images are SYNTHETIC assumptions and signatures are placeholders. They do not represent verified closed-source vendor formats.
            </div>
            
            <h2>Case Information</h2>
            <p><strong>Case ID:</strong> {report_data['case_info']['case_id']}</p>
            <p><strong>Examiner:</strong> {report_data['case_info']['examiner']}</p>
            <p><strong>Date:</strong> {report_data['date']}</p>
            <p><strong>Tool Version:</strong> {report_data['tool_version']}</p>

            <h2>Acquisition Details</h2>
            <p><strong>Source:</strong> {report_data['acquisition']['source']}</p>
            <p><strong>MD5:</strong> {report_data['acquisition']['md5']}</p>
            <p><strong>SHA-256:</strong> {report_data['acquisition']['sha256']}</p>

            <h2>Device Identification</h2>
            <p><strong>Vendor Matched:</strong> {report_data['identification']['vendor']}</p>
            <p><strong>Confidence:</strong> {report_data['identification']['confidence']}</p>

            <h2>Recordings (Parsed & Recovered)</h2>
            <table>
                <tr><th>ID</th><th>Channel</th><th>Start</th><th>End</th><th>Status</th><th>Confidence</th></tr>
                {''.join([f"<tr><td>{r['recording_id']}</td><td>{r['channel']}</td><td>{r['start']}</td><td>{r['end']}</td><td>{r['status']}</td><td>{r.get('confidence', '1.0')}</td></tr>" for r in report_data['recordings']])}
            </table>
            
            <h2>Timeline</h2>
            <table>
                <tr><th>Channel</th><th>Start (UTC)</th><th>End (UTC)</th><th>Status</th></tr>
                {''.join([f"<tr><td>{t['channel']}</td><td>{t['adjusted_start']}</td><td>{t['adjusted_end']}</td><td>{t['status']}</td></tr>" for t in report_data['timeline']])}
            </table>

            <h2>Chain of Custody & Hash Verification</h2>
            <p><strong>Verification Result:</strong> {report_data['verification']['result']}</p>
            <pre style="background: #f4f4f4; padding: 10px; overflow-x: auto; white-space: pre-wrap; font-size: 10px;">{report_data['verification']['log_excerpt']}</pre>

            <br><br>
            <p>_____________________________________</p>
            <p>Examiner Signature</p>
        </body>
        </html>
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def generate_pdf(self, report_data: dict, output_path: str):
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        
        alert_style = ParagraphStyle(
            'Alert', parent=styles['Normal'], backColor=colors.pink,
            textColor=colors.darkred, spaceBefore=10, spaceAfter=10, padding=10
        )
        
        story = []
        
        story.append(Paragraph("ForensiVue - Forensic Analysis Report", styles['Title']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("LIMITATIONS NOTICE: Testing images are SYNTHETIC assumptions and signatures are placeholders. They do not represent verified closed-source vendor formats.", alert_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Case Information", styles['Heading2']))
        story.append(Paragraph(f"Case ID: {report_data['case_info']['case_id']}", styles['Normal']))
        story.append(Paragraph(f"Examiner: {report_data['case_info']['examiner']}", styles['Normal']))
        story.append(Paragraph(f"Date: {report_data['date']}", styles['Normal']))
        story.append(Paragraph(f"Tool Version: {report_data['tool_version']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Acquisition Details", styles['Heading2']))
        story.append(Paragraph(f"Source: {report_data['acquisition']['source']}", styles['Normal']))
        story.append(Paragraph(f"MD5: {report_data['acquisition']['md5']}", styles['Normal']))
        story.append(Paragraph(f"SHA-256: {report_data['acquisition']['sha256']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Device Identification", styles['Heading2']))
        story.append(Paragraph(f"Vendor Matched: {report_data['identification']['vendor']}", styles['Normal']))
        story.append(Paragraph(f"Confidence: {report_data['identification']['confidence']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Recordings (Parsed & Recovered)", styles['Heading2']))
        rec_data = [["ID", "Ch", "Start", "End", "Status", "Conf"]]
        for r in report_data['recordings']:
            # Truncate strings to prevent PDF cell overflow
            start_str = str(r['start'])[:19]
            end_str = str(r['end'])[:19]
            rec_data.append([str(r['recording_id'])[:10], str(r['channel']), start_str, end_str, str(r['status']), str(r.get('confidence', '1.0'))])
            
        if len(rec_data) > 1:
            t = Table(rec_data, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.beige),
                ('GRID', (0,0), (-1,-1), 0.5, colors.black)
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No recordings found.", styles['Normal']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Timeline (Sample)", styles['Heading2']))
        tl_data = [["Channel", "Start (UTC)", "End (UTC)", "Status"]]
        # Limit to first 20 to avoid massive PDF for now
        for t_ev in report_data['timeline'][:20]:
            tl_data.append([str(t_ev['channel']), str(t_ev['adjusted_start'])[:19], str(t_ev['adjusted_end'])[:19], str(t_ev['status'])])
            
        if len(tl_data) > 1:
            t2 = Table(tl_data, repeatRows=1)
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.black)
            ]))
            story.append(t2)
        
        story.append(Spacer(1, 12))
        story.append(Paragraph("Chain of Custody & Verification", styles['Heading2']))
        story.append(Paragraph(f"Result: {report_data['verification']['result']}", styles['Normal']))
        story.append(Spacer(1, 30))
        
        story.append(Paragraph("_____________________________________", styles['Normal']))
        story.append(Paragraph("Examiner Signature", styles['Normal']))
        
        doc.build(story)
