import argparse
import sys
import json
from forensivue.core.audit_logger import AuditLogger
from forensivue.core.acquisition import AcquisitionManager
from forensivue.core.custody import CustodyExporter

def main():
    parser = argparse.ArgumentParser(description="ForensiVue CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Acquire
    acquire_parser = subparsers.add_parser("acquire", help="Acquire a forensic raw image")
    acquire_parser.add_argument("--source", required=True, help="Source device or file path")
    acquire_parser.add_argument("--dest", required=True, help="Destination .dd output path")
    acquire_parser.add_argument("--case", required=True, help="Case ID")
    acquire_parser.add_argument("--examiner", required=True, help="Examiner Name")
    acquire_parser.add_argument("--audit-log", default="audit.jsonl", help="Audit log path")
    
    # Verify Chain
    verify_parser = subparsers.add_parser("verify_chain", help="Verify the cryptographic audit chain")
    verify_parser.add_argument("--audit-log", default="audit.jsonl", help="Audit log path")
    
    # Export Custody
    export_parser = subparsers.add_parser("export_custody", help="Export custody chain to CSV/PDF")
    export_parser.add_argument("--audit-log", default="audit.jsonl", help="Audit log path")
    export_parser.add_argument("--csv", help="Output CSV path")
    export_parser.add_argument("--pdf", help="Output PDF path")
    
    # Timeline
    timeline_parser = subparsers.add_parser("timeline", help="Build unified timeline and find correlations")
    timeline_parser.add_argument("--source", required=True, help="Source evidence image")
    timeline_parser.add_argument("--audit-log", default="audit.jsonl", help="Audit log path")
    timeline_parser.add_argument("--json", action="store_true", help="Output as JSON")
    timeline_parser.add_argument("--table", action="store_true", help="Output as Table")
    timeline_parser.add_argument("--drift-correction", type=float, default=0.0, help="Manual offset in seconds")
    
    # Report
    report_parser = subparsers.add_parser("report", help="Generate PDF and HTML forensic reports")
    report_parser.add_argument("--source", required=True, help="Path to source image")
    report_parser.add_argument("--case", required=True, help="Case ID")
    report_parser.add_argument("--examiner", required=True, help="Examiner Name")
    report_parser.add_argument("--out", required=True, help="Output directory for reports")
    report_parser.add_argument("--audit-log", default="audit.jsonl", help="Audit log path")
    
    # Serve
    serve_parser = subparsers.add_parser("serve", help="Start FastAPI local web dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host IP")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port")
    
    args = parser.parse_args()
    
    # Safely get audit_log since some commands (like serve) might not define it
    audit_log_path = getattr(args, "audit_log", "audit.jsonl")
    logger = AuditLogger(audit_log_path)
    
    if args.command == "acquire":
        manager = AcquisitionManager(logger)
        try:
            print(f"Starting acquisition of {args.source} -> {args.dest}")
            record = manager.acquire_image(args.source, args.dest, args.case, args.examiner)
            print("Acquisition complete! Record:")
            print(json.dumps(record, indent=2))
        except Exception as e:
            print(f"Acquisition failed: {e}")
            sys.exit(1)
            
    elif args.command == "verify_chain":
        is_valid = logger.verify_chain()
        if is_valid:
            print("Audit chain is VALID.")
        else:
            print("Audit chain is TAMPERED/INVALID.")
            sys.exit(1)
            
    elif args.command == "export_custody":
        exporter = CustodyExporter(args.audit_log)
        if args.csv:
            exporter.export_csv(args.csv)
            print(f"Exported to {args.csv}")
        if args.pdf:
            exporter.export_pdf(args.pdf)
            print(f"Exported to {args.pdf}")
            
    elif args.command == "timeline":
        from forensivue.core.plugin_registry import PluginRegistry
        from forensivue.core.models import EvidenceItem
        from forensivue.core.timeline import TimelineManager
        
        registry = PluginRegistry(logger)
        registry.load_plugins()
        evidence = EvidenceItem(id="CLI-TL", path=args.source, acquisition_hash_md5="", acquisition_hash_sha256="")
        
        res = registry.parse_evidence(evidence)
        if res["status"] != "success":
            print("Failed to identify or parse source image")
            sys.exit(1)
            
        parser = registry.get_parsers()[res["parser"]]()
        recordings = parser.list_recordings(evidence)
        
        tm = TimelineManager(logger)
        tm.add_recordings(recordings)
        
        if args.drift_correction != 0.0:
            tm.apply_manual_correction(args.drift_correction, "CLI Manual correction")
            
        unified = tm.get_unified_timeline()
        
        if args.json:
            print(json.dumps(unified, indent=4))
            
        if args.table or not args.json:
            print(f"{'Channel':<8} | {'Start Time (UTC)':<28} | {'End Time (UTC)':<28} | {'Status':<10}")
            print("-" * 85)
            for ev in unified:
                print(f"{ev['channel']:<8} | {ev['adjusted_start']:<28} | {ev['adjusted_end']:<28} | {ev['status']:<10}")

    elif args.command == "report":
        from forensivue.core.plugin_registry import PluginRegistry
        from forensivue.core.models import EvidenceItem
        from forensivue.core.timeline import TimelineManager
        from forensivue.core.recovery import RecoveryManager
        from forensivue.core.reporting import ReportGenerator
        from forensivue.core.hash_utils import generate_file_hashes
        from forensivue.core.device_id import DeviceIdentifier
        from datetime import datetime
        import os
        
        print(f"[*] Starting full pipeline for {args.source}")
        
        # 1. Hashes
        print("[*] Computing hashes...")
        hashes = generate_file_hashes(args.source)
        
        # 2. Identification
        print("[*] Identifying device...")
        sig_file = os.path.join(os.path.dirname(__file__), "config", "signatures.yaml")
        identifier = DeviceIdentifier(sig_file, logger)
        id_results = identifier.identify(args.source)
        top_vendor = id_results[0]["vendor"] if id_results else "unknown"
        top_conf = id_results[0]["confidence"] if id_results else 0.0
        
        # 3. Parsing
        print("[*] Parsing filesystem...")
        registry = PluginRegistry(logger)
        registry.load_plugins()
        evidence = EvidenceItem(id=os.path.basename(args.source), path=args.source, acquisition_hash_md5=hashes["md5"], acquisition_hash_sha256=hashes["sha256"])
        
        res = registry.parse_evidence(evidence)
        parser_name = res["parser"]
        parser = registry.get_parsers()[parser_name]()
        recordings = parser.list_recordings(evidence)
        
        # 4. Recovery
        print("[*] Recovering data...")
        rec_mgr = RecoveryManager(logger)
        recovered_dir = os.path.join(args.out, "recovered")
        idx_rec = rec_mgr.index_recovery(evidence, parser, recovered_dir)
        carv_rec = rec_mgr.signature_carve(evidence, recovered_dir)
        
        # 5. Timeline
        print("[*] Building timeline...")
        tm = TimelineManager(logger)
        tm.add_recordings(recordings)
        timeline = tm.get_unified_timeline()
        
        # 6. Chain Verification
        print("[*] Verifying chain of custody...")
        is_valid = logger.verify_chain()
        verif_str = "VALID (Cryptographic chain intact)" if is_valid else "INVALID (Tampering detected)"
        
        # Extract small log snippet
        log_snippet = ""
        try:
            with open(args.audit_log, "r") as lf:
                lines = lf.readlines()
                log_snippet = "".join(lines[-10:])
        except Exception:
            log_snippet = "No log found."
            
        # 7. Formatting Report
        print("[*] Generating reports...")
        rep_data = {
            "case_info": {"case_id": args.case, "examiner": args.examiner},
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "tool_version": "ForensiVue v1.0",
            "acquisition": {"source": args.source, "md5": hashes["md5"], "sha256": hashes["sha256"]},
            "identification": {"vendor": top_vendor, "confidence": f"{top_conf*100:.1f}%"},
            "recordings": [],
            "timeline": timeline,
            "verification": {"result": verif_str, "log_excerpt": log_snippet}
        }
        
        for r in recordings:
            rep_data["recordings"].append({
                "recording_id": r.recording_id,
                "channel": r.channel_id,
                "start": r.start_time.utc_iso8601,
                "end": r.end_time.utc_iso8601,
                "status": r.status,
                "confidence": "1.0"
            })
            
        for r in idx_rec + carv_rec:
            rep_data["recordings"].append({
                "recording_id": r.get("original_id", "Carved"),
                "channel": "Unknown",
                "start": "Recovered",
                "end": "Recovered",
                "status": f"Recovered ({r['method']})",
                "confidence": str(r["score"])
            })
            
        rg = ReportGenerator(args.out)
        html_out = os.path.join(args.out, f"{args.case}_report.html")
        pdf_out = os.path.join(args.out, f"{args.case}_report.pdf")
        
        rg.generate_html(rep_data, html_out)
        rg.generate_pdf(rep_data, pdf_out)
        
        print(f"[+] PDF Report: {pdf_out}")
        print(f"[+] HTML Report: {html_out}")
        
    elif args.command == "serve":
        import uvicorn
        print(f"[*] Starting ForensiVue Dashboard on http://{args.host}:{args.port}")
        uvicorn.run("forensivue.api.main:app", host=args.host, port=args.port, reload=False)

if __name__ == "__main__":
    main()
