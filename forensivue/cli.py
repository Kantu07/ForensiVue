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
    
    args = parser.parse_args()
    logger = AuditLogger(args.audit_log)
    
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

if __name__ == "__main__":
    main()
