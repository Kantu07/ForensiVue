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

if __name__ == "__main__":
    main()
