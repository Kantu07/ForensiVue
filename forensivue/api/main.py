import os
import glob
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict, Any

from forensivue.core.plugin_registry import PluginRegistry
from forensivue.core.models import EvidenceItem
from forensivue.core.timeline import TimelineManager
from forensivue.core.recovery import RecoveryManager
from forensivue.core.reporting import ReportGenerator
from forensivue.core.hash_utils import generate_file_hashes
from forensivue.core.device_id import DeviceIdentifier
from forensivue.core.audit_logger import AuditLogger
from datetime import datetime

# Global instances for simplicity in single-user local dashboard
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
AUDIT_LOG_PATH = os.path.join(PROJECT_ROOT, "audit.jsonl")
logger = AuditLogger(AUDIT_LOG_PATH)
registry = PluginRegistry(logger)
registry.load_plugins()

app = FastAPI(title="ForensiVue Dashboard")

class ImageRequest(BaseModel):
    image_path: str

class ReportRequest(BaseModel):
    image_path: str
    case_id: str
    examiner: str

# Endpoints
@app.get("/api/images")
def list_images():
    gen_dir = os.path.join(PROJECT_ROOT, "generated")
    if not os.path.exists(gen_dir):
        return {"images": []}
    files = glob.glob(os.path.join(gen_dir, "*.dd"))
    return {"images": [os.path.relpath(f, PROJECT_ROOT) for f in files]}

@app.post("/api/pipeline/identify")
def identify_image(req: ImageRequest):
    full_path = os.path.join(PROJECT_ROOT, req.image_path)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Image not found")
        
    hashes = generate_file_hashes(full_path)
    
    sig_file = os.path.join(PROJECT_ROOT, "forensivue", "config", "signatures.yaml")
    identifier = DeviceIdentifier(sig_file, logger)
    id_results = identifier.identify(full_path)
    
    evidence = EvidenceItem(id=os.path.basename(full_path), path=full_path, acquisition_hash_md5=hashes["md5"], acquisition_hash_sha256=hashes["sha256"])
    res = registry.parse_evidence(evidence)
    parser_name = res["parser"]
    parser = registry.get_parsers()[parser_name]()
    recordings = parser.list_recordings(evidence)
    
    recs_out = []
    for r in recordings:
        recs_out.append({
            "id": r.recording_id,
            "channel": r.channel_id,
            "start": r.start_time.utc_iso8601,
            "end": r.end_time.utc_iso8601,
            "status": r.status
        })
        
    return {
        "hashes": hashes,
        "identification": id_results,
        "parser_used": parser_name,
        "recordings": recs_out
    }

@app.post("/api/pipeline/recover")
def recover_data(req: ImageRequest):
    full_path = os.path.join(PROJECT_ROOT, req.image_path)
    evidence = EvidenceItem(id=os.path.basename(full_path), path=full_path, acquisition_hash_md5="", acquisition_hash_sha256="")
    
    res = registry.parse_evidence(evidence)
    parser = registry.get_parsers()[res["parser"]]()
    
    rec_mgr = RecoveryManager(logger)
    recovered_dir = os.path.join(PROJECT_ROOT, "recovered", os.path.basename(full_path))
    
    idx_rec = rec_mgr.index_recovery(evidence, parser, recovered_dir)
    carv_rec = rec_mgr.signature_carve(evidence, recovered_dir)
    
    results = []
    for r in idx_rec + carv_rec:
        results.append({
            "original_id": r.get("original_id", "Carved"),
            "method": r["method"],
            "score": r["score"],
            "sha256": r["sha256"],
            "path": os.path.relpath(r["path"], PROJECT_ROOT)
        })
        
    return {"recovered": results}

@app.post("/api/pipeline/timeline")
def get_timeline(req: ImageRequest):
    full_path = os.path.join(PROJECT_ROOT, req.image_path)
    evidence = EvidenceItem(id=os.path.basename(full_path), path=full_path, acquisition_hash_md5="", acquisition_hash_sha256="")
    
    res = registry.parse_evidence(evidence)
    parser = registry.get_parsers()[res["parser"]]()
    recordings = parser.list_recordings(evidence)
    
    tm = TimelineManager(logger)
    tm.add_recordings(recordings)
    return {"timeline": tm.get_unified_timeline()}

@app.post("/api/pipeline/report")
def generate_report(req: ReportRequest):
    full_path = os.path.join(PROJECT_ROOT, req.image_path)
    
    # 1. Hashes
    hashes = generate_file_hashes(full_path)
    
    # 2. Identify
    sig_file = os.path.join(PROJECT_ROOT, "forensivue", "config", "signatures.yaml")
    identifier = DeviceIdentifier(sig_file, logger)
    id_results = identifier.identify(full_path)
    top_vendor = id_results[0]["vendor"] if id_results else "unknown"
    top_conf = id_results[0]["confidence"] if id_results else 0.0
    
    # 3. Parse
    evidence = EvidenceItem(id=os.path.basename(full_path), path=full_path, acquisition_hash_md5=hashes["md5"], acquisition_hash_sha256=hashes["sha256"])
    res = registry.parse_evidence(evidence)
    parser = registry.get_parsers()[res["parser"]]()
    recordings = parser.list_recordings(evidence)
    
    # 4. Recover
    rec_mgr = RecoveryManager(logger)
    recovered_dir = os.path.join(PROJECT_ROOT, "recovered", os.path.basename(full_path))
    idx_rec = rec_mgr.index_recovery(evidence, parser, recovered_dir)
    carv_rec = rec_mgr.signature_carve(evidence, recovered_dir)
    
    # 5. Timeline
    tm = TimelineManager(logger)
    tm.add_recordings(recordings)
    timeline = tm.get_unified_timeline()
    
    # 6. Verify
    is_valid = logger.verify_chain()
    verif_str = "VALID (Cryptographic chain intact)" if is_valid else "INVALID (Tampering detected)"
    
    rep_data = {
        "case_info": {"case_id": req.case_id, "examiner": req.examiner},
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool_version": "ForensiVue v1.0",
        "acquisition": {"source": full_path, "md5": hashes["md5"], "sha256": hashes["sha256"]},
        "identification": {"vendor": top_vendor, "confidence": f"{top_conf*100:.1f}%"},
        "recordings": [],
        "timeline": timeline,
        "verification": {"result": verif_str, "log_excerpt": "Verification completed via dashboard."}
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
        
    out_dir = os.path.join(PROJECT_ROOT, "reports", req.case_id)
    rg = ReportGenerator(out_dir)
    html_name = f"{req.case_id}_report.html"
    pdf_name = f"{req.case_id}_report.pdf"
    rg.generate_html(rep_data, os.path.join(out_dir, html_name))
    rg.generate_pdf(rep_data, os.path.join(out_dir, pdf_name))
    
    return {
        "pdf_url": f"/reports/{req.case_id}/{pdf_name}",
        "html_url": f"/reports/{req.case_id}/{html_name}"
    }

@app.get("/api/custody/log")
def get_audit_log():
    try:
        with open(AUDIT_LOG_PATH, "r") as f:
            lines = f.readlines()
            return {"log": "".join(lines[-50:])}
    except Exception:
        return {"log": "No log found."}

@app.get("/api/custody/verify")
def verify_custody():
    is_valid = logger.verify_chain()
    return {"valid": is_valid}

# Mount static files (ensure directories exist)
os.makedirs(os.path.join(PROJECT_ROOT, "reports"), exist_ok=True)
app.mount("/reports", StaticFiles(directory=os.path.join(PROJECT_ROOT, "reports")), name="reports")

static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
