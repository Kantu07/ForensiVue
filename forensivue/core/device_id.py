import yaml
import binascii
from typing import List, Dict, Any
from forensivue.core.audit_logger import AuditLogger

class DeviceIdentifier:
    """
    Identifies DVR/NVR vendor and model from a raw disk image
    using partition analysis, magic bytes, and string searches.
    """
    def __init__(self, signature_file: str, audit_logger: AuditLogger):
        self.signature_file = signature_file
        self.audit_logger = audit_logger
        self.signatures = self._load_signatures()
        
    def _load_signatures(self) -> List[Dict]:
        with open(self.signature_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return data.get("vendors", [])
        
    def identify(self, image_path: str) -> List[Dict[str, Any]]:
        self.audit_logger.log_action("IDENTIFY_DEVICE_START", {"image_path": image_path})
        
        candidates = []
        global_max_string_search = 0
        
        # Calculate maximum string search offset to buffer efficiently
        for vendor in self.signatures:
            for s in vendor.get("strings", []):
                if s["max_search_offset"] > global_max_string_search:
                    global_max_string_search = s["max_search_offset"]
                    
        with open(image_path, "rb") as f:
            # Buffer the header for string searches
            header_chunk = f.read(global_max_string_search)
            
            for vendor in self.signatures:
                name = vendor["name"]
                max_score = 0.0
                achieved_score = 0.0
                evidence_found = []
                
                # Check magic bytes (seek explicitly for each)
                for mb in vendor.get("magic_bytes", []):
                    weight = float(mb.get("weight", 0.0))
                    max_score += weight
                    offset = mb["offset"]
                    expected_hex = mb["value"].lower()
                    
                    try:
                        f.seek(offset)
                        read_len = len(expected_hex) // 2
                        data = f.read(read_len)
                        
                        if data and binascii.hexlify(data).decode('utf-8') == expected_hex:
                            achieved_score += weight
                            evidence_found.append({"type": "magic_bytes", "offset": offset, "matched": expected_hex})
                    except OSError:
                        pass # Ignore if file is smaller than offset
                        
                # Check strings in the pre-buffered chunk
                for s in vendor.get("strings", []):
                    weight = float(s.get("weight", 0.0))
                    max_score += weight
                    val_bytes = s["value"].encode('utf-8')
                    
                    # We only search up to this string's specific max_search_offset
                    search_area = header_chunk[:s["max_search_offset"]]
                    idx = search_area.find(val_bytes)
                    
                    if idx != -1:
                        achieved_score += weight
                        evidence_found.append({"type": "string", "matched": s["value"], "offset": idx})
                            
                # Calculate confidence if there are criteria
                if max_score > 0 and achieved_score > 0:
                    confidence = achieved_score / max_score
                    candidates.append({
                        "vendor": name,
                        "confidence": round(confidence, 4),
                        "evidence": evidence_found
                    })
                    
        # Sort candidates by confidence descending
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        
        if not candidates:
            candidates = [{"vendor": "unknown", "confidence": 1.0, "evidence": []}]
            
        self.audit_logger.log_action("IDENTIFY_DEVICE_COMPLETE", {"image_path": image_path, "candidates": candidates})
        return candidates
