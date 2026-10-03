from typing import List, Dict, Any
from forensivue.core.interfaces import BaseVendorParser
from forensivue.core.models import EvidenceItem, Recording

class GenericParser(BaseVendorParser):
    """
    A generic stub parser to prove the plugin architecture.
    Identifies any evidence file ending with '.generic_dvr'.
    """
    @classmethod
    def get_parser_name(cls) -> str:
        return "GenericStubParser"

    def identify(self, evidence: EvidenceItem) -> bool:
        # Fallback catches all unrecognized files
        return True

    def parse_filesystem(self, evidence: EvidenceItem) -> Dict[str, Any]:
        import os
        size = os.path.getsize(evidence.path) if os.path.exists(evidence.path) else 0
        return {
            "layout": "unknown", 
            "total_size": size,
            "status": "unrecognized"
        }

    def list_recordings(self, evidence: EvidenceItem) -> List[Recording]:
        # Never fabricate recordings we can't prove
        return []

    def extract_video(self, evidence: EvidenceItem, recording: Recording, output_path: str) -> str:
        raise NotImplementedError("Generic parser cannot extract video")

    def extract_metadata(self, evidence: EvidenceItem, recording: Recording) -> Dict[str, Any]:
        return {}
