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
        # Stub logic: recognize based on file extension
        return evidence.path.endswith(".generic_dvr")

    def parse_filesystem(self, evidence: EvidenceItem) -> Dict[str, Any]:
        return {
            "layout": "generic_fat32_stub", 
            "total_size": 1024,
            "status": "parsed"
        }

    def list_recordings(self, evidence: EvidenceItem) -> List[Recording]:
        return []

    def extract_video(self, evidence: EvidenceItem, recording: Recording, output_path: str) -> str:
        raise NotImplementedError("Generic parser cannot extract video")

    def extract_metadata(self, evidence: EvidenceItem, recording: Recording) -> Dict[str, Any]:
        return {}
