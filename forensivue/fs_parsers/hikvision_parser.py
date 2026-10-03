from typing import List, Dict, Any
from forensivue.core.interfaces import BaseVendorParser
from forensivue.core.models import EvidenceItem, Recording
from forensivue.fs_parsers.synthetic_utils import SyntheticLayoutParserMixin

class HikvisionParser(BaseVendorParser, SyntheticLayoutParserMixin):
    @classmethod
    def get_parser_name(cls) -> str:
        return "Hikvision"

    def identify(self, evidence: EvidenceItem) -> bool:
        try:
            with open(evidence.path, "rb") as f:
                f.seek(512)
                magic = f.read(9)
                return magic == b"HIKVISION"
        except OSError:
            return False

    def parse_filesystem(self, evidence: EvidenceItem) -> Dict[str, Any]:
        return {"layout": "SyntheticHikvision", "status": "parsed"}

    def list_recordings(self, evidence: EvidenceItem) -> List[Recording]:
        return self._parse_synthetic_index(evidence)

    def extract_video(self, evidence: EvidenceItem, recording: Recording, output_path: str) -> str:
        return self._extract_synthetic_video(evidence, recording, output_path)

    def extract_metadata(self, evidence: EvidenceItem, recording: Recording) -> Dict[str, Any]:
        return {"logs": "Mock Hikvision motion logs"}
