from abc import ABC, abstractmethod
from typing import List, Dict, Any
from forensivue.core.models import EvidenceItem, Recording

class BaseVendorParser(ABC):
    """
    Abstract base class for all DVR/NVR forensic parsers.
    Every new vendor plugin must implement this interface.
    """
    
    @classmethod
    @abstractmethod
    def get_parser_name(cls) -> str:
        """Returns the unique name of the vendor parser."""
        pass

    @abstractmethod
    def identify(self, evidence: EvidenceItem) -> bool:
        """
        Analyzes the evidence file/image to determine if it is
        supported by this parser (e.g., by checking magic headers).
        """
        pass
        
    @abstractmethod
    def parse_filesystem(self, evidence: EvidenceItem) -> Dict[str, Any]:
        """
        Parses the proprietary filesystem structures.
        Returns layout and metadata about the filesystem.
        """
        pass
        
    @abstractmethod
    def list_recordings(self, evidence: EvidenceItem) -> List[Recording]:
        """
        Lists all video recordings found in the evidence.
        """
        pass
        
    @abstractmethod
    def extract_video(self, evidence: EvidenceItem, recording: Recording, output_path: str) -> str:
        """
        Extracts a specific recording to the output path without altering the source.
        Returns the absolute path to the extracted file.
        """
        pass
        
    @abstractmethod
    def extract_metadata(self, evidence: EvidenceItem, recording: Recording) -> Dict[str, Any]:
        """
        Extracts detailed proprietary metadata (e.g., motion logs, smart events)
        associated with a specific recording.
        """
        pass
