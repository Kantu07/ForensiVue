# ForensiVue Vendor Plugin Template

Every vendor parser must implement the `BaseVendorParser` abstract class from `forensivue.core.interfaces`.

## Instructions
1. Create a new file in `forensivue/fs_parsers/` (e.g., `hikvision_parser.py`).
2. Import the necessary base classes and models.
3. Inherit from `BaseVendorParser`.
4. Implement all abstract methods.
5. The `PluginRegistry` will automatically discover your class.

## Example Template

```python
from typing import List, Dict, Any
from forensivue.core.interfaces import BaseVendorParser
from forensivue.core.models import EvidenceItem, Recording

class MyVendorParser(BaseVendorParser):
    @classmethod
    def get_parser_name(cls) -> str:
        return "MyVendorParser_v1"

    def identify(self, evidence: EvidenceItem) -> bool:
        # Determine if this parser can handle the evidence
        # Check magic bytes, file extensions, etc.
        return False

    def parse_filesystem(self, evidence: EvidenceItem) -> Dict[str, Any]:
        # Parse proprietary filesystem structures
        return {}

    def list_recordings(self, evidence: EvidenceItem) -> List[Recording]:
        # Return a list of all found recordings
        return []

    def extract_video(self, evidence: EvidenceItem, recording: Recording, output_path: str) -> str:
        # Extract the raw video stream to the output_path
        # Must NOT write to the evidence source
        return output_path

    def extract_metadata(self, evidence: EvidenceItem, recording: Recording) -> Dict[str, Any]:
        # Extract motion logs, timestamps, etc.
        return {}
```


**WARNING:** The `HikvisionParser` and `DahuaParser` examples in this repository, as well as the synthetic generator layouts, are based on **synthetic assumptions** for testing extraction logic. They are **NOT** based on verified proprietary vendor formats. All true vendor formats are strictly closed-source and must be researched individually.
