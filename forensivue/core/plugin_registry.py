import importlib
import pkgutil
import inspect
from typing import Dict, Type, Any

import forensivue.fs_parsers
from forensivue.core.interfaces import BaseVendorParser
from forensivue.core.models import EvidenceItem
from forensivue.core.audit_logger import AuditLogger

class PluginRegistry:
    """
    Manages auto-discovery, loading, and invocation of vendor parsers.
    Integrates with AuditLogger to ensure all interactions are forensically logged.
    """
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self._parsers: Dict[str, Type[BaseVendorParser]] = {}
        
    def load_plugins(self):
        """Auto-discovers vendor parsers from the fs_parsers package."""
        self._parsers.clear()
        package = forensivue.fs_parsers
        prefix = package.__name__ + "."
        
        for _, modname, _ in pkgutil.iter_modules(package.__path__, prefix):
            module = importlib.import_module(modname)
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BaseVendorParser) and obj is not BaseVendorParser:
                    parser_name = obj.get_parser_name()
                    self._parsers[parser_name] = obj
                    
        self.audit_logger.log_action("PLUGINS_LOADED", {"loaded_parsers": list(self._parsers.keys())})
        
    def get_parsers(self) -> Dict[str, Type[BaseVendorParser]]:
        return self._parsers

    def parse_evidence(self, evidence: EvidenceItem) -> Dict[str, Any]:
        """
        Attempts to identify the evidence using all loaded parsers,
        then calls parse_filesystem on the matching parser.
        Hooks the audit logger so every parse call is logged.
        """
        self.audit_logger.log_action("PARSE_INITIATED", {"evidence_id": evidence.id, "path": evidence.path})
        
        matched_parser_name = None
        parser_instance = None
        
        for name, parser_class in self._parsers.items():
            parser = parser_class()
            if parser.identify(evidence):
                matched_parser_name = name
                parser_instance = parser
                break
                
        if not matched_parser_name or not parser_instance:
            self.audit_logger.log_action("PARSE_FAILED", {"evidence_id": evidence.id, "reason": "unrecognized"})
            return {"status": "error", "reason": "unrecognized"}
            
        self.audit_logger.log_action("PARSER_IDENTIFIED", {"evidence_id": evidence.id, "parser": matched_parser_name})
        
        try:
            fs_info = parser_instance.parse_filesystem(evidence)
            self.audit_logger.log_action("PARSE_FILESYSTEM_SUCCESS", {"evidence_id": evidence.id, "parser": matched_parser_name})
            return {
                "status": "success",
                "parser": matched_parser_name,
                "filesystem_info": fs_info
            }
        except Exception as e:
            self.audit_logger.log_action("PARSE_FILESYSTEM_ERROR", {"evidence_id": evidence.id, "parser": matched_parser_name, "error": str(e)})
            return {"status": "error", "reason": f"Parsing failed: {str(e)}"}
