"""
Ghidra Analysis JSON Parsers and Normalizers

This module provides utilities to load, parse, normalize, and query
the JSON output from Ghidra's export_analysis.py script.
"""

import json
import re
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class GhidraAnalysisData:
    """
    Parses and provides convenient access to Ghidra analysis results.
    """

    def __init__(self, json_path: str):
        """
        Load analysis data from JSON file.

        Args:
            json_path: Path to ghidra_analysis.json file
        """
        self.json_path = json_path
        self.data = self._load_json(json_path)

        # Extract main components
        self.metadata = self.data.get("metadata", {})
        self.functions = self.data.get("functions", [])
        self.strings = self.data.get("strings", [])
        self.imports = self.data.get("imports", [])
        self.exports = self.data.get("exports", [])
        self.sections = self.data.get("sections", [])
        self.references = self.data.get("references", {})

        # Build indices for fast lookup
        self._build_indices()

        logger.info(
            f"Loaded analysis data: {len(self.functions)} functions, "
            f"{len(self.strings)} strings, {len(self.imports)} imports"
        )

    def _load_json(self, path: str) -> Dict:
        """Load JSON from file."""
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load JSON from {path}: {e}")
            raise

    def _build_indices(self):
        """Build lookup indices for fast queries."""
        # Function name -> function data
        self.func_by_name = {f["name"]: f for f in self.functions}

        # Function address -> function data
        self.func_by_addr = {f["address"]: f for f in self.functions}

        # Import library -> list of functions
        self.imports_by_lib = {}
        for imp in self.imports:
            lib = imp.get("library", "unknown")
            if lib not in self.imports_by_lib:
                self.imports_by_lib[lib] = []
            self.imports_by_lib[lib].append(imp)

    def get_function(self, identifier: str) -> Optional[Dict]:
        """
        Get function by name or address.

        Args:
            identifier: Function name or address

        Returns:
            Function dict or None if not found
        """
        # Try by name first
        if identifier in self.func_by_name:
            return self.func_by_name[identifier]

        # Try by address
        if identifier in self.func_by_addr:
            return self.func_by_addr[identifier]

        # Try partial match on name
        for name, func in self.func_by_name.items():
            if identifier.lower() in name.lower():
                return func

        return None

    def list_functions(
        self, limit: Optional[int] = None, filter_external: bool = True
    ) -> List[Dict]:
        """
        List all functions with optional filtering.

        Args:
            limit: Maximum number of functions to return
            filter_external: If True, exclude external/thunk functions

        Returns:
            List of function dicts
        """
        funcs = self.functions

        if filter_external:
            funcs = [f for f in funcs if not f.get("is_external", False)]

        if limit:
            funcs = funcs[:limit]

        return funcs

    def search_decompiled(self, pattern: str, case_sensitive: bool = False) -> List[Dict]:
        """
        Search for pattern in decompiled code.

        Args:
            pattern: Regex pattern or plain text to search
            case_sensitive: Whether search is case sensitive

        Returns:
            List of functions matching the pattern with match context
        """
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}. Using literal search.")
            regex = re.compile(re.escape(pattern), flags)

        matches = []
        for func in self.functions:
            decomp = func.get("decompiled")
            if not decomp:
                continue

            match_obj = regex.search(decomp)
            if match_obj:
                # Get context around match
                start = max(0, match_obj.start() - 100)
                end = min(len(decomp), match_obj.end() + 100)
                context = decomp[start:end]

                matches.append({
                    "function": func["name"],
                    "address": func["address"],
                    "match": match_obj.group(0),
                    "context": context,
                })

        logger.info(f"Found {len(matches)} functions matching pattern '{pattern}'")
        return matches

    def search_strings(self, pattern: str, case_sensitive: bool = False) -> List[Dict]:
        """
        Search for pattern in extracted strings.

        Args:
            pattern: Regex pattern or plain text
            case_sensitive: Whether search is case sensitive

        Returns:
            List of matching strings with addresses
        """
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error:
            regex = re.compile(re.escape(pattern), flags)

        matches = []
        for string in self.strings:
            value = string.get("value", "")
            if regex.search(value):
                matches.append(string)

        logger.info(f"Found {len(matches)} strings matching pattern '{pattern}'")
        return matches

    def get_xrefs_to_function(self, func_identifier: str) -> List[Dict]:
        """
        Get cross-references to a function (callers).

        Args:
            func_identifier: Function name or address

        Returns:
            List of functions that call this function
        """
        target_func = self.get_function(func_identifier)
        if not target_func:
            logger.warning(f"Function not found: {func_identifier}")
            return []

        target_name = target_func["name"]
        target_addr = target_func["address"]

        callers = []
        for func in self.functions:
            calls = func.get("calls", [])
            for call in calls:
                if call["name"] == target_name or call["address"] == target_addr:
                    callers.append({
                        "caller": func["name"],
                        "caller_address": func["address"],
                        "target": target_name,
                        "target_address": target_addr,
                    })

        logger.info(f"Found {len(callers)} callers of {target_name}")
        return callers

    def get_suspicious_imports(self) -> List[Dict]:
        """
        Identify potentially suspicious imports based on common patterns.

        Returns:
            List of suspicious imports with reasons
        """
        # Common suspicious API patterns for Windows malware
        suspicious_patterns = {
            r"CreateRemoteThread": "Code injection",
            r"VirtualAllocEx": "Memory manipulation",
            r"WriteProcessMemory": "Process memory modification",
            r"SetWindowsHookEx": "Keyboard/mouse hooking",
            r"GetAsyncKeyState": "Keystroke logging",
            r"InternetOpen|InternetConnect": "Network communication",
            r"URLDownloadToFile": "File download",
            r"WinExec|ShellExecute|CreateProcess": "Process execution",
            r"RegSetValue|RegCreateKey": "Registry modification",
            r"CryptEncrypt|CryptDecrypt": "Cryptography usage",
            r"IsDebuggerPresent": "Anti-debugging",
        }

        suspicious = []
        for imp in self.imports:
            func_name = imp.get("function", "")
            for pattern, reason in suspicious_patterns.items():
                if re.search(pattern, func_name, re.IGNORECASE):
                    suspicious.append({
                        **imp,
                        "reason": reason,
                        "severity": "high",
                    })
                    break

        logger.info(f"Identified {len(suspicious)} suspicious imports")
        return suspicious

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the analysis.

        Returns:
            Dict with key statistics and findings
        """
        return {
            "metadata": self.metadata,
            "statistics": {
                "total_functions": len(self.functions),
                "internal_functions": len(
                    [f for f in self.functions if not f.get("is_external")]
                ),
                "total_strings": len(self.strings),
                "total_imports": len(self.imports),
                "total_exports": len(self.exports),
                "memory_sections": len(self.sections),
            },
            "suspicious_imports": self.get_suspicious_imports(),
        }

    def export_function_list(self, output_path: str, format: str = "json"):
        """
        Export function list to file.

        Args:
            output_path: Output file path
            format: Export format ('json', 'csv', 'txt')
        """
        if format == "json":
            with open(output_path, "w") as f:
                json.dump(self.functions, f, indent=2)
        elif format == "csv":
            import csv

            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["name", "address", "size", "signature"]
                )
                writer.writeheader()
                for func in self.functions:
                    writer.writerow({
                        "name": func["name"],
                        "address": func["address"],
                        "size": func["size"],
                        "signature": func.get("signature", ""),
                    })
        elif format == "txt":
            with open(output_path, "w") as f:
                for func in self.functions:
                    f.write(f"{func['address']}\t{func['name']}\n")
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported function list to {output_path}")
