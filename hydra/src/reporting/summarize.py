"""
Analysis Summarization Module

Generates natural language summaries and structured findings from
Ghidra analysis data for Apify datasets.
"""

import logging
from typing import Dict, List, Any
from datetime import datetime

from src.ghidra.parsers import GhidraAnalysisData

logger = logging.getLogger(__name__)


class AnalysisSummarizer:
    """
    Generates summaries and findings from Ghidra analysis.
    """

    def __init__(self, analysis_data: GhidraAnalysisData):
        """
        Initialize summarizer with analysis data.

        Args:
            analysis_data: Parsed Ghidra analysis data
        """
        self.data = analysis_data

    def generate_findings(self) -> List[Dict[str, Any]]:
        """
        Generate structured findings for Apify Dataset.

        Returns:
            List of finding records
        """
        findings = []

        # Add metadata finding
        findings.append({
            "type": "metadata",
            "timestamp": datetime.utcnow().isoformat(),
            "binary_name": self.data.metadata.get("name", "unknown"),
            "executable_format": self.data.metadata.get("executable_format", "unknown"),
            "language": self.data.metadata.get("language", "unknown"),
            "compiler": self.data.metadata.get("compiler", "unknown"),
        })

        # Suspicious imports
        suspicious_imports = self.data.get_suspicious_imports()
        for imp in suspicious_imports:
            findings.append({
                "type": "suspicious_import",
                "severity": imp.get("severity", "medium"),
                "function": imp.get("function"),
                "library": imp.get("library"),
                "reason": imp.get("reason"),
                "recommendation": f"Investigate usage of {imp.get('function')} - {imp.get('reason')}",
            })

        # Suspicious strings
        suspicious_string_patterns = [
            (r"https?://", "URL found in binary"),
            (r"C:\\\\Windows\\\\System32", "System path reference"),
            (r"HKEY_", "Registry key reference"),
            (r"password|passwd|pwd", "Potential credential reference"),
            (r"\\.exe|\\.dll|\\.sys", "Executable/library reference"),
        ]

        for pattern, description in suspicious_string_patterns:
            matches = self.data.search_strings(pattern, case_sensitive=False)
            if matches:
                findings.append({
                    "type": "suspicious_string",
                    "severity": "medium",
                    "pattern": pattern,
                    "description": description,
                    "count": len(matches),
                    "examples": [s["value"] for s in matches[:3]],
                })

        # Code pattern analysis
        code_patterns = [
            (r"CreateRemoteThread|WriteProcessMemory", "Potential code injection"),
            (r"VirtualAlloc|VirtualProtect", "Memory manipulation"),
            (r"LoadLibrary|GetProcAddress", "Dynamic API resolution"),
            (r"IsDebuggerPresent|CheckRemoteDebuggerPresent", "Anti-debugging"),
        ]

        for pattern, description in code_patterns:
            matches = self.data.search_decompiled(pattern, case_sensitive=False)
            if matches:
                findings.append({
                    "type": "code_pattern",
                    "severity": "high",
                    "pattern": pattern,
                    "description": description,
                    "functions": [m["function"] for m in matches],
                    "count": len(matches),
                })

        logger.info(f"Generated {len(findings)} findings")
        return findings

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate a natural language summary of the analysis.

        Returns:
            Summary dict with overview, statistics, and recommendations
        """
        summary = self.data.get_summary()
        stats = summary["statistics"]
        suspicious_imports = summary["suspicious_imports"]

        # Generate overview text
        overview = (
            f"Analysis of {self.data.metadata.get('name', 'binary')} "
            f"({self.data.metadata.get('executable_format', 'unknown format')}). "
            f"The binary contains {stats['internal_functions']} internal functions, "
            f"{stats['total_imports']} imports, and {stats['total_strings']} strings."
        )

        # Threat assessment
        threat_level = "low"
        threat_indicators = []

        if len(suspicious_imports) > 5:
            threat_level = "high"
            threat_indicators.append(
                f"Contains {len(suspicious_imports)} suspicious API imports"
            )
        elif len(suspicious_imports) > 0:
            threat_level = "medium"
            threat_indicators.append(
                f"Contains {len(suspicious_imports)} potentially suspicious imports"
            )

        # Check for suspicious patterns
        code_injection_funcs = self.data.search_decompiled(
            r"CreateRemoteThread|WriteProcessMemory", case_sensitive=False
        )
        if code_injection_funcs:
            threat_level = "high"
            threat_indicators.append(
                "Code injection patterns detected in functions: "
                + ", ".join([f["function"] for f in code_injection_funcs[:3]])
            )

        # Generate recommendations
        recommendations = []

        if suspicious_imports:
            recommendations.append(
                "Review the suspicious imports and their usage in the code"
            )

        if threat_level in ["high", "medium"]:
            recommendations.append(
                "Execute in an isolated sandbox environment for dynamic analysis"
            )
            recommendations.append(
                "Monitor network activity and file system modifications"
            )

        recommendations.append(
            "Compare against known malware signatures using YARA rules"
        )

        return {
            "overview": overview,
            "threat_level": threat_level,
            "threat_indicators": threat_indicators,
            "statistics": stats,
            "recommendations": recommendations,
            "suspicious_imports": suspicious_imports[:10],  # Top 10
        }

    def generate_executive_summary(self) -> str:
        """
        Generate a brief executive summary in markdown format.

        Returns:
            Markdown formatted summary
        """
        summary = self.generate_summary()

        md = f"""# Malware Analysis Executive Summary

## Binary Information
- **Name**: {self.data.metadata.get('name', 'unknown')}
- **Format**: {self.data.metadata.get('executable_format', 'unknown')}
- **Architecture**: {self.data.metadata.get('language', 'unknown')}
- **Compiler**: {self.data.metadata.get('compiler', 'unknown')}

## Threat Assessment
- **Threat Level**: {summary['threat_level'].upper()}

"""

        if summary['threat_indicators']:
            md += "### Indicators:\n"
            for indicator in summary['threat_indicators']:
                md += f"- {indicator}\n"

        md += f"\n## Statistics\n"
        stats = summary['statistics']
        md += f"- **Functions**: {stats['internal_functions']} internal, {stats['total_functions']} total\n"
        md += f"- **Imports**: {stats['total_imports']}\n"
        md += f"- **Strings**: {stats['total_strings']}\n"
        md += f"- **Exports**: {stats['total_exports']}\n"

        if summary['suspicious_imports']:
            md += f"\n## Suspicious Imports\n"
            for imp in summary['suspicious_imports'][:5]:
                md += f"- **{imp['function']}** ({imp['library']}): {imp['reason']}\n"

        md += f"\n## Recommendations\n"
        for rec in summary['recommendations']:
            md += f"- {rec}\n"

        return md
