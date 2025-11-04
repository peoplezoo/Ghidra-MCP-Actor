"""
HTML Report Generation Module

Generates comprehensive HTML reports from Ghidra analysis data.
"""

import logging
from typing import Dict, Any
from jinja2 import Template

from src.ghidra.parsers import GhidraAnalysisData
from src.reporting.summarize import AnalysisSummarizer

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """
    Generates HTML reports from analysis data.
    """

    def __init__(self, analysis_data: GhidraAnalysisData):
        """
        Initialize report generator.

        Args:
            analysis_data: Parsed Ghidra analysis data
        """
        self.data = analysis_data
        self.summarizer = AnalysisSummarizer(analysis_data)

    def generate_report(self) -> str:
        """
        Generate a comprehensive HTML report.

        Returns:
            HTML report as string
        """
        summary = self.summarizer.generate_summary()
        findings = self.summarizer.generate_findings()

        # Prepare data for template
        report_data = {
            "metadata": self.data.metadata,
            "summary": summary,
            "findings": findings,
            "functions": self.data.list_functions(limit=50, filter_external=True),
            "suspicious_imports": summary["suspicious_imports"],
            "strings": self.data.strings[:50],  # First 50 strings
        }

        # Render HTML using template
        html = self._render_template(report_data)
        return html

    def _render_template(self, data: Dict[str, Any]) -> str:
        """
        Render HTML template with data.

        Args:
            data: Report data

        Returns:
            Rendered HTML
        """
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {{ metadata.name }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }

        h2 {
            font-size: 1.5em;
            margin: 30px 0 15px 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }

        h3 {
            font-size: 1.2em;
            margin: 20px 0 10px 0;
            color: #764ba2;
        }

        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .threat-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }

        .threat-low {
            background: #d4edda;
            color: #155724;
        }

        .threat-medium {
            background: #fff3cd;
            color: #856404;
        }

        .threat-high {
            background: #f8d7da;
            color: #721c24;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .severity-high {
            background: #dc3545;
            color: white;
        }

        .severity-medium {
            background: #ffc107;
            color: #333;
        }

        .severity-low {
            background: #28a745;
            color: white;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }

        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .metadata-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }

        .metadata-label {
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }

        .metadata-value {
            color: #555;
            word-break: break-all;
        }

        .code-block {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #764ba2;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
        }

        ul {
            margin: 15px 0;
            padding-left: 30px;
        }

        li {
            margin: 8px 0;
        }

        .finding-item {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Malware Analysis Report</h1>
            <p style="font-size: 1.1em; opacity: 0.9;">Binary: {{ metadata.name }}</p>
        </header>

        <div class="card">
            <h2>📊 Executive Summary</h2>
            <p style="margin: 15px 0;">{{ summary.overview }}</p>

            <div style="margin: 20px 0;">
                <strong>Threat Level:</strong>
                <span class="threat-badge threat-{{ summary.threat_level }}">
                    {{ summary.threat_level }}
                </span>
            </div>

            {% if summary.threat_indicators %}
            <div>
                <strong>Threat Indicators:</strong>
                <ul>
                    {% for indicator in summary.threat_indicators %}
                    <li>{{ indicator }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>

        <div class="card">
            <h2>📋 Binary Metadata</h2>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Format</div>
                    <div class="metadata-value">{{ metadata.executable_format }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Architecture</div>
                    <div class="metadata-value">{{ metadata.language }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Compiler</div>
                    <div class="metadata-value">{{ metadata.compiler }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Image Base</div>
                    <div class="metadata-value">{{ metadata.image_base }}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>📈 Statistics</h2>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Total Functions</div>
                    <div class="metadata-value">{{ summary.statistics.total_functions }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Internal Functions</div>
                    <div class="metadata-value">{{ summary.statistics.internal_functions }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Imports</div>
                    <div class="metadata-value">{{ summary.statistics.total_imports }}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Strings</div>
                    <div class="metadata-value">{{ summary.statistics.total_strings }}</div>
                </div>
            </div>
        </div>

        {% if suspicious_imports %}
        <div class="card">
            <h2>⚠️ Suspicious Imports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Function</th>
                        <th>Library</th>
                        <th>Reason</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {% for imp in suspicious_imports %}
                    <tr>
                        <td><code>{{ imp.function }}</code></td>
                        <td>{{ imp.library }}</td>
                        <td>{{ imp.reason }}</td>
                        <td>
                            <span class="severity-badge severity-{{ imp.severity }}">
                                {{ imp.severity }}
                            </span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if findings %}
        <div class="card">
            <h2>🔎 Detailed Findings</h2>
            {% for finding in findings %}
                {% if finding.type != 'metadata' %}
                <div class="finding-item">
                    <div class="finding-header">
                        <strong>{{ finding.type | replace('_', ' ') | title }}</strong>
                        {% if finding.severity %}
                        <span class="severity-badge severity-{{ finding.severity }}">
                            {{ finding.severity }}
                        </span>
                        {% endif %}
                    </div>
                    {% if finding.description %}
                    <p>{{ finding.description }}</p>
                    {% endif %}
                    {% if finding.functions %}
                    <p><strong>Functions:</strong> {{ finding.functions | join(', ') }}</p>
                    {% endif %}
                    {% if finding.examples %}
                    <p><strong>Examples:</strong></p>
                    <ul>
                        {% for example in finding.examples %}
                        <li><code>{{ example }}</code></li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endif %}
            {% endfor %}
        </div>
        {% endif %}

        <div class="card">
            <h2>🎯 Functions (Top 50)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Address</th>
                        <th>Size</th>
                        <th>Signature</th>
                    </tr>
                </thead>
                <tbody>
                    {% for func in functions %}
                    <tr>
                        <td><code>{{ func.name }}</code></td>
                        <td><code>{{ func.address }}</code></td>
                        <td>{{ func.size }} bytes</td>
                        <td><code>{{ func.signature }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>💡 Recommendations</h2>
            <ul>
                {% for rec in summary.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>

        <div class="footer">
            <p>Generated by Ghidra MCP Actor | Powered by Apify</p>
            <p>Report generated using Ghidra's headless analyzer</p>
        </div>
    </div>
</body>
</html>
        """

        template = Template(template_str)
        html = template.render(**data)
        return html


def generate_html_report(analysis_data: GhidraAnalysisData) -> str:
    """
    Convenience function to generate HTML report.

    Args:
        analysis_data: Parsed Ghidra analysis data

    Returns:
        HTML report string
    """
    generator = HTMLReportGenerator(analysis_data)
    return generator.generate_report()
