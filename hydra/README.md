# Ghidra MCP Actor - AI-Assisted Malware Analysis

[![Apify](https://img.shields.io/badge/Apify-Actor-00D4FF)](https://apify.com)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-11.0.1-red)](https://ghidra-sre.org/)
[![MCP](https://img.shields.io/badge/MCP-Enabled-green)](https://modelcontextprotocol.io)

An Apify Actor that integrates the NSA's **Ghidra** reverse engineering tool with the **Model Context Protocol (MCP)** to enable AI-assisted binary analysis. This actor automatically decompiles binaries in headless mode and exposes a set of tools that AI agents can invoke to inspect code structure, search for suspicious patterns, and generate human-readable security reports.

## 🚀 Features

- **Automated Binary Analysis**: Headless Ghidra decompilation and analysis
- **AI Integration via MCP**: Expose analysis tools to AI agents (Claude, ChatGPT, etc.)
- **Interactive Analysis**: Ask questions about binaries in natural language
- **Comprehensive Reports**: HTML reports with threat assessment and recommendations
- **YARA Scanning**: Integrate custom YARA rules for malware detection
- **Pattern Detection**: Automatically identify suspicious APIs, strings, and code patterns
- **Batch Processing**: Analyze multiple binaries in parallel
- **Cloud-Native**: Runs on Apify's platform with full storage integration

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [MCP Tools](#mcp-tools)
- [Output](#output)
- [Examples](#examples)
- [Development](#development)
- [Security](#security)

## 🚀 Quick Start

### Run on Apify

1. Go to the [Apify Console](https://console.apify.com)
2. Create a new actor or use this actor
3. Configure the input:

```json
{
  "binaryUrl": "https://example.com/sample.exe",
  "binaryName": "sample.exe",
  "generateReport": true
}
```

4. Run the actor
5. View results in Dataset and Key-Value Store

### Run Locally with Docker

```bash
# Build the Docker image
docker build -t ghidra-mcp-actor .

# Run analysis
docker run -v $(pwd)/input:/input -v $(pwd)/output:/output \
  ghidra-mcp-actor
```

## 📦 Installation

### Prerequisites

- Apify account (for cloud deployment)
- Docker (for local development)
- Python 3.11+ (for local development)

### Local Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ghidra-mcp-actor.git
cd ghidra-mcp-actor

# Install Apify CLI
npm install -g apify-cli

# Install dependencies
pip install -r requirements.txt

# Run locally
apify run
```

## 📖 Usage

See [USAGE.md](USAGE.md) for detailed usage instructions.

### Basic Analysis

```json
{
  "binaryUrl": "https://example.com/sample.exe",
  "binaryName": "sample.exe",
  "generateReport": true
}
```

### Interactive AI Analysis (MCP Mode)

```json
{
  "binaryUrl": "https://example.com/malware.exe",
  "binaryName": "malware.exe",
  "mcpMode": true
}
```

Then connect an AI agent to ask questions like:
- "What does this binary do?"
- "Are there any suspicious API calls?"
- "Show me functions that access the registry"
- "Search for functions that contain 'encrypt'"

### Custom YARA Rules

```json
{
  "binaryUrl": "https://example.com/sample.exe",
  "yaraRules": "rule Ransomware { ... }"
}
```

## 🛠️ MCP Tools

When running in MCP mode, the following tools are exposed to AI agents:

| Tool | Description | Parameters |
|------|-------------|------------|
| `list_functions` | List all functions in the binary | `limit`, `filter_external` |
| `get_function` | Get detailed function information | `identifier` (name or address) |
| `decompile` | Get decompiled pseudocode | `function` (name or address) |
| `search` | Search in decompiled code | `pattern`, `case_sensitive` |
| `strings` | Extract and search strings | `pattern`, `limit` |
| `xrefs` | Find cross-references | `symbol` |
| `imports` | List imported functions | `library`, `suspicious_only` |
| `yara_scan` | Scan with YARA rules | `rules` |
| `summary` | Get analysis summary | - |

## 📊 Output

### Dataset (Structured Findings)

JSON records with structured findings:

```json
{
  "type": "suspicious_import",
  "severity": "high",
  "function": "CreateRemoteThread",
  "library": "KERNEL32.dll",
  "reason": "Code injection",
  "recommendation": "Investigate usage..."
}
```

### Key-Value Store

- **REPORT.html**: Comprehensive HTML report with threat assessment
- **SUMMARY.md**: Executive summary in Markdown
- **ghidra_analysis.json**: Raw Ghidra analysis data

## 📚 Examples

See the [examples/](examples/) directory for:

- `basic_analysis.json`: Simple binary analysis
- `mcp_interactive.json`: Interactive AI analysis
- `custom_yara.json`: Custom YARA rules
- `batch_analysis.py`: Batch processing script

## 🔧 Development

### Project Structure

```
ghidra-mcp-actor/
├── src/
│   ├── main.py              # Actor entry point
│   ├── mcp_server.py        # MCP server implementation
│   ├── ghidra/
│   │   ├── run_headless.py  # Ghidra headless runner
│   │   └── parsers.py       # JSON parsing and normalization
│   ├── reporting/
│   │   ├── summarize.py     # Analysis summarization
│   │   └── render_html.py   # HTML report generation
│   └── index/
│       └── embed.py         # (Optional) Embeddings
├── ghidra_scripts/
│   └── export_analysis.py   # Ghidra Jython script
├── examples/                # Usage examples
├── Dockerfile               # Docker configuration
├── requirements.txt         # Python dependencies
├── apify.json              # Apify configuration
└── input_schema.json       # Input schema
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/
```

## 🔒 Security

### Important Considerations

- **Malware Handling**: This actor analyzes potentially malicious binaries. Always use in isolated environments.
- **Resource Limits**: Set appropriate timeouts for large or obfuscated binaries.
- **Data Privacy**: Be cautious about uploading proprietary binaries to cloud services.
- **YARA Rules**: Only use trusted YARA rules from reputable sources.

### Best Practices

1. Use sandboxed environments
2. Validate binary sources
3. Review logs for suspicious activity
4. Combine with dynamic analysis
5. Keep Ghidra updated

## 🙏 Acknowledgments

- [Ghidra](https://ghidra-sre.org/) - NSA's reverse engineering framework
- [Apify](https://apify.com/) - Web automation and data extraction platform
- [Model Context Protocol](https://modelcontextprotocol.io/) - AI integration standard
- The security research community

## 📧 Contact

For issues or questions:
- GitHub Issues: [Report an issue](https://github.com/YOUR_USERNAME/ghidra-mcp-actor/issues)
- Apify Forum: [Community discussion](https://community.apify.com)

---

**⚠️ Disclaimer**: This tool is for authorized security testing, research, and educational purposes only. Use responsibly and in compliance with applicable laws and regulations.
