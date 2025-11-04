# Ghidra MCP Actor - Usage Guide

This guide explains how to use the Ghidra MCP Actor for AI-assisted malware analysis.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Input Configuration](#input-configuration)
3. [Running Analysis](#running-analysis)
4. [Using MCP Server Mode](#using-mcp-server-mode)
5. [Understanding the Output](#understanding-the-output)
6. [Advanced Usage](#advanced-usage)

## Quick Start

### Method 1: Analyze a binary from URL

```json
{
  "binaryUrl": "https://example.com/sample.exe",
  "binaryName": "malware_sample.exe",
  "generateReport": true
}
```

### Method 2: Analyze base64-encoded binary

```json
{
  "binaryBase64": "TVqQAAMAAAAEAAAA...",
  "binaryName": "sample.exe",
  "generateReport": true
}
```

## Input Configuration

### Required Parameters

At least one of the following must be provided:

- `binaryUrl` (string): URL to download the binary from
- `binaryBase64` (string): Base64-encoded binary content

### Optional Parameters

- `binaryName` (string, default: "sample.exe"): Name for the binary file
- `yaraRules` (string): Custom YARA rules for malware detection
- `generateReport` (boolean, default: true): Generate HTML report
- `mcpMode` (boolean, default: false): Run as MCP server for interactive analysis

### Analysis Options

Configure Ghidra analysis behavior:

```json
{
  "analysisOptions": {
    "decompileAll": true,
    "extractStrings": true,
    "generateCallGraph": true,
    "timeout": 600
  }
}
```

Options:
- `decompileAll` (boolean, default: true): Decompile all functions
- `extractStrings` (boolean, default: true): Extract printable strings
- `generateCallGraph` (boolean, default: true): Generate call graph
- `timeout` (integer, default: 600): Analysis timeout in seconds

## Running Analysis

### Standard Analysis Mode

This mode performs analysis and generates comprehensive reports:

```json
{
  "binaryUrl": "https://example.com/suspicious.exe",
  "binaryName": "suspicious.exe",
  "generateReport": true,
  "analysisOptions": {
    "timeout": 600
  }
}
```

**Outputs:**
- **Dataset**: Structured findings (JSON records)
- **Key-Value Store**:
  - `REPORT.html`: Comprehensive HTML report
  - `SUMMARY.md`: Executive summary (Markdown)
  - `ghidra_analysis.json`: Raw analysis data

### MCP Server Mode

Run the actor as an MCP server for interactive AI analysis:

```json
{
  "binaryUrl": "https://example.com/malware.exe",
  "binaryName": "malware.exe",
  "mcpMode": true
}
```

The actor will start an MCP server that exposes analysis tools for AI agents.

## Using MCP Server Mode

When running in MCP mode, the actor exposes the following tools to AI agents:

### Available Tools

1. **list_functions**
   - Lists all functions in the binary
   - Parameters: `limit`, `filter_external`

2. **get_function**
   - Get detailed info about a specific function
   - Parameters: `identifier` (name or address)

3. **decompile**
   - Get decompiled pseudocode for a function
   - Parameters: `function` (name or address)

4. **search**
   - Search for patterns in decompiled code
   - Parameters: `pattern`, `case_sensitive`

5. **strings**
   - Extract and search strings from binary
   - Parameters: `pattern` (optional), `limit`

6. **xrefs**
   - Find cross-references to a function
   - Parameters: `symbol` (function name or address)

7. **imports**
   - List imported functions
   - Parameters: `library` (optional), `suspicious_only`

8. **yara_scan**
   - Scan binary with YARA rules
   - Parameters: `rules` (YARA rules text)

9. **summary**
   - Get comprehensive analysis summary
   - No parameters

### Example AI Interaction

Once the MCP server is running, an AI agent can interact with it:

**User**: "What does this binary do?"

**AI** (uses tools):
1. Calls `summary()` to get overview
2. Calls `imports(suspicious_only=true)` to check for malicious APIs
3. Calls `strings(pattern="http")` to find URLs
4. Calls `search(pattern="CreateRemoteThread")` to find code injection
5. Synthesizes findings into natural language response

**AI Response**: "This binary appears to be malware. It imports suspicious APIs like CreateRemoteThread and WriteProcessMemory (used for code injection), contains URLs pointing to command-and-control servers, and has anti-debugging checks."

## Understanding the Output

### Dataset (Structured Findings)

Each finding is a JSON record:

```json
{
  "type": "suspicious_import",
  "severity": "high",
  "function": "CreateRemoteThread",
  "library": "KERNEL32.dll",
  "reason": "Code injection",
  "recommendation": "Investigate usage of CreateRemoteThread"
}
```

**Finding Types:**
- `metadata`: Binary metadata
- `suspicious_import`: Potentially malicious imports
- `suspicious_string`: Suspicious strings found
- `code_pattern`: Suspicious code patterns

### HTML Report

Comprehensive report with:
- Executive summary with threat level
- Binary metadata (format, architecture, compiler)
- Statistics (functions, imports, strings)
- Suspicious imports table
- Detailed findings
- Function list
- Recommendations

### Executive Summary (Markdown)

Concise summary in markdown format, suitable for quick review or inclusion in reports.

### Raw Analysis JSON

Complete Ghidra analysis output with:
- All functions with decompiled code
- Extracted strings
- Imports/exports
- Memory sections
- Cross-references

## Advanced Usage

### Custom YARA Rules

Provide custom YARA rules for targeted detection:

```json
{
  "binaryUrl": "https://example.com/sample.exe",
  "yaraRules": "rule Ransomware {\n  strings:\n    $a = \"encrypted\" nocase\n    $b = \"bitcoin\" nocase\n  condition:\n    all of them\n}"
}
```

### Large Binary Analysis

For large binaries, increase the timeout:

```json
{
  "binaryUrl": "https://example.com/large.exe",
  "analysisOptions": {
    "timeout": 1800,
    "decompileAll": false
  }
}
```

Setting `decompileAll: false` speeds up analysis by only decompiling functions on-demand.

### Batch Analysis

You can run multiple actor instances in parallel to analyze multiple binaries:

```python
from apify_client import ApifyClient

client = ApifyClient('YOUR_API_TOKEN')

binaries = [
    "https://example.com/sample1.exe",
    "https://example.com/sample2.exe",
    "https://example.com/sample3.exe",
]

runs = []
for url in binaries:
    run = client.actor('YOUR_ACTOR_ID').call(run_input={
        "binaryUrl": url,
        "generateReport": True
    })
    runs.append(run)

# Retrieve results
for run in runs:
    dataset = client.dataset(run['defaultDatasetId']).list_items()
    print(dataset.items)
```

## Security Considerations

### Important Warnings

1. **Malware Handling**: This actor analyzes potentially malicious binaries. Always use in isolated environments.

2. **Resource Limits**: Large or obfuscated binaries can consume significant memory and CPU. Set appropriate timeouts.

3. **Data Privacy**: Be cautious about uploading proprietary or sensitive binaries to cloud services.

4. **YARA Rules**: Only use trusted YARA rules from reputable sources.

### Best Practices

1. **Use sandboxed environments** for running the actor
2. **Validate binary sources** before analysis
3. **Review logs** for any suspicious behavior
4. **Combine with dynamic analysis** for comprehensive assessment
5. **Keep Ghidra updated** by rebuilding the Docker image periodically

## Troubleshooting

### Analysis Timeout

If analysis times out:
- Increase `analysisOptions.timeout`
- Set `decompileAll: false` to skip full decompilation
- Check binary size (very large binaries may need more time)

### Decompilation Failures

Some functions may fail to decompile:
- Obfuscated code
- Corrupted binaries
- Unsupported architectures

Check the `decompiled` field in function data for error messages.

### MCP Server Connection Issues

If MCP server won't connect:
- Ensure actor is in STANDBY mode
- Check Apify logs for errors
- Verify MCP client configuration

## Examples

See the `examples/` directory for complete examples:
- `basic_analysis.json`: Simple binary analysis
- `mcp_interactive.json`: Interactive AI analysis setup
- `batch_analysis.py`: Batch processing script
- `custom_yara.json`: Custom YARA rules example

## Support

For issues or questions:
- GitHub Issues: [Report an issue](https://github.com/YOUR_USERNAME/ghidra-mcp-actor/issues)
- Apify Forum: [Ask the community](https://community.apify.com)
- Documentation: [Full documentation](https://docs.apify.com)
