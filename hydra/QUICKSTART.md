# Quick Start Guide - Ghidra MCP Actor

This guide will help you deploy and run the Ghidra MCP Actor in minutes.

## Prerequisites

- Windows 10/11, macOS, or Linux
- Git installed
- Node.js 18+ (for Apify CLI)
- Docker (optional, for local testing)

## Step 1: Install Apify CLI

Choose your platform:

### Windows (PowerShell)
```powershell
irm https://apify.com/install-cli.ps1 | iex
```

### macOS (Homebrew)
```bash
brew install apify-cli
```

### Linux/macOS/Windows (NPM)
```bash
npm install -g apify-cli
```

Verify installation:
```bash
apify --version
```

## Step 2: Get the Code

If you haven't already cloned the repository:

```bash
git clone https://github.com/YOUR_USERNAME/ghidra-mcp-actor.git
cd ghidra-mcp-actor
```

If you're already in the project directory (E:\ghira\hydra), you're ready to go!

## Step 3: Login to Apify

```bash
apify login
```

This will open your browser. Sign in or create an Apify account (free tier available).

## Step 4: Deploy to Apify

From the project directory:

```bash
apify push
```

This will:
- Upload your code to Apify
- Build the Docker image (takes ~5-10 minutes first time)
- Create the actor in your Apify account

**Note**: The first build takes longer because it downloads Ghidra (~500MB). Subsequent builds are cached.

## Step 5: Run Your First Analysis

### Option A: Via Apify Console (Easiest)

1. Go to [Apify Console](https://console.apify.com) → **My Actors**
2. Click on **ghidra-mcp-actor**
3. Click **▶ Start** button
4. Use this test input:

```json
{
  "binaryUrl": "https://github.com/corkami/pocs/raw/master/PE/tiny.exe",
  "binaryName": "tiny.exe",
  "generateReport": true,
  "analysisOptions": {
    "timeout": 300
  }
}
```

5. Click **Start** and wait for results (~2-3 minutes)

### Option B: Via CLI

```bash
apify call
```

When prompted, paste the JSON input above.

## Step 6: View Results

After the run completes:

### In Console:
1. **Dataset** tab: See structured findings (JSON)
2. **Key-value store** tab:
   - Open `REPORT.html` to view the full report
   - Download `SUMMARY.md` for executive summary
   - Download `ghidra_analysis.json` for raw data

### Via CLI:
```bash
# List recent runs
apify runs ls

# Get run details
apify runs info <RUN_ID>

# Download results
apify runs download <RUN_ID>
```

## Testing Locally (Optional)

### Build Docker Image

```bash
docker build -t ghidra-mcp-actor:local .
```

**Note**: This will take 10-15 minutes as it downloads Ghidra.

### Run Analysis Locally

```bash
# Create input file
cat > input.json << 'EOF'
{
  "binaryUrl": "https://github.com/corkami/pocs/raw/master/PE/tiny.exe",
  "binaryName": "tiny.exe",
  "generateReport": true
}
EOF

# Run the actor
docker run --rm \
  -e APIFY_LOCAL_STORAGE_DIR=/storage \
  -v $(pwd)/input.json:/input.json \
  -v $(pwd)/output:/storage \
  ghidra-mcp-actor:local
```

Results will be in `./output/` directory.

## Using MCP Server Mode (Interactive AI Analysis)

### Step 1: Deploy Actor in Standby Mode

In Apify Console:
1. Go to your actor settings
2. Enable **Run in standby** mode
3. Start with this input:

```json
{
  "binaryUrl": "https://github.com/corkami/pocs/raw/master/PE/tiny.exe",
  "binaryName": "tiny.exe",
  "mcpMode": true
}
```

### Step 2: Connect AI Agent

The actor will expose an MCP server. You can connect:

- **Claude Desktop** (via MCP configuration)
- **ChatGPT** (via MCP plugin)
- **Custom MCP client**

Example queries you can ask:
- "What does this binary do?"
- "Show me all functions that contain 'CreateFile'"
- "Are there any suspicious API calls?"
- "Search for encryption-related functions"

## Troubleshooting

### Build Takes Too Long
- First build downloads Ghidra (~500MB) and takes 10-15 minutes
- Subsequent builds are much faster (~2-3 minutes)

### "Ghidra analysis failed"
- Check the timeout setting (increase for large binaries)
- Verify the binary URL is accessible
- Some packed/obfuscated binaries may fail

### "Out of memory"
- In Apify Console, increase memory allocation:
  - Settings → Resources → Memory: 4096 MB (for large binaries)

### Local Docker Issues
- Ensure Docker has enough resources (4GB+ RAM)
- Check Docker logs: `docker logs <container-id>`

## Example Workflows

### Analyze a Suspicious Binary

```json
{
  "binaryUrl": "https://your-server.com/suspicious.exe",
  "binaryName": "suspicious.exe",
  "generateReport": true,
  "yaraRules": "rule Suspicious {\n  strings:\n    $a = \"CreateRemoteThread\"\n  condition:\n    $a\n}",
  "analysisOptions": {
    "timeout": 600
  }
}
```

### Batch Analysis (Multiple Binaries)

See `examples/batch_analysis.py` for a complete script.

```python
from apify_client import ApifyClient

client = ApifyClient('YOUR_API_TOKEN')

binaries = [
    "https://example.com/sample1.exe",
    "https://example.com/sample2.exe",
]

for url in binaries:
    run = client.actor('YOUR_ACTOR_ID').call(run_input={
        "binaryUrl": url,
        "generateReport": True
    })
    print(f"Started: {run['id']}")
```

### Custom YARA Rules

```json
{
  "binaryUrl": "https://example.com/sample.exe",
  "yaraRules": "rule Ransomware {\n  meta:\n    description = \"Detects ransomware\"\n  strings:\n    $crypto = \"CryptEncrypt\"\n    $ransom = \"bitcoin\"\n  condition:\n    all of them\n}"
}
```

## Next Steps

1. **Read Full Documentation**:
   - [USAGE.md](USAGE.md) - Detailed usage guide
   - [README.md](README.md) - Architecture and features

2. **Explore Examples**:
   - `examples/basic_analysis.json`
   - `examples/mcp_interactive.json`
   - `examples/custom_yara.json`
   - `examples/batch_analysis.py`

3. **Customize**:
   - Add your own YARA rules
   - Modify report templates
   - Extend MCP tools

4. **Set Up CI/CD**:
   - Add `APIFY_TOKEN` to GitHub Secrets
   - Push to main branch for auto-deployment

## Support

- **Documentation**: See [USAGE.md](USAGE.md)
- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/ghidra-mcp-actor/issues)
- **Community**: [Apify Discord](https://discord.com/invite/jyEM2PRvMU)

## Resources

- [Apify Documentation](https://docs.apify.com)
- [MCP Protocol](https://modelcontextprotocol.io)
- [Ghidra Documentation](https://ghidra-sre.org)
- [YARA Rules](https://yara.readthedocs.io)

---

**Ready to analyze malware with AI! 🚀**
