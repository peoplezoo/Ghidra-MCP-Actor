# Ghidra MCP Actor - AI-Assisted Malware Analysis

[![Apify](https://img.shields.io/badge/Apify-Actor-00D4FF)](https://apify.com)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-11.0.1-red)](https://ghidra-sre.org/)
[![MCP](https://img.shields.io/badge/MCP-Enabled-green)](https://modelcontextprotocol.io)

An Apify Actor that integrates the NSA's **Ghidra** reverse engineering tool with the **Model Context Protocol (MCP)** to enable AI-assisted binary analysis. This actor automatically decompiles binaries in headless mode and exposes a set of tools that AI agents can invoke to inspect code structure, search for suspicious patterns, and generate human-readable security reports.

1) Repository layout
ghidra-mcp-actor/
├─ apify.json
├─ input_schema.json
├─ Dockerfile
├─ README.md
├─ requirements.txt
├─ src/
│  ├─ main.py                 # Apify Actor entrypoint
│  ├─ mcp_server.py           # MCP stdio/SSE server (tools exposed here)
│  ├─ ghidra/
│  │  ├─ run_headless.py      # Python wrapper for analyzeHeadless
│  │  ├─ export_json.py       # Ghidra Jython script: exports JSON artifacts
│  │  └─ parsers.py           # JSON post-processing, normalization
│  ├─ reporting/
│  │  ├─ summarize.py         # NL summaries + findings to Dataset/KVS
│  │  └─ render_html.py       # HTML report generation
│  ├─ index/
│  │  ├─ embed.py             # optional: text embeddings over artifacts
│  │  └─ store.py             # retrieval index (faiss/chromadb/kv)
│  ├─ tools/
│  │  ├─ yara_tool.py         # YARA wrapper
│  │  ├─ capstone_tool.py     # Capstone disasm helpers
│  │  ├─ lief_tool.py         # LIEF metadata
│  │  └─ strings_tool.py      # fast strings extraction fallback
│  ├─ cli.py                  # Standalone CLI entry (non-Apify)
│  └─ util/
│     ├─ io.py                # artifact IO helpers
│     ├─ log.py               # structured logging
│     └─ schema.py            # pydantic models for artifacts and tool IO
└─ tests/
   ├─ test_parsers.py
   ├─ test_run_headless.py
   └─ fixtures/
      └─ tiny.bin             # minimal sample (or create at test-time)


2) Requirements
requirements.txt
apify==3.1.2
pydantic==2.9.2
rich==13.9.2
uvicorn==0.32.0
fastapi==0.115.2
orjson==3.10.7
yara-python==4.5.1
capstone==5.0.1
lief==0.14.1
r2pipe==1.9.0
numpy==2.1.2
faiss-cpu==1.8.0.post1 ; platform_system != "Windows"
chromadb==0.5.11
tiktoken==0.8.0
openai==1.51.2
anthropic==0.36.0


Adjust FAISS/Chroma as needed. If FAISS is problematic in your base image, drop it and keep Chroma only.


3) Dockerfile (Apify runtime + Ghidra headless)
# Start from Apify Python runtime
FROM apify/actor-python:3.1.2

USER root
ENV DEBIAN_FRONTEND=noninteractive

# Install JDK and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    wget unzip curl jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# --- Ghidra installation ---
ARG GHIDRA_VERSION=11.2.1
ARG GHIDRA_ZIP=ghidra_${GHIDRA_VERSION}_PUBLIC_20240925.zip
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}/${GHIDRA_ZIP}

RUN mkdir -p /opt/ghidra && \
    curl -L -o /tmp/ghidra.zip "${GHIDRA_URL}" && \
    unzip /tmp/ghidra.zip -d /opt/ghidra && \
    rm /tmp/ghidra.zip

ENV GHIDRA_HOME=/opt/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC
ENV PATH="${GHIDRA_HOME}:${PATH}"

# Python dependencies
COPY requirements.txt /project/requirements.txt
RUN pip install --no-cache-dir -r /project/requirements.txt

# Actor code
COPY src /project/src
COPY apify.json /project/apify.json
COPY input_schema.json /project/input_schema.json
WORKDIR /project

# Health check (optional)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD python -c "import sys; import os; sys.exit(0)"

# Actor entrypoint
CMD ["python", "-m", "src.main"]


If a Ghidra URL/version changes, only update the ARGs. Tested with JDK 17. Ghidra runs headless fine with analyzeHeadless.


4) Apify actor manifest
apify.json
{
  "name": "ghidra-mcp-actor",
  "version": "0.1",
  "buildTag": "latest",
  "environmentVariables": [
    { "key": "OPENAI_API_KEY", "value": "get-from-secrets" },
    { "key": "ANTHROPIC_API_KEY", "value": "get-from-secrets" }
  ],
  "dockerfile": "./Dockerfile"
}


5) Input schema
input_schema.json
{
  "title": "Ghidra MCP Actor input",
  "type": "object",
  "schemaVersion": 1,
  "properties": {
    "binaryUrls": {
      "title": "Binary URLs",
      "type": "array",
      "items": { "type": "string" },
      "description": "HTTP(S) URLs to binaries to analyze"
    },
    "mcpMode": {
      "title": "Run MCP Server",
      "type": "boolean",
      "description": "Expose MCP tools over stdio (Actor logs/streams)",
      "default": false
    },
    "rules": {
      "title": "YARA rules (inline)",
      "type": "string",
      "description": "Optional YARA rules to apply"
    },
    "embedding": {
      "title": "Embed Artifacts",
      "type": "boolean",
      "default": true
    },
    "summarize": {
      "title": "Generate NL Summary",
      "type": "boolean",
      "default": true
    }
  },
  "required": []
}


6) Ghidra headless wrapper
src/ghidra/run_headless.py
import os, subprocess, tempfile, shutil, json, uuid
from pathlib import Path
from .parsers import collect_artifacts

GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/opt/ghidra/ghidra_11.2.1_PUBLIC")

def _ghidra_bin():
    return str(Path(GHIDRA_HOME) / "support" / "analyzeHeadless")

def run(binary_path: str, workdir: str, script_dir: str, post_script: str = "export_json.py") -> dict:
    proj_dir = Path(workdir) / f"gh_proj_{uuid.uuid4().hex}"
    proj_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        _ghidra_bin(),
        str(proj_dir),
        "job",
        "-import", binary_path,
        "-scriptPath", script_dir,
        "-postScript", post_script
    ]

    env = os.environ.copy()
    env["JAVA_TOOL_OPTIONS"] = env.get("JAVA_TOOL_OPTIONS", "") + " -Djava.awt.headless=true"

    subprocess.run(cmd, check=True, env=env)

    # Ghidra script should write artifacts.json next to the imported file or into project dir
    artifacts_json = list(proj_dir.rglob("artifacts.json"))
    if not artifacts_json:
        raise RuntimeError("artifacts.json not produced by Ghidra script")
    with open(artifacts_json[0], "r", encoding="utf-8") as f:
        raw = json.load(f)
    return collect_artifacts(raw, base_dir=str(proj_dir))


7) Ghidra export script (Jython)
src/ghidra/export_json.py (placed on -scriptPath)
#@category Analysis.Export
#@menupath Tools.Export JSON artifacts
# Produces artifacts.json with functions, strings, symbols, xrefs basic info

import json
from ghidra.program.model.symbol import SymbolType

out = {}

currentProgram = getCurrentProgram()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
symtab = currentProgram.getSymbolTable()

# Functions
funcs = []
for f in fm.getFunctions(True):
    entry = f.getEntryPoint()
    funcs.append({
        "name": f.getName(),
        "entry": str(entry),
        "size": f.getBody().getNumAddresses(),
        "params": [p.getName() for p in f.getParameters()],
        "isThunk": f.isThunk(),
    })
out["functions"] = funcs

# Strings (simple)
strings = []
string_mgr = currentProgram.getListing().getDefinedData(True)
# fallback: quick scan of defined data labeled as strings
# This is simplistic; for production use Ghidra's StringSearch utilities.
count = 0
iter = listing.getData(True)
while iter.hasNext() and count < 5000:
    d = iter.next()
    if d.isDefined() and d.getDataType().getName().lower().find("string") >= 0:
        try:
            strings.append({"addr": str(d.getAddress()), "value": str(d.getValue())})
            count += 1
        except:
            pass
out["strings"] = strings

# Symbols
symbols = []
for s in symtab.getAllSymbols(True):
    if s.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL, SymbolType.GLOBAL):
        symbols.append({
            "name": s.getName(),
            "addr": str(s.getAddress()),
            "type": str(s.getSymbolType()),
        })
out["symbols"] = symbols

# Xrefs (lightweight: symbol -> references count)
xrefs = []
for s in symtab.getAllSymbols(True):
    refs = getReferencesTo(s.getAddress())
    if refs and len(refs) > 0:
        xrefs.append({
            "to": str(s.getAddress()),
            "count": len(refs)
        })
out["xrefs"] = xrefs

# Write artifacts.json in project directory
import os
proj_dir = currentProgram.getDomainFile().getParent().getFileSystem().getPath()
with open(os.path.join(proj_dir, "artifacts.json"), "w") as f:
    json.dump(out, f)
print("export_json.py -> artifacts.json")


8) Artifact parsing and normalization
src/ghidra/parsers.py
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class Function(BaseModel):
    name: str
    entry: str
    size: int
    params: List[str]
    isThunk: bool

class Symbol(BaseModel):
    name: str
    addr: str
    type: str

class XRef(BaseModel):
    to: str
    count: int

class Artifacts(BaseModel):
    functions: List[Function] = []
    strings: List[Dict[str, str]] = []
    symbols: List[Symbol] = []
    xrefs: List[XRef] = []

def collect_artifacts(raw: Dict[str, Any], base_dir: str) -> Dict[str, Any]:
    # Pydantic validation + normalized structure
    data = Artifacts(**raw).model_dump()
    data["base_dir"] = base_dir
    return data


9) MCP server with tool definitions
src/mcp_server.py
import json, sys
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from .ghidra.run_headless import run as ghidra_run
from .tools.yara_tool import run_yara
from .tools.strings_tool import fast_strings
from .reporting.summarize import summarize_findings

# Minimal stdio-based MCP protocol sketch:
# Read line-delimited JSON commands: {"tool":"decompile","args":{...}}
# Respond with {"ok":true,"result":{...}} or {"ok":false,"error":"..."}

class DecompileArgs(BaseModel):
    path: str

def handle_decompile(args: Dict[str, Any]) -> Dict[str, Any]:
    dargs = DecompileArgs(**args)
    artifacts = ghidra_run(dargs.path, "/tmp", script_dir="/project/src/ghidra")
    return {"artifacts": artifacts}

class StringsArgs(BaseModel):
    path: str
    min_len: int = 4

def handle_strings(args: Dict[str, Any]) -> Dict[str, Any]:
    sargs = StringsArgs(**args)
    return {"strings": fast_strings(sargs.path, sargs.min_len)}

class YaraArgs(BaseModel):
    path: str
    rules: str

def handle_yara(args: Dict[str, Any]) -> Dict[str, Any]:
    yargs = YaraArgs(**args)
    return {"matches": run_yara(yargs.rules, yargs.path)}

TOOLS = {
    "decompile": handle_decompile,
    "strings": handle_strings,
    "yara_scan": handle_yara,
    "summarize": lambda a: {"summary": summarize_findings(a.get("artifacts", {}))}
}

def serve_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            tool = req.get("tool")
            args = req.get("args", {})
            if tool not in TOOLS:
                raise ValueError(f"unknown tool '{tool}'")
            res = TOOLS[tool](args)
            sys.stdout.write(json.dumps({"ok": True, "result": res}) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"ok": False, "error": str(e)}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    serve_stdio()


10) Apify entrypoint
src/main.py
import os, json, tempfile
from apify import Actor
from pathlib import Path
from .util.io import download_to_path, save_kv, push_dataset_item
from .ghidra.run_headless import run as ghidra_run
from .tools.yara_tool import run_yara
from .reporting.summarize import summarize_findings
from .reporting.render_html import render_html_report

async def _process_binary(url: str, rules: str|None, do_embed: bool, do_summarize: bool):
    tmp = tempfile.mkdtemp()
    bin_path = download_to_path(url, tmp)
    artifacts = ghidra_run(bin_path, tmp, script_dir="/project/src/ghidra")

    yara_matches = []
    if rules:
        yara_matches = run_yara(rules, bin_path)

    summary = summarize_findings({"artifacts": artifacts, "yara": yara_matches}) if do_summarize else None
    html = render_html_report(artifacts, yara_matches, summary)

    # Save outputs
    item = {
        "sourceUrl": url,
        "artifacts": artifacts,
        "yara": yara_matches,
        "summary": summary
    }
    await push_dataset_item(item)
    report_key = f"report_{Path(bin_path).name}.html"
    await save_kv(report_key, html, content_type="text/html")
    return {"dataset_item": item, "report_key": report_key}

async def main():
    async with Actor:
        input_ = await Actor.get_input() or {}
        urls = input_.get("binaryUrls", [])
        rules = input_.get("rules")
        do_embed = bool(input_.get("embedding", True))
        do_summarize = bool(input_.get("summarize", True))
        mcp_mode = bool(input_.get("mcpMode", False))

        results = []
        for url in urls:
            results.append(await _process_binary(url, rules, do_embed, do_summarize))

        await Actor.set_value("RESULTS.json", results)

        if mcp_mode:
            # Run MCP in the foreground on stdio; logs stream to platform
            from .mcp_server import serve_stdio
            serve_stdio()

if __name__ == "__main__":
    import asyncio; asyncio.run(main())


11) Utilities
src/util/io.py
import aiohttp, asyncio, os
from apify import Actor

def download_to_path(url: str, out_dir: str) -> str:
    import requests, pathlib
    fn = url.split("/")[-1] or "binary.bin"
    path = str(pathlib.Path(out_dir)/fn)
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(1<<20):
                if chunk:
                    f.write(chunk)
    return path

async def save_kv(key: str, data: str|bytes, content_type: str):
    # Key-Value store
    await Actor.set_value(key, data, content_type=content_type)

async def push_dataset_item(item: dict):
    await Actor.push_data(item)


12) Tools (examples)
src/tools/strings_tool.py
def fast_strings(path: str, min_len: int = 4):
    out = []
    with open(path, "rb") as f:
        data = f.read()
    run = bytearray()
    for b in data:
        if 32 <= b <= 126:
            run.append(b)
        else:
            if len(run) >= min_len:
                out.append(run.decode("ascii", errors="ignore"))
            run.clear()
    if len(run) >= min_len:
        out.append(run.decode("ascii", errors="ignore"))
    return out

src/tools/yara_tool.py
import yara, tempfile

def run_yara(rules: str, sample_path: str):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(rules)
        rule_path = f.name
    compiled = yara.compile(filepath=rule_path)
    matches = compiled.match(sample_path)
    return [m.rule for m in matches]


13) Reporting
src/reporting/summarize.py
def summarize_findings(doc: dict) -> str:
    a = doc.get("artifacts", {})
    y = doc.get("yara", [])
    fcount = len(a.get("functions", []))
    scount = len(a.get("strings", []))
    xcount = len(a.get("xrefs", []))
    ylist = ", ".join(y) if y else "none"
    return (
        f"Functions: {fcount}; Strings: {scount}; Xrefs: {xcount}. "
        f"YARA matches: {ylist}."
    )

src/reporting/render_html.py
from html import escape

def render_html_report(artifacts: dict, yara_matches: list, summary: str|None) -> str:
    def li(items, key): 
        return "".join(f"<li>{escape(str(x.get(key, '')))}</li>" for x in items)
    funcs = artifacts.get("functions", [])
    strings = artifacts.get("strings", [])
    ylis = "".join(f"<li>{escape(m)}</li>" for m in yara_matches)
    return f"""<!doctype html><meta charset="utf-8"><title>Ghidra Report</title>
<h1>Ghidra MCP Report</h1>
<p>{escape(summary or '')}</p>
<h2>Functions</h2><ul>{''.join(f"<li>{escape(f.get('name',''))} @ {escape(f.get('entry',''))}</li>" for f in funcs)}</ul>
<h2>Strings (sample)</h2><ul>{''.join(f"<li>{escape(s.get('value',''))}</li>" for s in strings[:200])}</ul>
<h2>YARA</h2><ul>{ylis}</ul>"""


14) Standalone CLI
src/cli.py
import argparse, json
from .ghidra.run_headless import run as ghidra_run
from .tools.yara_tool import run_yara
from .reporting.summarize import summarize_findings
from .reporting.render_html import render_html_report

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--yara", help="inline yara rules file")
    ap.add_argument("--html", help="output html file")
    args = ap.parse_args()

    artifacts = ghidra_run(args.path, "/tmp", script_dir="/project/src/ghidra")
    yara_rules = open(args.yara).read() if args.yara else None
    matches = run_yara(yara_rules, args.path) if yara_rules else []
    summary = summarize_findings({"artifacts": artifacts, "yara": matches})
    print(json.dumps({"artifacts": artifacts, "yara": matches, "summary": summary}, indent=2))

    if args.html:
        html = render_html_report(artifacts, matches, summary)
        open(args.html, "w").write(html)

if __name__ == "__main__":
    main()


15) Tests (pytest)
tests/test_parsers.py
from src.ghidra.parsers import collect_artifacts

def test_collect_artifacts_roundtrip():
    raw = {"functions":[], "strings":[], "symbols":[], "xrefs":[]}
    out = collect_artifacts(raw, base_dir="/tmp")
    assert out["base_dir"] == "/tmp"
    assert set(out.keys()) >= {"functions","strings","symbols","xrefs","base_dir"}

tests/test_run_headless.py (mocked)
import src.ghidra.run_headless as rh

def test_has_analyzeHeadless_bin():
    assert "analyzeHeadless" in rh._ghidra_bin()


For CI, keep headless integration test mocked or behind an opt-in flag due to image size/time.


16) Local development
Build:
docker build -t ghidra-mcp-actor:dev .

Run actor locally (mount a sample binary):
docker run --rm -e APIFY_LOCAL_STORAGE_DIR=/data \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -v $PWD/devdata:/data \
  -v $PWD/samples:/samples \
  ghidra-mcp-actor:dev

Run CLI inside container:
docker run --rm -v $PWD/samples:/samples ghidra-mcp-actor:dev \
  python -m src.cli /samples/tiny.bin --html /samples/report.html


17) Apify Platform deployment
Initialize and push:
npm i -g apify-cli
apify login    # paste APIFY_TOKEN
apify push     # builds and uploads per apify.json

Run on platform with input (example):
{
  "binaryUrls": ["https://example.org/bin/sample.bin"],
  "mcpMode": false,
  "rules": "rule suspicious { strings: $a = \"CreateRemoteThread\" condition: $a }",
  "embedding": false,
  "summarize": true
}

Outputs:


Dataset: per-binary JSON with artifacts, YARA matches, summary


Key-Value Store: RESULTS.json plus report_<name>.html



18) MCP usage examples (stdio)
Send tool calls line-by-line JSON over stdin:
{"tool":"decompile","args":{"path":"/samples/tiny.bin"}}
{"tool":"strings","args":{"path":"/samples/tiny.bin","min_len":5}}
{"tool":"yara_scan","args":{"path":"/samples/tiny.bin","rules":"rule r{strings:$a=\"MZ\" condition:$a}"}}
{"tool":"summarize","args":{"artifacts":{"functions":[],"strings":[],"symbols":[],"xrefs":[]}}}

Response per line:
{"ok":true,"result":{...}}

Wire this to your MCP client/host as a stdio server.

19) CI/CD (GitHub Actions)
.github/workflows/ci.yml
name: ci

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  test-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt pytest
      - name: Run unit tests
        run: pytest -q

  docker-build:
    runs-on: ubuntu-latest
    needs: test-build
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t ghidra-mcp-actor:ci .

  deploy-apify:
    runs-on: ubuntu-latest
    needs: docker-build
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Install Apify CLI
        run: npm i -g apify-cli
      - name: Apify Push
        env:
          APIFY_TOKEN: ${{ secrets.APIFY_TOKEN }}
        run: apify push --silent


Store APIFY_TOKEN, OPENAI_API_KEY, ANTHROPIC_API_KEY in GitHub repo secrets.


20) Security and sandboxing


Never execute analyzed binaries. Treat input as untrusted.


Disable outbound network during analysis if possible (Apify runs are already sandboxed).


Strip or redact path/PII in reports.


Enforce file size cap (e.g., 200 MB) and type checks (PE/ELF/Mach-O) before headless run.


Timeouts for Ghidra headless per sample. Kill process tree on timeout.


Add in src/ghidra/run_headless.py:
subprocess.run(cmd, check=True, env=env, timeout=1800)


21) Extending tools
Add: list_functions, xrefs(symbol), search(pattern), export_cg (call graph via Ghidra script), capstone_disasm(range), lief_metadata. Expose each via TOOLS map in mcp_server.py.

22) Minimal README (operator instructions)
README.md should contain:


Purpose and scope


Inputs (binaryUrls, rules, mcpMode)


Outputs (Dataset, KVS report)


Local build/run, CLI usage


MCP integration notes


Limits and known issues (huge binaries, packed malware, anti-analysis)



23) Coding standard for “codex” execution


Keep all file and module paths exactly as specified.


Respect the exact JSON formats in MCP requests/responses.


Ensure export_json.py is discoverable by -scriptPath /project/src/ghidra.


Produce artifacts.json in the project directory from the Ghidra script.


On Apify, never block on MCP if mcpMode=false; only start MCP loop if explicitly enabled.


Fail fast on missing Ghidra binary or artifacts; return structured errors.



24) Quick start checklist


Set secrets: APIFY_TOKEN, OPENAI_API_KEY (optional), ANTHROPIC_API_KEY (optional).


apify login → apify push.


Run with sample input. Verify Dataset and KVS artifacts.


Toggle mcpMode=true for interactive MCP tool calls via stdio.


Review report_*.html for content and links.


This is sufficient for full deployment on Apify, MCP tool exposure, and a usable standalone CLI.Building an Apify Actor for AI-Assisted Malware Analysis (Ghidra + MCP Integration)

Overview: We will build an Apify Actor that integrates the NSA’s Ghidra reverse engineering tool with the Model Context Protocol (MCP) to enable AI-assisted binary analysis. This actor will automatically decompile a provided binary in headless mode and expose a set of tools (functions) that an AI agent can invoke (via MCP) to inspect the code structure, search for patterns (like suspicious API calls or signatures), and generate human-readable reports. The result is a powerful malware analysis assistant that can answer questions in plain English about the binary’s behavior. In the following steps, we outline how to implement this actor, including setting up Ghidra in the environment, developing the analysis scripts, exposing interactive tools for an LLM, and integrating continuous deployment on Apify’s platform.

Step 1: Setting Up the Environment (Choose Python MCP Server)

Use Python for MCP Server: We’ll use Python for this actor due to its strong fit for running Ghidra and AI integration tasks. Python makes it easy to orchestrate subprocess calls to Ghidra’s headless analyzer and to use security libraries (e.g. yara-python for YARA scans, capstone for disassembly, r2pipe or lief for binary parsing) in pre- or post-processing. Unlike a Node.js environment (which is great for web scraping), a Python runtime has no overhead of headless browsers and is ideal for long-running computation and CLI tools. Apify fully supports Python Actors, including running in standby (long-running) mode for servers, which we’ll leverage for the MCP interface. (If your team is strictly JavaScript-focused, Apify provides a TypeScript MCP server template as well, but here we proceed with Python for its native Ghidra integration capability.)

Apify Actor Base Image: In Apify, every actor runs in a Docker container. We will create a custom Dockerfile for our actor. Start from Apify’s official Python base image (e.g. apify/actor-python-v1) and add Ghidra and required libraries. For example, the Dockerfile may use an Ubuntu base (the Apify image is Debian-based) and include steps to install Java (Ghidra requires a JDK) and download Ghidra:

# Use Apify's Python base image
FROM apify/actor-python-v1

# Install Java (for Ghidra) and other system deps
RUN apt-get update && apt-get install -y openjdk-17-jdk wget unzip && rm -rf /var/lib/apt/lists/*

# Download and extract Ghidra (e.g., version 10.3.3)
RUN wget -O /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20231012.zip \
 && unzip /tmp/ghidra.zip -d /opt \
 && rm /tmp/ghidra.zip

# Set GHIDRA_HOME environment variable (optional, for convenience)
ENV GHIDRA_HOME=/opt/ghidra_10.3.3_PUBLIC

# Copy actor source code
COPY . /app

# Install Python dependencies
RUN pip install -r /app/requirements.txt

# Set the entrypoint to run our actor's main script
ENTRYPOINT ["python", "-m", "src.main"]


In the above, we install OpenJDK, download Ghidra, and copy our code. The ENTRYPOINT uses a Python module src.main which we’ll create in the next steps.

Note: The actor’s Dockerfile ensures Ghidra and all Python libraries are present when the actor runs on Apify. This way, the actor can execute Ghidra’s headless analyzer and perform analysis tasks seamlessly.

Step 2: Automated Binary Ingestion and Headless Decompilation

Input Handling: Define the actor’s input schema to accept a binary file or a file URL. In Apify, the default Key-Value Store is used for actor inputs/outputs. We can allow the user to upload a file directly as the actor’s input (the file would be accessible via Actor.get_input() as a JSON containing perhaps a link to the file on Apify’s storage). Alternatively, the input can be a URL to the binary or base64-encoded content. For simplicity, assume we get a file path or URL from Actor.get_input().

Running Ghidra Headlessly: Ghidra provides a script analyzeHeadless (in the Ghidra support/ folder) for command-line analysis. We will use Python’s subprocess module to invoke this and perform analysis on the input binary. Typically, we create a temporary Ghidra project for each run. For example, to analyze a file malware.exe and run a Ghidra script after analysis, the command looks like:

./analyzeHeadless /path/to/project/dir ProjectName -import malware.exe -postScript analyze.py


According to Ghidra docs, we can include the -scriptPath argument if our script is not in the default scripts directory. The StackExchange example below shows a basic usage of analyzeHeadless with a Python script:

“Using the following command I can run it, just like the Java file:
./analyzeHeadless ghidra-project-directory -import binary-file -postscript yourpythonscript”

In our actor code, we’ll do something similar. For instance, in Python:

import subprocess, os
binary_path = "/tmp/input_binary"  # assume we saved the input file to /tmp
project_dir = "/tmp/ghidra_project"
script_path = "/app/ghidra_scripts"  # directory in our image with custom Ghidra scripts
script_name = "export_analysis.py"

os.makedirs(project_dir, exist_ok=True)
cmd = [
    os.path.join(os.getenv("GHIDRA_HOME", "/opt/ghidra_10.3.3_PUBLIC"), "support", "analyzeHeadless"),
    project_dir, "analysisProject",              # project directory and name
    "-import", binary_path, 
    "-postScript", script_name,                  # run our script after analysis
    "-scriptPath", script_path,
    "-deleteProject"  # remove the Ghidra project after running, if not needed for output
]
result = subprocess.run(cmd, check=True, capture_output=True, text=True)
print(result.stdout)


In this snippet, export_analysis.py would be a Ghidra script we provide (likely written in Jython, i.e., Python 2.7 syntax or Java) that runs inside Ghidra to extract data. For example, the script can iterate over all functions and output their names, addresses, and decompiled code to a JSON file. We might have the script write to a file (e.g., /tmp/output.json) or print to stdout. Since Ghidra’s Jython environment can use Ghidra APIs, it can produce structured data about the program.

Designing Ghidra Scripts: A custom Ghidra headless script (Java or Jython) is needed to get rich analysis. For instance, export_analysis.py could do: enumerate all functions (currentProgram.getListing().getFunctions(true) in Ghidra API), and for each function use the decompiler API to get pseudocode, then output JSON. Ghidra’s scripting API allows writing to files; we can have it write a JSON to disk or print lines that our Python code captures. (Ensure the script runs with Python 2 syntax if using Jython, or write in Java – whichever is easier for you. The key is that the script runs within Ghidra and has access to currentProgram.)

Alternate approach: Instead of using Ghidra’s -postScript, one could use Pyhidra (a Python library that integrates Ghidra via JPype) to perform analysis in-process. The blog by clearbluejar introduces pyghidra-mcp, which runs Ghidra headlessly via Python for advanced automation. This is an option if you want pure Python control (it uses Ghidra’s FlatAPI through JPype), but it’s more complex. For our instructions, we’ll stick to invoking Ghidra’s own headless tool for reliability.

Step 3: Implementing Analysis Tools (Functions) for Code Exploration

After Ghidra has analyzed the binary, we will have an output (JSON or other structured data) describing the program (functions, strings, references, etc.). We now implement tool functions in our Python actor code to expose this information and perform additional analysis. These tool functions correspond to actions an analyst or AI might want to do. Based on the plan, we have tools such as:

list_functions() – Returns a list of all functions identified in the binary, including their names and addresses. (Data comes from the Ghidra analysis JSON.)

decompile(function_name or address) – Returns the decompiled pseudocode for a given function. This uses the output from Ghidra’s decompiler (either retrieved from the JSON or by invoking Ghidra’s decompiler on the fly via a script). The pseudocode is helpful for an AI to reason about what the function does.

xrefs(symbol) – Finds cross-references to a given symbol (function or address). For example, this can list all the places where a particular function is called. (This helps trace program flow – e.g., find which functions call a suspicious function.)

strings() – Extracts printable strings from the binary. This can be done via strings utility or using Ghidra’s data items. The tool will return suspicious or noteworthy strings (URLs, file paths, etc.) that often give clues in malware.

search(pattern) – Searches the disassembly or decompiled code for a given pattern (e.g., a specific API name or byte sequence). This helps locate where certain behaviors (like registry modifications, network communication strings, etc.) occur.

yara_scan(rule) – Runs YARA rules against the binary to match known malware signatures. We can integrate yara-python to load a YARA rule (provided as input or pre-defined rulesets) and scan the binary’s bytes. Matching rule names can be returned as indicators of compromise.

**export_cg() / export_cdg() – Exports the program’s call graph or control flow graph. Using Ghidra’s API or a post-processing library, we can generate a graph of function calls. For example, with Ghidra’s FlatProgramAPI or Pyhidra we could produce a call graph and then output it in a format like Mermaid Markdown or GraphML
github.com
. The actor can save this graph visualization as an image or HTML for the user. This is useful to see the overall structure of the program’s execution.

Each of these tools will be implemented as a Python function in our actor. They will likely operate on the data produced by the headless analysis (the JSON or any artifacts). For example, list_functions() will load the JSON (which contains a list of functions discovered) and return that list (perhaps truncated or formatted). decompile(name) might look up the function in the JSON and return the stored pseudocode text. If the JSON doesn’t contain pseudocode for all functions by default, we might on-demand run Ghidra’s decompiler for that function (via a quick headless script or using ghidra_bridge). But storing all pseudocode in the initial analysis may be easier for speed (at cost of memory).

Data structures: We can load the JSON into Python (using json module) to get dictionaries/lists representing the program. Consider structuring it like:

{
  "functions": [
    {"name": "main", "address": "0x401000", "decompiled": "int main() { ... }", "calls": ["sub_401100", "..."] },
    ...
  ],
  "strings": ["Error: invalid license", "http://malicious.site/...", ...],
  "imports": ["CreateFileA", "RegSetValue", ...],
  ...
}


This way, our tool functions can easily query this object. For instance, search("CreateFile") can check in each function’s decompiled text for that substring, or search in the imports list.

Example – Implementing strings(): We could simply call subprocess.run(["strings", binary_path]) in absence of Ghidra, but Ghidra’s analysis might have more context. However, using the Unix strings utility on the binary file is straightforward. We then filter the output or just return it. If integrated in the Ghidra script, you might have output those to JSON as well.

Testing the tools locally: After implementing, run the actor locally (apify run using the CLI) with a known binary (even a simple HelloWorld or an open-source malware sample) to ensure each tool returns reasonable data. This helps verify that Ghidra’s headless analysis succeeded (e.g., the JSON is populated) and that our Python functions correctly parse and return the info.

Step 4: Integrating MCP for Interactive Q&A

With the core analysis and tool functions in place, we now expose these tools via MCP so that an AI assistant (LLM) can call them during a conversation. In Apify’s MCP architecture, our actor itself will function as an MCP server (specifically, an HTTP SSE server in standby mode) providing these tools to clients (AI agents). Here’s how to set that up:

Use Apify’s MCP server template: Apify provides a Python MCP server template that handles a lot of boilerplate (like SSE connections, session management)
apify.com
. We can leverage this. The template typically defines a main.py that launches the server, and a server.py that defines how to execute tool calls. In our actor, we will integrate our tool functions into this framework.

Define Tools for MCP: In the MCP protocol, each tool has a name, description, and a schema for parameters. We can map our Python functions (list_functions, decompile, etc.) as MCP tools. For example, a tool definition for list_functions might include a description “List all functions in the binary and their addresses” and specify no parameters. A tool for decompile would require a parameter like function_name or address. The MCP server will expose these so that the AI knows they exist. (In practice, Apify’s MCP integration may generate a tool list from an OpenAPI spec or similar behind the scenes, but our job is to register the functions in code.)

Implementing the Server Loop: Our actor will run in standby mode (long-lived process). In the main function, if we detect APIFY_META_ORIGIN=STANDBY (which Apify sets when the actor is started as a persistent service), we start our server. For example, using the template’s classes:

from apify import Actor
from server import MCPToolServer  # hypothetical server class that handles SSE

async with Actor:
    if Actor.is_at_home() and os.getenv('APIFY_META_ORIGIN') == 'STANDBY':
        server = MCPToolServer(tools=[list_functions, decompile, xrefs, strings, search, yara_scan, export_cg])
        server.run(host="0.0.0.0", port=os.getenv('ACTOR_STANDBY_PORT', 8000))
    else:
        # If not in standby, just run once (e.g., if user ran actor in task mode)
        run_analysis_once()


In this pseudo-code, MCPToolServer would handle translating LLM requests (coming via SSE) into calls to our functions, and then send back the results. The Apify MCP template likely uses a similar approach (wrapping either a stdio or SSE based protocol).

Streaming Responses and Progress: Some of our tools (like the initial decompilation) can be slow. MCP supports streaming partial results via server-sent events. We can make our functions yield intermediate messages. For example, as decompile() processes a large function, it could send a few lines at a time. In code, this might mean using Python generators or callbacks to the MCP framework to push updates. The details depend on the MCP library, but conceptually we want the user (or AI) to see progress (e.g., “Analyzing binary… 50% complete”).

Attach Artifacts via Apify Resources: For very large outputs (like an entire decompiled file or a call graph image), it’s often better not to send everything through the chat. Instead, we can save these artifacts to Apify storage and just send a reference. Apify’s MCP server and clients support the concept of resources (which map to Apify Datasets or Key-Value Stores). For example, our actor could save the full HTML report to the default key-value store as REPORT.html, and then the AI’s answer can include a link or mention of that resource. The AI agent could then retrieve it if needed. Because Apify Datasets and KV stores are accessible via API, an MCP client could follow up by fetching those if instructed. (In practice, we might instruct the AI via the system prompt that if output is too large, provide a link to the Apify resource.)

Security Considerations: Ensure that the actor doesn’t expose dangerous functionality. Only the intended tools should be callable. Apify’s MCP integration typically whitelists which tools an agent can use. We will whitelist our defined functions and not allow arbitrary code execution. Also, handle input validation (e.g., if search(pattern) is called, make sure the pattern is a reasonable length, to avoid ReDoS or overly long processing).

At this stage, our actor is essentially a service: when run, it either performs a one-off analysis (if used like a normal actor task) or, in standby mode, it waits for incoming requests from an AI via MCP. The AI agent (LLM), such as Claude or ChatGPT through an MCP client, can now converse with the actor. It might ask something like, “What does this binary do?”. The LLM (through the MCP client) will see that tools like list_functions, decompile, etc. are available and can invoke them. For example, it might call strings() to see if any suspicious URLs are present, then call list_functions() and decompile("InstallKeylogger") if it finds a function with that name, and then summarize the findings in natural language. The synergy between the LLM and our tools allows complex analysis tasks to be done interactively.

Step 5: Generating Reports and Output Artifacts

Besides the interactive Q&A, the actor should produce a comprehensive report for the human user. This was one of the key features (“Comprehensive reporting with highlighted security concerns and recommendations”). We will compile the findings into a report at the end of an analysis run (or upon request via a tool call).

Structured Findings (Dataset): We can push important results into the Apify Dataset (which is like an array of JSON records). For example, each suspicious finding could be one record: {"type": "suspicious_call", "function": "xyz", "detail": "Calls CreateRemoteThread (potential code injection)"} or {"type": "metadata", "compiler": "MSC++ 2015", "arch": "x64"} etc. Pushing data is easy using Apify SDK: await Actor.push_data(item) appends to the dataset. This structured output can be further used in integrations or just for the user to see in JSON form.

Human-Readable Report (Key-Value Store): Use the default Key-Value Store (which is like a dict of files) to save a rendered report. For instance, we can generate an HTML or Markdown report summarizing the binary analysis:

Include basic file info (hashes, size, import table summary).

List potentially malicious indicators (strings, suspicious API calls, unusual sections, etc.).

Include a table of functions with brief descriptions (if we have an AI, we could even have the LLM draft descriptions of what each key function does).

Provide recommendations (e.g. “This binary likely steals credentials; ensure to check network connections to XYZ”).

We then save this report. For example, using Python SDK:

report_content = generate_html_report(analysis_data)
await Actor.set_value("REPORT.html", report_content, content_type="text/html")


This stores the report in the default key-value store under the key “REPORT.html”. We can also generate a PDF: if we have an HTML, we might call an HTML-to-PDF actor or library, or use a headless browser, but that adds complexity. Apify provides an online viewer for HTML, so HTML is usually fine. We could still offer a PDF by rendering via a tool like WeasyPrint if needed. Save it as REPORT.pdf similarly.

Additional artifacts: We mentioned possibly exporting the Ghidra project or graphs. We can zip the Ghidra project directory (if -deleteProject wasn’t used) and save it:

shutil.make_archive("/tmp/project_archive", 'zip', project_dir)
await Actor.set_value("GHIDRA_PROJECT.zip", open("/tmp/project_archive.zip","rb").read(), content_type="application/zip")


Now the user (or AI) can download the entire Ghidra project (which they could open in Ghidra GUI for deeper manual analysis if desired). Likewise, if we created a call graph image (say callgraph.png), we store it similarly with content_type="image/png". All these files will be accessible via the Apify web UI or API for the run.

Finally, when the actor run (in non-standby mode) completes, we will have:

Structured JSON results in the Dataset (viewable or downloadable as .json).

One or more files in the Key-Value Store: the main report, and any attachments (graphs, project zip, etc.).

Logs of the run (which might include Ghidra’s analysis log – consider filtering sensitive data if any).

These outputs align with Apify’s storage system, making it easy to share or integrate. In MCP usage, the AI can reference these as needed (for example, the AI answer might say “I’ve saved a detailed report and decompilation in the run’s Key-Value Store for review”).

Step 6: Deployment and CI/CD Integration on Apify

With the actor developed and tested locally, the next step is deploying it to Apify and setting up continuous integration for ongoing development:

Deploying the Actor: You can deploy the actor via the Apify CLI or by linking a GitHub repository. Using the CLI, you would run apify login (to authenticate) and then apify push to upload your code and build it on Apify. If using a Git repo, in the Apify console you can set the source to “GitHub repository” and provide the repo URL. Don’t forget to include the Dockerfile and all necessary files (Ghidra scripts, etc.) in the repo so that Apify can build the image.

Build and Runtime Settings: In Apify Console, configure memory and timeout as needed. Ghidra can be memory intensive; consider using a larger memory setting (e.g., 2GB or more) for complex binaries. Also, set the actor to allow standby. There’s a toggle for allowing the actor to run indefinitely (for MCP servers). Enable that so our MCP server mode works. You might also specify that the actor should auto-start in standby if you want it always ready (or you can start it on demand).

Continuous Integration via GitHub Actions: To ensure that any change to the code is automatically deployed, set up a CI workflow. A simple approach is to use Apify’s GitHub integration, which rebuilds the actor on each commit to a specific branch. Alternatively, use GitHub Actions to call the Apify API:

Save your Apify API token in the repository’s secrets (e.g. APIFY_TOKEN).

Add an Action YAML (as shown in Apify docs) that runs on push. This Action can run tests (if you have any) and then invoke Apify’s build endpoint. For example, using a generic webhook action:

on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Push to Apify
        uses: apify/push-actor-action@v1
        with:
          apify_token: ${{ secrets.APIFY_TOKEN }}
          actor_id: <YOUR_USERNAME>/<YOUR_ACTOR_NAME>
          version: 0.0.1


This uses Apify’s official GitHub Action to push the actor code and trigger a build. (Alternatively, call the build API endpoint with curl – both methods are fine.) According to Apify’s documentation, automating builds can save time and reduce errors, and you can use GitHub Actions or Bitbucket Pipelines for this.

Ensure the Docker build completes successfully in CI. If Ghidra download is part of the build, it might take a bit of time – you could cache it or keep the image updated separately if needed. Apify’s base images are cached, but our custom layers (JDK and Ghidra) will add to build time.

Testing in CI: If possible, include a basic test in the CI workflow. For instance, after building the actor, you might run a short test job (perhaps using Apify CLI in headless mode) with a tiny binary just to ensure the tools work. This could catch issues early. (For example, test that list_functions() returns a known function from a known binary).

Monitoring and Updates: Once deployed, use Apify’s console to monitor the actor’s runs. For an MCP server, you can start a live run in Standby and then connect an MCP client (like Apify’s Tester or Claude with the server URL). Monitor logs to see tool calls and responses. As you develop new features or fix bugs, push updates through your CI. The Apify integration will automatically rebuild the actor on each commit to main (or whichever branch you set), keeping the deployment up-to-date.

Conclusion and Next Steps: Following these steps, you will have a fully functional Apify actor that uses Ghidra to perform deep malware analysis and interacts with AI agents via MCP. It automates what would typically be hours of manual reverse-engineering work into a pipeline that can produce answers in minutes. The modular design (distinct tool functions and JSON-based data exchange) makes it extensible: you can add more tools (e.g., a tool to extract PE headers or a tool to emulate code). And because all results are stored in Apify storages, they can be easily shared or fed into other systems. With CI/CD integration, improvements to the actor can be deployed continuously, ensuring the tool stays updated as you refine detection techniques or upgrade Ghidra versions.

Finally, remember that if your organization later prefers a different stack, you could reimplement the MCP server in TypeScript using Apify’s template (the core ideas remain the same). But Python should serve well for this use case, giving you a powerful, AI-enhanced reverse engineering assistant running on Apify. Good luck with your implementation!
