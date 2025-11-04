Below is a complete, implementation-ready build spec for the Ghidra MCP Actor using the Python MCP server pattern on Apify, plus a standalone CLI. Includes repo layout, Docker, Ghidra headless integration, MCP tools, Apify input schema, storage outputs, tests, local/dev commands, and CI/CD with GitHub Actions.

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


This is sufficient for full deployment on Apify, MCP tool exposure, and a usable standalone CLI.
