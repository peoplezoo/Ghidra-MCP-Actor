"""
Ghidra MCP Actor - Main Entry Point

This is the main entry point for the Apify Actor. It handles:
1. Binary ingestion (URL or base64)
2. Running Ghidra headless analysis
3. Generating reports and storing to Apify storage
4. Running as MCP server for interactive AI analysis
"""

import os
import sys
import asyncio
import logging
import base64
import hashlib
from pathlib import Path
from typing import Optional

import requests
from apify import Actor

from src.ghidra.run_headless import GhidraRunner
from src.ghidra.parsers import GhidraAnalysisData
from src.reporting.summarize import AnalysisSummarizer
from src.reporting.render_html import generate_html_report
from src.mcp_server import start_mcp_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class GhidraActorError(Exception):
    """Custom exception for actor errors."""
    pass


async def download_binary(url: str, output_path: str) -> None:
    """
    Download binary from URL.

    Args:
        url: URL to download from
        output_path: Path to save binary

    Raises:
        GhidraActorError: If download fails
    """
    logger.info(f"Downloading binary from: {url}")
    try:
        response = requests.get(url, timeout=300, stream=True)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info(f"Downloaded binary to: {output_path} ({os.path.getsize(output_path)} bytes)")
    except Exception as e:
        raise GhidraActorError(f"Failed to download binary: {e}")


def decode_binary(base64_content: str, output_path: str) -> None:
    """
    Decode base64 binary content.

    Args:
        base64_content: Base64 encoded binary
        output_path: Path to save decoded binary

    Raises:
        GhidraActorError: If decoding fails
    """
    logger.info("Decoding base64 binary content")
    try:
        binary_data = base64.b64decode(base64_content)
        with open(output_path, "wb") as f:
            f.write(binary_data)
        logger.info(f"Decoded binary to: {output_path} ({len(binary_data)} bytes)")
    except Exception as e:
        raise GhidraActorError(f"Failed to decode base64 binary: {e}")


def calculate_hashes(file_path: str) -> dict:
    """
    Calculate file hashes.

    Args:
        file_path: Path to file

    Returns:
        Dict with hash values
    """
    logger.info("Calculating file hashes")
    hashes = {}

    with open(file_path, "rb") as f:
        data = f.read()
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()

    logger.info(f"Hashes: MD5={hashes['md5']}, SHA256={hashes['sha256']}")
    return hashes


async def run_analysis(
    binary_path: str,
    timeout: int = 600,
) -> str:
    """
    Run Ghidra analysis on binary.

    Args:
        binary_path: Path to binary file
        timeout: Analysis timeout in seconds

    Returns:
        Path to analysis JSON output

    Raises:
        GhidraActorError: If analysis fails
    """
    logger.info("Starting Ghidra analysis")

    try:
        runner = GhidraRunner()
        result = runner.analyze_binary(
            binary_path=binary_path,
            timeout=timeout,
        )

        if not result["success"]:
            raise GhidraActorError("Analysis completed but output not found")

        logger.info(f"Analysis completed successfully: {result['output_path']}")
        return result["output_path"]

    except Exception as e:
        raise GhidraActorError(f"Ghidra analysis failed: {e}")


async def generate_and_store_reports(
    analysis_data: GhidraAnalysisData,
    binary_path: str,
    hashes: dict,
) -> None:
    """
    Generate and store reports to Apify storage.

    Args:
        analysis_data: Parsed analysis data
        binary_path: Path to original binary
        hashes: File hashes
    """
    logger.info("Generating reports")

    # Generate findings for dataset
    summarizer = AnalysisSummarizer(analysis_data)
    findings = summarizer.generate_findings()

    # Add file hashes to first finding
    if findings:
        findings[0]["hashes"] = hashes

    # Push findings to dataset
    logger.info(f"Pushing {len(findings)} findings to dataset")
    for finding in findings:
        await Actor.push_data(finding)

    # Generate HTML report
    logger.info("Generating HTML report")
    html_report = generate_html_report(analysis_data)
    await Actor.set_value("REPORT.html", html_report, content_type="text/html")
    logger.info("HTML report saved to key-value store")

    # Generate and save markdown summary
    logger.info("Generating executive summary")
    exec_summary = summarizer.generate_executive_summary()
    await Actor.set_value("SUMMARY.md", exec_summary, content_type="text/markdown")
    logger.info("Executive summary saved to key-value store")

    # Save raw analysis JSON
    with open("/tmp/analysis_output/ghidra_analysis.json", "rb") as f:
        await Actor.set_value(
            "ghidra_analysis.json",
            f.read(),
            content_type="application/json",
        )
    logger.info("Raw analysis JSON saved to key-value store")


async def run_mcp_mode(analysis_json: str, binary_path: str) -> None:
    """
    Run actor as MCP server for interactive analysis.

    Args:
        analysis_json: Path to analysis JSON
        binary_path: Path to binary file
    """
    logger.info("Starting MCP server mode")
    await start_mcp_server(analysis_json, binary_path)


async def main() -> None:
    """
    Main actor entry point.
    """
    async with Actor:
        logger.info("=" * 60)
        logger.info("Ghidra MCP Actor Started")
        logger.info("=" * 60)

        # Get actor input
        actor_input = await Actor.get_input() or {}
        logger.info(f"Actor input: {actor_input}")

        # Check if running in MCP standby mode
        is_standby = os.getenv("APIFY_META_ORIGIN") == "STANDBY"
        mcp_mode = actor_input.get("mcpMode", False) or is_standby

        # Extract input parameters
        binary_url = actor_input.get("binaryUrl")
        binary_base64 = actor_input.get("binaryBase64")
        binary_name = actor_input.get("binaryName", "sample.exe")
        analysis_options = actor_input.get("analysisOptions", {})
        generate_report = actor_input.get("generateReport", True)

        # Validate input
        if not binary_url and not binary_base64:
            raise GhidraActorError(
                "Either 'binaryUrl' or 'binaryBase64' must be provided"
            )

        # Setup paths
        binary_path = f"/tmp/{binary_name}"
        analysis_json_path = "/tmp/analysis_output/ghidra_analysis.json"

        try:
            # Step 1: Obtain binary
            if binary_url:
                await download_binary(binary_url, binary_path)
            elif binary_base64:
                decode_binary(binary_base64, binary_path)

            # Calculate hashes
            hashes = calculate_hashes(binary_path)

            # Step 2: Run Ghidra analysis
            timeout = analysis_options.get("timeout", 600)
            analysis_json_path = await run_analysis(binary_path, timeout)

            # Step 3: Parse analysis data
            logger.info("Parsing analysis data")
            analysis_data = GhidraAnalysisData(analysis_json_path)

            # Step 4: Generate and store reports (if not in MCP mode)
            if generate_report and not mcp_mode:
                await generate_and_store_reports(analysis_data, binary_path, hashes)

            # Step 5: If MCP mode, start MCP server
            if mcp_mode:
                logger.info("Entering MCP server mode")
                await run_mcp_mode(analysis_json_path, binary_path)
            else:
                logger.info("=" * 60)
                logger.info("Analysis completed successfully!")
                logger.info("=" * 60)
                logger.info("Results:")
                logger.info(f"  - Dataset: {len(analysis_data.functions)} findings")
                logger.info("  - HTML Report: REPORT.html (Key-Value Store)")
                logger.info("  - Summary: SUMMARY.md (Key-Value Store)")
                logger.info("  - Raw Data: ghidra_analysis.json (Key-Value Store)")
                logger.info("=" * 60)

        except GhidraActorError as e:
            logger.error(f"Actor error: {e}")
            await Actor.fail(status_message=str(e))
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            await Actor.fail(status_message=f"Unexpected error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
