"""
Ghidra Headless Runner Module

This module handles running Ghidra's analyzeHeadless tool to perform
automated binary analysis using the export_analysis.py script.
"""

import os
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class GhidraRunner:
    """Wrapper for running Ghidra headless analysis."""

    def __init__(self, ghidra_home: Optional[str] = None):
        """
        Initialize the Ghidra runner.

        Args:
            ghidra_home: Path to Ghidra installation. If None, uses GHIDRA_HOME env var.
        """
        self.ghidra_home = ghidra_home or os.getenv("GHIDRA_HOME", "/opt/ghidra")
        self.analyze_headless = os.path.join(
            self.ghidra_home, "support", "analyzeHeadless"
        )

        if not os.path.exists(self.analyze_headless):
            raise RuntimeError(
                f"Ghidra analyzeHeadless not found at: {self.analyze_headless}"
            )

        logger.info(f"Initialized GhidraRunner with GHIDRA_HOME={self.ghidra_home}")

    def analyze_binary(
        self,
        binary_path: str,
        project_dir: str = "/tmp/ghidra_projects",
        project_name: str = "AnalysisProject",
        script_path: str = "/app/ghidra_scripts",
        script_name: str = "export_analysis.py",
        output_dir: str = "/tmp/analysis_output",
        timeout: int = 600,
        delete_project: bool = True,
    ) -> Dict:
        """
        Run Ghidra headless analysis on a binary file.

        Args:
            binary_path: Path to the binary file to analyze
            project_dir: Directory for Ghidra project
            project_name: Name for the Ghidra project
            script_path: Directory containing Ghidra scripts
            script_name: Name of the analysis export script
            output_dir: Directory for output JSON
            timeout: Analysis timeout in seconds
            delete_project: Whether to delete project after analysis

        Returns:
            Dict containing analysis results and metadata

        Raises:
            RuntimeError: If analysis fails
        """
        # Create necessary directories
        os.makedirs(project_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        # Validate binary exists
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        logger.info(f"Starting Ghidra analysis of: {binary_path}")

        # Build analyzeHeadless command
        cmd = [
            self.analyze_headless,
            project_dir,
            project_name,
            "-import",
            binary_path,
            "-postScript",
            script_name,
            "-scriptPath",
            script_path,
        ]

        if delete_project:
            cmd.append("-deleteProject")

        logger.info(f"Running command: {' '.join(cmd)}")

        try:
            # Run Ghidra analysis
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
            )

            logger.info("Ghidra analysis completed successfully")
            logger.debug(f"STDOUT:\n{result.stdout}")

            if result.stderr:
                logger.warning(f"STDERR:\n{result.stderr}")

            # Check for output JSON
            output_json = os.path.join(output_dir, "ghidra_analysis.json")
            if not os.path.exists(output_json):
                raise RuntimeError(
                    f"Analysis output not found at: {output_json}. "
                    "Check Ghidra logs for errors."
                )

            return {
                "success": True,
                "output_path": output_json,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra analysis timed out after {timeout} seconds")
            raise RuntimeError(f"Analysis timed out after {timeout} seconds")

        except subprocess.CalledProcessError as e:
            logger.error(f"Ghidra analysis failed with exit code {e.returncode}")
            logger.error(f"STDOUT:\n{e.stdout}")
            logger.error(f"STDERR:\n{e.stderr}")
            raise RuntimeError(
                f"Ghidra analysis failed with exit code {e.returncode}: {e.stderr}"
            )

    def quick_info(self, binary_path: str) -> Dict:
        """
        Get quick binary information without full analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            Dict with basic binary information
        """
        import magic

        info = {
            "path": binary_path,
            "size": os.path.getsize(binary_path),
            "file_type": None,
        }

        try:
            # Use python-magic to get file type
            info["file_type"] = magic.from_file(binary_path)
        except Exception as e:
            logger.warning(f"Could not determine file type: {e}")

        return info
