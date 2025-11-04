"""
Batch Analysis Example

This script demonstrates how to analyze multiple binaries in parallel
using the Ghidra MCP Actor via the Apify API.
"""

from apify_client import ApifyClient
import time

# Initialize the ApifyClient with your API token
client = ApifyClient('YOUR_APIFY_API_TOKEN')

# Actor ID - replace with your actual actor ID
ACTOR_ID = 'YOUR_USERNAME/ghidra-mcp-actor'

# List of binaries to analyze
binaries = [
    {
        "url": "https://example.com/sample1.exe",
        "name": "sample1.exe"
    },
    {
        "url": "https://example.com/sample2.exe",
        "name": "sample2.exe"
    },
    {
        "url": "https://example.com/sample3.dll",
        "name": "sample3.dll"
    },
]

def analyze_binary(binary_url: str, binary_name: str):
    """
    Submit a binary for analysis.

    Args:
        binary_url: URL to the binary
        binary_name: Name for the binary

    Returns:
        Run info dict
    """
    print(f"Starting analysis of {binary_name}...")

    run_input = {
        "binaryUrl": binary_url,
        "binaryName": binary_name,
        "generateReport": True,
        "analysisOptions": {
            "timeout": 600
        }
    }

    # Start the actor run
    run = client.actor(ACTOR_ID).call(run_input=run_input)

    print(f"  Run ID: {run['id']}")
    print(f"  Status: {run['status']}")

    return run


def get_results(run_id: str):
    """
    Retrieve analysis results from a run.

    Args:
        run_id: The actor run ID

    Returns:
        Dict with dataset items and key-value store
    """
    run = client.run(run_id).get()

    # Get dataset items (findings)
    dataset_id = run['defaultDatasetId']
    dataset_items = client.dataset(dataset_id).list_items()

    # Get key-value store (reports)
    kvs_id = run['defaultKeyValueStoreId']
    kvs = client.key_value_store(kvs_id)

    results = {
        "status": run['status'],
        "findings": dataset_items.items,
        "reports": {
            "html": kvs.get_record('REPORT.html'),
            "summary": kvs.get_record('SUMMARY.md'),
            "raw_json": kvs.get_record('ghidra_analysis.json'),
        }
    }

    return results


def main():
    """Main function to run batch analysis."""
    print("=" * 60)
    print("Ghidra MCP Actor - Batch Analysis")
    print("=" * 60)

    # Submit all binaries for analysis
    runs = []
    for binary in binaries:
        run = analyze_binary(binary["url"], binary["name"])
        runs.append({
            "run_id": run["id"],
            "name": binary["name"]
        })
        time.sleep(1)  # Small delay between submissions

    print(f"\n{len(runs)} analysis runs started!")
    print("\nWaiting for results...\n")

    # Wait for all runs to complete and retrieve results
    all_results = []
    for run_info in runs:
        run_id = run_info["run_id"]
        name = run_info["name"]

        print(f"Checking status of {name}...")

        # Wait for run to complete
        while True:
            run = client.run(run_id).get()
            status = run['status']

            if status in ['SUCCEEDED', 'FAILED', 'ABORTED']:
                break

            print(f"  Status: {status} - waiting...")
            time.sleep(10)

        if status == 'SUCCEEDED':
            print(f"  ✓ Analysis completed successfully!")
            results = get_results(run_id)
            all_results.append({
                "name": name,
                "results": results
            })
        else:
            print(f"  ✗ Analysis failed with status: {status}")

    # Print summary
    print("\n" + "=" * 60)
    print("Analysis Summary")
    print("=" * 60)

    for result in all_results:
        name = result["name"]
        findings = result["results"]["findings"]

        print(f"\n{name}:")
        print(f"  Total findings: {len(findings)}")

        # Count findings by type
        finding_types = {}
        for finding in findings:
            ftype = finding.get("type", "unknown")
            finding_types[ftype] = finding_types.get(ftype, 0) + 1

        for ftype, count in finding_types.items():
            print(f"    - {ftype}: {count}")

        # Show threat level if available
        for finding in findings:
            if finding.get("type") == "metadata":
                if "threat_level" in finding:
                    print(f"  Threat Level: {finding['threat_level'].upper()}")

    print("\n" + "=" * 60)
    print("Batch analysis complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
