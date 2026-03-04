#!/usr/bin/env python3.11
"""
SolSift CLI - Command-line interface for smart contract auditing
Usage: python3.11 cli.py <path-to-file-or-folder> [options]
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path
from typing import List, Dict
import requests

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import from app (when available), otherwise use API-only mode
try:
    from app.services.tools.registry import tool_registry

    HAS_APP_MODULES = True
except ImportError:
    HAS_APP_MODULES = False


# API Base URL
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


def find_solidity_files(path: str) -> List[str]:
    """Find all Solidity files (.sol) in a given path"""
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    sol_files = []

    if path_obj.is_file():
        if path_obj.suffix == ".sol":
            sol_files.append(str(path_obj))
        else:
            raise ValueError(f"File is not a Solidity file: {path}")
    else:
        # Recursively find all .sol files
        sol_files = [str(f) for f in path_obj.rglob("*.sol")]

    if not sol_files:
        raise ValueError(f"No Solidity files found in: {path}")

    return sorted(sol_files)


def read_contract_code(file_path: str) -> str:
    """Read contract code from file"""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def format_results(job_id: str, file_path: str) -> Dict:
    """Format audit results for display - fetches from API"""
    try:
        # Get results from API
        results_response = requests.get(
            f"{API_BASE_URL}/api/v1/audit/results/{job_id}", timeout=10
        )

        if results_response.status_code != 200:
            raise Exception(f"Failed to get results: {results_response.status_code}")

        results_data = results_response.json()

        return {
            "file": file_path,
            "job_id": job_id,
            "status": results_data.get("status", "unknown"),
            "critical": len(
                [
                    v
                    for v in results_data.get("vulnerabilities", [])
                    if v.get("severity") == "critical"
                ]
            ),
            "high": len(
                [
                    v
                    for v in results_data.get("vulnerabilities", [])
                    if v.get("severity") == "high"
                ]
            ),
            "medium": len(
                [
                    v
                    for v in results_data.get("vulnerabilities", [])
                    if v.get("severity") == "medium"
                ]
            ),
            "low": len(
                [
                    v
                    for v in results_data.get("vulnerabilities", [])
                    if v.get("severity") == "low"
                ]
            ),
            "info": len(
                [
                    v
                    for v in results_data.get("vulnerabilities", [])
                    if v.get("severity") == "info"
                ]
            ),
            "total": len(results_data.get("vulnerabilities", [])),
            "vulnerabilities": [
                {
                    "type": v.get("vulnerability_type", "unknown"),
                    "severity": v.get("severity", "unknown"),
                    "swc_id": v.get("swc_id"),
                    "description": v.get("description"),
                    "line": v.get("line_number"),
                    "tools": v.get("affected_tools", []),
                }
                for v in results_data.get("vulnerabilities", [])
            ],
        }
    except Exception as e:
        # Return empty result if API call fails
        return {
            "file": file_path,
            "job_id": job_id,
            "status": "error",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
            "vulnerabilities": [],
        }


def print_summary(results: List[Dict]) -> None:
    """Print summary of audit results"""
    print("\n" + "=" * 80)
    print("                        SOLSIFT AUDIT SUMMARY")
    print("=" * 80 + "\n")

    total_critical = sum(r["critical"] for r in results)
    total_high = sum(r["high"] for r in results)
    total_medium = sum(r["medium"] for r in results)
    total_low = sum(r["low"] for r in results)
    total_info = sum(r["info"] for r in results)
    total_vulns = sum(r["total"] for r in results)

    print(f"📊 OVERALL STATISTICS")
    print(f"{'─' * 80}")
    print(f"  Total Files Analyzed:     {len(results)}")
    print(f"  Total Vulnerabilities:    {total_vulns}")
    print(f"    🔴 Critical:            {total_critical}")
    print(f"    🟠 High:                {total_high}")
    print(f"    🟡 Medium:              {total_medium}")
    print(f"    🟢 Low:                 {total_low}")
    print(f"    🔵 Info:                {total_info}\n")

    print(f"📁 DETAILED RESULTS")
    print(f"{'─' * 80}")

    for result in results:
        status_icon = "✅" if result["total"] == 0 else "⚠️ "
        print(f"\n{status_icon} {result['file']}")
        print(f"   Job ID: {result['job_id']}")
        print(f"   Status: {result['status']}")
        print(f"   Vulnerabilities: {result['total']} ", end="")

        if result["critical"] > 0:
            print(f"(🔴 {result['critical']} critical ", end="")
        if result["high"] > 0:
            print(f"🟠 {result['high']} high ", end="")
        if result["medium"] > 0:
            print(f"🟡 {result['medium']} medium ", end="")
        if result["low"] > 0:
            print(f"🟢 {result['low']} low ", end="")
        if result["info"] > 0:
            print(f"🔵 {result['info']} info", end="")
        print(")")

        if result["vulnerabilities"]:
            print(f"\n   Vulnerabilities:")
            for vuln in result["vulnerabilities"]:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "🔵",
                }.get(vuln["severity"], "❓")

                line_str = f" (line {vuln['line']})" if vuln["line"] else ""
                print(
                    f"     {severity_icon} [{vuln['swc_id']}] {vuln['type']}{line_str}"
                )
                print(f"        {vuln['description'][:70]}...")
                print(f"        Tools: {', '.join(vuln['tools'])}")

    print("\n" + "=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="SolSift - Smart Contract Audit Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3.11 cli.py ./contracts/MyContract.sol
  python3.11 cli.py ./contracts --output json
  python3.11 cli.py ./contracts --tools slither,mythril
        """,
    )

    parser.add_argument("path", help="Path to Solidity file or folder with contracts")

    parser.add_argument(
        "-o",
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    parser.add_argument(
        "-t",
        "--tools",
        default="slither,mythril",
        help="Comma-separated list of tools to use (default: slither,mythril)",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    try:
        # Find all Solidity files
        sol_files = find_solidity_files(args.path)
        tools = [t.strip() for t in args.tools.split(",")]

        if args.verbose:
            print(f"\n📄 Found {len(sol_files)} Solidity file(s)")
            for f in sol_files:
                print(f"   • {f}")
            print(f"\n🔧 Using tools: {', '.join(tools)}")
            print(f"⏳ Starting analysis...\n")

        # Process each file
        results = []

        for sol_file in sol_files:
            if args.verbose:
                print(f"Analyzing: {sol_file}...", end=" ", flush=True)

            try:
                # Read contract code
                code = read_contract_code(sol_file)

                # Create audit job via API
                response = requests.post(
                    f"{API_BASE_URL}/api/v1/audit/submit",
                    json={"contract_code": code},
                    timeout=10,
                )

                if response.status_code != 200:
                    raise Exception(
                        f"API error: {response.status_code} - {response.text}"
                    )

                response_data = response.json()
                job_id = response_data.get("id")

                if not job_id:
                    raise Exception("No id in API response")

                # Wait for analysis to complete
                max_retries = 360  # 360 seconds timeout (6 minutes)
                retry_count = 0

                while retry_count < max_retries:
                    # Get job status
                    status_response = requests.get(
                        f"{API_BASE_URL}/api/v1/audit/status/{job_id}", timeout=10
                    )

                    if status_response.status_code != 200:
                        raise Exception(
                            f"Failed to get job status: {status_response.status_code}"
                        )

                    status_data = status_response.json()
                    job_status = status_data.get("status")

                    if job_status == "completed" or job_status == "failed":
                        break

                    time.sleep(1)
                    retry_count += 1

                if job_status == "failed":
                    raise Exception(f"Audit failed: {status_data.get('error_message')}")

                # Get formatted results from API
                result = format_results(job_id, sol_file)
                results.append(result)

                if args.verbose:
                    print(f"✅ (Job: {job_id})")

            except Exception as e:
                print(f"❌ Error analyzing {sol_file}: {str(e)}")
                continue

        # Output results
        if args.output == "json":
            print(json.dumps(results, indent=2))
        else:
            print_summary(results)

        # Return exit code based on critical vulnerabilities
        total_critical = sum(r["critical"] for r in results)
        sys.exit(1 if total_critical > 0 else 0)

    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
