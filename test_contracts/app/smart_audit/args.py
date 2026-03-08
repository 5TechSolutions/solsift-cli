from __future__ import annotations

import argparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit .sol files from vulnerable/clean folders."
    )
    parser.add_argument(
        "--vulnerable-dir",
        required=True,
        help="Directory with contracts expected to be vulnerable",
    )
    parser.add_argument(
        "--clean-dir",
        required=True,
        help="Directory with contracts expected to be clean",
    )
    parser.add_argument(
        "--tools",
        default=None,
        help="Comma-separated tools passed to CLI via -t (optional)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Limit number of files to scan (split as evenly as possible across both folders)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible file sampling",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel scans to run (default: 1)",
    )
    return parser.parse_args()
