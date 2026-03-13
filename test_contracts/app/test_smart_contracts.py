#!/usr/bin/env python3
"""
Batch audit Solidity files from two folders.

CLI execution mode:
- always run CLI in Docker
"""

from __future__ import annotations

import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from smart_audit.args import parse_args
from smart_audit.output import build_output_path, write_output
from smart_audit.results import build_summary
from smart_audit.scanning import scan_targets
from smart_audit.targeting import collect_targets, select_targets


RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULT_FILE_PREFIX = "audit_results"
CLI_SCRIPT = Path(__file__).resolve().parents[2] / "cli.py"
DEFAULT_CLI_TOOLS = "slither,mythril"


def print_console_summary(
    summary: dict[str, Any],
    run_duration_seconds: float,
    output_path: Path,
    run_mode: str,
    tools: str | None,
    seed: int | None,
    workers: int,
    count_requested: int | None,
) -> None:
    def print_classifier_section(title: str, classifier_data: dict[str, dict[str, Any]]) -> None:
        if not classifier_data:
            return

        print(f"\n{title}:")
        for name, stats in classifier_data.items():
            evaluated = stats.get("evaluated_files", 0)
            detected = stats.get("detected_vulnerable", 0)
            correct = stats.get("correct_predictions", 0)
            tp = stats.get("true_positive", 0)
            tn = stats.get("true_negative", 0)
            fp = stats.get("false_positive", 0)
            fn = stats.get("false_negative", 0)
            acc = stats.get("accuracy_pct", 0.0)
            print(
                f"- {name}: detected={detected}/{evaluated}, correct={correct}/{evaluated}, "
                f"TP/TN/FP/FN={tp}/{tn}/{fp}/{fn}, acc={acc:.2f}%"
            )

    print("\n=== Run Summary ===")
    print(f"Duration: {run_duration_seconds:.2f}s")
    print(f"Run mode: {run_mode}")
    print(f"Requested count: {count_requested}")
    print(f"Workers: {workers}")
    print(f"Tools: {tools}")
    print(f"Seed: {seed}")
    print(f"Total files: {summary.get('total_files', 0)}")
    print(f"Scan OK: {summary.get('scan_ok', 0)}")
    print(f"Scan errors: {summary.get('scan_errors', 0)}")
    print(
        "TP/TN/FP/FN: "
        f"{summary.get('true_positive', 0)}/"
        f"{summary.get('true_negative', 0)}/"
        f"{summary.get('false_positive', 0)}/"
        f"{summary.get('false_negative', 0)}"
    )
    print_classifier_section(
        title="Per-tool performance",
        classifier_data=summary.get("by_tool", {}),
    )
    print_classifier_section(
        title="Combination performance",
        classifier_data=summary.get("by_tool_combination", {}),
    )
    print(f"Saved results to {output_path}")


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)
    use_local_cli = os.environ.get("SOLSIFT_BATCH_IN_CONTAINER") == "1"
    run_started_utc = datetime.now(timezone.utc)
    run_start = time.perf_counter()
    run_timestamp = run_started_utc.strftime("%Y%m%d_%H%M%S")
    output_path = build_output_path(RESULTS_DIR, RESULT_FILE_PREFIX, run_timestamp)

    try:
        vulnerable_dir = Path(args.vulnerable_dir)
        clean_dir = Path(args.clean_dir)

        if not vulnerable_dir.exists():
            raise FileNotFoundError(f"Vulnerable directory does not exist: {vulnerable_dir}")
        if not clean_dir.exists():
            raise FileNotFoundError(f"Clean directory does not exist: {clean_dir}")

        print(f"Collecting Solidity files from vulnerable dir: {vulnerable_dir}")
        collect_start = time.perf_counter()
        vulnerable_targets = collect_targets(vulnerable_dir, True, "vulnerable")
        vulnerable_collect_time = round(time.perf_counter() - collect_start, 3)
        print(
            f"Collected {len(vulnerable_targets)} vulnerable files in "
            f"{vulnerable_collect_time:.2f}s"
        )

        print(f"Collecting Solidity files from clean dir: {clean_dir}")
        collect_start = time.perf_counter()
        clean_targets = collect_targets(clean_dir, False, "clean")
        clean_collect_time = round(time.perf_counter() - collect_start, 3)
        print(
            f"Collected {len(clean_targets)} clean files in "
            f"{clean_collect_time:.2f}s"
        )

        targets, selected_vulnerable_count, selected_clean_count = select_targets(
            vulnerable_targets=vulnerable_targets,
            clean_targets=clean_targets,
            count=args.count,
            rng=rng,
        )
        print(
            f"Selected {len(targets)} files "
            f"({selected_vulnerable_count} vulnerable, {selected_clean_count} clean)"
        )

        if not targets:
            raise ValueError("No .sol files found in provided directories")

        if args.workers <= 0:
            raise ValueError("--workers must be > 0")

        effective_tools = args.tools.strip() if args.tools and args.tools.strip() else DEFAULT_CLI_TOOLS
        entries = scan_targets(
            targets=targets,
            tools=effective_tools,
            workers=args.workers,
            use_local_cli=use_local_cli,
            cli_script=CLI_SCRIPT,
        )

        run_duration_seconds = round(time.perf_counter() - run_start, 3)
        summary = build_summary(entries, tools_arg=effective_tools)
        run_mode = "local_cli" if use_local_cli else "docker_cli"
        output_payload = {
            "generated_at_utc": run_started_utc.isoformat(),
            "run_mode": run_mode,
            "vulnerable_dir": str(vulnerable_dir),
            "clean_dir": str(clean_dir),
            "count_requested": args.count,
            "count_scanned": len(targets),
            "count_scanned_vulnerable": selected_vulnerable_count,
            "count_scanned_clean": selected_clean_count,
            "tools": effective_tools,
            "seed": args.seed,
            "workers": args.workers,
            "duration_seconds": run_duration_seconds,
            "summary": summary,
            "results": entries,
        }

        write_output(output_path, output_payload)
        print_console_summary(
            summary=summary,
            run_duration_seconds=run_duration_seconds,
            output_path=output_path,
            run_mode=run_mode,
            tools=effective_tools,
            seed=args.seed,
            workers=args.workers,
            count_requested=args.count,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
