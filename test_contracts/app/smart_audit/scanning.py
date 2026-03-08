from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from pathlib import Path
from typing import Any

from smart_audit.execution import run_docker_cli, run_local_cli
from smart_audit.models import TargetFile
from smart_audit.results import build_entry, build_runtime_error_entry


def scan_target(
    target: TargetFile,
    tools: str | None,
    use_local_cli: bool,
    cli_script: Path,
) -> dict[str, Any]:
    try:
        if use_local_cli:
            return_code, stdout, stderr = run_local_cli(target, tools, cli_script)
        else:
            return_code, stdout, stderr = run_docker_cli(target, tools)
    except Exception as exc:
        return build_runtime_error_entry(target, str(exc))

    return build_entry(
        target=target,
        cli_return_code=return_code,
        stdout=stdout,
        stderr=stderr,
    )


def scan_targets(
    targets: list[TargetFile],
    tools: str | None,
    workers: int,
    use_local_cli: bool,
    cli_script: Path,
) -> list[dict[str, Any]]:
    total = len(targets)

    if workers <= 1:
        entries: list[dict[str, Any]] = []
        for idx, target in enumerate(targets, start=1):
            print(f"[{idx}/{total}] start: {target.dataset_type}: {target.path.name}")
            scan_start = time.perf_counter()
            entry = scan_target(target, tools, use_local_cli, cli_script)
            entries.append(entry)
            scan_duration = round(time.perf_counter() - scan_start, 3)
            detected_by_tools = entry.get("detected_by_tools", [])
            tools_text = ",".join(detected_by_tools) if detected_by_tools else "-"
            print(
                f"[{idx}/{total}] done: {target.dataset_type}: {target.path.name} "
                f"(ok={entry.get('scan_ok')}, found={entry.get('found_count', 0)}, "
                f"tools={tools_text}, {scan_duration:.2f}s)"
            )
        return entries

    print(f"Running {total} scans in parallel with workers={workers}")
    indexed_entries: dict[int, dict[str, Any]] = {}
    job_meta: dict[Any, tuple[int, TargetFile, float]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for idx, target in enumerate(targets, start=1):
            print(f"[{idx}/{total}] start: {target.dataset_type}: {target.path.name}")
            future = executor.submit(scan_target, target, tools, use_local_cli, cli_script)
            job_meta[future] = (idx, target, time.perf_counter())

        for future in as_completed(job_meta):
            idx, target, scan_start = job_meta[future]
            entry = future.result()
            scan_duration = round(time.perf_counter() - scan_start, 3)
            detected_by_tools = entry.get("detected_by_tools", [])
            tools_text = ",".join(detected_by_tools) if detected_by_tools else "-"
            print(
                f"[{idx}/{total}] done: {target.dataset_type}: {target.path.name} "
                f"(ok={entry.get('scan_ok')}, found={entry.get('found_count', 0)}, "
                f"tools={tools_text}, {scan_duration:.2f}s)"
            )
            indexed_entries[idx] = entry

    return [indexed_entries[idx] for idx in range(1, total + 1)]
