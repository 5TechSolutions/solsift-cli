from __future__ import annotations

import json
from typing import Any

from smart_audit.models import TargetFile


def extract_json_payload(raw_output: str) -> Any:
    text = (raw_output or "").strip()
    if not text:
        raise ValueError("CLI produced empty output")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        return json.loads(text[start : end + 1])

    raise ValueError("Could not parse JSON payload from CLI output")


def normalize_tools(raw_tools: Any) -> list[str]:
    if not isinstance(raw_tools, list):
        return []
    return [str(tool) for tool in raw_tools if tool is not None]


def summarize_found(
    vulnerabilities: list[dict[str, Any]],
) -> tuple[bool, list[dict[str, Any]], int, list[str]]:
    normalized: list[dict[str, Any]] = []
    found_count = 0
    detected_by_tools: set[str] = set()

    for item in vulnerabilities:
        severity = str(item.get("severity", "unknown")).lower()
        tools = normalize_tools(item.get("tools", []))
        record = {
            "type": item.get("type"),
            "severity": severity,
            "swc_id": item.get("swc_id"),
            "line": item.get("line"),
            "tools": tools,
        }
        normalized.append(record)

        if severity != "info":
            found_count += 1
            detected_by_tools.update(tools)

    return found_count > 0, normalized, found_count, sorted(detected_by_tools)


def build_entry(
    target: TargetFile,
    cli_return_code: int,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "file_name": target.path.name,
        "file_path": str(target.path),
        "relative_path": target.path.relative_to(target.base_dir).as_posix(),
        "dataset_type": target.dataset_type,
        "expected_vulnerable": target.expected_vulnerable,
        "scan_ok": False,
        "cli_return_code": cli_return_code,
        "found_vulnerable": False,
        "found_count": 0,
        "detected_by_tools": [],
        "reported_total": 0,
        "found_vulnerabilities": [],
        "error": None,
        "correct_prediction": None,
    }

    stderr = stderr or ""
    stdout = stdout or ""

    if stderr.strip():
        entry["stderr"] = stderr.strip()

    try:
        payload = extract_json_payload(stdout)
        if not isinstance(payload, list) or not payload:
            raise ValueError("CLI returned empty result list")

        result = payload[0]
        vulns = result.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            raise ValueError("Invalid vulnerabilities format in CLI output")

        found_vulnerable, normalized, found_count, detected_by_tools = summarize_found(vulns)

        entry["scan_ok"] = True
        entry["found_vulnerable"] = found_vulnerable
        entry["found_count"] = found_count
        entry["detected_by_tools"] = detected_by_tools
        entry["reported_total"] = len(vulns)
        entry["found_vulnerabilities"] = normalized
        entry["correct_prediction"] = target.expected_vulnerable == found_vulnerable
    except Exception as exc:
        entry["error"] = str(exc)
        if stdout.strip():
            entry["stdout"] = stdout.strip()

    return entry


def build_runtime_error_entry(target: TargetFile, error_message: str) -> dict[str, Any]:
    return {
        "file_name": target.path.name,
        "file_path": str(target.path),
        "relative_path": target.path.relative_to(target.base_dir).as_posix(),
        "dataset_type": target.dataset_type,
        "expected_vulnerable": target.expected_vulnerable,
        "scan_ok": False,
        "cli_return_code": -1,
        "found_vulnerable": False,
        "found_count": 0,
        "detected_by_tools": [],
        "reported_total": 0,
        "found_vulnerabilities": [],
        "error": error_message,
        "correct_prediction": None,
    }


def build_summary(entries: list[dict[str, Any]]) -> dict[str, int]:
    ok_entries = [e for e in entries if e.get("scan_ok")]
    err_entries = [e for e in entries if not e.get("scan_ok")]

    tp = sum(1 for e in ok_entries if e["expected_vulnerable"] and e["found_vulnerable"])
    tn = sum(1 for e in ok_entries if not e["expected_vulnerable"] and not e["found_vulnerable"])
    fp = sum(1 for e in ok_entries if not e["expected_vulnerable"] and e["found_vulnerable"])
    fn = sum(1 for e in ok_entries if e["expected_vulnerable"] and not e["found_vulnerable"])

    return {
        "total_files": len(entries),
        "scan_ok": len(ok_entries),
        "scan_errors": len(err_entries),
        "expected_vulnerable": sum(1 for e in entries if e["expected_vulnerable"]),
        "expected_clean": sum(1 for e in entries if not e["expected_vulnerable"]),
        "found_vulnerable": sum(1 for e in ok_entries if e["found_vulnerable"]),
        "found_clean": sum(1 for e in ok_entries if not e["found_vulnerable"]),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
    }
