from __future__ import annotations

import json
from itertools import combinations
from typing import Any

from smart_audit.models import TargetFile

DEFAULT_CLI_TOOLS = ("slither", "mythril")


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


def parse_tools_argument(tools_arg: str | None) -> list[str]:
    if tools_arg is None:
        return []

    parsed: list[str] = []
    for raw_name in tools_arg.split(","):
        normalized = raw_name.strip().lower()
        if normalized and normalized not in parsed:
            parsed.append(normalized)
    return parsed


def collect_detected_tools(entry: dict[str, Any]) -> set[str]:
    detected_tools: set[str] = set()

    for raw_tool in entry.get("detected_by_tools", []):
        normalized = str(raw_tool).strip().lower()
        if normalized:
            detected_tools.add(normalized)

    for item in entry.get("found_vulnerabilities", []):
        for raw_tool in item.get("tools", []):
            normalized = str(raw_tool).strip().lower()
            if normalized:
                detected_tools.add(normalized)

    return detected_tools


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

        # Count every reported vulnerability, including "info".
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


def _pct(value: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((value / total) * 100, 2)


def build_classifier_stats(
    entries: list[dict[str, Any]],
    selected_tools: set[str],
) -> dict[str, int | float]:
    expected_vulnerable = sum(1 for e in entries if e["expected_vulnerable"])
    expected_clean = len(entries) - expected_vulnerable

    tp = tn = fp = fn = 0

    for entry in entries:
        expected = bool(entry["expected_vulnerable"])
        detected = bool(selected_tools & collect_detected_tools(entry))

        if expected and detected:
            tp += 1
        elif expected and not detected:
            fn += 1
        elif not expected and detected:
            fp += 1
        else:
            tn += 1

    detected_vulnerable = tp + fp
    detected_clean = tn + fn
    correct_predictions = tp + tn

    return {
        "evaluated_files": len(entries),
        "expected_vulnerable": expected_vulnerable,
        "expected_clean": expected_clean,
        "detected_vulnerable": detected_vulnerable,
        "detected_clean": detected_clean,
        "correct_predictions": correct_predictions,
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "accuracy_pct": _pct(correct_predictions, len(entries)),
        "detection_rate_pct": _pct(detected_vulnerable, len(entries)),
        "precision_pct": _pct(tp, detected_vulnerable),
        "recall_pct": _pct(tp, tp + fn),
    }


def resolve_requested_tools(entries: list[dict[str, Any]], tools_arg: str | None) -> list[str]:
    parsed_tools = parse_tools_argument(tools_arg)
    if parsed_tools:
        return parsed_tools

    # Fallback when --tools was omitted: first try to infer from results, then CLI defaults.
    inferred = sorted({tool for entry in entries for tool in collect_detected_tools(entry)})
    if inferred:
        return inferred

    return list(DEFAULT_CLI_TOOLS)


def build_summary(entries: list[dict[str, Any]], tools_arg: str | None = None) -> dict[str, Any]:
    ok_entries = [e for e in entries if e.get("scan_ok")]
    err_entries = [e for e in entries if not e.get("scan_ok")]

    tp = sum(1 for e in ok_entries if e["expected_vulnerable"] and e["found_vulnerable"])
    tn = sum(1 for e in ok_entries if not e["expected_vulnerable"] and not e["found_vulnerable"])
    fp = sum(1 for e in ok_entries if not e["expected_vulnerable"] and e["found_vulnerable"])
    fn = sum(1 for e in ok_entries if e["expected_vulnerable"] and not e["found_vulnerable"])

    requested_tools = resolve_requested_tools(ok_entries, tools_arg)
    by_tool: dict[str, dict[str, int | float]] = {
        tool: build_classifier_stats(ok_entries, {tool}) for tool in requested_tools
    }

    by_tool_combination: dict[str, dict[str, Any]] = {}
    for size in range(2, len(requested_tools) + 1):
        for combo in combinations(requested_tools, size):
            combo_key = "+".join(combo)
            by_tool_combination[combo_key] = {
                "tools": list(combo),
                **build_classifier_stats(ok_entries, set(combo)),
            }

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
        "requested_tools": requested_tools,
        "by_tool": by_tool,
        "by_tool_combination": by_tool_combination,
    }
