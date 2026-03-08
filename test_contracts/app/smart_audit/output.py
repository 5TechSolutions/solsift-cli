from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def build_output_path(
    results_dir: Path,
    result_file_prefix: str,
    timestamp: str | None = None,
) -> Path:
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return results_dir / f"{result_file_prefix}_{timestamp}.json"


def write_output(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
