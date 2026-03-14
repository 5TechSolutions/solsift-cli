from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class TargetFile:
    path: Path
    base_dir: Path
    expected_vulnerable: bool
    dataset_type: str

