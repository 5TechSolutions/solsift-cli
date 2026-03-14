from __future__ import annotations

import random
from pathlib import Path

from smart_audit.models import TargetFile


def collect_targets(base_dir: Path, expected_vulnerable: bool, dataset_type: str) -> list[TargetFile]:
    files = sorted(p for p in base_dir.rglob("*.sol") if p.is_file())
    return [
        TargetFile(
            path=file_path,
            base_dir=base_dir,
            expected_vulnerable=expected_vulnerable,
            dataset_type=dataset_type,
        )
        for file_path in files
    ]


def choose_dataset_for_extra_slot(
    left_vulnerable: int,
    left_clean: int,
    rng: random.Random,
) -> str | None:
    if left_vulnerable <= 0 and left_clean <= 0:
        return None
    if left_vulnerable <= 0:
        return "clean"
    if left_clean <= 0:
        return "vulnerable"
    if left_vulnerable == left_clean:
        return "vulnerable" if rng.choice([True, False]) else "clean"
    return "vulnerable" if left_vulnerable > left_clean else "clean"


def allocate_target_counts(
    vulnerable_total: int,
    clean_total: int,
    target_count: int,
    rng: random.Random,
) -> tuple[int, int]:
    take_vulnerable = min(target_count // 2, vulnerable_total)
    take_clean = min(target_count // 2, clean_total)

    remaining = target_count - take_vulnerable - take_clean
    left_vulnerable = vulnerable_total - take_vulnerable
    left_clean = clean_total - take_clean

    while remaining > 0:
        dataset = choose_dataset_for_extra_slot(left_vulnerable, left_clean, rng)
        if dataset is None:
            break

        if dataset == "vulnerable":
            take_vulnerable += 1
            left_vulnerable -= 1
        else:
            take_clean += 1
            left_clean -= 1

        remaining -= 1

    return take_vulnerable, take_clean


def select_targets(
    vulnerable_targets: list[TargetFile],
    clean_targets: list[TargetFile],
    count: int | None,
    rng: random.Random,
) -> tuple[list[TargetFile], int, int]:
    if count is None:
        selected_vulnerable = vulnerable_targets
        selected_clean = clean_targets
        return selected_vulnerable + selected_clean, len(selected_vulnerable), len(selected_clean)

    if count <= 0:
        raise ValueError("--count must be > 0")

    total_available = len(vulnerable_targets) + len(clean_targets)
    target_count = min(count, total_available)

    take_vulnerable, take_clean = allocate_target_counts(
        vulnerable_total=len(vulnerable_targets),
        clean_total=len(clean_targets),
        target_count=target_count,
        rng=rng,
    )

    selected_vulnerable = rng.sample(vulnerable_targets, take_vulnerable)
    selected_clean = rng.sample(clean_targets, take_clean)
    return selected_vulnerable + selected_clean, len(selected_vulnerable), len(selected_clean)

