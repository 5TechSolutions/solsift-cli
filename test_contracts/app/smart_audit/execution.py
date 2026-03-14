from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from smart_audit.models import TargetFile


DOCKER_IMAGE = "solsift-cli"


def decode_output(data: bytes | None) -> str:
    if not data:
        return ""

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    process = subprocess.run(
        cmd,
        capture_output=True,
        text=False,
        check=False,
    )
    stdout = decode_output(process.stdout)
    stderr = decode_output(process.stderr)
    return process.returncode, stdout, stderr


def run_local_cli(target: TargetFile, tools: str | None, cli_script: Path) -> tuple[int, str, str]:
    cmd = [sys.executable, str(cli_script), str(target.path), "-o", "json"]
    if tools:
        cmd.extend(["-t", tools])
    return run_command(cmd)


def run_docker_cli(target: TargetFile, tools: str | None) -> tuple[int, str, str]:
    relative_path = target.path.relative_to(target.base_dir).as_posix()
    in_container_path = f"./contracts/{relative_path}"

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{target.base_dir.resolve()}:/app/contracts",
    ]

    docker_network = os.environ.get("DOCKER_NETWORK")
    if docker_network:
        cmd.extend(["--network", docker_network])

    api_base_url = os.environ.get("API_BASE_URL")
    if api_base_url:
        cmd.extend(["-e", f"API_BASE_URL={api_base_url}"])

    cmd.extend([DOCKER_IMAGE, in_container_path, "-o", "json"])

    if tools:
        cmd.extend(["-t", tools])

    return run_command(cmd)
