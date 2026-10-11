"""Helpers for tests that work on a temporary git repository."""

import subprocess
from pathlib import Path

GIT_IDENTITY = ["-c", "user.name=test", "-c", "user.email=test@example.com"]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *GIT_IDENTITY, *args], cwd=repo, capture_output=True, text=True, check=True).stdout


def write(repo: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
