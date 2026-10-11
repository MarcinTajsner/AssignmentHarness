"""All git operations of the harness.

The target repository is only ever used as the source of `git clone`. Every
change, test run and commit happens in clones under .work/.

Diffs are handled as bytes end to end: decoding and re-encoding them as text
would let Python translate line endings on Windows and corrupt the patch.
"""

import subprocess
from pathlib import Path

# Commits are made with an explicit identity, independent of the user's git config.
HARNESS_IDENTITY = ("-c", "user.name=harness", "-c", "user.email=harness@local")


class GitError(RuntimeError):
    """A git command failed."""


def _git(*args: str, cwd: Path | None = None) -> bytes:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitError(f"git {' '.join(args)} failed: {stderr}")
    return result.stdout


def clone(source: Path, dest: Path) -> Path:
    """Fresh clone of `source` into `dest` (which must not exist yet)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git("clone", "--quiet", str(source), str(dest))
    return dest


def head_sha(repo: Path) -> str:
    """SHA of the commit the clone is on. Recorded for the audit trail only."""
    return _git("rev-parse", "HEAD", cwd=repo).decode().strip()


def has_uncommitted_changes(repo: Path) -> bool:
    return bool(_git("status", "--porcelain", cwd=repo).strip())


def current_branch(repo: Path) -> str:
    """Name of the checked-out branch: the one an accepted fix would be merged into."""
    return _git("symbolic-ref", "--short", "HEAD", cwd=repo).decode().strip()


def diff_all(repo: Path) -> bytes:
    """Everything changed in the working tree relative to HEAD, new and deleted files included."""
    _git("add", "--all", cwd=repo)
    return staged_diff(repo)


def staged_diff(repo: Path) -> bytes:
    """The staged changes relative to HEAD."""
    return _git("diff", "--cached", "--binary", "--no-renames", cwd=repo)


def staged_numstat(repo: Path) -> list[tuple[int, int, str]]:
    """(lines added, lines removed, path) for every staged file. Binary files count as 0 lines."""
    out = _git("diff", "--cached", "--numstat", "--no-renames", "-z", cwd=repo).decode("utf-8", errors="replace")
    stats = []
    for record in filter(None, out.split("\0")):
        added, removed, path = record.split("\t", 2)
        stats.append((0 if added == "-" else int(added), 0 if removed == "-" else int(removed), path))
    return stats


def read_file(repo: Path, spec: str) -> bytes | None:
    """Raw file content at a git spec: "HEAD:<path>" (before) or ":<path>" (staged). None if absent."""
    if subprocess.run(["git", "cat-file", "-e", spec], cwd=repo, capture_output=True).returncode != 0:
        return None
    return _git("cat-file", "blob", spec, cwd=repo)


def apply_index(repo: Path, patch_file: Path) -> None:
    """Apply a patch to the working tree and stage it. All or nothing: on failure nothing changes."""
    _git("apply", "--index", str(patch_file.resolve()), cwd=repo)


def commit_branch(repo: Path, branch: str, message: str) -> str:
    """Create `branch` at HEAD, commit the staged changes on it and return the commit SHA."""
    _git("switch", "--quiet", "--create", branch, cwd=repo)
    _git(*HARNESS_IDENTITY, "commit", "--quiet", "--message", message, cwd=repo)
    return head_sha(repo)
