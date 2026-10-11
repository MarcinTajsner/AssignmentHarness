"""Shared fixtures.

Tests build a tiny git repository in a temporary directory, so they need neither
the homework repository nor Maven nor network access.
"""

import pytest

from tests.helpers import git, write


@pytest.fixture
def make_repo(tmp_path):
    """Create a git repository with `files` committed on branch main."""

    def make(files: dict[str, str], name: str = "repo"):
        repo = tmp_path / name
        repo.mkdir()
        git(repo, "init", "--quiet", "--initial-branch=main")
        write(repo, files)
        git(repo, "add", "--all")
        git(repo, "commit", "--quiet", "-m", "initial")
        return repo

    return make
