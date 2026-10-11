"""Proposers: the untrusted side of the harness.

A proposer gets a finding and a scratch clone of the target repository. It
edits files in the clone (or not) and returns a Proposal. The Validator never
relies on the proposer's account of what it changed: it computes the diff from
the scratch clone itself.
"""

import json
from pathlib import Path
from typing import Protocol

from core import workspace
from core.models import Finding, Proposal, ProposalStatus


class ProposalError(RuntimeError):
    """The proposer produced no usable proposal."""


class Proposer(Protocol):
    source: str  # e.g. "fixture/baseline" or "llm/<model>"

    def propose(self, finding: Finding, scratch: Path) -> Proposal: ...


class FixtureProposer:
    """Replays recorded agent output from <directory>/<finding id>.json and .diff.

    The JSON holds what the agent said (status, rationale). The .diff holds the
    file edits it made; they are applied to the scratch clone.
    """

    def __init__(self, directory: Path):
        self.directory = directory
        self.source = f"fixture/{directory.name}"

    def propose(self, finding: Finding, scratch: Path) -> Proposal:
        meta_file = self.directory / f"{finding.id}.json"
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            status = ProposalStatus(meta["status"])
            rationale = meta["rationale"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise ProposalError(f"no usable recorded proposal in {meta_file}: {e}") from e
        if not isinstance(rationale, str):
            raise ProposalError(f"{meta_file}: rationale must be a string")

        if status is ProposalStatus.CHANGED:
            try:
                workspace.apply_index(scratch, self.directory / f"{finding.id}.diff")
            except workspace.GitError as e:
                raise ProposalError(f"recorded edits for {finding.id} do not apply: {e}") from e

        return Proposal(finding_id=finding.id, status=status, rationale=rationale, source=self.source)


class LLMProposer:
    """Stub for a real agent.

    A real implementation would give an LLM the finding plus read/edit tools
    limited to the scratch clone (no shell, no git, no credentials), present all
    repository content as untrusted data, and collect its status and rationale.
    """

    def __init__(self, model: str):
        self.source = f"llm/{model}"

    def propose(self, finding: Finding, scratch: Path) -> Proposal:
        raise NotImplementedError("LLMProposer is a stub; use FixtureProposer.")
