"""Data passed between the pipeline stages.

Trust: anything that comes from the target repository (findings.json) or from
the agent (Proposal.status, Proposal.rationale) is untrusted. Facts and
BuildResult are produced by the Validator itself.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class ProposalStatus(StrEnum):
    CHANGED = "changed"  # the agent edited files in its scratch clone
    NO_SAFE_FIX = "no_safe_fix"  # the agent declined: it sees no safe fix


class Verdict(StrEnum):
    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    REJECT = "REJECT"


@dataclass(frozen=True)
class Finding:
    """One entry from findings.json (scanner output, untrusted)."""

    id: str
    cve: str
    severity: str
    service: str
    package: str
    installed_version: str
    fixed_version: str | None
    path: str
    sla_days_remaining: int
    notes: str


@dataclass(frozen=True)
class Proposal:
    """What the Proposer hands to the Validator, next to the edited files."""

    finding_id: str  # set by the wrapper
    status: ProposalStatus  # from the agent
    rationale: str  # from the agent; shown to humans only, never used for decisions
    source: str  # set by the wrapper, e.g. "fixture/baseline" or "llm/<model>"


@dataclass(frozen=True)
class DependencyChange:
    file: str
    package: str  # "PyYAML", "groupId:artifactId", or "${name.version}" for a POM version property
    old_version: str | None  # None: dependency added
    new_version: str | None  # None: dependency removed; "(managed)": no explicit version in the POM


@dataclass(frozen=True)
class SuspiciousAddition:
    """An added line matching a known-risky pattern. Any hit rejects the change; no hits never prove it safe."""

    file: str
    line: int  # line number in the new file; 0 for binary content
    rule: str
    text: str


@dataclass(frozen=True)
class Facts:
    """What the Validator itself reads out of the proposed change. Described in DESIGN.md, section 2.2."""

    changed_files: list[str]
    lines_added: int
    lines_removed: int
    dependency_changes: list[DependencyChange]
    touches_source: bool  # production source code (not tests)
    touches_tests: bool  # test sources
    touches_test_config: bool  # which tests run: POM excludes/skip flags, pytest config files
    touches_ci: bool  # CI configuration, e.g. anything under .github/
    suspicious_additions: list[SuspiciousAddition]


@dataclass(frozen=True)
class BuildResult:
    """Outcome of building and testing one service in a clone."""

    service: str
    tests_passed: bool  # the regular test suite finished with no failures
    log_dir: str
    tests_run: int = 0  # tests executed by the regular suite (skipped ones not counted)
    failed_tests: list[str] = field(default_factory=list)
    excluded_tests: dict[str, bool] = field(default_factory=dict)  # disabled in build config, run separately: pattern -> passed
    resolved_versions: dict[str, str] = field(default_factory=dict)  # package -> version that actually ended up in the build
    duration_s: float = 0.0  # regular suite wall time; informational only, never used for decisions
    error: str | None = None  # the build could not run at all (tooling problem, timeout)


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reasons: list[str]
