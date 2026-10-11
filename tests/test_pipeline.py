"""The whole pipeline on a temporary repository, with builds replaced by FakeBuildRunner."""

import json
import subprocess
from pathlib import Path

from core import audit, pipeline, workspace
from core.build import FakeBuildRunner
from core.models import BuildResult
from core.proposer import FixtureProposer
from tests.helpers import git, write

LOCK = "services/py/requirements.lock"
CI = ".github/workflows/ci.yml"


def finding(finding_id: str, package: str, installed: str, fixed: str) -> dict:
    return {"id": finding_id, "cve": f"CVE-0000-{finding_id}", "severity": "high", "service": "py",
            "package": package, "installed_version": installed, "fixed_version": fixed, "path": "direct",
            "sla_days_remaining": 10, "notes": ""}


def record_proposal(source: Path, fixtures: Path, finding_id: str, edits: dict[str, str]) -> None:
    """Record an agent proposal as a fixture: make the edits in a clone and store the diff."""
    scratch = workspace.clone(source, fixtures.parent / "recording" / finding_id)
    write(scratch, edits)
    (fixtures / f"{finding_id}.diff").write_bytes(workspace.diff_all(scratch))
    (fixtures / f"{finding_id}.json").write_text(json.dumps({"status": "changed", "rationale": "trust me"}))


def fake_build(clone: Path, service: str) -> BuildResult:
    """Pretend to build: the resolved versions are whatever requirements.lock pins."""
    pins = dict(line.split("==") for line in (clone / LOCK).read_text().split())
    return BuildResult(service, tests_passed=True, log_dir="-", tests_run=3, resolved_versions=pins)


def test_pipeline_end_to_end(make_repo, tmp_path):
    repo = make_repo({
        "findings/findings.json": json.dumps({"findings": [
            finding("F-1", "pkg", "1.0", "1.1"),
            finding("F-2", "other", "2.0", "2.1"),
            finding("F-3", "third", "3.0", "3.1"),
        ]}),
        LOCK: "pkg==1.0\nother==2.0\nthird==3.0\n",
        CI: "name: ci\n",
    })
    fixtures = tmp_path / "fixtures" / "scenario"
    fixtures.mkdir(parents=True)
    record_proposal(repo, fixtures, "F-1", {LOCK: "pkg==1.1\nother==2.0\nthird==3.0\n"})
    record_proposal(repo, fixtures, "F-2", {LOCK: "pkg==1.0\nother==2.1\nthird==3.0\n", CI: "name: ci\nenv:\n  X: y\n"})
    # F-3 has no recorded proposal at all.
    builder = FakeBuildRunner(fake_build)

    out = pipeline.run(repo, FixtureProposer(fixtures), builder, tmp_path / "runs", tmp_path / "work",
                       progress=lambda message: None)

    results = {fid: json.loads((out / fid / "result.json").read_text(encoding="utf-8")) for fid in ("F-1", "F-2", "F-3")}
    assert {fid: r["decision"]["verdict"] for fid, r in results.items()} == {
        "F-1": "ACCEPT", "F-2": "REJECT", "F-3": "REVIEW"}

    # ACCEPT: the commit on harness/F-1 is exactly the recorded patch, and merging is only described.
    commit = results["F-1"]["commit"]
    committed = subprocess.run(["git", "diff", "--binary", "main", commit["branch"]], cwd=commit["clone"],
                               capture_output=True, check=True).stdout
    assert committed == (out / "F-1" / "patch.diff").read_bytes()
    assert results["F-1"]["next_action"]["executed"] is False

    # REJECT before the build: the CI change was never built or run.
    assert results["F-2"]["decision"]["reasons"][0].startswith("[X1]")
    assert [clone.parent.name for clone, _ in builder.calls if clone.name == "clean"] == ["F-1"]

    # A missing proposal fails closed.
    assert results["F-3"]["decision"]["reasons"][0].startswith("[N1]")

    # Reports and a verifiable audit log.
    assert (out / "summary.md").exists()
    assert (out / "F-3" / "review.md").exists() and not (out / "F-1" / "review.md").exists()
    assert audit.verify(out / "audit.jsonl") == []

    # The target repository is untouched.
    assert git(repo, "status", "--porcelain") == ""
    assert git(repo, "branch", "--list").split() == ["*", "main"]
