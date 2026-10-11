"""The harness pipeline: from findings to decisions.

For every finding the proposer edits a scratch clone; the Validator computes
the diff itself, applies it to a clean clone, computes facts, builds and
tests, and the policy decides. A failure fails closed for that finding only:
it is recorded and handed to the policy, and the other findings carry on.
"""

import dataclasses
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from core import audit, policy, report, workspace
from core.build import BuildRunner
from core.facts import compute_facts
from core.findings import load_findings
from core.models import BuildResult, Decision, Facts, Finding, Proposal, ProposalStatus, Verdict
from core.proposer import Proposer

FINDINGS_PATH = "findings/findings.json"  # inside the target repository
HARNESS_DIR = Path(__file__).resolve().parent.parent


def run(
    repo: Path,
    proposer: Proposer,
    builder: BuildRunner | None,
    runs_dir: Path,
    work_dir: Path,
    findings_file: Path | None = None,
    progress: Callable[[str], None] = print,
) -> Path:
    """Process every finding. `builder=None` skips builds. Returns the run's output directory."""
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out, work = runs_dir / run_id, work_dir / run_id
    out.mkdir(parents=True)
    audit_log = out / "audit.jsonl"

    progress(f"run {run_id}: cloning {repo} for the baseline")
    baseline_clone = workspace.clone(repo, work / "baseline")
    base_sha = workspace.head_sha(baseline_clone)
    findings_path = findings_file or baseline_clone / FINDINGS_PATH
    findings = load_findings(findings_path)

    run_info = {
        "run_id": run_id,
        "started": _now(),
        "target_repo": str(repo),
        "base_sha": base_sha,
        "findings_sha256": _sha256(findings_path.read_bytes()),
        "proposer": proposer.source,
        "harness": _harness_version(),
    }
    audit.append(audit_log, {"event": "run_started", **run_info})

    # Tests on the unchanged code, once per service: tells "broken by the change"
    # apart from "already broken before".
    baselines: dict[str, BuildResult] = {}
    if builder is not None:
        for service in sorted({f.service for f in findings}):
            progress(f"baseline: building and testing {service}")
            packages = sorted({f.package for f in findings if f.service == service})
            baselines[service] = builder.run(baseline_clone, service, packages, out / "baseline-logs" / service)
    baseline_data = {service: dataclasses.asdict(result) for service, result in baselines.items()}
    _write_json(out / "baseline.json", {"base_sha": base_sha, "builds": baseline_data})

    records = []
    for finding in findings:
        progress(f"{finding.id}: {finding.package} in {finding.service}")
        record = _process(finding, repo, base_sha, proposer, builder, baselines.get(finding.service),
                          work / finding.id, out / finding.id)
        if record["decision"]["verdict"] == Verdict.REVIEW:
            report.write_review(out / finding.id / "review.md", record, baseline_data.get(finding.service))
        audit.append(audit_log, _audit_entry(run_id, record, out / finding.id / "result.json"))
        records.append(record)
        progress(f"{finding.id}: {record['decision']['verdict']} - {'; '.join(record['decision']['reasons'])}")

    problems = audit.verify(audit_log)
    report.write_summary(out / "summary.md", run_info, baseline_data, records, problems)
    progress(f"audit log: {'intact' if not problems else 'BROKEN: ' + '; '.join(problems)}")
    return out


def _process(
    finding: Finding,
    repo: Path,
    base_sha: str,
    proposer: Proposer,
    builder: BuildRunner | None,
    baseline: BuildResult | None,
    work: Path,
    out: Path,
) -> dict:
    """Run one finding through the stages; writes and returns its result.json record."""
    out.mkdir(parents=True)
    patch_file = out / "patch.diff"
    proposal: Proposal | None = None
    facts: Facts | None = None
    build: BuildResult | None = None
    clean: Path | None = None
    decision: Decision | None = None
    error: str | None = None

    stage = "propose"
    try:
        scratch = workspace.clone(repo, work / "agent")
        proposal = proposer.propose(finding, scratch)

        stage = "diff"
        patch = workspace.diff_all(scratch)  # computed by the Validator, not reported by the agent
        patch_file.write_bytes(patch)
        if (proposal.status is ProposalStatus.CHANGED) != bool(patch):
            raise ValueError(f"proposal status is {proposal.status} but the diff is {'not ' if patch else ''}empty")

        if patch:
            stage = "apply"
            clean = workspace.clone(repo, work / "clean")
            if workspace.head_sha(clean) != base_sha:
                raise RuntimeError("the target repository changed during the run")
            workspace.apply_index(clean, patch_file)

            stage = "facts"
            facts = compute_facts(clean)

            stage = "pre-build policy"
            decision = policy.pre_build(finding, proposal, facts)
            if decision is None and builder is not None:
                stage = "build"
                build = builder.run(clean, finding.service, _packages(finding, facts), out / "logs")
    except Exception as e:  # any failure is recorded and fails closed for this finding only
        error = f"{stage}: {type(e).__name__}: {e}"
        decision = None

    if decision is None:
        decision = policy.decide(finding, proposal, facts, build, baseline, error)

    commit = next_action = None
    if decision.verdict is Verdict.ACCEPT:
        try:
            commit, next_action = _commit(finding, proposal, clean, base_sha)
        except Exception as e:
            error = f"commit: {type(e).__name__}: {e}"
            decision = policy.decide(finding, proposal, facts, build, baseline, error)

    patch = patch_file.read_bytes() if patch_file.exists() else None
    record = {
        "finding": dataclasses.asdict(finding),
        "base_sha": base_sha,
        "proposal": dataclasses.asdict(proposal) if proposal else None,
        "patch": {"file": patch_file.name, "sha256": _sha256(patch), "bytes": len(patch)} if patch else None,
        "facts": dataclasses.asdict(facts) if facts else None,
        "build": dataclasses.asdict(build) if build else None,
        "error": error,
        "decision": dataclasses.asdict(decision),
        "commit": commit,
        "next_action": next_action,
    }
    _write_json(out / "result.json", record)
    return record


def _packages(finding: Finding, facts: Facts) -> list[str]:
    """Packages whose resolved versions the build should report: the finding's and every changed one."""
    changed = [c.package for c in facts.dependency_changes if not c.package.startswith("${")]
    return list(dict.fromkeys([finding.package, *changed]))


def _commit(finding: Finding, proposal: Proposal | None, clean: Path | None, base_sha: str) -> tuple[dict, dict]:
    """Commit the accepted patch on harness/<finding id> in the clean clone. Merging is a stub."""
    if clean is None or proposal is None:
        raise RuntimeError("nothing to commit")
    target = workspace.current_branch(clean)
    branch = f"harness/{finding.id}"
    message = (
        f"fix({finding.id}): {finding.cve} in {finding.package}\n\n"
        f"Proposed by {proposal.source}; accepted by the harness policy.\nBase: {base_sha}\n"
    )
    sha = workspace.commit_branch(clean, branch, message)
    commit = {"branch": branch, "sha": sha, "clone": str(clean)}
    next_action = {
        "action": "merge",
        "executed": False,  # stub: a real system would push the branch and merge it
        "branch": branch,
        "commit": sha,
        "into": target,
    }
    return commit, next_action


def _audit_entry(run_id: str, record: dict, result_file: Path) -> dict:
    """One audit line per finding. result_sha256 ties the detailed result.json to the chain."""
    finding, decision = record["finding"], record["decision"]
    return {
        "event": "finding_decided",
        "time": _now(),
        "run_id": run_id,
        "finding_id": finding["id"],
        "cve": finding["cve"],
        "package": finding["package"],
        "service": finding["service"],
        "base_sha": record["base_sha"],
        "proposal_source": record["proposal"]["source"] if record["proposal"] else None,
        "patch_sha256": record["patch"]["sha256"] if record["patch"] else None,
        "result_sha256": _sha256(result_file.read_bytes()),
        "verdict": decision["verdict"],
        "reasons": decision["reasons"],
        "commit_sha": record["commit"]["sha"] if record["commit"] else None,
    }


def _harness_version() -> dict:
    """Which rules made the decisions: the harness commit, and a hash of policy.py in case it is uncommitted."""
    try:
        commit = workspace.head_sha(HARNESS_DIR)
        uncommitted = workspace.has_uncommitted_changes(HARNESS_DIR)
    except workspace.GitError:  # e.g. the harness was unpacked from a zip
        commit, uncommitted = None, None
    # Line endings normalized, so the hash does not depend on how git checked the file out (core.autocrlf).
    policy = (HARNESS_DIR / "core" / "policy.py").read_bytes().replace(b"\r\n", b"\n")
    return {
        "commit": commit,
        "uncommitted_changes": uncommitted,
        "policy_sha256": _sha256(policy),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
