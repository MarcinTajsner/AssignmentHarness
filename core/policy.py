"""Decision policy: ACCEPT, REVIEW or REJECT, with reasons. The rules are described in DESIGN.md, section 2.

Pure functions over data: no files, no git, no network. Every verdict in the
harness comes from here, including the ones for failed pipeline stages.

Principles:
- Autonomy depends on the risk of the change and the strength of the evidence,
  not on how urgent the vulnerability is. Urgency (SLA) is reported, never a gate.
- ACCEPT only when every condition holds. Anything uncertain goes to a person.
- REJECT when the agent oversteps its job or touches the gates that judge it,
  or when the change demonstrably does not fix the finding or breaks tests.

Each reason starts with the id of its rule, e.g. "[X1]", so it can be looked up in DESIGN.md, section 2.3.
"""

import re

from core.build import SERVICES_DIR
from core.facts import is_dependency_manifest
from core.models import BuildResult, Decision, Facts, Finding, Proposal, ProposalStatus, Verdict


def pre_build(finding: Finding, proposal: Proposal, facts: Facts) -> Decision | None:
    """Reject before the build, so code from a change that is rejected anyway is never executed.

    None means: build it, then call decide().
    """
    reasons = []
    if facts.touches_ci:
        reasons.append("[X1] changes CI configuration: the agent may not change the gate that checks it")
    if facts.touches_test_config:
        reasons.append("[X2] changes which tests run (test excludes, skip flags or pytest config)")
    for hit in facts.suspicious_additions:
        reasons.append(f"[X3] suspicious addition in {hit.file}:{hit.line} ({hit.rule})")
    service_dir = f"{SERVICES_DIR}/{finding.service}/"
    outside = [path for path in facts.changed_files if not path.startswith(service_dir)]
    if outside:
        reasons.append(f"[X4] changes files outside {service_dir}: {', '.join(outside)}")
    return Decision(Verdict.REJECT, reasons) if reasons else None


def decide(
    finding: Finding,
    proposal: Proposal | None,
    facts: Facts | None,
    build: BuildResult | None,
    baseline: BuildResult | None,
    error: str | None,
) -> Decision:
    """Final decision. Any input may be missing (None) when a stage failed or was skipped."""
    urgency = _urgency(finding)

    # No evidence: a person has to look.
    if error:
        return Decision(Verdict.REVIEW, [f"[N1] the harness could not validate the proposal: {error}", *urgency])
    if proposal is None or proposal.status is ProposalStatus.NO_SAFE_FIX:
        return Decision(Verdict.REVIEW, ["[N2] the agent found no safe fix: a person has to remediate this finding",
                                         *urgency])
    if facts is None or build is None:
        return Decision(Verdict.REVIEW, ["[N3] not built: there is no test evidence", *urgency])
    if build.error:
        return Decision(Verdict.REVIEW, [f"[N3] the build could not run: {build.error}", *urgency])

    resolved = build.resolved_versions.get(finding.package)

    # The change demonstrably fails its purpose.
    rejections = []
    if resolved is not None and _version(resolved):
        if finding.fixed_version and _version(resolved) < _version(finding.fixed_version):
            rejections.append(f"[R1] {finding.package} in the build is {resolved}, "
                              f"below the fixed version {finding.fixed_version}")
        elif _version(resolved) <= _version(finding.installed_version):
            rejections.append(f"[R1] {finding.package} in the build is {resolved}, not newer than the "
                              f"vulnerable {finding.installed_version}: the finding is not fixed")
    if baseline is not None and baseline.tests_passed and not build.tests_passed:
        failed = ", ".join(build.failed_tests) or "the build failed before tests could run"
        rejections.append(f"[R2] tests passed before the change and fail after it: {failed}")
    if rejections:
        return Decision(Verdict.REJECT, rejections)

    # Anything that makes the change riskier or the evidence weaker goes to a person.
    reasons = []
    extra = [path for path in facts.changed_files if not is_dependency_manifest(path)]
    if extra:
        kinds = [kind for kind, present in (("production code", facts.touches_source), ("tests", facts.touches_tests))
                 if present]
        detail = f" (includes {' and '.join(kinds)})" if kinds else ""
        reasons.append(f"[V1] changes more than the dependency manifest{detail}: {', '.join(extra)}")

    others = sorted({c.package for c in facts.dependency_changes if not _same_package(c.package, finding.package)})
    if others:
        reasons.append(f"[V2] also changes other dependencies: {', '.join(others)}")

    if resolved is not None and _major(resolved) != _major(finding.installed_version):
        reasons.append(f"[V3] major version jump: {finding.installed_version} -> {resolved}")

    if not finding.fixed_version:
        reasons.append(f"[V4] the scanner reports no fixed version, so the harness cannot confirm that "
                       f"{resolved or 'the change'} fixes {finding.cve}")
    if resolved is None:
        reasons.append(f"[V4] {finding.package} is not found in the build after the change: "
                       "removed on purpose, or the version check failed")
    elif not _version(resolved):
        reasons.append(f"[V4] cannot compare the version {resolved} of {finding.package}")

    if baseline is None:
        reasons.append("[V5] no baseline build to compare the tests with")
    elif baseline.error:
        reasons.append(f"[V5] the baseline build could not run, so there is nothing to compare the tests with: "
                       f"{baseline.error}")
    elif not baseline.tests_passed:
        reasons.append("[V5] tests already failed before the change, so they prove nothing about it")
    elif build.tests_run == 0:
        reasons.append("[V5] no tests ran")
    elif build.tests_run < baseline.tests_run:
        reasons.append(f"[V5] fewer tests ran than before the change: {build.tests_run} instead of {baseline.tests_run}")

    if baseline is not None:
        regressed = [test for test, passed in build.excluded_tests.items()
                     if not passed and baseline.excluded_tests.get(test)]
        if regressed:
            reasons.append(f"[V6] tests the repository excludes passed before the change and fail after it: "
                           f"{', '.join(regressed)}. The change alters behaviour that the regular suite does not check")

    if reasons:
        return Decision(Verdict.REVIEW, [*reasons, *urgency])
    return Decision(Verdict.ACCEPT, [
        f"[OK] dependency-only change of {finding.package}: {finding.installed_version} -> {resolved} "
        f"(fixed version {finding.fixed_version}); all {build.tests_run} test(s) passed, as many as before the change; "
        "no excluded test regressed",
    ])


def _urgency(finding: Finding) -> list[str]:
    """Informational only: urgency says how soon a person should look, never whether."""
    days = finding.sla_days_remaining
    if days < 0:
        return [f"[info] SLA overdue by {-days} days: review urgently"]
    if days <= 7:
        return [f"[info] SLA: {days} days left"]
    return []


def _version(version: str) -> tuple[int, ...]:
    """Numeric parts of a version, e.g. "5.4.1" -> (5, 4, 1). Empty if there are none."""
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _major(version: str) -> int | None:
    parts = _version(version)
    return parts[0] if parts else None


def _same_package(changed: str, package: str) -> bool:
    """Whether a dependency change refers to the finding's package.

    Covers PyPI name normalization (PyYAML == pyyaml) and POM version properties
    named after the artifact (${snakeyaml.version} for org.yaml:snakeyaml).
    """
    def normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    artifact = package.split(":")[-1]
    return normalize(changed) == normalize(package) or changed == f"${{{artifact}.version}}"
