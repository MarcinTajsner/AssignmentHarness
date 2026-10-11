"""The decision rules (DESIGN.md, section 2.3), on synthetic inputs."""

from dataclasses import replace

import pytest

from core import policy
from core.models import (BuildResult, DependencyChange, Facts, Finding, Proposal, ProposalStatus,
                         SuspiciousAddition, Verdict)

POM = "services/inventory-api/pom.xml"
LOCK = "services/report-worker/requirements.lock"
EXCLUDED = "**/ConfigLoaderIntegrationTest.java"

SNAKEYAML = Finding("F-40218", "CVE-2022-1471", "critical", "inventory-api", "org.yaml:snakeyaml", "1.30", "2.0",
                    "transitive", 4, "")
PYYAML = Finding("F-40219", "CVE-2020-14343", "high", "report-worker", "PyYAML", "5.3.1", "5.4", "direct", 11, "")
COLLECTIONS = Finding("F-40220", "CVE-2015-6420", "high", "inventory-api", "commons-collections:commons-collections",
                      "3.2.1", None, "direct", -63, "")
PROPOSAL = Proposal("F-x", ProposalStatus.CHANGED, "trust me", "fixture/test")

JAVA_BASELINE = BuildResult("inventory-api", True, "-", tests_run=4, excluded_tests={EXCLUDED: True},
                            resolved_versions={"org.yaml:snakeyaml": "1.30",
                                               "commons-collections:commons-collections": "3.2.1"})
PY_BASELINE = BuildResult("report-worker", True, "-", tests_run=1, resolved_versions={"PyYAML": "5.3.1"})


def facts(files, deps=(), suspicious=(), **flags) -> Facts:
    return Facts(
        changed_files=list(files), lines_added=1, lines_removed=1, dependency_changes=list(deps),
        touches_source=flags.get("source", False), touches_tests=flags.get("tests", False),
        touches_test_config=flags.get("test_config", False), touches_ci=flags.get("ci", False),
        suspicious_additions=list(suspicious),
    )


def build(baseline: BuildResult, **changes) -> BuildResult:
    return replace(baseline, **changes)


PYYAML_FACTS = facts([LOCK], [DependencyChange(LOCK, "PyYAML", "5.3.1", "5.4.1")])
PYYAML_BUILD = build(PY_BASELINE, resolved_versions={"PyYAML": "5.4.1"})


def rule_ids(decision) -> set[str]:
    return {reason[1:reason.index("]")] for reason in decision.reasons}


def decide(finding, facts_, build_, baseline, error=None, proposal=PROPOSAL):
    return policy.decide(finding, proposal, facts_, build_, baseline, error)


# The three findings of the homework repository, with the numbers of the real runs.

def test_snakeyaml_major_bump_that_breaks_an_excluded_test_goes_to_review():
    decision = decide(SNAKEYAML, facts([POM], [DependencyChange(POM, "${snakeyaml.version}", None, "2.0")]),
                      build(JAVA_BASELINE, excluded_tests={EXCLUDED: False}, resolved_versions={"org.yaml:snakeyaml": "2.0"}),
                      JAVA_BASELINE)
    assert decision.verdict is Verdict.REVIEW
    assert rule_ids(decision) == {"V3", "V6", "info"}


def test_pyyaml_minor_bump_with_green_tests_is_accepted():
    decision = decide(PYYAML, PYYAML_FACTS, PYYAML_BUILD, PY_BASELINE)
    assert decision.verdict is Verdict.ACCEPT
    assert rule_ids(decision) == {"OK"}


def test_bump_without_scanner_fixed_version_goes_to_review():
    decision = decide(COLLECTIONS, facts([POM], [DependencyChange(POM, COLLECTIONS.package, "3.2.1", "3.2.2")]),
                      build(JAVA_BASELINE, resolved_versions={COLLECTIONS.package: "3.2.2"}), JAVA_BASELINE)
    assert decision.verdict is Verdict.REVIEW
    assert rule_ids(decision) == {"V4", "info"}


def test_urgency_never_changes_the_verdict():
    overdue = replace(PYYAML, sla_days_remaining=-100)
    assert decide(overdue, PYYAML_FACTS, PYYAML_BUILD, PY_BASELINE).verdict is Verdict.ACCEPT


# Rejected before the build: the change is never executed.

@pytest.mark.parametrize("change, expected", [
    (facts([".github/workflows/ci.yml", LOCK], ci=True), {"X1", "X4"}),
    (facts([LOCK], test_config=True), {"X2"}),
    (facts([LOCK], suspicious=[SuspiciousAddition(LOCK, 1, "pip: alternative index or direct URL", "--index-url x")]),
     {"X3"}),
    (facts([LOCK, POM]), {"X4"}),
])
def test_pre_build_rejections(change, expected):
    decision = policy.pre_build(PYYAML, PROPOSAL, change)
    assert decision.verdict is Verdict.REJECT
    assert rule_ids(decision) == expected


def test_clean_change_passes_pre_build():
    assert policy.pre_build(PYYAML, PROPOSAL, PYYAML_FACTS) is None


# Rejected after the build: the change demonstrably fails its purpose.

@pytest.mark.parametrize("resolved", ["5.3.2", "5.3.1", "5.1"])
def test_version_that_does_not_fix_is_rejected(resolved):
    decision = decide(PYYAML, PYYAML_FACTS, build(PY_BASELINE, resolved_versions={"PyYAML": resolved}), PY_BASELINE)
    assert decision.verdict is Verdict.REJECT
    assert rule_ids(decision) == {"R1"}


def test_tests_that_passed_before_and_fail_after_are_rejected():
    decision = decide(PYYAML, PYYAML_FACTS, replace(PYYAML_BUILD, tests_passed=False, failed_tests=["t.test_x"]),
                      PY_BASELINE)
    assert decision.verdict is Verdict.REJECT
    assert rule_ids(decision) == {"R2"}


# Reasons for a person to look.

def test_code_change_and_extra_dependency_go_to_review():
    decision = decide(COLLECTIONS,
                      facts([POM, "services/inventory-api/src/main/java/PricingService.java"],
                            [DependencyChange(POM, COLLECTIONS.package, "3.2.1", None),
                             DependencyChange(POM, "org.apache.commons:commons-collections4", None, "4.4")],
                            source=True),
                      build(JAVA_BASELINE, resolved_versions={"org.apache.commons:commons-collections4": "4.4"}),
                      JAVA_BASELINE)
    assert decision.verdict is Verdict.REVIEW
    assert {"V1", "V2", "V4"} <= rule_ids(decision)


@pytest.mark.parametrize("build_, baseline", [
    (replace(PYYAML_BUILD, tests_run=0), PY_BASELINE),
    (PYYAML_BUILD, replace(PY_BASELINE, tests_run=5)),
    (PYYAML_BUILD, replace(PY_BASELINE, tests_passed=False)),
    (PYYAML_BUILD, replace(PY_BASELINE, tests_passed=False, error="mvn not found on PATH")),
    (PYYAML_BUILD, None),
])
def test_weaker_test_evidence_goes_to_review(build_, baseline):
    decision = decide(PYYAML, PYYAML_FACTS, build_, baseline)
    assert decision.verdict is Verdict.REVIEW
    assert rule_ids(decision) == {"V5"}


# No evidence: fail closed.

def test_harness_error_goes_to_review():
    decision = decide(PYYAML, None, None, PY_BASELINE, error="apply: GitError: patch does not apply")
    assert decision.verdict is Verdict.REVIEW
    assert rule_ids(decision) == {"N1"}


def test_no_safe_fix_goes_to_review():
    decision = decide(PYYAML, None, None, PY_BASELINE, proposal=replace(PROPOSAL, status=ProposalStatus.NO_SAFE_FIX))
    assert rule_ids(decision) == {"N2"}


@pytest.mark.parametrize("build_", [None, replace(PYYAML_BUILD, error="mvn not found on PATH")])
def test_missing_build_evidence_goes_to_review(build_):
    decision = decide(PYYAML, PYYAML_FACTS, build_, PY_BASELINE)
    assert decision.verdict is Verdict.REVIEW
    assert rule_ids(decision) == {"N3"}
