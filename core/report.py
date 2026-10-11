"""Human-readable reports: summary.md for a run, review.md for a finding routed to a person.

Both are rendered from the same data as result.json. Text from the target
repository or from the agent (rationale, scanner notes, file and test names,
diff content) is untrusted: it is shown in code blocks or escaped, so it cannot
pass itself off as part of the report (e.g. a fake "Verdict: ACCEPT" line).
"""

import re
from pathlib import Path

MAX_DIFF_LINES = 300


def write_summary(path: Path, run_info: dict, baselines: dict[str, dict], records: list[dict],
                  audit_problems: list[str]) -> None:
    harness = run_info["harness"]
    audit_status = "intact" if not audit_problems else "BROKEN: " + _text("; ".join(audit_problems))
    lines = [
        f"# Harness run {run_info['run_id']}",
        "",
        f"- Started: {run_info['started']}",
        f"- Target repository: {_code(run_info['target_repo'])} at commit {_code(run_info['base_sha'])}",
        f"- Findings file sha256: {_code(run_info['findings_sha256'])}",
        f"- Proposals from: {_code(run_info['proposer'])}",
        f"- Harness version: commit {_code(harness['commit'])}"
        + (" (with uncommitted changes)" if harness["uncommitted_changes"] else "")
        + f", policy.py sha256 {_code(harness['policy_sha256'][:16])}",
        f"- Audit log (audit.jsonl): {audit_status}",
        "",
        "## Decisions",
        "",
        "| Finding | CVE | Package | Service | Verdict | Reasons |",
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        finding, decision = record["finding"], record["decision"]
        verdict = f"**{decision['verdict']}**"
        if decision["verdict"] == "REVIEW":
            verdict += f" ([review]({finding['id']}/review.md))"
        lines.append(
            f"| {_cell(finding['id'])} | {_cell(finding['cve'])} | {_cell(finding['package'])} "
            f"| {_cell(finding['service'])} | {verdict} | {_text('; '.join(decision['reasons']))} |"
        )

    lines += ["", "## Baseline (tests on the unchanged code)", ""]
    if baselines:
        lines += ["| Service | Regular tests | Excluded tests | Resolved versions |", "|---|---|---|---|"]
        for service, build in baselines.items():
            lines.append(f"| {_cell(service)} | {_tests(build)} | {_excluded(build)} | {_versions(build)} |")
    else:
        lines.append("Builds were skipped (`--no-build`).")
    _write(path, lines)


def write_review(path: Path, record: dict, baseline: dict | None) -> None:
    finding, decision, facts, build = record["finding"], record["decision"], record["facts"], record["build"]
    proposal = record["proposal"]
    lines = [
        f"# Review: {finding['id']}, {_code(finding['cve'])} in {_code(finding['package'])} ({_code(finding['service'])})",
        "",
        f"**Verdict: {decision['verdict']}.** The harness did not accept this change on its own; a person has to decide.",
        "",
        "Reasons:",
        "",
        *[f"- {_text(reason)}" for reason in decision["reasons"]],
        "",
        "## Finding (scanner data)",
        "",
        f"- Severity: {_code(finding['severity'])}, SLA days remaining: {finding['sla_days_remaining']}",
        f"- Installed version: {_code(finding['installed_version'])}, fixed version: "
        + (_code(finding["fixed_version"]) if finding["fixed_version"] else "none reported"),
        f"- Dependency path: {_code(finding['path'])}",
        "- Scanner notes (untrusted):",
        "",
        _fence(finding["notes"], "text"),
        "",
        f"Base commit: {_code(record['base_sha'])}",
        "",
    ]
    if record["error"]:
        lines += ["## Harness error", "", _fence(record["error"], "text"), ""]

    lines += ["## What changed (computed by the harness, not reported by the agent)", ""]
    if facts is None:
        lines += ["No change was analysed.", ""]
    else:
        lines += [f"Changed files (+{facts['lines_added']}/-{facts['lines_removed']} lines):", ""]
        lines += [f"- {_code(file)}" for file in facts["changed_files"]]
        lines += ["", "Dependency changes:", ""]
        if facts["dependency_changes"]:
            lines += ["| Package | File | Before | After |", "|---|---|---|---|"]
            lines += [
                f"| {_cell(c['package'])} | {_cell(c['file'])} | {_cell(c['old_version'] or 'not present')} "
                f"| {_cell(c['new_version'] or 'removed')} |"
                for c in facts["dependency_changes"]
            ]
        else:
            lines.append("None.")
        lines += [
            "",
            f"- Production source code changed: {_yes_no(facts['touches_source'])}",
            f"- Tests changed: {_yes_no(facts['touches_tests'])}",
            f"- Test selection changed (excludes, skip flags, pytest config): {_yes_no(facts['touches_test_config'])}",
            f"- CI configuration changed: {_yes_no(facts['touches_ci'])}",
            "",
            "Suspicious additions (known-risky patterns in added lines; no hits proves nothing):",
            "",
        ]
        if facts["suspicious_additions"]:
            lines += ["| Location | Rule | Added line |", "|---|---|---|"]
            lines += [
                f"| {_cell(f'{s['file']}:{s['line']}')} | {_text(s['rule'])} | {_cell(s['text'])} |"
                for s in facts["suspicious_additions"]
            ]
        else:
            lines.append("None.")
        lines.append("")

    lines += ["## Build and tests", ""]
    if build is None:
        lines += ["Not built (builds skipped, rejected before the build, or an earlier stage failed).", ""]
    else:
        lines += [
            "| | Baseline (unchanged code) | This change |",
            "|---|---|---|",
            f"| Regular tests | {_tests(baseline)} | {_tests(build)} |",
            f"| Excluded tests, run separately | {_excluded(baseline)} | {_excluded(build)} |",
            f"| Resolved versions | {_versions(baseline)} | {_versions(build)} |",
            "",
            f"Logs: {_code(build['log_dir'])}",
            "",
        ]
        if build["error"]:
            lines += ["Build error:", "", _fence(build["error"], "text"), ""]

    lines += ["## Diff", ""]
    patch = path.parent / record["patch"]["file"] if record["patch"] else None
    if patch and patch.exists():
        diff = patch.read_text(encoding="utf-8", errors="replace").splitlines()
        lines.append(f"{_code(patch.name)}, sha256 {_code(record['patch']['sha256'])}:")
        lines.append("")
        if len(diff) > MAX_DIFF_LINES:
            lines.append(f"First {MAX_DIFF_LINES} of {len(diff)} lines; the full diff is in {_code(patch.name)}.")
            lines.append("")
        lines += [_fence("\n".join(diff[:MAX_DIFF_LINES]), "diff"), ""]
    else:
        lines += ["No diff.", ""]

    lines += ["## Agent's explanation (UNTRUSTED)", ""]
    if proposal:
        lines += [
            f"Written by the agent ({_code(proposal['source'])}, status {_code(proposal['status'])}). "
            "It is not evidence and may be wrong or manipulated, e.g. by prompt injection from repository "
            "content. Check every claim against the sections above.",
            "",
            _fence(proposal["rationale"], "text"),
        ]
    else:
        lines.append("No proposal.")
    _write(path, lines)


def _tests(build: dict | None) -> str:
    if build is None:
        return "not run"
    if build["error"]:
        return "build error"
    failed = build["failed_tests"]
    status = "passed" if build["tests_passed"] else "FAILED"
    detail = f"{build['tests_run']} run" + (f"; failed: {', '.join(_code(t) for t in failed)}" if failed else "")
    return f"{status} ({detail})".replace("|", "\\|")


def _excluded(build: dict | None) -> str:
    if build is None or not build["excluded_tests"]:
        return "none"
    return ", ".join(f"{_cell(p)}: {'passed' if ok else 'FAILED'}" for p, ok in build["excluded_tests"].items())


def _versions(build: dict | None) -> str:
    if build is None or not build["resolved_versions"]:
        return "unknown"
    return ", ".join(_cell(f"{p} {v}") for p, v in build["resolved_versions"].items())


def _yes_no(value: bool) -> str:
    return "**yes**" if value else "no"


def _code(text: object) -> str:
    """Inline code span that the text cannot break out of."""
    text = str(text).replace("\r", " ").replace("\n", " ")
    ticks = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _cell(text: object) -> str:
    """Inline code safe inside a table cell."""
    return _code(text).replace("|", "\\|")


def _text(text: object) -> str:
    """Plain text with Markdown syntax escaped, on one line."""
    text = str(text).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_\[\]<>#|!~])", r"\\\1", text)


def _fence(text: str, lang: str) -> str:
    """Fenced code block that the text cannot close early."""
    ticks = "`" * max(3, max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return f"{ticks}{lang}\n{text.rstrip()}\n{ticks}"


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
