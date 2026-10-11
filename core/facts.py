"""Facts the Validator computes itself about a proposed change.

Input is the clean clone: the base commit plus exactly the proposed patch,
staged. Everything here comes from git and from parsing the changed files,
never from what the agent says it did.
"""

import re
import xml.etree.ElementTree as ET  # does not resolve external entities
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath

from core import workspace
from core.models import DependencyChange, Facts, SuspiciousAddition


class FactsError(RuntimeError):
    """A changed file cannot be analysed (e.g. pom.xml is no longer valid XML)."""


CI_PATHS = (".github/", ".gitlab-ci.yml", ".circleci/", "Jenkinsfile")
PYTEST_CONFIG_FILES = {"pytest.ini", "tox.ini", "setup.cfg"}
SOURCE_EXTENSIONS = {".py", ".java", ".kt", ".scala", ".groovy", ".js", ".ts", ".go", ".rb", ".sh", ".ps1"}
# POM elements that decide which tests run (surefire/failsafe configuration and properties).
POM_TEST_SELECTION_TAGS = {
    "exclude", "include", "test", "skip", "skipTests", "skipITs",
    "testFailureIgnore", "maven.test.skip", "maven.test.failure.ignore",
}
# "name==version" in requirements files; extras and environment markers are allowed.
_PIN = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")


def _python(path: str) -> bool:
    return path.endswith(".py")


def _java(path: str) -> bool:
    return path.endswith(".java")


def _pom(path: str) -> bool:
    return PurePosixPath(path).name == "pom.xml"


def _requirements(path: str) -> bool:
    return _is_requirements(PurePosixPath(path).name)


def _any(path: str) -> bool:
    return True


# Known-risky patterns, matched against added lines only. A deny-list: easy to
# evade, so a hit escalates and points a reviewer at the line, while no hits
# prove nothing. A real system would use semgrep/bandit/CodeQL here.
SUSPICIOUS_PATTERNS: list[tuple[str, Callable[[str], bool], re.Pattern[str]]] = [
    ("python: process execution", _python, re.compile(r"\b(os\.system|os\.popen|os\.exec\w*|subprocess\.|pty\.spawn)")),
    ("python: dynamic code execution", _python, re.compile(r"(?<![\w.])(eval|exec|compile|__import__)\s*\(|\bimportlib\.")),
    ("python: unsafe deserialization", _python, re.compile(r"\b(pickle|marshal|shelve)\.loads?\b|\byaml\.(unsafe_)?load\s*\((?![^)]*SafeLoader)")),
    ("python: environment/secrets access", _python, re.compile(r"\bos\.(environ|getenv)\b")),
    ("python: network access", _python, re.compile(r"\b(socket|requests|urllib|httpx|http\.client)\.")),
    ("java: process execution", _java, re.compile(r"Runtime\.getRuntime\(\)\.exec|\bProcessBuilder\b")),
    ("java: unsafe deserialization", _java, re.compile(r"\bObjectInputStream\b|\bXMLDecoder\b|\.readObject\s*\(")),
    ("java: reflection / dynamic class loading", _java, re.compile(r"Class\.forName|\.setAccessible\s*\(|\bURLClassLoader\b")),
    ("java: environment/secrets access", _java, re.compile(r"System\.getenv")),
    ("java: network access", _java, re.compile(r"new\s+(URL|Socket)\s*\(|\bHttpClient\b")),
    ("maven: plugin that runs commands", _pom, re.compile(r"exec-maven-plugin|maven-antrun-plugin|groovy-maven-plugin")),
    ("maven: extra artifact repository", _pom, re.compile(r"<(plugin)?[Rr]epositor(y|ies)>")),
    ("pip: alternative index or direct URL", _requirements, re.compile(r"--(extra-)?index-url|--find-links|\bhttps?://|\bgit\+")),
    ("hard-coded secret", _any, re.compile(r"(?i)\w*(token|secret|passw(or)?d|api[_-]?key)\w*['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+]{8,}")),
]

_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def compute_facts(clean: Path) -> Facts:
    stats = workspace.staged_numstat(clean)
    paths = [path for _, _, path in stats]

    dependency_changes: list[DependencyChange] = []
    touches_test_config = False
    for path in paths:
        name = PurePosixPath(path).name
        before = workspace.read_file(clean, f"HEAD:{path}")
        after = workspace.read_file(clean, f":{path}")
        if name == "pom.xml":
            old_versions, old_tests = _parse_pom(path, before)
            new_versions, new_tests = _parse_pom(path, after)
            dependency_changes += _version_changes(path, old_versions, new_versions)
            touches_test_config |= old_tests != new_tests
        elif _is_requirements(name):
            dependency_changes += _version_changes(path, _parse_pins(before), _parse_pins(after))
        touches_test_config |= name in PYTEST_CONFIG_FILES

    return Facts(
        changed_files=paths,
        lines_added=sum(added for added, _, _ in stats),
        lines_removed=sum(removed for _, removed, _ in stats),
        dependency_changes=dependency_changes,
        touches_source=any(_is_source_path(path) for path in paths),
        touches_tests=any(_is_test_path(path) for path in paths),
        touches_test_config=touches_test_config,
        touches_ci=any(path.startswith(CI_PATHS) for path in paths),
        suspicious_additions=_scan(workspace.staged_diff(clean).decode("utf-8", errors="replace")),
    )


def _scan(diff: str) -> list[SuspiciousAddition]:
    hits = []
    for file, line_no, text in _added_lines(diff):
        if text is None:
            hits.append(SuspiciousAddition(file, 0, "binary content (cannot be inspected)", ""))
            continue
        for rule, applies_to, pattern in SUSPICIOUS_PATTERNS:
            if applies_to(file) and pattern.search(text):
                hits.append(SuspiciousAddition(file, line_no, rule, text.strip()[:160]))
    return hits


def _added_lines(diff: str) -> Iterator[tuple[str, int, str | None]]:
    """(file, line number in the new file, text) for every added line; text None for binary content."""
    file, old_left, new_left, line_no = "", 0, 0, 0
    for raw in diff.split("\n"):
        if old_left > 0 or new_left > 0:  # inside a hunk
            if raw.startswith("+"):
                yield file, line_no, raw[1:]
                line_no += 1
                new_left -= 1
            elif raw.startswith("-"):
                old_left -= 1
            elif not raw.startswith("\\"):  # context line ("\ No newline at end of file" is not)
                line_no += 1
                old_left -= 1
                new_left -= 1
        elif raw.startswith("diff --git "):
            header = raw.removeprefix("diff --git ")
            file = header.rsplit(" b/", 1)[-1] if " b/" in header else header
        elif raw.startswith("GIT binary patch") or raw.startswith("Binary files "):
            yield file, 0, None
        elif match := _HUNK.match(raw):
            old_left = int(match.group(1) or 1)
            line_no = int(match.group(2))
            new_left = int(match.group(3) or 1)


def is_dependency_manifest(path: str) -> bool:
    """pom.xml or a requirements file: the files a dependency-only fix is expected to touch."""
    name = PurePosixPath(path).name
    return name == "pom.xml" or _is_requirements(name)


def _is_source_path(path: str) -> bool:
    return PurePosixPath(path).suffix in SOURCE_EXTENSIONS and not _is_test_path(path)


def _is_test_path(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        "/src/test/" in f"/{path}"
        or "/tests/" in f"/{path}"
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _is_requirements(name: str) -> bool:
    return name.startswith("requirements") and name.endswith((".txt", ".lock", ".in"))


def _version_changes(path: str, old: dict[str, str], new: dict[str, str]) -> list[DependencyChange]:
    return [
        DependencyChange(file=path, package=package, old_version=old.get(package), new_version=new.get(package))
        for package in sorted(old.keys() | new.keys())
        if old.get(package) != new.get(package)
    ]


def _parse_pins(content: bytes | None) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (content or b"").decode("utf-8", errors="replace").splitlines():
        if match := _PIN.match(line):
            pins[match.group(1)] = match.group(2)
    return pins


def _parse_pom(path: str, content: bytes | None) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Versions declared in a POM, and the elements that select which tests run."""
    if content is None:
        return {}, []
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise FactsError(f"{path}: not valid XML: {e}") from e
    for element in root.iter():
        element.tag = element.tag.split("}")[-1]  # drop the Maven namespace

    versions: dict[str, str] = {}
    parent = root.find("parent")
    if parent is not None:
        versions[_coordinates(parent)] = _text(parent, "version") or "(managed)"
    for dependency in root.iter("dependency"):
        versions[_coordinates(dependency)] = _text(dependency, "version") or "(managed)"
    properties = root.find("properties")
    if properties is not None:
        for prop in properties:
            if prop.tag.endswith(".version"):
                versions["${" + prop.tag + "}"] = (prop.text or "").strip()

    tests = sorted(
        (element.tag, (element.text or "").strip())
        for element in root.iter()
        if element.tag in POM_TEST_SELECTION_TAGS
    )
    return versions, tests


def _coordinates(element: ET.Element) -> str:
    return f"{_text(element, 'groupId')}:{_text(element, 'artifactId')}"


def _text(element: ET.Element, child: str) -> str | None:
    found = element.find(child)
    return found.text.strip() if found is not None and found.text else None
