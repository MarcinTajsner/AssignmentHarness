"""Building and testing one service in a clone.

A build executes code from the proposed change (tests, build plugins), so it
runs with a reduced environment: only the variables a build needs, none of the
user's tokens or cloud credentials. That limits the damage; it is not a sandbox.
"""

import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET  # does not resolve external entities
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from core.models import BuildResult

SERVICES_DIR = "services"  # target repository layout: services/<service>/
TIMEOUT_S = 900

PYTEST = "pytest==9.1.1"
# Installing the target's pinned packages can mean building old releases from
# source. PyYAML 5.4.x does not build with Cython 3, and setuptools' bundled
# distutils raises an exception that PyYAML 5.3.1's setup.py does not catch
# when no C compiler is available, so it fails instead of falling back to pure Python.
BUILD_CONSTRAINTS = "cython<3\n"
INSTALL_ENV = {"SETUPTOOLS_USE_DISTUTILS": "stdlib"}

# Environment variables a build may see. Everything else is dropped.
ENV_ALLOWLIST = {
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "TEMP", "TMP", "LANG", "LC_ALL",
    "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "JAVA_HOME", "MAVEN_HOME", "M2_HOME", "MAVEN_OPTS",
}

# Values from the repository passed as command-line arguments. On Windows mvn is
# a .cmd script run through cmd.exe, so shell metacharacters (& | < > ^ % " and
# spaces) could inject commands. Only these characters are allowed.
_SAFE_ARG = re.compile(r"[A-Za-z0-9_*?./#$:,-]+")


class BuildError(RuntimeError):
    """The build could not run: tool missing, timeout."""


class BuildRunner(Protocol):
    def run(self, clone: Path, service: str, packages: list[str], log_dir: Path) -> BuildResult:
        """Build and test `service` in `clone`; report the resolved versions of `packages`."""
        ...


class RealBuildRunner:
    def __init__(self, target_python: str = "3.11", timeout_s: int = TIMEOUT_S):
        self.target_python = target_python
        self.timeout_s = timeout_s

    def run(self, clone: Path, service: str, packages: list[str], log_dir: Path) -> BuildResult:
        service_dir = clone / SERVICES_DIR / service
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            if (service_dir / "pom.xml").is_file():
                return self._maven(service, service_dir, packages, log_dir)
            if (service_dir / "requirements.lock").is_file():
                return self._python(service, clone, service_dir, packages, log_dir)
            raise BuildError(f"no known build system in {service_dir}")
        except (BuildError, OSError) as e:
            return BuildResult(service=service, tests_passed=False, log_dir=str(log_dir), error=str(e))

    def _maven(self, service: str, service_dir: Path, packages: list[str], log_dir: Path) -> BuildResult:
        mvn = ["mvn", "--batch-mode", "--no-transfer-progress"]

        start = time.monotonic()
        exit_code = self._run([*mvn, "test"], service_dir, log_dir / "mvn-test.log")
        duration_s = round(time.monotonic() - start, 1)
        tests_run, failed = _collect_surefire_reports(service_dir, log_dir / "surefire-reports")

        # Tests the POM excludes are run one pattern at a time: an excluded test
        # cannot fail the regular suite, so it must be checked separately.
        excluded: dict[str, bool] = {}
        for i, pattern in enumerate(_surefire_excludes(service_dir / "pom.xml")):
            if not _SAFE_ARG.fullmatch(pattern):
                excluded[pattern] = False
                continue
            code = self._run(
                [*mvn, "test", f"-Dtest={pattern}", "-Dsurefire.failIfNoSpecifiedTests=false"],
                service_dir, log_dir / f"mvn-excluded-{i}.log",
            )
            run, fail = _collect_surefire_reports(service_dir, log_dir / f"surefire-excluded-{i}")
            excluded[pattern] = code == 0 and run > 0 and not fail

        resolved: dict[str, str] = {}
        safe_packages = [p for p in packages if _SAFE_ARG.fullmatch(p)]
        if safe_packages:
            tree = log_dir / "dependency-tree.txt"
            self._run(
                [*mvn, "dependency:tree", f"-Dincludes={','.join(safe_packages)}", f"-DoutputFile={tree}"],
                service_dir, log_dir / "mvn-dependency-tree.log",
            )
            resolved = _parse_dependency_tree(tree, safe_packages)

        return BuildResult(
            service=service,
            tests_passed=exit_code == 0 and not failed,
            log_dir=str(log_dir),
            tests_run=tests_run,
            failed_tests=failed,
            excluded_tests=excluded,
            resolved_versions=resolved,
            duration_s=duration_s,
        )

    def _python(self, service: str, clone: Path, service_dir: Path, packages: list[str], log_dir: Path) -> BuildResult:
        # The venv sits next to the clone, not inside it: the target's .gitignore
        # does not ignore it, so inside it would dirty the clone.
        venv = clone.with_name(f"{clone.name}-{service}-venv")
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # --no-config: uv must not read settings (e.g. a package index) from the untrusted repository.
        uv_pip = ["uv", "pip"]

        if self._run(["uv", "venv", "--no-config", "--python", self.target_python, str(venv)],
                     service_dir, log_dir / "uv-venv.log") != 0:
            raise BuildError(f"could not create a Python {self.target_python} venv (log: {log_dir / 'uv-venv.log'})")

        constraints = log_dir / "build-constraints.txt"
        constraints.write_text(BUILD_CONSTRAINTS, encoding="utf-8")
        installed = self._run(
            [*uv_pip, "install", "--no-config", "--python", str(venv), "--build-constraint", str(constraints),
             "-r", "requirements.lock", PYTEST],
            service_dir, log_dir / "uv-pip-install.log", extra_env=INSTALL_ENV,
        )
        if installed != 0:
            # The pinned dependencies do not install: the change breaks the build.
            return BuildResult(service=service, tests_passed=False, log_dir=str(log_dir))

        report = log_dir / "pytest-report.xml"
        start = time.monotonic()
        exit_code = self._run(
            [str(python), "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={report}"],
            service_dir, log_dir / "pytest.log",
        )
        duration_s = round(time.monotonic() - start, 1)
        tests_run, failed = _read_junit_reports([report] if report.is_file() else [])

        listing = log_dir / "pip-list.json"
        self._run([*uv_pip, "list", "--no-config", "--python", str(venv), "--format", "json"],
                  service_dir, log_dir / "uv-pip-list.log", stdout_to=listing)

        return BuildResult(
            service=service,
            # pytest exit code 5 means "no tests collected": like Maven, that is not a failure by itself;
            # tests_run = 0 shows it.
            tests_passed=exit_code in (0, 5) and not failed,
            log_dir=str(log_dir),
            tests_run=tests_run,
            failed_tests=failed,
            resolved_versions=_installed_versions(listing, packages),
            duration_s=duration_s,
        )

    def _run(self, cmd: list[str], cwd: Path, log: Path,
             extra_env: dict[str, str] | None = None, stdout_to: Path | None = None) -> int:
        """Run a command with the reduced environment and return its exit code.

        Output goes to `log`; with `stdout_to`, stdout goes there instead and only stderr to `log`.
        """
        exe = shutil.which(cmd[0])
        if exe is None:
            raise BuildError(f"{cmd[0]} not found on PATH")
        env = {**_build_env(), **(extra_env or {})}
        try:
            with log.open("wb") as out:
                if stdout_to is None:
                    completed = subprocess.run([exe, *cmd[1:]], cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                                               env=env, timeout=self.timeout_s)
                else:
                    with stdout_to.open("wb") as data:
                        completed = subprocess.run([exe, *cmd[1:]], cwd=cwd, stdout=data, stderr=out,
                                                   env=env, timeout=self.timeout_s)
        except subprocess.TimeoutExpired as e:
            raise BuildError(f"{' '.join(cmd)} timed out after {self.timeout_s}s (log: {log})") from e
        return completed.returncode


class FakeBuildRunner:
    """Returns prepared results instead of building, for tests that must not need Maven or Python 3.11.

    `respond(clone, service)` produces the result. Calls are recorded, so a test
    can also check that something was not built at all.
    """

    def __init__(self, respond: Callable[[Path, str], BuildResult]):
        self.respond = respond
        self.calls: list[tuple[Path, str]] = []

    def run(self, clone: Path, service: str, packages: list[str], log_dir: Path) -> BuildResult:
        self.calls.append((clone, service))
        return self.respond(clone, service)


def _build_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.upper() in ENV_ALLOWLIST}


def _collect_surefire_reports(service_dir: Path, keep_in: Path) -> tuple[int, list[str]]:
    """Move the surefire reports of the last run into the log directory and read them.

    Returns (tests run, failed tests as "Class.method"). Moving them out also
    keeps the next run's reports separate.
    """
    reports = service_dir / "target" / "surefire-reports"
    if not reports.is_dir():
        return 0, []
    shutil.copytree(reports, keep_in, dirs_exist_ok=True)
    shutil.rmtree(reports)
    return _read_junit_reports(sorted(keep_in.glob("TEST-*.xml")))


def _read_junit_reports(reports: list[Path]) -> tuple[int, list[str]]:
    """(tests run, failed tests as "Class.method") from JUnit XML reports (surefire and pytest)."""
    tests_run, failed = 0, []
    for report in reports:
        try:
            root = ET.parse(report).getroot()
        except ET.ParseError:
            failed.append(f"<unreadable report {report.name}>")
            continue
        for case in root.iter("testcase"):
            if case.find("skipped") is not None:
                continue
            tests_run += 1
            if case.find("failure") is not None or case.find("error") is not None:
                failed.append(f"{case.get('classname')}.{case.get('name')}")
    return tests_run, failed


def _surefire_excludes(pom: Path) -> list[str]:
    """<exclude> patterns of the maven-surefire-plugin configuration."""
    try:
        root = ET.parse(pom).getroot()
    except (ET.ParseError, OSError):
        return []
    for element in root.iter():
        element.tag = element.tag.split("}")[-1]  # drop the Maven namespace
    patterns = []
    for plugin in root.iter("plugin"):
        artifact = plugin.find("artifactId")
        if artifact is not None and (artifact.text or "").strip() == "maven-surefire-plugin":
            patterns += [(e.text or "").strip() for e in plugin.iter("exclude")]
    return patterns


def _installed_versions(listing: Path, packages: list[str]) -> dict[str, str]:
    """Versions of `packages` in `uv pip list --format json` output. Names compare as PyPI normalizes them."""
    try:
        entries = json.loads(listing.read_text(encoding="utf-8"))
        installed = {_normalize(entry["name"]): entry["version"] for entry in entries}
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    return {p: installed[_normalize(p)] for p in packages if _normalize(p) in installed}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_dependency_tree(tree: Path, packages: list[str]) -> dict[str, str]:
    """Versions of `packages` in `mvn dependency:tree` output ("group:artifact:type[:classifier]:version:scope")."""
    resolved: dict[str, str] = {}
    if not tree.is_file():
        return resolved
    for line in tree.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.lstrip(" |+-\\").split(":")
        if len(parts) >= 5 and f"{parts[0]}:{parts[1]}" in packages:
            resolved[f"{parts[0]}:{parts[1]}"] = parts[-2]
    return resolved
