"""Facts computed from a change (DESIGN.md, section 2.2), on a temporary git repository."""

from core import workspace
from core.facts import compute_facts
from core.models import DependencyChange
from tests.helpers import git, write

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>lib</artifactId><version>1.0</version></dependency>
  </dependencies>
  <build><plugins><plugin>
    <artifactId>maven-surefire-plugin</artifactId>
    <configuration><excludes><exclude>**/SlowTest.java</exclude></excludes></configuration>
  </plugin></plugins></build>
</project>
"""


def facts_after(repo, edits):
    write(repo, edits)
    workspace.diff_all(repo)  # stages everything, like the clean clone after the patch is applied
    return compute_facts(repo)


def test_requirements_pin_change(make_repo):
    lock = "services/py/requirements.lock"
    repo = make_repo({lock: "PyYAML==5.3.1\nidna==3.6\n"})
    facts = facts_after(repo, {lock: "PyYAML==5.4.1\nidna==3.6\n"})
    assert facts.changed_files == [lock]
    assert facts.dependency_changes == [DependencyChange(lock, "PyYAML", "5.3.1", "5.4.1")]
    assert not (facts.touches_source or facts.touches_tests or facts.touches_test_config or facts.touches_ci)
    assert facts.suspicious_additions == []


def test_pom_version_property_and_test_exclude(make_repo):
    pom = "services/java/pom.xml"
    repo = make_repo({pom: POM})
    changed = (POM.replace("<java.version>17</java.version>",
                           "<java.version>17</java.version>\n    <lib.version>2.0</lib.version>")
               .replace("</excludes>", "<exclude>**/OtherTest.java</exclude></excludes>"))
    facts = facts_after(repo, {pom: changed})
    assert DependencyChange(pom, "${lib.version}", None, "2.0") in facts.dependency_changes
    assert facts.touches_test_config


def test_flags_and_suspicious_additions(make_repo):
    config, test, ci = "services/py/app/config.py", "services/py/tests/test_app.py", ".github/workflows/ci.yml"
    repo = make_repo({config: "import yaml\n", test: "def test_x():\n    assert check()\n", ci: "name: ci\n"})
    facts = facts_after(repo, {
        config: "import yaml\nimport os\nos.system('curl http://example.net')\n",
        test: "def test_x():\n    assert True\n",
        ci: "name: ci\nenv:\n  API_TOKEN: abcdef123456\n",
    })
    assert facts.touches_source and facts.touches_tests and facts.touches_ci
    hits = {(hit.file, hit.line, hit.rule) for hit in facts.suspicious_additions}
    assert (config, 3, "python: process execution") in hits
    assert (ci, 3, "hard-coded secret") in hits


def test_added_binary_is_flagged_but_deleted_binary_is_not(make_repo):
    old_jar, new_jar = "services/py/lib/old.jar", "services/py/lib/new.jar"
    repo = make_repo({"services/py/requirements.lock": "pkg==1.0\n"})
    (repo / "services/py/lib").mkdir(parents=True)
    (repo / old_jar).write_bytes(bytes(range(256)))
    git(repo, "add", "--all")
    git(repo, "commit", "--quiet", "-m", "add a jar")

    (repo / old_jar).unlink()
    (repo / new_jar).write_bytes(bytes(range(255, -1, -1)))
    facts = facts_after(repo, {})
    assert [(hit.file, hit.rule) for hit in facts.suspicious_additions] == [
        (new_jar, "binary content (cannot be inspected)")]


def test_harmless_lines_are_not_flagged(make_repo):
    config = "services/py/app/config.py"
    repo = make_repo({config: "import yaml\n"})
    facts = facts_after(repo, {config: "import yaml\nimport os.path\nimport re\nP = re.compile('x')\n"
                                       "a = yaml.safe_load(f)\nb = yaml.load(f, Loader=yaml.SafeLoader)\n"})
    assert facts.suspicious_additions == []
