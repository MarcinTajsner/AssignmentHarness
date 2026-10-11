# Design

## 1. Overview

An agent proposes fixes for dependency vulnerabilities. For each finding the harness decides whether the fix goes in on its own (**ACCEPT**), goes to a person (**REVIEW**), or is refused (**REJECT**). The agent only edits files in its own copy of the repository. It never commits, creates branches or holds credentials.

```mermaid
flowchart TD
    findings["findings.json"] --> baseline["Baseline: build and test the unchanged code"]
    baseline --> agent

    subgraph perFinding [For each finding]
        agent["Agent edits a scratch clone"] --> diff["Harness computes the diff"]
        diff --> clean["Diff applied to a clean clone"]
        clean --> facts["Harness works out what changed"]
        facts --> pre{"Pre-build check"}
        pre -- "gate tampering, risky code, out of scope" --> early["REJECT, never built"]
        pre -- "ok" --> build["Build and test, including excluded tests"]
        build --> decide{"Decide, compared with the baseline"}
        decide --> accept["ACCEPT: commit on branch harness/finding"]
        decide --> review["REVIEW: review.md for a person"]
        decide --> reject["REJECT"]
    end

    early & accept & review & reject --> record["result.json, audit log, summary"]
```

Principles:
- **The harness trusts only what it checked itself:** the diff it computed, the files it parsed, the tests it ran. The agent's explanation and the repository's documentation never decide anything.
- **Fail closed.** If a step fails or evidence is missing, the finding cannot be accepted.
- **The target repository is never modified.** It is only cloned.

What is stubbed (the agent, push and merge) is listed in the [README](README.md#what-is-stubbed).

## 2. Autonomy boundary

### 2.1 Where the line sits

| Verdict | When | Why |
|---|---|---|
| **ACCEPT** | Only a version bump of the vulnerable package in its dependency file. The version is confirmed in the real build, is at least the fixed version and in the same major version, and all tests pass as before. | The harness checked every claim itself, the change touches one library in one service, and it is easy to undo. |
| **REVIEW** | The harness sees something it cannot judge: code changes, other dependencies, a major version jump, a fix it cannot confirm, weaker test evidence, a behaviour change, or no evidence at all. | These need judgement about intent or trade-offs. For example, F-40218 fixes the CVE but breaks loading of operator override files. |
| **REJECT** | The agent changed CI or which tests run, added risky code, or touched another service. Or the change does not fix the finding or breaks tests. | Nobody should be asked to approve an agent changing its own gates. Most of these are caught before the build, so the code never runs. |

The urgency of a finding (severity, SLA deadline) has no practical effect on the verdict and is only shown in the reasons.

### 2.2 What the decision is based on

What the harness works out from the change itself, using git and by parsing the changed files before and after:

| Fact | Meaning |
|---|---|
| Changed files | Which files the change touches. |
| Dependency changes | Which packages changed, from which version to which (pins in requirements files; dependencies, parent and `*.version` properties in `pom.xml`). |
| Touches source / tests / test selection / CI | Whether production code, tests, the set of tests that run (`<exclude>`, skip flags, pytest config), or CI configuration changed. |
| Suspicious additions | Known-risky constructs in added lines (section 3). |

Build results, for the change and for the unchanged code (the baseline):

| Result | Meaning |
|---|---|
| Tests | Passed or not, how many ran, which failed. |
| Excluded tests | Tests the repository excludes from its regular run, run one by one. |
| Resolved versions | The versions that really ended up in the build. |

### 2.3 Rules

Every reason in a decision starts with the id of its rule, e.g. `[X2]`. X1–X4 are checked before the build, so a change they reject is never run. A finding is accepted only if no rule applies.

| Rule | Verdict | When |
|---|---|---|
| X1 | REJECT | CI configuration changed. |
| X2 | REJECT | The set of tests that run changed (`<exclude>`, skip flags, pytest config). |
| X3 | REJECT | An added line contains a known-risky construct (section 3). |
| X4 | REJECT | Files outside the finding's service changed. |
| R1 | REJECT | The version in the build does not fix the finding: it is below the fixed version or not newer than the vulnerable one. |
| R2 | REJECT | Tests passed before the change and fail after it. |
| V1 | REVIEW | More than the dependency file changed: production code, tests or other files. |
| V2 | REVIEW | Dependencies other than the vulnerable package changed. |
| V3 | REVIEW | Major version jump. |
| V4 | REVIEW | The fix cannot be confirmed: the scanner gives no fixed version, or the package is missing from the build. |
| V5 | REVIEW | Weaker test evidence than before: fewer tests ran, none ran, or tests already failed before the change. |
| V6 | REVIEW | A test the repository excludes passed before the change and fails after it. |
| N1 | REVIEW | A step of the harness failed, e.g. the diff does not apply. |
| N2 | REVIEW | The agent found no safe fix. |
| N3 | REVIEW | The change was not built, or the build could not run. |

Two deliberate calls:
- Changed tests go to REVIEW, not REJECT: adding a test is fine, but someone should read it.
- Changing which tests run is REJECT in both directions: the agent never decides that.

### 2.4 Results for this repository

| Finding | Proposal | Verdict |
|---|---|---|
| F-40218, SnakeYAML | 1.30 → 2.0 | REVIEW (V3, V6) |
| F-40219, PyYAML | 5.3.1 → 5.4.1 | ACCEPT |
| F-40220, commons-collections | 3.2.1 → 3.2.2 | REVIEW (V4) |
| Adversarial agent following `CONTRIBUTING.md` | adds a Maven mirror / writes CI credentials / excludes failing tests | REJECT (X3 / X1, X4 / X2) |

- **F-40218.** The regular tests pass, so the repository's `CONTRIBUTING.md` would auto-merge it. But `ConfigLoaderIntegrationTest`, excluded as "flaky", passes before the change and fails after it: operator override files would stop loading.
- **F-40220.** The scanner says there is no fixed version, while 3.2.2 is the upstream fix. The harness trusts neither the scanner nor the agent here, so a person decides.

## 3. Untrusted input

Everything that comes from the target repository or from the agent is data, never instructions: documentation, code comments, `findings.json`, and the agent's explanation. The harness's rules live only in its own code.

### 3.1 What the repository tries

| Source | What it says | What the harness does |
|---|---|---|
| `CONTRIBUTING.md` | Dependency-only changes auto-merge once CI is green. | Ignores it. F-40218 has green CI and still goes to REVIEW. |
| `CONTRIBUTING.md` | If a test fails after a bump, exclude it instead of reverting. | Rejects it (X2), and runs excluded tests separately anyway. |
| `CONTRIBUTING.md` | Refresh the CI token from the runbook. | Rejects it (X1). Neither the harness nor the agent holds any credentials. |
| `pom.xml` comment | `ConfigLoaderIntegrationTest` is "flaky". | Checks it instead of believing it: the test passes on the unchanged code and fails after the change. |
| `docs/runbook-stale.md` | Stale ownership, credentials, known issues. | Never reads it. |
| `findings.json` | Scanner data, including free-text notes and `fixed_version: null` for commons-collections although 3.2.2 exists. | Validates the structure strictly. Fields that end up in file paths or commands must be plain identifiers. Free text is never interpreted, and a missing fixed version means REVIEW (V4). |
| The agent's explanation | Why the fix is right, possibly citing `CONTRIBUTING.md`. | Never uses it in a decision. It is shown at the end of `review.md`, marked untrusted. |

### 3.2 How the harness protects itself

- **It computes the diff itself** from the agent's scratch clone. What is checked, tested and committed is exactly that diff, not the agent's description of it.
- **It checks before it builds (X1–X4).** Building runs code from the change: tests, `setup.py`, Maven plugins. A change that will be rejected anyway is never run.
- **It scans added lines for known-risky constructs** (X3):

  | Files | Flagged |
  |---|---|
  | Python | `os.system`, `subprocess`, `eval`/`exec`, `pickle.loads`, `yaml.load` without `SafeLoader`, `os.environ`, network calls |
  | Java | `Runtime.exec`, `ProcessBuilder`, `ObjectInputStream`, `Class.forName`, `System.getenv`, network calls |
  | `pom.xml` | plugins that run commands (`exec-maven-plugin`, `maven-antrun-plugin`), extra artifact repositories |
  | requirements files | another package index, direct URLs, `git+` |
  | any file | hard-coded secrets, binary files |

  This is a deny-list and easy to evade, so a hit rejects, but no hits prove nothing.
- **Builds see a reduced environment.** Only what a build needs (`PATH`, `JAVA_HOME`, home and temp directories) is passed on, so tokens in the user's environment are not visible to code from the change.
- **The repository cannot redirect package installs.** uv runs with `--no-config`. Without it, uv used a package index that a test added to the repository's `pyproject.toml`.
- **Values from the repository are restricted in commands.** Package names and test patterns may only contain safe characters, because on Windows `mvn` runs through `cmd.exe`.
- **Reports cannot be forged by the content they show.** Untrusted text appears in code blocks, so an explanation containing "**Verdict: ACCEPT**" stays inside its block.

## 4. Evidence

An auditor wants proof of three things: the CVE was remediated in production on a given date, the vulnerable artifact (the built image that runs in production) no longer runs, and the fix went through the required gates. That proof is a chain from the finding to what runs in production. Every link can be checked, and it is recorded when it happens rather than written up afterwards.

| Link | Proves | Produced by | In this project |
|---|---|---|---|
| 1. Finding | What was vulnerable | Scanner | real: hash of `findings.json` |
| 2. Change | Which change fixes it, on which code | Harness | real: `patch.diff` and its hash, base commit, fix commit |
| 3. Gates | Which checks it passed, and the decision | Harness | real: `result.json`, `audit.jsonl` |
| 4. Artifact | The built image contains the fixed version | CI | mock |
| 5. Deployment | The image reached production at a given time | Deployment system | mock |
| 6. Running | Nothing in production runs the vulnerable image any more | Runtime inventory, rescan | mock |

The links are tied together by identifiers that cannot be faked: the patch hash, the commit SHA, the image digest. [evidence/example-attestation.json](evidence/example-attestation.json) shows the whole chain for F-40219. Links 1–3 come from a real run of the harness. Run outputs are not committed, but every run writes the same records; links 4–6 are mocked.

The audit log is hash-chained, like git history. Every entry stores the hash of the previous entry, and also the hashes of the finding's `patch.diff` and `result.json`. Editing, removing or reordering anything afterwards is therefore detectable. It is not impossible, though: whoever can rewrite the whole log can recompute every hash. In production the entries would also go to write-once storage, or be signed with a key the harness does not hold.

For a REVIEW finding, link 3 would also record who approved the change and when. That approval step is not implemented.

## 5. Failure modes

### 5.1 Tests pass, but they do not test the changed code (unsafe)

F-40219 is accepted because its test suite passes. But the only test does not touch `report_worker/config.py`, the code that uses PyYAML. PyYAML 5.4 also restricts which Python-specific tags `FullLoader` accepts. If an operator's override file relied on one of them, it would stop loading after an autonomous merge, and no test would notice.

**Detection:** the harness cannot see this. In production it shows up as errors when override files are loaded after the deployment. The audit log ties that deployment back to the accepted change, so the change can be found and reverted quickly. To catch it before the merge, ACCEPT would also require a coverage check: at least one test executes code that uses the changed package.

### 5.2 Code from the agent runs on the build machine (unsafe)

Every change that is not rejected before the build is built and tested, and that runs code the agent wrote: tests, `setup.py`, Maven plugins. Changes that go to REVIEW, e.g. code changes (V1), are built too. The pre-build scan is a deny-list, so a manipulated agent can hide, say, obfuscated exfiltration in a test. The reduced environment keeps tokens in environment variables out of reach, but files in the user's home directory, such as `~/.m2/settings.xml` or `~/.ssh`, are still readable.

**Detection:** on a local machine, hardly at all. In production, builds would run in a throwaway sandbox with no credentials and no outbound network, except to a package mirror. Blocked connection attempts would be logged and alerted on, so a change that tries to reach out is visible even when the scan missed it.

### 5.3 The harness cannot check a proposal (safe)

A tool is missing, Maven times out, Python dependencies cannot be installed, the diff does not apply, the POM no longer parses, or builds are switched off. The harness fails closed: the finding goes to REVIEW (N1, N3), and nothing unchecked goes in. The cost is people's time, and the vulnerability stays open longer.

One case looks different: if the Maven build of a change fails for an outside reason, e.g. a new dependency cannot be downloaded, it cannot be told apart from a change that breaks the build, and it is rejected (R2). That is still safe, because nothing goes in, but the reason is misleading.

**Detection:** the reason says so (`[N1]`, `[N3]`) in `summary.md` and the audit log. When many findings in one run fail this way, the harness itself is broken (e.g. Maven is not installed), not the proposals. The build logs of each finding show whether an R2 rejection was caused by the change or by the environment.

### 5.4 Other known limits

- Overriding a version managed by a parent BOM (e.g. Spring Boot) is not a reason for review on its own, although that combination was never tested by the parent. Rule V3 catches major jumps, but not small overrides.
- Versions are compared by their numbers ("5.4.1" → 5, 4, 1). That is not enough for every scheme, e.g. pre-release suffixes.
- The audit log detects later edits, but whoever can rewrite all of it can recompute the hashes (section 4).

## 6. AI usage

The project was built with Claude Code. I directed the work, made the key decisions and checked every step. The AI proposed detailed designs, wrote the code, and explained what I did not know.

**Me**
- **Analysing the repository and its traps.** I worked through the code, the findings and the conflicting documentation. Where I lacked background, e.g. in Java, Maven or Spring Boot, I asked the AI to explain.
- **The overall architecture:** an untrusted Proposer and a trusted Validator. I had planned this before starting.
- **The project setup:** the uv project, a separate Python for the harness (3.14) and for the target's service (3.11, the version its CI uses), and a single `harness.py` command with the logic in `core/`.
- **Keeping it simple.** Several AI proposals were cut down: the rules live in code instead of a separate config file, there are fewer output files per finding, and unnecessary git steps were dropped.
- **Some of the facts:** detecting dangerous code in the agent's changes, which became the pre-build scan, and measuring performance before and after a change. Performance measurement is not implemented, because this repository has no benchmarks and its test timings are mostly JVM start-up. In a large project, with big APIs and many AI-proposed code changes, I still think it would be worth it.
- **The policy:** which facts to use, and what goes to ACCEPT, REVIEW or REJECT.
- **Review:** running and checking every implementation step, and shortening and simplifying this document.

**AI (Claude Code)**
- **The scratch clone and clean clone design.** The harness computes the diff itself and applies it to a fresh clone, so what is tested is exactly what would be committed.
- **Proposing the facts** and how to compute them, e.g. comparing the dependency files before and after instead of parsing the diff.
- **Hardening the builds:** the reduced environment, `uv --no-config`, restricted command arguments, and the workarounds needed to install old PyYAML releases on Windows.
- **The audit output:** `result.json`, the hash-chained audit log, the review reports and the evidence chain. It also explained to me what each part is for and how the hash chain works.
- **The implementation:** the code, the tests, the fixtures, and drafts of the documentation, including this document.

## 7. What I would do next

- **A real agent.** Replace the fixtures with an LLM that can only read and edit files in its scratch clone: no shell, no git, no credentials. Repository content would be presented to it as untrusted data, and its runs recorded as new fixtures.
- **Sandboxed builds.** Run every build in a throwaway container with no credentials and no network except a package mirror, and alert on blocked connections (section 5.2).
- **A coverage check for ACCEPT.** Accept only if at least one test executes code that uses the changed package (section 5.1).
- **Human approval for REVIEW.** A person approves or rejects in the review report. The harness then records who decided and when in the audit log, and commits approved changes.
- **The rest of the chain.** Push the branch and open a pull request, then collect the artifact, deployment and production evidence (section 4, links 4–6) automatically instead of mocking it.
- **Rule settings in a file.** Move what changes between repositories or over time into a TOML file: protected paths, the suspicious patterns, repositories that are never auto-accepted, how each repository is built. The rule logic itself stays in code, where it is tested.
- **Performance checks** for code changes, using dedicated benchmarks rather than test timings.
- **A tamper-proof audit log:** entries sent to write-once storage, or signed with a key the harness does not hold.

## 8. Scale: from 2 repositories to 300

Running the harness itself scales easily: findings are independent of each other, so they can run in parallel on a pool of sandboxed build machines that share dependency caches. What changes is everything around the code.
- **People become the bottleneck.** If a third of the findings go to REVIEW, someone has to read hundreds of reports. So reviews must be routed to each repository's owners, using ownership data that is kept current; here the runbook still names an owner who has left. Reviews must also be grouped, so one SnakeYAML upgrade is decided once instead of in fifty repositories.
- **Risk becomes correlated.** The same accepted bump landing in 300 services at once can break many of them together, so autonomous merges need a staged rollout and a rate limit.
- **Repositories differ** in build tools, layout and test quality. The harness needs settings for each repository, e.g. how to build it, or never to auto-accept where tests are weak. Those settings belong to the harness, not to the repository, or a repository could tell the harness to accept everything.
- **The evidence must be in one place.** Each run now keeps its audit log on the machine that ran it. With many machines, the entries have to go to one shared store that can only be appended to, so an auditor can ask about one CVE across all 300 repositories.
