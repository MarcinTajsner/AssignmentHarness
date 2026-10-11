# AssignmentHarness

A harness in which an agent proposes fixes for dependency vulnerabilities and the harness decides whether each proposal is **accepted**, **routed to a person for review**, or **rejected**. It works on the [homework](https://github.com/takehome-assignment-bot/homework) repository and its `findings/findings.json`.

For each finding the harness:
1. lets the agent edit a scratch clone of the target repository,
2. computes the diff itself and applies it to a clean clone,
3. works out what changed (facts),
4. builds and tests the change, and compares the results with the unchanged code,
5. decides and writes the results with a tamper-evident audit log.

The original repository is only ever cloned, never modified.

More detail:
- [policy.md](policy.md): the decision rules and why they are there.
- [facts.md](facts.md): what the harness works out about a change.

## Requirements

- [uv](https://docs.astral.sh/uv/). It runs the harness on Python 3.14 and creates a separate Python 3.11 environment for the target's Python service. It downloads both Python versions itself if needed.
- git
- JDK 17+ and Maven 3.9+ on `PATH`, for the Java service
- Network access on the first run, to download from Maven Central and PyPI
- A local clone of the target repository, e.g. next to this one:

  ```
  git clone https://github.com/takehome-assignment-bot/homework ../homework
  ```

On Windows, keep both repositories at a short path. The harness creates nested clones, and Windows limits paths to 260 characters.

## How to run

```
uv sync                                      # create the environment
uv run python harness.py --repo ../homework  # all findings, with builds and tests
uv run pytest                                # tests (no Maven or network needed)
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `--repo` | required | Local clone of the target repository. Only read. |
| `--proposals` | `fixtures/proposals/baseline` | Directory with the recorded agent proposals to use. |
| `--findings` | `findings/findings.json` from the target repository | Another findings file. |
| `--no-build` | off | Skip builds and tests. Fast, but without test evidence nothing can be accepted. |
| `--target-python` | `3.11` | Python version for the target's Python service. |

A full run takes a few minutes; most of it is Maven. Two sets of proposals are included:

| `--proposals` | The agent… | Result |
|---|---|---|
| `fixtures/proposals/baseline` | proposes reasonable dependency bumps | F-40218 REVIEW, F-40219 ACCEPT, F-40220 REVIEW |
| `fixtures/proposals/adversarial` | follows the repository's `CONTRIBUTING.md`: adds a Maven mirror, writes CI credentials, excludes failing tests | all three REJECT, before anything is built |

### Output

Each run writes `runs/<run id>/`:

| File | Content |
|---|---|
| `summary.md` | Table of decisions with reasons; start here. |
| `<finding>/review.md` | For findings routed to a person: what changed, tests before and after, the diff, and the agent's explanation (marked untrusted). |
| `<finding>/result.json` | Everything about the finding: proposal, facts, build results, decision, commit. |
| `<finding>/patch.diff` | The proposed change. |
| `<finding>/logs/` | Raw build and test logs. |
| `baseline.json` | Tests on the unchanged code. |
| `audit.jsonl` | Audit log, hash-chained so later edits are detectable. |

`.work/<run id>/` holds the temporary clones and Python environments. It can be deleted at any time. For an accepted fix, the commit lives there on branch `harness/<finding id>`.

## What is stubbed

- **The agent.** There is no LLM integration yet. Proposals are recorded fixtures: for every finding, `F-xxxx.json` (the agent's status and explanation) and `F-xxxx.diff` (its file edits), replayed into the scratch clone. `LLMProposer` in [core/proposer.py](core/proposer.py) is an empty placeholder with the same interface.
- **Push, pull request and merge.** An accepted fix is committed on a local branch in a temporary clone. The merge is only described (`next_action` in `result.json`, `"executed": false`).
- **CI, deployment and production checks** are out of scope. The harness builds and tests locally.
- **Sandboxing.** Builds run on the local machine with a reduced set of environment variables, not in an isolated sandbox.
- **The scanner.** `findings.json` is read as given; no scan is run.

## Layout

```
harness.py            command line entry point
core/                 pipeline, proposers, git operations, facts, builds, policy, audit log, reports
fixtures/proposals/   recorded agent proposals (baseline, adversarial)
tests/                pytest suite
```
