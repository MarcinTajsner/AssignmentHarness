"""Vulnerability patching harness: command line entry point.

    uv run python harness.py --repo ../homework
"""

from pathlib import Path

import click

from core import pipeline
from core.build import RealBuildRunner
from core.findings import FindingsError
from core.proposer import FixtureProposer
from core.workspace import GitError

ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / "runs"  # results of each run
WORK_DIR = ROOT / ".work"  # temporary clones and venvs


@click.command()
@click.option(
    "--repo",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Local clone of the target repository. Read-only: used as the source for git clone.",
)
@click.option(
    "--findings",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Findings file. Default: findings/findings.json from the baseline clone.",
)
@click.option(
    "--proposals",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=ROOT / "fixtures" / "proposals" / "baseline",
    show_default="fixtures/proposals/baseline",
    help="Directory with recorded agent proposals (F-xxxx.json + F-xxxx.diff).",
)
@click.option(
    "--no-build",
    is_flag=True,
    help="Skip builds and tests. Without test evidence no finding can be ACCEPTed.",
)
@click.option(
    "--target-python",
    default="3.11",
    show_default=True,
    help="Python version for the target service's venv (passed to `uv venv --python`).",
)
def main(repo: Path, findings: Path | None, proposals: Path, no_build: bool, target_python: str) -> None:
    """Decide whether agent-proposed dependency fixes are accepted, reviewed, or rejected.

    For every finding: get a proposal, validate it, decide.
    """
    try:
        out = pipeline.run(
            repo=repo.resolve(),
            proposer=FixtureProposer(proposals.resolve()),
            builder=None if no_build else RealBuildRunner(target_python),
            runs_dir=RUNS_DIR,
            work_dir=WORK_DIR,
            findings_file=findings.resolve() if findings else None,
            progress=click.echo,
        )
    except (FindingsError, GitError) as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"results: {out}")


if __name__ == "__main__":
    main()
