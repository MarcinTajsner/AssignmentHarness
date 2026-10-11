"""Loading findings.json (scanner output).

The file comes from the target repository, so it is untrusted: its structure
is checked strictly. Free-text fields (notes, path, cve) are carried along as
data and never interpreted.
"""

import json
import re
from pathlib import Path

from core.models import Finding


class FindingsError(ValueError):
    """findings.json is missing, malformed, or has an unexpected structure."""


# Required fields and their allowed types. Unknown extra fields are ignored.
_FIELDS: dict[str, tuple[type, ...]] = {
    "id": (str,),
    "cve": (str,),
    "severity": (str,),
    "service": (str,),
    "package": (str,),
    "installed_version": (str,),
    "fixed_version": (str, type(None)),
    "path": (str,),
    "sla_days_remaining": (int,),
    "notes": (str,),
}

# These fields end up in file paths, git branch names and command-line
# arguments, so they must be plain identifiers: no path separators, no "..",
# no leading dash.
_IDENTIFIERS: dict[str, re.Pattern[str]] = {
    "id": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"),
    "service": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"),
    "package": re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"),
}


def load_findings(path: Path) -> list[Finding]:
    """Read and validate findings.json. Raises FindingsError on anything unexpected."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise FindingsError(f"cannot read {path}: {e}") from e

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise FindingsError(f"{path}: expected an object with a 'findings' list")

    findings = [_parse(i, item) for i, item in enumerate(data["findings"])]

    ids = [f.id for f in findings]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise FindingsError(f"{path}: duplicate finding ids: {', '.join(duplicates)}")
    return findings


def _parse(index: int, item: object) -> Finding:
    where = f"findings[{index}]"
    if not isinstance(item, dict):
        raise FindingsError(f"{where}: expected an object")

    for name, types in _FIELDS.items():
        if name not in item:
            raise FindingsError(f"{where}: missing field '{name}'")
        value = item[name]
        # bool is a subclass of int, but true/false is never a valid value here.
        if isinstance(value, bool) or not isinstance(value, types):
            expected = " or ".join("null" if t is type(None) else t.__name__ for t in types)
            raise FindingsError(f"{where}.{name}: expected {expected}, got {type(value).__name__}")

    for name, pattern in _IDENTIFIERS.items():
        if not pattern.fullmatch(item[name]):
            raise FindingsError(f"{where}.{name}: {item[name]!r} is not a plain identifier")

    return Finding(**{name: item[name] for name in _FIELDS})
