"""Append-only audit log (JSON Lines) with a hash chain.

In plain words, this works like git history. A hash is a fingerprint of a piece
of text: the same text always gives the same hash, and changing a single
character gives a completely different one. Every line of the log stores the
hash of the line before it (prev_hash), just as every git commit stores the
hash of its parent, plus its own hash. Change, delete or reorder an old line
and the fingerprints stop matching; verify() reports where.

Why: an auditor only trusts a record that was written when the decision was
made and could not be quietly edited afterwards, e.g. turning a REVIEW into an
ACCEPT. Each finding's entry also stores the hashes of its patch.diff and
result.json, so those files are covered too.

Limit: this makes tampering detectable, not impossible. Whoever can rewrite the
whole file can recompute every hash. A real system would also send the entries
to write-once storage or sign them with a key the harness does not hold.
"""

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64  # prev_hash of the first entry


def append(log: Path, entry: dict) -> dict:
    """Append `entry` to the log, chained to the last entry. Returns the stored record."""
    record = {**entry, "prev_hash": _last_hash(log)}
    record["hash"] = _hash(record)
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    return record


def verify(log: Path) -> list[str]:
    """Problems found in the chain. An empty list means the log is intact."""
    problems = []
    prev = GENESIS
    for number, line in enumerate(log.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            record = json.loads(line)
        except ValueError:
            problems.append(f"entry {number}: not valid JSON")
            continue
        if record.get("prev_hash") != prev:
            problems.append(f"entry {number}: does not follow the previous entry (removed, inserted or reordered)")
        if _hash({k: v for k, v in record.items() if k != "hash"}) != record.get("hash"):
            problems.append(f"entry {number}: content was changed after it was written")
        prev = record.get("hash")
    return problems


def _last_hash(log: Path) -> str:
    if not log.exists():
        return GENESIS
    lines = log.read_text(encoding="utf-8").splitlines()
    return json.loads(lines[-1])["hash"] if lines else GENESIS


def _hash(record: dict) -> str:
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
