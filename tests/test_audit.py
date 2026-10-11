"""The hash-chained audit log detects later edits."""

import json

import pytest

from core import audit


@pytest.fixture
def lines(tmp_path):
    log = tmp_path / "audit.jsonl"
    for verdict in ("REVIEW", "ACCEPT", "REJECT"):
        audit.append(log, {"event": "finding_decided", "verdict": verdict})
    return log.read_text(encoding="utf-8").splitlines()


def verify(tmp_path, lines):
    log = tmp_path / "check.jsonl"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return audit.verify(log)


def test_intact_log_verifies(tmp_path, lines):
    assert verify(tmp_path, lines) == []


def test_changed_entry_is_detected(tmp_path, lines):
    entry = json.loads(lines[0])
    entry["verdict"] = "ACCEPT"
    problems = verify(tmp_path, [json.dumps(entry), *lines[1:]])
    assert any("entry 1" in p and "changed" in p for p in problems)


def test_removed_entry_is_detected(tmp_path, lines):
    assert verify(tmp_path, [lines[0], lines[2]]) != []


def test_reordered_entries_are_detected(tmp_path, lines):
    assert verify(tmp_path, [lines[1], lines[0], lines[2]]) != []
