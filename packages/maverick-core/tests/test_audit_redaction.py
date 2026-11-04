"""Audit log redaction — secrets in payloads never land on disk in plaintext."""
from __future__ import annotations

import json
from pathlib import Path


def _read_first(path: Path) -> dict:
    return json.loads(path.read_text().splitlines()[0])


def test_anthropic_key_redacted(tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=1.0, kind=EventKind.TOOL_RESULT,
        payload={"name": "shell",
                 "output_summary": "leaked: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
    ))
    files = list(tmp_path.glob("*.ndjson"))
    assert len(files) == 1
    row = _read_first(files[0])
    assert "sk-ant-api03-AAAAAA" not in json.dumps(row)
    assert "[REDACTED" in row["output_summary"]


def test_openai_key_redacted(tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=2.0, kind=EventKind.TOOL_RESULT,
        payload={"name": "shell",
                 "output_summary": "key: sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
    ))
    row = _read_first(list(tmp_path.glob("*.ndjson"))[0])
    body = json.dumps(row)
    assert "sk-proj-AAA" not in body
    assert "[REDACTED" in row["output_summary"]


def test_redaction_walks_nested_lists_and_dicts(tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=3.0, kind=EventKind.TOOL_RESULT,
        payload={
            "name": "shell",
            "nested": {
                "deeper": ["one", "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            },
        },
    ))
    row = _read_first(list(tmp_path.glob("*.ndjson"))[0])
    body = json.dumps(row)
    assert "ghp_AAA" not in body


def test_redaction_no_secrets_passes_through_unchanged(tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=4.0, kind=EventKind.TOOL_RESULT,
        payload={"name": "shell", "output_summary": "ls /tmp -- nothing of interest"},
    ))
    row = _read_first(list(tmp_path.glob("*.ndjson"))[0])
    assert row["output_summary"] == "ls /tmp -- nothing of interest"
    assert row["name"] == "shell"


def test_anonymous_mode_anonymizes_audit_payload(monkeypatch, tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    monkeypatch.setenv("MAVERICK_ANON", "1")
    home_path = str(Path.home() / "case_notes.txt")

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=5.0,
        kind=EventKind.GOAL_START,
        goal_id=123,
        payload={
            "title": "Jane Patient diabetes plan",
            "description": "Call jane.patient@example.com at 415-555-1212",
            "channel": "slack-C123",
            "user_id": "user-123",
            "path": home_path,
            "nested": {"email": "jane.patient@example.com"},
        },
    ))

    row = _read_first(list(tmp_path.glob("*.ndjson"))[0])
    body = json.dumps(row)
    assert "Jane Patient" not in body
    assert "jane.patient@example.com" not in body
    assert "415-555-1212" not in body
    assert "slack-C123" not in body
    assert "user-123" not in body
    assert home_path not in body
    assert row["goal_id"].startswith("goal_id#")
    assert row["channel"].startswith("channel#")
    assert row["path"] == "case_notes.txt"


def test_anonymous_mode_hashes_principal_bearing_audit_fields(monkeypatch, tmp_path: Path):
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    monkeypatch.setenv("MAVERICK_ANON", "1")

    al = AuditLog(audit_dir=tmp_path)
    al.record(AuditEvent(
        ts=6.0,
        kind=EventKind.APPROVAL_DECISION,
        payload={
            "approval_id": 123,
            "status": "approved",
            "decided_by": "user:alice@example.com",
            "principal": "user:bob@example.com",
            "claimed_by": "user:carol@example.com",
            "created_by": "user:dana@example.com",
        },
    ))

    row = _read_first(list(tmp_path.glob("*.ndjson"))[0])
    body = json.dumps(row)
    assert "alice@example.com" not in body
    assert "bob@example.com" not in body
    assert "carol@example.com" not in body
    assert "dana@example.com" not in body
    assert row["decided_by"].startswith("decided_by#")
    assert row["principal"].startswith("principal#")
    assert row["claimed_by"].startswith("claimed_by#")
    assert row["created_by"].startswith("created_by#")
    assert row["approval_id"] == 123
    assert row["status"] == "approved"
