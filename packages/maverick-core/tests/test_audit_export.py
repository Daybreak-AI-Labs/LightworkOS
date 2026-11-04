"""SIEM-friendly audit-log export: `maverick audit export` + helpers.

HOME-isolated so tests read/write a throwaway ``~/.maverick``. Events are
written with the real writer API (``AuditLog`` / ``AuditEvent``) so the
on-disk NDJSON shape is authentic.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner
from maverick.audit.events import AuditEvent, EventKind
from maverick.audit.export import iter_audit_events, to_cef, to_jsonl
from maverick.audit.writer import AuditLog
from maverick.file_lock import private_path_is_restricted


def test_cef_header_escapes_pipe_in_kind():
    # CEF header fields are '|'-delimited (extension values are not). A '|' in a
    # header field (e.g. a future/plugin-supplied kind) must be escaped so it
    # can't shift the header columns and corrupt the record.
    line = to_cef({"kind": "policy|halt", "agent": "x"})
    assert line.startswith("CEF:0|Lightwork|maverick-agent|")
    # both kind header slots carry the escaped form, not a raw delimiter
    assert "policy\\|halt|policy\\|halt|" in line


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _write_today(audit_dir, **payload) -> None:
    """Append one authentic event to today's day-file via the real writer."""
    log = AuditLog(audit_dir)
    ev = AuditEvent(
        ts=1_000_000.0,
        kind=payload.pop("kind", EventKind.TOOL_CALL),
        agent="system",
        goal_id=1,
        payload=payload,
    )
    assert log.record(ev)


def _write_day(audit_dir, day: str, **payload) -> None:
    """Place one authentic event in a specific day-file.

    Uses the same serialization the writer uses (``AuditEvent.to_dict`` ->
    ``json.dumps``) so the on-disk shape matches, while pinning the day-file
    name (the writer always names by *now*).
    """
    audit_dir.mkdir(parents=True, exist_ok=True)
    ev = AuditEvent(
        ts=1_000_000.0,
        kind=payload.pop("kind", EventKind.TOOL_CALL),
        agent="system",
        goal_id=1,
        payload=payload,
    )
    line = json.dumps(ev.to_dict(), default=str) + "\n"
    with open(audit_dir / f"{day}.ndjson", "a", encoding="utf-8") as f:
        f.write(line)


# --- helpers ----------------------------------------------------------------

def test_to_jsonl_roundtrips():
    ev = {"v": 1, "kind": "tool_call", "name": "read_file", "goal_id": 1}
    line = to_jsonl(ev)
    assert "\n" not in line
    assert json.loads(line) == ev


def test_to_cef_header_and_extensions():
    ev = {"v": 1, "kind": "tool_call", "agent": "system", "name": "read_file"}
    cef = to_cef(ev)
    assert cef.startswith("CEF:0|Lightwork|maverick-agent|")
    assert "|tool_call|tool_call|" in cef
    assert "name=read_file" in cef
    assert "kind=tool_call" in cef


def test_to_cef_escapes_special_chars():
    ev = {"kind": "tool_call", "blob": "a=b\\c\nd"}
    cef = to_cef(ev)
    assert "blob=a\\=b\\\\c\\nd" in cef
    assert "\n" not in cef


def test_to_cef_severity_bumps_for_denial():
    low = to_cef({"kind": "tool_call"})
    high = to_cef({"kind": "shield_block"})
    # default low severity vs bumped denial severity
    assert low.split("|")[6] == "2"
    assert int(high.split("|")[6]) > 2


def test_to_cef_skips_nonscalar_fields():
    ev = {"kind": "tool_call", "name": "x", "nested": {"a": 1}, "items": [1, 2]}
    cef = to_cef(ev)
    assert "name=x" in cef
    assert "nested=" not in cef
    assert "items=" not in cef


# --- iter_audit_events ------------------------------------------------------

def test_iter_missing_dir_is_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    assert list(iter_audit_events()) == []


def test_iter_reads_today(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="read_file", input_summary="x")

    events = list(iter_audit_events())
    assert len(events) == 1
    assert events[0]["kind"] == "tool_call"
    assert events[0]["name"] == "read_file"


def test_iter_all_spans_two_day_files_and_skips_anchors(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="today_tool")
    _write_day(audit_dir, "2020-01-01", name="old_tool")
    # An anchors.ndjson tip-ledger must be excluded by --all (matches verify).
    (audit_dir / "anchors.ndjson").write_text('{"anchor": true}\n', encoding="utf-8")

    names = {e.get("name") for e in iter_audit_events(all_days=True)}
    assert "today_tool" in names
    assert "old_tool" in names
    assert all(e.get("kind") != "anchor" for e in iter_audit_events(all_days=True))


def test_iter_streams_file_lines_without_reading_whole_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_day(audit_dir, "2020-01-01", name="streamed_tool")

    def fail_read_text(self, *args, **kwargs):
        raise AssertionError("iter_audit_events must stream instead of read_text()")

    monkeypatch.setattr(Path, "read_text", fail_read_text)
    names = {e.get("name") for e in iter_audit_events(day="2020-01-01")}
    assert names == {"streamed_tool"}


def test_iter_day_selects_one_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="today_tool")
    _write_day(audit_dir, "2020-01-01", name="old_tool")

    names = {e.get("name") for e in iter_audit_events(day="2020-01-01")}
    assert names == {"old_tool"}


def test_iter_tenant_reads_tenant_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tenant_dir = tmp_path / ".maverick" / "tenants" / "acme" / "audit"
    _write_today(tenant_dir, name="tenant_tool")
    # Nothing in the legacy dir, so a tenant hit proves tenant resolution.
    legacy_dir = tmp_path / ".maverick" / "audit"
    _write_today(legacy_dir, name="legacy_tool")

    names = {e.get("name") for e in iter_audit_events(tenant="acme")}
    assert names == {"tenant_tool"}


# --- CLI: maverick audit export --------------------------------------------

def test_cli_registers_export():
    from maverick.cli import main
    assert "export" in main.commands["audit"].commands


def test_cli_export_json_roundtrips(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="read_file", input_summary="hello")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export"])
    assert res.exit_code == 0, res.output
    rows = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["name"] == "read_file"
    assert rows[0]["kind"] == "tool_call"


def test_cli_export_cef(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="read_file")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "--format", "cef"])
    assert res.exit_code == 0, res.output
    line = res.output.strip().splitlines()[0]
    assert line.startswith("CEF:0|Lightwork|maverick-agent|")
    assert "name=read_file" in line


def test_cli_export_all_spans_two_days(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="today_tool")
    _write_day(audit_dir, "2020-01-01", name="old_tool")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "--all"])
    assert res.exit_code == 0, res.output
    names = {json.loads(line)["name"]
             for line in res.output.splitlines() if line.strip()}
    assert names == {"today_tool", "old_tool"}


def test_cli_export_active_tenant_denied_without_entitlement(monkeypatch, tmp_path):
    from maverick.cli import main
    from maverick.tenant.registry import create_tenant

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    # Provision the namespace before writing retained data, as a real tenant does.
    create_tenant("freeco", plan="free")
    monkeypatch.setenv("MAVERICK_TENANT", "freeco")
    tenant_dir = tmp_path / ".maverick" / "tenants" / "freeco" / "audit"
    _write_today(tenant_dir, name="tenant_tool")

    res = CliRunner().invoke(main, ["audit", "export"])
    assert res.exit_code == 2
    assert "tenant 'freeco' plan does not include SIEM audit export" in res.output
    assert "tenant_tool" not in res.output


def test_cli_export_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tenant_dir = tmp_path / ".maverick" / "tenants" / "acme" / "audit"
    _write_today(tenant_dir, name="tenant_tool")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "--tenant", "acme"])
    assert res.exit_code == 0, res.output
    rows = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert [r["name"] for r in rows] == ["tenant_tool"]


def test_cli_export_output_file_is_0600(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="read_file")

    out = tmp_path / "export.jsonl"
    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert out.exists()
    assert private_path_is_restricted(out, 0o600)
    rows = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert rows[0]["name"] == "read_file"


def test_cli_export_rejects_output_over_selected_day_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_today(audit_dir, name="read_file")
    day_file = audit_dir / f"{_today()}.ndjson"
    before = day_file.read_text(encoding="utf-8")

    from maverick.cli import main
    res = CliRunner().invoke(
        main, ["audit", "export", "--day", _today(), "-o", str(day_file)]
    )
    assert res.exit_code != 0
    assert "refusing to write audit export over a source audit log file" in res.output
    assert day_file.read_text(encoding="utf-8") == before


def test_cli_export_all_rejects_output_over_included_day_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_day(audit_dir, "2020-01-01", name="old_tool")
    _write_today(audit_dir, name="today_tool")
    old_file = audit_dir / "2020-01-01.ndjson"
    before = old_file.read_text(encoding="utf-8")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "--all", "-o", str(old_file)])
    assert res.exit_code != 0
    assert "refusing to write audit export over a source audit log file" in res.output
    assert old_file.read_text(encoding="utf-8") == before


def test_cli_export_empty_log_exits_zero(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export"])
    assert res.exit_code == 0, res.output


# --- since/until date window ------------------------------------------------

def test_iter_since_until_window(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_day(audit_dir, "2020-01-01", name="jan")
    _write_day(audit_dir, "2020-06-15", name="jun")
    _write_day(audit_dir, "2020-12-31", name="dec")

    names = {e.get("name")
             for e in iter_audit_events(since="2020-06-01", until="2020-07-01")}
    assert names == {"jun"}


def test_iter_since_is_inclusive_and_open_ended(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_day(audit_dir, "2020-01-01", name="jan")
    _write_day(audit_dir, "2020-06-15", name="jun")

    # since only -> everything on/after that date (inclusive).
    names = {e.get("name") for e in iter_audit_events(since="2020-06-15")}
    assert names == {"jun"}


def test_cli_export_since_until(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_day(audit_dir, "2020-01-01", name="jan")
    _write_day(audit_dir, "2020-06-15", name="jun")
    _write_day(audit_dir, "2020-12-31", name="dec")

    from maverick.cli import main
    res = CliRunner().invoke(
        main, ["audit", "export", "--since", "2020-06-01", "--until", "2020-07-01"]
    )
    assert res.exit_code == 0, res.output
    names = {json.loads(line)["name"]
             for line in res.output.splitlines() if line.strip()}
    assert names == {"jun"}


def test_cli_export_rejects_bad_date(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "--since", "nope"])
    assert res.exit_code == 2
    assert "YYYY-MM-DD" in res.output


def test_cli_export_rejects_unpadded_window_date(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "export", "--since", "2020-1-1"])
    assert res.exit_code == 2
    assert "YYYY-MM-DD" in res.output
