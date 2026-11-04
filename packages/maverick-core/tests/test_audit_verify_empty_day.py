"""`audit verify` on a day with no events is CLEAN, not a missing_file FAIL.

A regulated client enabled [audit] sign,
ran a benign goal (which records no security events -- the audit log is a
security-event log, the execution trace lives in the world model), then ran
`maverick audit verify` as a routine check. With no day-file for today it
reported a scary "FAIL: 1 issue(s) ... line 0: missing_file" while the
cross-file tip-ledger simultaneously said "intact" -- contradictory and
alarming. An absent day-file that no anchor claims existed is the empty/clean
state, not tampering; verify_anchors remains the authority on a suspicious
absence (it FAILs when an anchor references a now-missing file).
"""
from __future__ import annotations

from click.testing import CliRunner


def _run(tmp_path, monkeypatch, args):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.cli import main
    return CliRunner().invoke(main, ["audit", "verify", *args])


def test_empty_audit_log_verifies_clean(tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, [])
    assert res.exit_code == 0, res.output
    assert "missing_file" not in res.output
    assert "FAIL" not in res.output
    assert "no audit entries" in res.output.lower()


def test_explicit_missing_file_still_fails(tmp_path, monkeypatch):
    # Naming a specific file that isn't there is a real error, unchanged.
    missing = tmp_path / "2020-01-01.ndjson"
    res = _run(tmp_path, monkeypatch, ["--file", str(missing)])
    assert res.exit_code == 1, res.output


def test_missing_day_with_audit_artifacts_still_fails(tmp_path, monkeypatch):
    from maverick import audit
    from maverick.audit import signing

    monkeypatch.setattr(signing, "_have_crypto", lambda: True)
    monkeypatch.setattr(
        audit,
        "verify_chain",
        lambda path, **_kwargs: [signing.ChainBreak(0, "missing_file", str(path))],
    )
    monkeypatch.setattr(audit, "verify_anchors", lambda *_args, **_kwargs: [])
    audit_dir = tmp_path / ".maverick" / "audit"
    (audit_dir / "keys").mkdir(parents=True)

    res = _run(tmp_path, monkeypatch, ["--day", "2026-01-02"])
    assert res.exit_code == 1, res.output
    assert "missing_file" in res.output
