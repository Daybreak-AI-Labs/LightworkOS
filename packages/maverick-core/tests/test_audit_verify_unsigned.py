"""`audit verify` on a default (unsigned) deployment must say *unsigned*, not
*malformed*.

Signing is opt-in (``[audit] sign`` / ``MAVERICK_AUDIT_SIGN``), so the default
audit log has rows with no hash/sig/key_id at all. ``verify_chain`` used to
classify every such row as ``malformed — missing hash/sig/key_id`` — the same
vocabulary as real tampering — so an out-of-the-box install could never tell
"signing was never on" from "someone stripped the signatures". The CLI also
spammed one line per row.

Contract pinned here:
  - a row with NONE of hash/sig/key_id  -> reason ``unsigned``
  - a row with SOME of them             -> still ``malformed`` (suspicious)
  - CLI: all-unsigned file -> one actionable UNVERIFIABLE line naming the
    [audit] sign knob, still exit 1 (automation must not pass unverifiable
    evidence as clean).
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from click.testing import CliRunner
from maverick.audit.signing import verify_chain


def _write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_fully_unsigned_rows_classified_unsigned(tmp_path):
    f = tmp_path / "2026-06-11.ndjson"
    _write_rows(f, [{"kind": "consent_prompt", "agent": "system"},
                    {"kind": "consent_result", "agent": "system"}])
    breaks = verify_chain(f)
    assert len(breaks) == 2
    assert all(b.reason == "unsigned" for b in breaks), breaks


def test_partially_signed_row_stays_malformed(tmp_path):
    f = tmp_path / "2026-06-11.ndjson"
    _write_rows(f, [{"kind": "x", "hash": "ab" * 32}])  # hash but no sig/key_id
    breaks = verify_chain(f)
    assert len(breaks) == 1
    assert breaks[0].reason == "malformed"


def test_cli_unsigned_day_is_one_actionable_line(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    audit_dir = tmp_path / ".maverick" / "audit"
    _write_rows(audit_dir / f"{day}.ndjson",
                [{"kind": "consent_prompt"}, {"kind": "consent_result"}])

    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "verify"])

    assert res.exit_code == 1  # unverifiable evidence must not pass as clean
    out = res.output
    assert "UNVERIFIABLE" in out
    assert "[audit] sign" in out
    # No per-row tamper vocabulary for the expected-unsigned case.
    assert "malformed" not in out


def test_pubkey_expectation_makes_fully_stripped_rows_malformed(tmp_path, monkeypatch):
    from maverick.audit import signing

    if not signing._have_crypto():
        import pytest
        pytest.skip("cryptography not installed")

    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    audit_dir = tmp_path / "audit"
    log = AuditLog(audit_dir, sign=True)
    assert log.record(AuditEvent(ts=1.0, kind="x", payload={})) is True

    day_file = next(audit_dir.glob("*.ndjson"))
    signed_row = json.loads(day_file.read_text(encoding="utf-8").splitlines()[0])
    pubkey_hex = (signing.KEY_DIR / f"{signed_row['key_id']}.pub").read_bytes().hex()
    for field in ("hash", "sig", "key_id", "prev_hash"):
        signed_row.pop(field, None)
    _write_rows(day_file, [signed_row])

    breaks = verify_chain(day_file, pubkey_hex=pubkey_hex)
    assert len(breaks) == 1
    assert breaks[0].reason == "malformed"
    assert "possible stripped" in breaks[0].detail


def test_leftover_prev_hash_makes_stripped_row_malformed(tmp_path):
    f = tmp_path / "2026-06-11.ndjson"
    _write_rows(f, [{"kind": "x", "prev_hash": "ab" * 32}])

    breaks = verify_chain(f)

    assert len(breaks) == 1
    assert breaks[0].reason == "malformed"
