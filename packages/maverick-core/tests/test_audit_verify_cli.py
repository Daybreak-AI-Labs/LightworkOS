"""`maverick audit verify` CLI: tamper-evidence gate for CI / SOC 2.

The command walks the Ed25519 hash-chain of the audit day-file(s) plus the
cross-file tip-ledger and exits 1 on any break, 0 when clean. These tests drive
it via Click's ``CliRunner`` with a HOME-isolated audit dir so the writer, the
signing keys, and the verifier all resolve to the same throwaway location.

When ``cryptography`` is unavailable the chain can't be checked at all, so the
command must report that state as a verification break and exit 1; automation
should not pass unverifiable evidence as clean. That path is asserted
unconditionally; the signed-chain tests skip without crypto.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner
from maverick.cli import main

_HAVE_CRYPTO = True
try:  # match the kernel's fail-soft crypto convention
    import cryptography  # noqa: F401
except ImportError:  # pragma: no cover - exercised only on crypto-less envs
    _HAVE_CRYPTO = False


def _isolate_home(monkeypatch, tmp_path):
    """Point HOME at a tmp dir so the audit dir + signing keys are throwaway.

    The command resolves the audit dir via ``paths.data_dir("audit")`` and the
    verifier resolves keys via ``signing._key_dir()`` -> ``data_dir``; both call
    ``Path.home()`` at call time, so a patched HOME redirects all of them to the
    same isolated tree. ``signing.KEY_DIR`` is reset to its legacy sentinel so
    the tenant-aware ``_key_dir()`` branch (the one that follows HOME) is used.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows parity
    from maverick.audit import signing

    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick import paths

    return paths.data_dir("audit")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _write_signed_events(audit_dir, n=3):
    """Write ``n`` real signed + chained events into today's day-file."""
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    log = AuditLog(audit_dir, sign=True)
    for i in range(n):
        ok = log.record(AuditEvent(ts=time.time(), kind="tool_call", payload={"i": i}))
        assert ok, "signed audit write should succeed"
    return audit_dir / f"{_today()}.ndjson"


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_verify_clean_chain_exits_zero(tmp_path, monkeypatch):
    audit_dir = _isolate_home(monkeypatch, tmp_path)
    day_file = _write_signed_events(audit_dir, n=3)
    assert day_file.exists()

    result = CliRunner().invoke(main, ["audit", "verify"])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_verify_detects_tampered_line_exits_one(tmp_path, monkeypatch):
    audit_dir = _isolate_home(monkeypatch, tmp_path)
    day_file = _write_signed_events(audit_dir, n=3)

    # Corrupt one line on disk: flip a character inside the signed payload so the
    # row's content no longer matches its recorded hash/signature.
    lines = day_file.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"i": 1', '"i": 99', 1)
    assert lines[1] != "", "expected a non-empty second row to corrupt"
    day_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = CliRunner().invoke(main, ["audit", "verify"])
    assert result.exit_code == 1, result.output
    assert "FAIL" in result.output



@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_verify_detects_deleted_unanchored_day_file(tmp_path, monkeypatch):
    audit_dir = _isolate_home(monkeypatch, tmp_path)
    day_file = _write_signed_events(audit_dir, n=1)
    day_file.unlink()

    result = CliRunner().invoke(main, ["audit", "verify", "--day", _today()])
    assert result.exit_code == 1, result.output
    assert "missing_file" in result.output

@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_verify_all_sweeps_every_day_file(tmp_path, monkeypatch):
    audit_dir = _isolate_home(monkeypatch, tmp_path)
    # Today's file (real write path) plus a hand-rolled corrupt older day-file.
    _write_signed_events(audit_dir, n=2)
    bad_day = audit_dir / "2020-01-01.ndjson"
    bad_day.write_text('{"kind": "tool_call", "not": "signed"}\n', encoding="utf-8")

    result = CliRunner().invoke(main, ["audit", "verify", "--all"])
    assert result.exit_code == 1, result.output
    # The corrupt older file is reported by name; the swept set includes it.
    assert "2020-01-01.ndjson" in result.output


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_verify_explicit_file(tmp_path, monkeypatch):
    audit_dir = _isolate_home(monkeypatch, tmp_path)
    day_file = _write_signed_events(audit_dir, n=2)

    result = CliRunner().invoke(main, ["audit", "verify", "--file", str(day_file)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_verify_reports_no_crypto_state_and_exits_one(tmp_path, monkeypatch):
    """With crypto unavailable the verification gate must fail closed.

    Forced unconditionally by patching ``signing._have_crypto`` to False so the
    lower-level verifier reports ``no_crypto`` even in an env that *does* have
    ``cryptography``.
    """
    _isolate_home(monkeypatch, tmp_path)
    from maverick.audit import signing

    monkeypatch.setattr(signing, "_have_crypto", lambda: False)

    result = CliRunner().invoke(main, ["audit", "verify"])
    assert result.exit_code == 1, result.output
    assert "no_crypto" in result.output
    assert "cryptography not installed" in result.output
