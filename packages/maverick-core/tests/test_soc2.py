"""Tests for the SOC 2 evidence collector (``maverick.soc2``).

Hermetic: the autouse ``_isolate_maverick_home`` fixture in ``conftest.py``
points ``~/.maverick`` at a per-test temp dir, so these never touch a real
home or audit log. We monkeypatch the per-control ``enabled()`` predicates on
their *defining* modules (the collector imports them lazily by dotted path, so
patching the source attribute is what it sees).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import maverick.capability as capability
import maverick.crypto_at_rest as crypto_at_rest
import maverick.oidc as oidc
import maverick.paths as paths
import maverick.quotas as quotas
import pytest
from maverick import soc2


def test_returns_expected_shape():
    """The snapshot always carries the documented top-level + control keys."""
    ev = soc2.collect_soc2_evidence()
    assert isinstance(ev, dict)

    assert set(ev) >= {
        "version",
        "collected_at",
        "controls",
        "audit_log",
        "audit_signing_key",
    }
    assert isinstance(ev["version"], str)
    assert isinstance(ev["collected_at"], float)

    controls = ev["controls"]
    assert set(controls) == {
        "capability_enforcement",
        "tenant_isolation",
        "usage_quotas",
        "oidc_auth",
        "encryption_at_rest",
        "data_subject_export",
    }
    # Every control probe reports a status from the known vocabulary.
    known = {
        soc2.STATUS_ENABLED,
        soc2.STATUS_DISABLED,
        soc2.STATUS_ABSENT,
        soc2.STATUS_UNKNOWN,
    }
    for probe in controls.values():
        assert probe["status"] in known

    # The audit sub-probes are dicts with a status.
    assert isinstance(ev["audit_log"], dict)
    assert "status" in ev["audit_log"]
    assert isinstance(ev["audit_signing_key"], dict)
    assert "status" in ev["audit_signing_key"]


def test_is_json_serializable():
    """An auditor / CLI serializes this to JSON — it must round-trip."""
    import json

    ev = soc2.collect_soc2_evidence()
    assert json.loads(json.dumps(ev)) == ev


def test_toggle_on_is_reflected(monkeypatch):
    """Flipping each enabled() predicate ON flips the snapshot to ``enabled``."""
    monkeypatch.setattr(capability, "capability_enforced", lambda: True)
    monkeypatch.setattr(paths, "tenant_by_user_enabled", lambda: True)
    monkeypatch.setattr(quotas, "quotas_enforced", lambda: True)
    monkeypatch.setattr(oidc, "oidc_enabled_as_configured", lambda: True)
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: True)

    controls = soc2.collect_soc2_evidence()["controls"]
    assert controls["capability_enforcement"] == {
        "status": soc2.STATUS_ENABLED,
        "enabled": True,
    }
    assert controls["tenant_isolation"]["status"] == soc2.STATUS_ENABLED
    assert controls["tenant_isolation"]["enabled"] is True
    assert controls["usage_quotas"]["status"] == soc2.STATUS_ENABLED
    assert controls["usage_quotas"]["enabled"] is True
    assert controls["oidc_auth"]["status"] == soc2.STATUS_ENABLED
    assert controls["oidc_auth"]["enabled"] is True
    assert controls["encryption_at_rest"]["status"] == soc2.STATUS_ENABLED
    assert controls["encryption_at_rest"]["enabled"] is True


def test_toggle_off_is_reflected(monkeypatch):
    """Flipping each enabled() predicate OFF flips the snapshot to ``disabled``."""
    monkeypatch.setattr(capability, "capability_enforced", lambda: False)
    monkeypatch.setattr(paths, "tenant_by_user_enabled", lambda: False)
    monkeypatch.setattr(quotas, "quotas_enforced", lambda: False)
    monkeypatch.setattr(oidc, "oidc_enabled_as_configured", lambda: False)
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: False)

    controls = soc2.collect_soc2_evidence()["controls"]
    for cid in (
        "capability_enforcement",
        "tenant_isolation",
        "usage_quotas",
        "oidc_auth",
        "encryption_at_rest",
    ):
        assert controls[cid]["status"] == soc2.STATUS_DISABLED
        assert controls[cid]["enabled"] is False


def test_toggle_changes_snapshot(monkeypatch):
    """The same probe reports different statuses as the toggle moves on->off."""
    monkeypatch.setattr(capability, "capability_enforced", lambda: True)
    on = soc2.collect_soc2_evidence()["controls"]["capability_enforcement"]["status"]
    monkeypatch.setattr(capability, "capability_enforced", lambda: False)
    off = soc2.collect_soc2_evidence()["controls"]["capability_enforcement"]["status"]
    assert on == soc2.STATUS_ENABLED
    assert off == soc2.STATUS_DISABLED
    assert on != off


def test_oidc_probe_reflects_real_toggle_by_default():
    """``maverick.oidc`` ships and is off by default -> ``disabled`` (a real toggle,
    not ``absent``). Its presence is what makes OIDC an Implemented control."""
    probe = soc2.collect_soc2_evidence()["controls"]["oidc_auth"]
    assert probe["status"] == soc2.STATUS_DISABLED
    assert probe["enabled"] is False


def test_oidc_probe_is_unknown_when_configuration_is_unreadable(monkeypatch, tmp_path):
    """Unreadable configuration is evidence of nothing: not the fail-closed True."""
    cfg = tmp_path / "config.toml"
    cfg.write_text("[auth.oidc]\nenabled = [\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_OIDC_ENABLED", raising=False)
    probe = soc2.collect_soc2_evidence()["controls"]["oidc_auth"]
    assert probe["status"] == soc2.STATUS_UNKNOWN
    assert probe["enabled"] is None


def test_absent_optional_module_is_absent_not_crash():
    """A genuinely-missing optional module -> ``absent`` (and never raises).

    Exercised directly on ``_probe_toggle`` with a module name guaranteed not to
    exist, so the test stays true even as OIDC (which ships) toggles on/off.
    This is the path a future-only optional control would take.
    """
    probe = soc2._probe_toggle("maverick._definitely_not_a_real_module", "anything")
    assert probe["status"] == soc2.STATUS_ABSENT
    assert probe["enabled"] is None


def test_present_module_missing_attr_is_absent():
    """A shipped module without the expected predicate -> ``absent``, not a crash."""
    probe = soc2._probe_toggle("maverick.capability", "no_such_predicate_xyz")
    assert probe["status"] == soc2.STATUS_ABSENT
    assert probe["enabled"] is None


def test_failsoft_when_toggle_probe_raises(monkeypatch):
    """A predicate that throws -> that control is ``unknown``; dict still returns."""

    def boom():
        raise RuntimeError("config blew up")

    monkeypatch.setattr(capability, "capability_enforced", boom)

    ev = soc2.collect_soc2_evidence()
    assert isinstance(ev, dict)
    probe = ev["controls"]["capability_enforcement"]
    assert probe["status"] == soc2.STATUS_UNKNOWN
    assert probe["enabled"] is None
    assert "config blew up" in probe.get("error", "")
    # The blast radius is one control — the others still report normally.
    assert ev["controls"]["tenant_isolation"]["status"] in {
        soc2.STATUS_ENABLED,
        soc2.STATUS_DISABLED,
    }


def test_failsoft_when_toggle_probe_raises_base_exception(monkeypatch):
    """Even a ``BaseException`` (e.g. a native-crypto pyo3 panic) is contained.

    A half-installed crypto backend raises ``BaseException``, which ``except
    Exception`` would miss. The probe must still degrade to ``unknown``.
    """

    def panic():
        raise BaseException("native backend panic")  # noqa: TRY002

    monkeypatch.setattr(capability, "capability_enforced", panic)

    ev = soc2.collect_soc2_evidence()
    assert isinstance(ev, dict)
    assert ev["controls"]["capability_enforcement"]["status"] == soc2.STATUS_UNKNOWN


def test_encryption_at_rest_toggle_changes_snapshot(monkeypatch):
    """Encryption at rest is a real toggle: on -> ``enabled``, off -> ``disabled``.

    ``maverick.crypto_at_rest`` ships, so the control is never ``absent``; only
    its ``at_rest_enabled()`` predicate moves the status.
    """
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: True)
    on = soc2.collect_soc2_evidence()["controls"]["encryption_at_rest"]
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: False)
    off = soc2.collect_soc2_evidence()["controls"]["encryption_at_rest"]

    assert on == {"status": soc2.STATUS_ENABLED, "enabled": True}
    assert off == {"status": soc2.STATUS_DISABLED, "enabled": False}


def test_failsoft_when_encryption_probe_raises(monkeypatch):
    """An ``at_rest_enabled()`` that throws -> ``unknown``; the dict still returns
    and the blast radius is just this one control."""

    def boom():
        raise RuntimeError("crypto config blew up")

    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", boom)

    ev = soc2.collect_soc2_evidence()
    assert isinstance(ev, dict)
    probe = ev["controls"]["encryption_at_rest"]
    assert probe["status"] == soc2.STATUS_UNKNOWN
    assert probe["enabled"] is None
    assert "crypto config blew up" in probe.get("error", "")
    # data_subject_export (a sibling probe) is unaffected.
    assert ev["controls"]["data_subject_export"]["status"] == soc2.STATUS_ENABLED


def test_data_subject_export_present_is_enabled():
    """``maverick.dsar.export_subject_data`` ships -> ``data_subject_export`` is
    ``enabled``. It is a *presence* probe, so it never reports ``disabled``."""
    probe = soc2.collect_soc2_evidence()["controls"]["data_subject_export"]
    assert probe == {"status": soc2.STATUS_ENABLED, "enabled": True}


def test_probe_present_absent_when_module_missing():
    """The presence probe degrades to ``absent`` for a module/attr that does not
    exist, mirroring ``_probe_toggle``'s absent path (and never raising)."""
    assert soc2._probe_present(
        "maverick._definitely_not_a_real_module", "anything"
    ) == {"status": soc2.STATUS_ABSENT, "enabled": False}
    assert soc2._probe_present("maverick.dsar", "no_such_export_xyz") == {
        "status": soc2.STATUS_ABSENT,
        "enabled": False,
    }


def test_failsoft_when_audit_probe_raises(monkeypatch):
    """An exploding audit sub-probe is contained; snapshot still returns a dict."""

    def boom():
        raise RuntimeError("audit subsystem on fire")

    monkeypatch.setattr(soc2, "_probe_audit_chain", boom)
    monkeypatch.setattr(soc2, "_probe_signing_key", boom)

    ev = soc2.collect_soc2_evidence()
    assert isinstance(ev, dict)
    assert ev["audit_log"] == {"status": soc2.STATUS_UNKNOWN}
    assert ev["audit_signing_key"] == {"status": soc2.STATUS_UNKNOWN}


def test_audit_chain_empty_on_fresh_home():
    """With an isolated, empty home there are no day-files -> ``empty``."""
    probe = soc2.collect_soc2_evidence()["audit_log"]
    # Fresh isolated home: no audit written yet. Tolerate ``no_crypto`` in case
    # ``cryptography`` is absent in the matrix, but the common case is ``empty``.
    assert probe["status"] in {"empty", "no_crypto", soc2.STATUS_UNKNOWN}


def _write_one_event(*, sign: bool):
    """Write a single audit event to the isolated home via a fresh AuditLog.

    Uses an explicit ``AuditLog`` (not the process singleton, which caches its
    signing decision at construction) so each test controls signing in its own
    isolated home. Returns the resolved audit dir.
    """
    from maverick.audit import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    log = AuditLog(sign=sign)
    assert log.record(
        AuditEvent(ts=0.0, kind=EventKind.GOAL_START, payload={"title": "soc2 test"})
    )
    return log.audit_dir


def test_audit_chain_unsigned_when_signing_off(monkeypatch):
    """Day-files written with signing OFF report ``unsigned`` (not ``broken``).

    ``unsigned`` is a benign configuration state; conflating it with ``broken``
    would falsely alarm an auditor. Works whether or not crypto is installed.
    The deployment must be CONFIGURED signing-off, not just write unsigned
    rows: under the secure default signing is otherwise expected, and unsigned
    rows on a signing host are correctly treated as a strip attack.
    """
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    _write_one_event(sign=False)
    probe = soc2.collect_soc2_evidence()["audit_log"]
    # With crypto present the per-row "missing hash/sig" maps to ``unsigned``.
    # With crypto absent ``verify_chain`` short-circuits to ``no_crypto``. With a
    # *broken* native crypto backend (it panics), the probe is fail-soft
    # ``unknown``. The load-bearing assertion is that it is never ``broken`` —
    # signing-off must not be mistaken for tampering.
    assert probe["status"] in {"unsigned", "no_crypto", soc2.STATUS_UNKNOWN}
    assert probe["status"] != "broken"


def test_audit_chain_unsigned_completed_day_without_signing_is_not_broken(
    tmp_path, monkeypatch
):
    """A completed day-file with no anchor ledger is NOT tampering when the
    deployment never signs (no signing config, no signing key).

    The cross-file anchor ledger only exists for signed deployments, so an
    honestly-unsigned deployment legitimately has none. Reporting that as
    ``broken`` would falsely signal tampering on every unsigned deployment the
    day after its first audit file (and fail ``maverick compliance --strict``).
    A *signed* log whose ledger was stripped still reports ``broken`` -- that
    case keeps a signing key, so signing stays expected (see the stripped-log
    test below).
    """
    import json

    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    monkeypatch.setattr(soc2, "_audit_signing_expected", lambda: False)
    past_day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    (tmp_path / f"{past_day}.ndjson").write_text(
        json.dumps({"kind": "tool_call", "ts": "2026-01-01T00:00:00+00:00"})
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(soc2, "_resolve_audit_dir", lambda: tmp_path)

    probe = soc2.collect_soc2_evidence()["audit_log"]

    assert probe["status"] in {"unsigned", "no_crypto"}
    assert probe["status"] != "broken"
    assert probe["files_checked"] == 1
    assert probe["anchors_checked"] is True


def test_audit_chain_uses_anchor_verification(tmp_path, monkeypatch):
    """Anchor breaks must make the SOC 2 audit status broken."""
    import maverick.audit as audit

    class Break:
        reason = "anchored_file_deleted"
        detail = "2026-01-01.ndjson is anchored but missing"

    calls = {"anchors": 0}

    def fake_verify_anchors(audit_dir):
        assert audit_dir == tmp_path
        calls["anchors"] += 1
        return [Break()]

    monkeypatch.setattr(soc2, "_resolve_audit_dir", lambda: tmp_path)
    monkeypatch.setattr(audit, "verify_chain", lambda path: [])
    monkeypatch.setattr(audit, "verify_anchors", fake_verify_anchors)

    probe = soc2.collect_soc2_evidence()["audit_log"]
    assert calls["anchors"] == 1
    assert probe["status"] == "broken"
    assert probe["first_reason"] == "anchored_file_deleted"
    assert probe["files_checked"] == 0
    assert probe["anchors_checked"] is True


def _write_signed_past_day(audit_dir, monkeypatch, days_ago: int = 1, rows: int = 2):
    """Create and anchor a signed completed day-file for audit-integrity tests."""
    from maverick.audit import signing
    from maverick.audit.signing import AuditSigner, ensure_anchors

    try:
        crypto_ok = signing._have_crypto()
    except BaseException:  # noqa: BLE001 — broken native crypto backend panics
        crypto_ok = False
    if not crypto_ok:
        pytest.skip("cryptography unavailable; no signed anchor chain to verify")

    monkeypatch.setattr(signing, "KEY_DIR", audit_dir / "keys")
    day = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for i in range(rows):
        signer.write({"kind": "tool_call", "i": i})
    assert ensure_anchors(audit_dir) == 1
    return day


def test_audit_chain_broken_when_anchored_day_file_deleted(tmp_path, monkeypatch):
    """SOC 2 evidence must include anchor verification for whole-file deletion."""
    day = _write_signed_past_day(tmp_path, monkeypatch)
    monkeypatch.setattr(soc2, "_resolve_audit_dir", lambda: tmp_path)

    (tmp_path / f"{day}.ndjson").unlink()

    probe = soc2.collect_soc2_evidence()["audit_log"]
    assert probe["status"] == "broken"
    assert probe["first_reason"] == "anchored_file_deleted"
    assert probe["files_checked"] == 0
    assert probe["anchors_checked"] is True


def test_audit_chain_broken_when_anchor_ledger_deleted(tmp_path, monkeypatch):
    """A clean per-day chain is not enough if the anchor ledger is missing."""
    _write_signed_past_day(tmp_path, monkeypatch)
    monkeypatch.setattr(soc2, "_resolve_audit_dir", lambda: tmp_path)

    from maverick.audit import signing

    (tmp_path / signing.ANCHOR_FILENAME).unlink()

    probe = soc2.collect_soc2_evidence()["audit_log"]
    assert probe["status"] == "broken"
    assert probe["first_reason"] == "anchor_ledger_missing"
    assert probe["files_checked"] == 1
    assert probe["anchors_checked"] is True


def test_audit_chain_broken_when_signed_log_stripped_and_anchors_deleted(
    tmp_path, monkeypatch
):
    """Stripping signing fields must not downgrade a signed log to unsigned."""
    day = _write_signed_past_day(tmp_path, monkeypatch)
    monkeypatch.setattr(soc2, "_resolve_audit_dir", lambda: tmp_path)

    import json

    from maverick.audit import signing

    day_file = tmp_path / f"{day}.ndjson"
    stripped_rows = []
    for line in day_file.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        for field in ("hash", "sig", "key_id", "prev_hash"):
            row.pop(field, None)
        stripped_rows.append(json.dumps(row))
    day_file.write_text("\n".join(stripped_rows) + "\n", encoding="utf-8")
    (tmp_path / signing.ANCHOR_FILENAME).unlink()
    (tmp_path / signing.ANCHOR_MARKER_FILENAME).unlink()

    probe = soc2.collect_soc2_evidence()["audit_log"]

    assert probe["status"] == "broken"
    # Stripped signing fields on a signing-expected host are flagged as a strip/
    # downgrade attempt (the more specific row-level break), detected
    # before the anchor loop runs, so it is the reported first_reason.
    assert probe["first_reason"] == "missing_signature_fields"
    # status == "broken" short-circuits before the unsigned-row count is added,
    # so the key is intentionally absent on this path.
    assert probe["files_checked"] == 1
    assert probe["anchors_checked"] is True


def test_audit_chain_ok_after_a_signed_write():
    """After a real *signed* audit write, the chain verifies clean (``ok``).

    Skips when ``cryptography`` is unavailable — either genuinely absent (then
    the chain status is ``no_crypto``, not ``ok``) or a broken native install
    that panics on import (a ``BaseException``). This test asserts the happy
    ``ok`` path; the fail-soft / unsigned paths are covered above.
    """
    import pytest
    from maverick.audit import signing

    try:
        crypto_ok = signing._have_crypto()
    except BaseException:  # noqa: BLE001 — broken native crypto backend panics
        crypto_ok = False
    if not crypto_ok:
        pytest.skip("cryptography unavailable; no signed chain to verify")

    _write_one_event(sign=True)

    ev = soc2.collect_soc2_evidence()
    assert ev["audit_log"]["status"] == "ok"
    assert ev["audit_log"]["files_checked"] >= 1
    # A signed write implies the trust-anchor key was created.
    assert ev["audit_signing_key"]["status"] == soc2.STATUS_ENABLED
    assert ev["audit_signing_key"]["present"] is True


def test_signing_key_offhost_marker_is_not_current_signing_capability(monkeypatch):
    """Off-host (KMS) key custody leaves a ``.injected`` marker + ``.pub`` and NO
    local ``.key``. It remains a verification anchor, but a restarted process
    without reinjected private material must fail the signing-capability gate."""
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", raising=False)
    from maverick.audit import signing

    key_dir = signing._key_dir()
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "abc123.injected").write_text("")
    (key_dir / "abc123.pub").write_bytes(b"\x00" * 32)

    sk = soc2.collect_soc2_evidence()["audit_signing_key"]
    assert sk["status"] == soc2.STATUS_ABSENT
    assert sk["present"] is False
    assert sk["offhost_key"] is False
    assert sk["key_count"] == 0  # no local private .key on disk
    assert sk["historical_injected_key_count"] == 1
    assert sk["verification_anchor_present"] is True


def test_signing_key_offhost_env_counts_as_present(monkeypatch):
    """A KMS-sourced signing key injected via env counts as present even before a
    key file or marker exists on disk."""
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", "00" * 32)
    sk = soc2.collect_soc2_evidence()["audit_signing_key"]
    assert sk["status"] == soc2.STATUS_ENABLED
    assert sk["offhost_key"] is True
    assert sk["verification_anchor_present"] is True
    assert "MAVERICK_AUDIT_SIGNING_KEY" not in os.environ


def test_signing_key_malformed_env_is_configured_but_not_usable(monkeypatch):
    """A nonempty setting is not evidence that this process can sign."""
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", "not-an-ed25519-key")
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", raising=False)

    sk = soc2.collect_soc2_evidence()["audit_signing_key"]

    assert sk["status"] == soc2.STATUS_ABSENT
    assert sk["present"] is False
    assert sk["raw_key_configured"] is True
    assert sk["raw_key_usable"] is False
    assert sk["offhost_key"] is False
    assert "MAVERICK_AUDIT_SIGNING_KEY" not in os.environ


def test_signing_key_absent_when_no_anchor_anywhere(monkeypatch):
    """No local key, no marker, no env -> genuinely absent."""
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", raising=False)
    sk = soc2.collect_soc2_evidence()["audit_signing_key"]
    assert sk["status"] == soc2.STATUS_ABSENT
    assert sk["present"] is False
    assert sk["offhost_key"] is False
    assert sk["verification_anchor_present"] is False
