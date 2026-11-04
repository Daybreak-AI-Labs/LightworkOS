"""Feature-scoped strict receipts retain the ordinary audit API's context.

Faults are injected only at named writer seams. Positive persistence cases use
the actual local signed writer, native tenant directories and chain verifier.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from maverick import audit, compliance_profiles
from maverick.audit import signing, writer
from maverick.audit.errors import AuditRefused
from maverick.audit.events import AuditEvent
from maverick.paths import data_dir, tenant_scope


def rows(path):
    return [json.loads(line) for file in path.glob("*.ndjson")
            for line in file.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.parametrize("required", [False, True])
def test_reserved_option_routes_same_event_without_entering_payload(monkeypatch, required):
    calls = []
    sink = SimpleNamespace(
        record=lambda event: calls.append(("ordinary", event)) or True,
        record_strict_signed=lambda event: calls.append(("strict", event)) or True,
    )
    monkeypatch.setattr(writer, "default_audit_log", lambda: sink)
    with audit.goal_context(71):
        assert audit.record("feature-receipt", agent="feature", _require_signed=required,
                            status="selected", opaque_digest="a" * 64) is True
    assert len(calls) == 1
    mode, event = calls[0]
    assert mode == ("strict" if required else "ordinary")
    assert isinstance(event, AuditEvent) and event.goal_id == 71 and event.agent == "feature"
    assert event.kind == "feature-receipt" and event.ts > 0
    assert event.payload == {"status": "selected", "opaque_digest": "a" * 64}


@pytest.mark.parametrize("invalid", [None, 0, 1, "true", [], {}])
def test_required_option_rejects_nonboolean_before_resolving_sink(monkeypatch, invalid):
    def unavailable():
        pytest.fail("invalid receipt mode must fail before touching the audit sink")

    monkeypatch.setattr(writer, "default_audit_log", unavailable)
    with pytest.raises(TypeError, match="_require_signed.*bool"):
        audit.record("feature-receipt", _require_signed=invalid)


def test_disabled_signing_is_not_enabled_by_required_receipt(tmp_path, monkeypatch):
    sink = writer.AuditLog(tmp_path / "disabled", sign=False)
    monkeypatch.setattr(writer, "_default", sink)
    with pytest.raises(AuditRefused, match="signing is disabled"):
        audit.record("feature-receipt", _require_signed=True)
    assert sink.signing_enabled is False and rows(sink.audit_dir) == []
    # Existing ordinary callers still follow the deployment's unsigned policy.
    assert audit.record("ordinary-event") is True
    assert len(rows(sink.audit_dir)) == 1 and "sig" not in rows(sink.audit_dir)[0]


@pytest.mark.parametrize("ack", [False, None, 1, "acknowledged"])
def test_module_shortcut_preserves_sink_acknowledgement_without_truthy_coercion(monkeypatch, ack):
    sink = SimpleNamespace(record_strict_signed=lambda event: ack)
    monkeypatch.setattr(writer, "default_audit_log", lambda: sink)
    assert audit.record("feature-receipt", _require_signed=True) is ack


@pytest.mark.parametrize("ack", [False, None, 0, 1, "acknowledged", True])
def test_strict_sink_accepts_only_literal_true_from_signer(tmp_path, monkeypatch, ack):
    sink = writer.AuditLog(tmp_path / "acknowledgement", sign=True)
    signer = SimpleNamespace(write=lambda *args, **kwargs: ack)
    monkeypatch.setattr(sink, "_signer_for", lambda path: signer)
    assert sink.record_strict_signed(AuditEvent(ts=1.0, kind="feature-receipt")) is (ack is True)


@pytest.mark.parametrize("failure", [OSError("write failed"), ValueError("invalid signature state")])
def test_strict_signer_write_failures_do_not_acknowledge(tmp_path, monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    sink = writer.AuditLog(tmp_path / "failed-write", sign=True)
    monkeypatch.setattr(sink, "_signer_for", lambda path: SimpleNamespace(write=fail))
    monkeypatch.setattr(writer, "_default", sink)
    assert audit.record("feature-receipt", _require_signed=True) is False
    assert rows(sink.audit_dir) == []


def test_public_required_path_refuses_missing_crypto_without_unsigned_row(tmp_path, monkeypatch):
    def missing_crypto(path):
        raise ImportError("test-only missing signing dependency")

    sink = writer.AuditLog(tmp_path / "missing-crypto", sign=True)
    monkeypatch.setattr(writer, "_default", sink)
    monkeypatch.setattr(signing, "AuditSigner", missing_crypto)
    monkeypatch.setattr(compliance_profiles, "requires_floor", lambda floor: False)
    with pytest.raises(AuditRefused, match="unsigned fallback"):
        audit.record("feature-receipt", _require_signed=True)
    assert rows(sink.audit_dir) == []


def test_public_required_path_preserves_custody_refusal(tmp_path, monkeypatch):
    refusal = signing.OffHostSigningRequiredError("test-only off-host custody refusal")

    def refuse(path):
        raise refusal

    sink = writer.AuditLog(tmp_path / "custody", sign=True)
    monkeypatch.setattr(writer, "_default", sink)
    monkeypatch.setattr(signing, "AuditSigner", refuse)
    with pytest.raises(signing.OffHostSigningRequiredError) as caught:
        audit.record("feature-receipt", _require_signed=True)
    assert caught.value is refusal and rows(sink.audit_dir) == []


def test_native_signed_rows_preserve_goal_fallback_override_and_reset(tmp_path, monkeypatch):
    sink = writer.AuditLog(tmp_path / "context", sign=True)
    monkeypatch.setattr(writer, "_default", sink)
    with audit.goal_context(42):
        assert audit.record("context-inherited", agent="feature", _require_signed=True) is True
        assert audit.record("context-explicit", goal_id=7, _require_signed=True) is True
    assert audit.record("context-reset", _require_signed=True) is True
    actual = rows(sink.audit_dir)
    assert [row["goal_id"] for row in actual] == [42, 7, None]
    assert all(row.get("sig") and "_require_signed" not in row for row in actual)
    assert all(signing.verify_chain(path) == [] for path in sink.audit_dir.glob("*.ndjson"))


def test_native_required_receipts_remain_in_separate_tenant_chains(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    paths = {}
    for tenant, goal in (("required-a", 11), ("required-b", 22)):
        with tenant_scope(tenant=tenant), audit.goal_context(goal):
            paths[tenant] = data_dir("audit")
            assert audit.record("tenant-feature", tenant_marker=tenant, _require_signed=True) is True
    assert paths["required-a"] != paths["required-b"]
    for tenant, goal in (("required-a", 11), ("required-b", 22)):
        with tenant_scope(tenant=tenant):
            actual = rows(paths[tenant])
            assert len(actual) == 1 and actual[0]["goal_id"] == goal
            assert actual[0]["tenant_marker"] == tenant and actual[0].get("sig")
            assert "_require_signed" not in actual[0]
            assert all(signing.verify_chain(path) == [] for path in paths[tenant].glob("*.ndjson"))
    assert rows(data_dir("audit", tenant=None)) == []


def test_public_required_path_refuses_tampered_existing_chain(tmp_path, monkeypatch):
    sink = writer.AuditLog(tmp_path / "tampered", sign=True)
    monkeypatch.setattr(writer, "_default", sink)
    assert audit.record("first", _require_signed=True) is True
    path = next(sink.audit_dir.glob("*.ndjson"))
    row = rows(sink.audit_dir)[0]
    row["sig"] = "0" * 128
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert signing.verify_chain(path)
    assert audit.record("second", _require_signed=True) is False
    assert len(rows(sink.audit_dir)) == 1
