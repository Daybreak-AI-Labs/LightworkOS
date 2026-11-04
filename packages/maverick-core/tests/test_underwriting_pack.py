"""The underwriting evidence pack: derived summary bound to the signed pack.

What matters: the pack requires enabled model-risk assurance, the summary's
digest binds it, the embedded assurance pack still verifies externally, and
absent modules degrade to ``enabled: false`` sections rather than errors.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from maverick import config
from maverick import model_risk_assurance as mra
from maverick import underwriting_pack as uwp

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _probe = ed25519.Ed25519PrivateKey.generate()
    _CRYPTO_OK = True
except Exception:  # pragma: no cover - environment-dependent
    _CRYPTO_OK = False

requires_crypto = pytest.mark.skipif(
    not _CRYPTO_OK, reason="cryptography backend unavailable",
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_pack_requires_model_risk_assurance(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    with pytest.raises(uwp.UnderwritingPackError, match="model-risk"):
        uwp.export_underwriting_pack(actor="broker-liaison")


@requires_crypto
def test_pack_summarizes_and_stays_externally_verifiable():
    officer = mra.ModelRiskAssuranceOfficer()
    now = time.time()
    observation = officer.observe_asset(
        asset_type="model",
        source="uw_test",
        source_id="credit-scorer",
        display_name="Credit scorer",
        version_digest=hashlib.sha256(b"credit-v1").hexdigest(),
        actor="inventory-operator",
        observed_at=now,
        metadata={},
        dependencies=[],
    )
    officer.record_evidence(
        observation["asset_id"],
        source_id="card-1",
        evidence_kind="model_card",
        result="passed",
        scope_digest=hashlib.sha256(b"scope").hexdigest(),
        artifact_digest=observation["version_digest"],
        actor="model-validator",
        observed_at=now,
        valid_until=now + 86_400,
        summary="Model card recorded.",
        metrics={},
    )

    pack = uwp.export_underwriting_pack(actor="broker-liaison")
    summary = pack["summary"]
    assert pack["schema"] == uwp.PACK_SCHEMA
    assert summary["inventory_count"] == 1
    assert summary["evidence_by_kind"]["model_card"]["passed"] == 1
    assert summary["eu_conformity"] == {"enabled": False}
    # Incident posture now reports both reporting registers with a notice,
    # even when neither is enabled (73fc1e4d).
    incidents = summary["serious_incidents"]
    assert incidents["enabled"] is False
    assert incidents["declarations"] == 0 and incidents["overdue"] == 0
    assert incidents["notice"]
    assert summary["ai_literacy"] == {"enabled": False}
    assert summary["assurance_pack_sha256"] == pack["assurance_pack"]["pack_sha256"]

    digest = hashlib.sha256(
        json.dumps(summary, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    assert pack["summary_sha256"] == digest

    inner = pack["assurance_pack"]
    attestation = inner["attestation"]
    registry = {attestation["key_id"]: attestation["public_key"]}
    assert mra.verify_assurance_pack(inner, trusted_pubkeys=registry) is True
    assert summary["notice"] == uwp.NON_CERTIFICATION_NOTICE
