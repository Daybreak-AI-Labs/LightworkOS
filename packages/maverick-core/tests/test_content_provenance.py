"""Signed content-provenance manifests: bound to bytes, externally verified.

What matters: a manifest verifies only against an external key registry with
the exact content bytes, any tamper — body, receipt, content, or key — is a
refusal, and the feature fails closed when disabled.
"""
from __future__ import annotations

import pytest
from maverick import config
from maverick import content_provenance as prov

try:  # the audit signer needs the cryptography backend (same gate as test_oidc)
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
        "[content_provenance]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_disabled_fails_closed(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert prov.enabled() is False
    with pytest.raises(prov.ContentProvenanceConfigError, match="enable"):
        prov.create_manifest(b"x", asset_id="MAA-" + "a" * 32,
                             modality="text", actor="operator")


@requires_crypto
def test_manifest_signs_and_verifies_against_external_registry():
    content = b"An AI-generated summary paragraph."
    manifest = prov.create_manifest(
        content,
        asset_id="MAA-" + "a" * 32,
        modality="text",
        actor="publisher",
        receipt_id="AER-123",
    )
    assert manifest["schema"] == prov.MANIFEST_SCHEMA
    assert manifest["regulation"]["citation"] == "Art. 50(2)"
    attestation = manifest["attestation"]
    registry = {attestation["key_id"]: attestation["public_key"]}

    assert prov.verify_manifest(
        manifest, trusted_pubkeys=registry, content=content,
    ) is True
    # Without the content, structural + signature verification still holds.
    assert prov.verify_manifest(manifest, trusted_pubkeys=registry) is True


@requires_crypto
def test_any_tamper_is_a_refusal():
    content = b"original bytes"
    manifest = prov.create_manifest(
        content, asset_id="MAA-" + "a" * 32, modality="text", actor="publisher",
    )
    attestation = manifest["attestation"]
    registry = {attestation["key_id"]: attestation["public_key"]}

    # Different content bytes.
    assert prov.verify_manifest(
        manifest, trusted_pubkeys=registry, content=b"replaced bytes",
    ) is False
    # Tampered claim body.
    doctored = {**manifest, "asset_id": "MAA-" + "f" * 32}
    assert prov.verify_manifest(
        doctored, trusted_pubkeys=registry, content=content,
    ) is False
    # A receipt rebound to a different manifest digest.
    rebound = {
        **manifest,
        "attestation": {
            **attestation,
            "receipt": {**attestation["receipt"], "manifest_sha256": "0" * 64},
        },
    }
    assert prov.verify_manifest(
        rebound, trusted_pubkeys=registry, content=content,
    ) is False
    # An empty or wrong key registry.
    assert prov.verify_manifest(
        manifest, trusted_pubkeys={}, content=content,
    ) is False
    assert prov.verify_manifest(
        manifest, trusted_pubkeys=None, content=content,
    ) is False


@requires_crypto
def test_input_validation():
    with pytest.raises(ValueError, match="modality"):
        prov.create_manifest(
            b"x", asset_id="MAA-" + "a" * 32, modality="hologram",
            actor="publisher",
        )
    with pytest.raises(ValueError, match="content"):
        prov.create_manifest(
            b"", asset_id="MAA-" + "a" * 32, modality="text", actor="publisher",
        )
    with pytest.raises(ValueError, match="asset_id"):
        prov.create_manifest(b"x", asset_id="", modality="text", actor="publisher")
