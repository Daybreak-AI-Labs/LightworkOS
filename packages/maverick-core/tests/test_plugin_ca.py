"""Plugin signing CA: root -> publisher cert -> artifact chain, fail-closed."""
from __future__ import annotations

import pytest

cryptography = pytest.importorskip("cryptography")

from maverick.file_lock import private_path_is_restricted  # noqa: E402
from maverick.plugin_ca import (  # noqa: E402
    PluginCA,
    new_publisher_keypair,
    sign_artifact,
    verify_artifact,
)


@pytest.fixture
def ca(tmp_path):
    ca = PluginCA(tmp_path / "ca")
    ca.init_root()
    return ca


@pytest.fixture
def artifact(tmp_path):
    p = tmp_path / "plugin.py"
    p.write_text("def factory(): ...\n", encoding="utf-8")
    return p


def test_init_root_creates_keys_0600(tmp_path):
    ca = PluginCA(tmp_path / "ca")
    pub = ca.init_root()
    assert len(pub) == 64  # raw ed25519 pub, hex
    ca_dir = tmp_path / "ca"
    assert private_path_is_restricted(ca_dir, 0o700)
    assert private_path_is_restricted(ca_dir / "root.key", 0o600)
    assert private_path_is_restricted(ca_dir / "root.pub", 0o644)
    assert private_path_is_restricted(ca_dir / "revocations.json", 0o600)
    with pytest.raises(RuntimeError, match="already exists"):
        ca.init_root()


def test_full_chain_verifies(ca, artifact):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme-plugins", pub)
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub(),
                          revoked=ca.revoked_serials())
    assert res.ok and res.publisher == "acme-plugins"


def test_wrong_root_refused(ca, artifact, tmp_path):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub)
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    other = PluginCA(tmp_path / "other")
    other_pub = other.init_root()
    res = verify_artifact(artifact, bundle, root_pub=other_pub,
                          revoked=ca.revoked_serials())
    assert not res.ok and "not signed by the configured root" in res.reason


def test_tampered_artifact_refused(ca, artifact):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub)
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    artifact.write_text("def factory(): return 'evil'\n", encoding="utf-8")
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub(),
                          revoked=ca.revoked_serials())
    assert not res.ok and "digest mismatch" in res.reason


def test_signature_by_other_key_refused(ca, artifact):
    _priv_a, pub_a = new_publisher_keypair()
    priv_b, _pub_b = new_publisher_keypair()
    cert = ca.issue("acme", pub_a)
    # signed with B's key but cert binds A's pubkey
    bundle = sign_artifact(artifact, publisher_priv_hex=priv_b, cert=cert)
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub(),
                          revoked=ca.revoked_serials())
    assert not res.ok and "artifact signature invalid" in res.reason


def test_tampered_cert_refused(ca, artifact):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub)
    cert["publisher"] = "evil-corp"  # mutate after issuing
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub(),
                          revoked=ca.revoked_serials())
    assert not res.ok and "not signed by the configured root" in res.reason


def test_expired_cert_refused(ca, artifact):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub, days=1, now=1_000_000.0)
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub(),
                          now=1_000_000.0 + 2 * 86400)
    assert not res.ok and "expired" in res.reason


def test_revoked_cert_refused(ca, artifact):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub)
    ca.revoke(cert["serial"], reason="key leaked")
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub(),
                          revoked=ca.revoked_serials())
    assert not res.ok and "revoked" in res.reason


def test_crl_signature_required(ca, tmp_path):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub)
    ca.revoke(cert["serial"])
    # tamper with the CRL -> its signature no longer verifies -> fail closed
    crl_path = tmp_path / "ca" / "revocations.json"
    import json
    crl = json.loads(crl_path.read_text())
    crl["revoked"]["bogus-serial"] = {"at": 0, "reason": "forged"}
    crl_path.write_text(json.dumps(crl))
    with pytest.raises(RuntimeError, match="CRL signature invalid"):
        ca.revoked_serials()


def test_missing_revocation_data_fails_closed(ca, artifact):
    priv, pub = new_publisher_keypair()
    cert = ca.issue("acme", pub)
    bundle = sign_artifact(artifact, publisher_priv_hex=priv, cert=cert)
    res = verify_artifact(artifact, bundle, root_pub=ca.root_pub())
    assert not res.ok and "revocation data required" in res.reason


def test_missing_cert_fields_fail_closed(ca, artifact):
    res = verify_artifact(artifact, {"digest": "x", "sig": "y", "cert": {}},
                          root_pub=ca.root_pub(), revoked=ca.revoked_serials())
    assert not res.ok and "cert missing" in res.reason


def test_issue_requires_publisher(ca):
    _priv, pub = new_publisher_keypair()
    with pytest.raises(ValueError):
        ca.issue("   ", pub)
