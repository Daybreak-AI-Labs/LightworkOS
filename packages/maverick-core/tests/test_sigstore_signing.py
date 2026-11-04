"""Sigstore keyless signing: injected signer/verifier seams, fail-closed verify."""
from __future__ import annotations

import sys

import pytest
from maverick import sigstore_signing
from maverick.sigstore_signing import (
    SigstoreUnavailable,
    bundle_path_for,
    sign_artifact,
    verify_artifact,
)

IDENTITY = "dev@example.com"
ISSUER = "https://github.com/login/oauth"


@pytest.fixture
def artifact(tmp_path):
    p = tmp_path / "skill.md"
    p.write_bytes(b"---\nname: demo\n---\nbody\n")
    return p


@pytest.fixture
def no_sigstore(monkeypatch):
    """Force `import sigstore` to fail even if the extra is installed."""
    monkeypatch.setitem(sys.modules, "sigstore", None)


def _ok_verifier(calls):
    def verifier(data, bundle_json, identity, issuer):
        calls.append((data, bundle_json, identity, issuer))
    return verifier


# ---- signing ---------------------------------------------------------------

def test_bundle_path_is_sibling_sigstore_json(artifact):
    assert bundle_path_for(artifact).name == "skill.md.sigstore.json"
    assert bundle_path_for(artifact).parent == artifact.parent


def test_sign_writes_bundle_via_injected_signer(artifact):
    seen = []

    def fake_signer(data: bytes) -> str:
        seen.append(data)
        return '{"bundle": "fake"}'

    out = sign_artifact(artifact, signer=fake_signer)
    assert out == bundle_path_for(artifact)
    assert out.read_text(encoding="utf-8") == '{"bundle": "fake"}'
    assert seen == [artifact.read_bytes()]


def test_sign_missing_artifact_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        sign_artifact(tmp_path / "nope.bin", signer=lambda d: "x")


def test_sign_rejects_empty_bundle_from_signer(artifact):
    with pytest.raises(ValueError, match="empty bundle"):
        sign_artifact(artifact, signer=lambda d: "   ")
    assert not bundle_path_for(artifact).exists()


def test_sign_without_sigstore_extra_is_informative(artifact, no_sigstore):
    with pytest.raises(SigstoreUnavailable, match=r"packages/maverick-core\[sigstore\]"):
        sign_artifact(artifact)


# ---- verification (fails CLOSED) -------------------------------------------

def test_verify_ok_with_injected_verifier(artifact):
    calls = []
    sign_artifact(artifact, signer=lambda d: '{"b": 1}')
    result = verify_artifact(
        artifact, None, identity=IDENTITY, issuer=ISSUER, verifier=_ok_verifier(calls),
    )
    assert result.ok and result.reason == "verified"
    # the verifier saw the artifact bytes, the bundle text, and the pinned pair
    assert calls == [(artifact.read_bytes(), '{"b": 1}', IDENTITY, ISSUER)]


def test_verify_uses_explicit_bundle_path(artifact, tmp_path):
    other = tmp_path / "elsewhere.json"
    other.write_text('{"b": 2}', encoding="utf-8")
    calls = []
    result = verify_artifact(
        artifact, other, identity=IDENTITY, issuer=ISSUER, verifier=_ok_verifier(calls),
    )
    assert result.ok
    assert calls[0][1] == '{"b": 2}'


def test_verify_missing_bundle_refused_without_calling_verifier(artifact):
    calls = []
    result = verify_artifact(
        artifact, None, identity=IDENTITY, issuer=ISSUER, verifier=_ok_verifier(calls),
    )
    assert not result.ok
    assert "bundle not found" in result.reason
    assert calls == []


def test_verify_missing_artifact_refused(tmp_path):
    bundle = tmp_path / "b.json"
    bundle.write_text("{}", encoding="utf-8")
    result = verify_artifact(
        tmp_path / "gone.bin", bundle, identity=IDENTITY, issuer=ISSUER,
        verifier=_ok_verifier([]),
    )
    assert not result.ok and "artifact not found" in result.reason


def test_verify_empty_identity_or_issuer_refused(artifact):
    sign_artifact(artifact, signer=lambda d: "{}")
    for ident, iss in (("", ISSUER), (IDENTITY, "  ")):
        result = verify_artifact(
            artifact, None, identity=ident, issuer=iss, verifier=_ok_verifier([]),
        )
        assert not result.ok and "pinned" in result.reason


def test_verifier_exception_means_refusal(artifact):
    sign_artifact(artifact, signer=lambda d: "{}")

    def wrong_identity(data, bundle_json, identity, issuer):
        raise ValueError(f"certificate identity mismatch: wanted {identity}")

    result = verify_artifact(
        artifact, None, identity=IDENTITY, issuer=ISSUER, verifier=wrong_identity,
    )
    assert not result.ok
    assert "ValueError" in result.reason and "identity mismatch" in result.reason


def test_verify_without_sigstore_extra_refuses_closed(artifact, no_sigstore):
    sign_artifact(artifact, signer=lambda d: "{}")
    result = verify_artifact(artifact, None, identity=IDENTITY, issuer=ISSUER)
    assert not result.ok
    assert "packages/maverick-core[sigstore]" in result.reason


# ---- CLI -------------------------------------------------------------------

def test_cli_sign_missing_file_exits_2(tmp_path, capsys):
    rc = sigstore_signing.main(["sign", str(tmp_path / "missing.bin")])
    assert rc == 2
    assert "sign failed" in capsys.readouterr().err


def test_cli_sign_without_sigstore_exits_2(artifact, no_sigstore, capsys):
    rc = sigstore_signing.main(["sign", str(artifact)])
    assert rc == 2
    assert "packages/maverick-core[sigstore]" in capsys.readouterr().err


def test_cli_verify_refuses_on_missing_bundle(artifact, capsys):
    rc = sigstore_signing.main([
        "verify", str(artifact), str(artifact) + ".sigstore.json",
        "--identity", IDENTITY, "--issuer", ISSUER,
    ])
    assert rc == 1
    assert "REFUSED" in capsys.readouterr().err
