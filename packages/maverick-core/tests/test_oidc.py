"""Adversarial test matrix for OIDC ID-token verification (maverick.oidc).

Every token here is minted locally with a freshly-generated RSA keypair
(via ``cryptography``, already a dep) and verified by injecting the *public*
key — so NO network call is made (PyJWKClient is only used when no key is
injected). Each test asserts a single security property; together they prove
the non-negotiable requirements:

  1. valid token            -> VerifiedPrincipal with principal == user:<sub>
  2. expired (exp in past)  -> OIDCError
  3. wrong audience         -> OIDCError
  4. wrong issuer           -> OIDCError
  5. alg: none              -> OIDCError
  6. alg-confusion (HS256   -> OIDCError   (the public-key-as-HMAC-secret attack)
     signed w/ public key)
  7. tampered signature     -> OIDCError
  8. missing sub            -> OIDCError
  9. oidc_enabled() env/config + default-off

If the sandbox's ``cryptography`` is broken (no ``_cffi_backend``), the whole
RSA-dependent matrix is SKIPPED (not xfailed) — CI has working crypto and is
the real gate. The config/default-off tests need no crypto and always run.
"""
from __future__ import annotations

import time

import pytest
from maverick.oidc import (
    DEFAULT_ALGORITHMS,
    OIDCConfig,
    OIDCError,
    VerifiedPrincipal,
    load_oidc_config,
    oidc_enabled,
    verify_oidc_token,
)

# ---- crypto availability gate -------------------------------------------------
# A clean venv pulls a working cryptography+cffi; the system interpreter in this
# sandbox is missing _cffi_backend. Probe once and skip the RSA matrix if it's
# broken, rather than letting every test error out with an opaque import crash.
_CRYPTO_OK = True
_CRYPTO_SKIP_REASON = ""
try:  # noqa: SIM105
    import jwt  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    _probe = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _probe.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
except Exception as _e:  # pragma: no cover - env-dependent
    _CRYPTO_OK = False
    _CRYPTO_SKIP_REASON = f"working cryptography/PyJWT unavailable: {type(_e).__name__}: {_e}"

requires_crypto = pytest.mark.skipif(not _CRYPTO_OK, reason=_CRYPTO_SKIP_REASON)


ISSUER = "https://issuer.example.com"
AUDIENCE = "maverick-client-id"
SUB = "abc123-user"


def _config(**overrides) -> OIDCConfig:
    base = dict(
        enabled=True,
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_uri="https://issuer.example.com/jwks",  # never hit: key is injected
        algorithms=list(DEFAULT_ALGORITHMS),
    )
    base.update(overrides)
    return OIDCConfig(**base)


@pytest.fixture(scope="module")
def rsa_keys():
    """A (private_pem, public_pem, public_key_obj) RSA keypair for minting +
    verifying tokens locally."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem, pub


def _claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "sub": SUB,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "email": "user@example.com",
    }
    claims.update(overrides)
    # Allow tests to delete a claim by passing it as None.
    return {k: v for k, v in claims.items() if v is not None}


def _mint(priv_pem, *, alg="RS256", headers=None, **claim_overrides) -> str:
    return jwt.encode(
        _claims(**claim_overrides),
        priv_pem,
        algorithm=alg,
        headers=headers or {"kid": "test-key-1"},
    )


def _forge_hs256_with_secret(secret: bytes, **claim_overrides) -> str:
    """Hand-forge an HS256 JWT, computing the HMAC ourselves so we can use the
    RSA *public key bytes* as the secret.

    This is exactly the alg-confusion attacker's tool: modern PyJWT refuses to
    ``encode`` an HMAC token from a PEM/asymmetric key (its own encode-side
    guard), so we bypass ``jwt.encode`` and build the compact token by hand.
    A verifier that accepts HS256 + the public key would validate this; ours
    must reject it on the algorithm allowlist alone.
    """
    import base64
    import hashlib
    import hmac
    import json

    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-1"}
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(_claims(**claim_overrides), separators=(",", ":")).encode())
    signing_input = h + b"." + p
    sig = b64(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()


# ---- (1) valid token ----------------------------------------------------------


@requires_crypto
def test_valid_token_returns_principal(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem)
    principal = verify_oidc_token(token, config=_config(), signing_key=pub_pem)
    assert isinstance(principal, VerifiedPrincipal)
    assert principal.sub == SUB
    assert principal.principal == f"user:{SUB}"
    assert principal.issuer == ISSUER
    assert principal.audience == AUDIENCE
    assert principal.claims["email"] == "user@example.com"


@requires_crypto
def test_valid_token_with_public_key_object(rsa_keys):
    """A key *object* (not just PEM bytes) is accepted as the injected key."""
    priv_pem, _, pub_obj = rsa_keys
    token = _mint(priv_pem)
    principal = verify_oidc_token(token, config=_config(), signing_key=pub_obj)
    assert principal.principal == f"user:{SUB}"


@requires_crypto
@pytest.mark.parametrize("subject", [" alice", "alice "])
def test_edge_whitespace_subject_is_rejected_not_canonicalized(rsa_keys, subject):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem, sub=subject)

    with pytest.raises(OIDCError, match="sub"):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


@requires_crypto
def test_subject_at_principal_length_boundary_is_accepted(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    subject = "x" * 251
    principal = verify_oidc_token(
        _mint(priv_pem, sub=subject), config=_config(), signing_key=pub_pem,
    )

    assert principal.sub == subject
    assert len(principal.principal) == 256


# ---- (2) expired --------------------------------------------------------------


@requires_crypto
def test_expired_token_rejected(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    now = int(time.time())
    token = _mint(priv_pem, iat=now - 7200, exp=now - 3600)
    with pytest.raises(OIDCError):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


# ---- (3) wrong audience -------------------------------------------------------


@requires_crypto
def test_wrong_audience_rejected(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem, aud="some-other-client")
    with pytest.raises(OIDCError):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


# ---- (4) wrong issuer ---------------------------------------------------------


@requires_crypto
def test_wrong_issuer_rejected(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem, iss="https://evil.example.com")
    with pytest.raises(OIDCError):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


# ---- (5) alg: none ------------------------------------------------------------


@requires_crypto
def test_alg_none_rejected(rsa_keys):
    """An unsigned (alg=none) token must never authenticate."""
    _, pub_pem, _ = rsa_keys
    # PyJWT refuses to encode alg=none with a key, so build the token by hand.
    unsigned = jwt.encode(
        _claims(), key=None, algorithm="none", headers={"kid": "test-key-1"}
    )
    with pytest.raises(OIDCError):
        verify_oidc_token(unsigned, config=_config(), signing_key=pub_pem)


# ---- (6) alg-confusion: HS256 signed with the RSA public key ------------------


@requires_crypto
def test_alg_confusion_hs256_with_public_key_rejected(rsa_keys):
    """The classic alg-confusion attack: sign with HS256 using the PUBLIC key
    bytes as the HMAC secret. A verifier that allows HMAC would accept this,
    turning the public key into a forgery key. Our asymmetric-only allowlist
    must reject it."""
    _, pub_pem, _ = rsa_keys
    # Public key bytes used as the HMAC secret (forged by hand to bypass
    # PyJWT's own encode-side guard).
    forged = _forge_hs256_with_secret(pub_pem)
    with pytest.raises(OIDCError):
        # Verify with the public key, exactly as a naive server would.
        verify_oidc_token(forged, config=_config(), signing_key=pub_pem)


@requires_crypto
def test_hs256_rejected_even_if_config_lists_it(rsa_keys):
    """Defence in depth: even if a hand-edited config smuggles HS256 into the
    algorithms list, the verifier strips it and refuses to verify with HMAC."""
    _, pub_pem, _ = rsa_keys
    forged = _forge_hs256_with_secret(pub_pem)
    # Bypass _normalize_algorithms by constructing OIDCConfig directly with HS256.
    cfg = OIDCConfig(
        enabled=True, issuer=ISSUER, audience=AUDIENCE,
        jwks_uri="https://x/jwks", algorithms=["HS256"],
    )
    with pytest.raises(OIDCError):
        verify_oidc_token(forged, config=cfg, signing_key=pub_pem)


# ---- (7) tampered signature ---------------------------------------------------


@requires_crypto
def test_tampered_signature_rejected(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem)
    # Flip characters in the signature segment (3rd dot-delimited part).
    head, payload, sig = token.split(".")
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = f"{head}.{payload}.{bad_sig}"
    with pytest.raises(OIDCError):
        verify_oidc_token(tampered, config=_config(), signing_key=pub_pem)


# ---- (8) missing sub ----------------------------------------------------------


@requires_crypto
def test_missing_sub_rejected(rsa_keys):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem, sub=None)  # drop the sub claim
    with pytest.raises(OIDCError):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


@requires_crypto
@pytest.mark.parametrize(
    "invalid_sub",
    ["x" * 252, "alice\n", "alice\x7f", "alice\u0085"],
    ids=["overlong", "newline", "delete-control", "unicode-control"],
)
def test_non_printable_or_overlong_sub_rejected(rsa_keys, invalid_sub):
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem, sub=invalid_sub)
    with pytest.raises(OIDCError, match="sub"):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


@requires_crypto
@pytest.mark.parametrize("missing", ["iss", "aud", "exp", "iat"])
def test_missing_required_claim_rejected(rsa_keys, missing):
    """exp/iat/aud/iss are all required, mirroring options={"require": [...]}."""
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem, **{missing: None})
    with pytest.raises(OIDCError):
        verify_oidc_token(token, config=_config(), signing_key=pub_pem)


# ---- key resolution / injection seam -----------------------------------------


@requires_crypto
def test_unknown_kid_via_injected_resolver_rejected(rsa_keys):
    """A PyJWKClient-like resolver that can't find the kid -> OIDCError (no
    fallback key)."""
    priv_pem, _, _ = rsa_keys
    token = _mint(priv_pem, headers={"kid": "unknown-kid"})

    class _NoKeyResolver:
        def get_signing_key_from_jwt(self, _token):
            raise Exception("kid 'unknown-kid' not found in JWKS")

    with pytest.raises(OIDCError):
        verify_oidc_token(token, config=_config(), signing_key=_NoKeyResolver())


@requires_crypto
def test_injected_jwk_resolver_happy_path(rsa_keys):
    """A resolver exposing get_signing_key_from_jwt is used to pick the key by
    kid (the PyJWKClient contract), without any network."""
    priv_pem, pub_pem, _ = rsa_keys
    token = _mint(priv_pem)

    class _Key:
        key = pub_pem

    class _Resolver:
        def get_signing_key_from_jwt(self, _token):
            return _Key()

    principal = verify_oidc_token(token, config=_config(), signing_key=_Resolver())
    assert principal.principal == f"user:{SUB}"


# ---- config / failure-shape (no crypto needed) --------------------------------


def test_missing_config_raises_not_returns():
    """No issuer/audience configured -> OIDCError, never a principal. This is
    the fail-CLOSED property and must hold even without crypto."""
    with pytest.raises(OIDCError):
        verify_oidc_token("whatever", config=OIDCConfig(enabled=True))


def test_empty_token_rejected():
    with pytest.raises(OIDCError):
        verify_oidc_token("", config=_config(), signing_key=b"unused")


def test_pyjwt_missing_gives_actionable_error(monkeypatch):
    """If PyJWT isn't installed, verification raises a clear OIDCError telling
    the operator to install the extra — it does NOT crash with ImportError and
    does NOT fail open."""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "jwt":
            raise ModuleNotFoundError("No module named 'jwt'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    with pytest.raises(OIDCError) as ei:
        verify_oidc_token("a.b.c", config=_config(), signing_key=b"unused")
    assert "maverick-agent[oidc]" in str(ei.value) or "pyjwt" in str(ei.value).lower()


# ---- (9) oidc_enabled() env / config + default-off ----------------------------


def test_oidc_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))  # no config.toml -> empty config
    monkeypatch.delenv("MAVERICK_OIDC_ENABLED", raising=False)
    assert oidc_enabled() is False


def test_oidc_enabled_via_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    assert oidc_enabled() is True


def test_oidc_env_overrides_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "true")
    monkeypatch.setenv("MAVERICK_OIDC_ISSUER", "https://env-issuer")
    monkeypatch.setenv("MAVERICK_OIDC_AUDIENCE", "env-aud")
    monkeypatch.setenv("MAVERICK_OIDC_JWKS_URI", "https://env/jwks")
    monkeypatch.setenv("MAVERICK_OIDC_ALGORITHMS", "RS256, HS256, none")
    cfg = load_oidc_config()
    assert cfg.enabled is True
    assert cfg.issuer == "https://env-issuer"
    assert cfg.audience == "env-aud"
    assert cfg.jwks_uri == "https://env/jwks"
    # HS256/none are stripped by normalization; only the asymmetric one remains.
    assert cfg.algorithms == ["RS256"]


def test_oidc_enabled_via_config(monkeypatch, tmp_path):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text(
        "[auth.oidc]\n"
        "enabled = true\n"
        'issuer = "https://cfg-issuer"\n'
        'audience = "cfg-aud"\n'
        'jwks_uri = "https://cfg/jwks"\n'
        'algorithms = ["ES256"]\n'
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_OIDC_ENABLED", raising=False)
    monkeypatch.delenv("MAVERICK_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("MAVERICK_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("MAVERICK_OIDC_JWKS_URI", raising=False)
    monkeypatch.delenv("MAVERICK_OIDC_ALGORITHMS", raising=False)
    assert oidc_enabled() is True
    cfg = load_oidc_config()
    assert cfg.issuer == "https://cfg-issuer"
    assert cfg.audience == "cfg-aud"
    assert cfg.algorithms == ["ES256"]


def test_config_algorithms_default_to_asymmetric(monkeypatch, tmp_path):
    """A config with no algorithms key falls back to the asymmetric default."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_OIDC_ALGORITHMS",):
        monkeypatch.delenv(env, raising=False)
    cfg = load_oidc_config()
    assert cfg.algorithms == DEFAULT_ALGORITHMS
