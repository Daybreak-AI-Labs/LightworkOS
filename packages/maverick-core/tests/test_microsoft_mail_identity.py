"""Microsoft sign-in identity is accepted only from a verified, bound ID token.

``microsoft_mail.verified_identity`` runs unstubbed: tokens are signed with a
locally generated RSA key and the only stub is the JWKS fetch, which serves
that key for the tenant's fixed Microsoft key URL. No network is used.
"""
from __future__ import annotations

import time

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from maverick import _oidc_jwks, microsoft_mail  # noqa: E402

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT_ID = "synthetic-client-id"
NONCE = "synthetic-request-nonce"
KID = "fixture-key"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNING = _key()
OTHER = _key()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    from maverick import config
    config.reset_config_cache()
    _oidc_jwks._resolvers.clear()
    fetched = []
    public = jwt.algorithms.RSAAlgorithm.to_jwk(SIGNING.public_key(), as_dict=True)
    jwks = {"keys": [{**public, "kid": KID, "use": "sig", "alg": "RS256"}]}

    def fetch_data(client):
        fetched.append(client.uri)
        if client.uri != f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys":
            raise AssertionError(f"unexpected key URL {client.uri}")
        return jwks

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch_data)
    yield fetched
    _oidc_jwks._resolvers.clear()
    config.reset_config_cache()


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT_ID,
        "sub": "fixture-subject", "tid": TENANT, "ver": "2.0", "nonce": NONCE,
        "iat": now, "nbf": now, "exp": now + 600,
        "email": "mailbox@example.test", "name": "Fixture Mailbox",
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def _token(key=SIGNING, *, kid=KID, **overrides):
    return jwt.encode(_claims(**overrides), key, algorithm="RS256", headers={"kid": kid})


def _verify(token, *, client_id=CLIENT_ID, nonce=NONCE):
    return microsoft_mail.verified_identity({"id_token": token}, client_id=client_id, nonce=nonce)


def test_a_correctly_signed_matching_token_is_accepted(isolated):
    identity = _verify(_token())
    assert identity == {"provider": "microsoft", "subject": "fixture-subject", "tenant_id": TENANT,
                        "display_name": "Fixture Mailbox", "email": "mailbox@example.test"}
    assert isolated == [f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"]


@pytest.mark.parametrize("token, verify", [
    pytest.param(lambda: _token(aud="another-client"), {}, id="wrong-audience"),
    pytest.param(lambda: _token(), {"client_id": "another-client"}, id="token-for-another-application"),
    pytest.param(lambda: _token(iss="https://login.microsoftonline.com/common/v2.0"), {}, id="wrong-issuer"),
    pytest.param(lambda: _token(iss="https://sts.windows.net/" + TENANT + "/"), {}, id="v1-issuer"),
    pytest.param(lambda: _token(nonce="another-request"), {}, id="wrong-nonce"),
    pytest.param(lambda: _token(nonce=None), {}, id="token-without-nonce"),
    pytest.param(lambda: _token(), {"nonce": ""}, id="request-without-nonce"),
    pytest.param(lambda: _token(OTHER), {}, id="invalid-signature"),
    pytest.param(lambda: _token(exp=int(time.time()) - 600, iat=int(time.time()) - 1200,
                                nbf=int(time.time()) - 1200), {}, id="expired"),
    pytest.param(lambda: _token(exp=None), {}, id="no-expiry"),
    pytest.param(lambda: _token(ver="1.0"), {}, id="v1-token"),
    pytest.param(lambda: _token(kid="unknown-key"), {}, id="unknown-signing-key"),
])
def test_an_unverified_or_unbound_token_is_refused(token, verify):
    with pytest.raises(Exception) as refused:
        _verify(token(), **verify)
    assert not isinstance(refused.value, (AssertionError, TypeError))


def test_an_unsigned_or_symmetric_token_is_refused():
    claims = _claims()
    unsigned = jwt.encode(claims, None, algorithm="none", headers={"kid": KID})
    symmetric = jwt.encode(claims, "shared-secret-shared-secret-shared", algorithm="HS256",  # pragma: allowlist secret
                           headers={"kid": KID})
    for token in (unsigned, symmetric):
        with pytest.raises(Exception) as refused:
            _verify(token)
        assert not isinstance(refused.value, (AssertionError, TypeError))
