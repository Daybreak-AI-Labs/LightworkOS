"""Finite JWKS reuse/rotation under real local signatures, without an IdP."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from maverick import _oidc_jwks as resolvers
from maverick.oidc import OIDCConfig, OIDCError, verify_oidc_token

jwt = pytest.importorskip("jwt", reason="optional OIDC dependency is not installed")


@pytest.fixture
def environment(monkeypatch):
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]
    state = SimpleNamespace(now=0.0, clients=[], fetches=0, keys=[SimpleNamespace(key_id="a", key=keys[0].public_key())],
                            failure=False, entered=None, release=None)

    class Client:
        def __init__(self, uri, **kwargs):
            state.clients.append((uri, kwargs))

        def get_signing_keys(self, *, refresh):
            assert refresh is True
            state.fetches += 1
            if state.entered:
                state.entered.set()
                assert state.release.wait(3)
            if state.failure:
                raise RuntimeError("synthetic key endpoint unavailable")
            return list(state.keys)

    monkeypatch.setattr(jwt, "PyJWKClient", Client)
    monkeypatch.setattr(resolvers, "time", SimpleNamespace(monotonic=lambda: state.now))
    resolvers._resolvers.clear()
    config = OIDCConfig(enabled=True, issuer="https://issuer.example", audience="lightwork",
                        jwks_uri="https://issuer.example/jwks", algorithms=["RS256"])

    def token(kid="a", index=0, **claims):
        now = datetime.now(timezone.utc)
        return jwt.encode({"sub": "exact-user", "iss": config.issuer, "aud": config.audience,
                           "iat": now, "exp": now + timedelta(minutes=10), **claims},
                          keys[index], algorithm="RS256", headers={"kid": kid})

    yield state, config, token, keys
    resolvers._resolvers.clear()


def test_repeated_verification_reuses_only_finite_public_keys(environment):
    state, config, token, _keys = environment
    for _ in range(3):
        assert verify_oidc_token(token(), config=config).principal == "user:exact-user"
    assert len(state.clients) == state.fetches == 1
    assert state.clients[0][1] == {"timeout": 5.0, "cache_keys": False, "cache_jwk_set": False}
    with pytest.raises(OIDCError):
        verify_oidc_token(token(aud="another-client"), config=config)
    assert state.fetches == 1  # a cached key is not cached claim verification
    state.now = 301
    state.failure = True
    with pytest.raises(OIDCError):
        verify_oidc_token(token(), config=config)
    assert state.fetches == 2
    assert not next(iter(resolvers._resolvers.values())).keys


def test_unknown_kids_share_refresh_cooldown_and_rotated_keys_refresh(environment):
    state, config, token, keys = environment
    verify_oidc_token(token(), config=config)
    for index in range(20):
        with pytest.raises(OIDCError):
            verify_oidc_token(token(f"unknown-{index}"), config=config)
    assert state.fetches == 1
    state.now = 11
    state.keys = [SimpleNamespace(key_id="b", key=keys[1].public_key())]
    assert verify_oidc_token(token("b", 1), config=config).sub == "exact-user"
    assert state.fetches == 2
    with pytest.raises(OIDCError):
        verify_oidc_token(token(), config=config)
    assert state.fetches == 2


def test_changed_issuer_uri_audience_and_algorithm_select_distinct_policy(environment):
    state, config, token, _keys = environment
    for field, value in (("issuer", "https://other.example"), ("jwks_uri", "https://other.example/jwks"),
                         ("audience", "another-client"), ("algorithms", ["RS256", "ES256"])):
        changed = replace(config, **{field: value})
        if field in ("issuer", "audience"):
            with pytest.raises(OIDCError):
                verify_oidc_token(token(), config=changed)
        else:
            verify_oidc_token(token(), config=changed)
    assert len(state.clients) == state.fetches == 4


def test_concurrent_cold_start_fetches_once(environment):
    state, config, token, _keys = environment
    state.entered, state.release = threading.Event(), threading.Event()
    value = token()
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(verify_oidc_token, value, config=config) for _ in range(8)]
        assert state.entered.wait(2)
        state.release.set()
        assert [future.result(timeout=3).sub for future in futures] == ["exact-user"] * 8
    assert len(state.clients) == state.fetches == 1


def test_registry_and_key_count_are_bounded(environment):
    state, config, token, _keys = environment
    for index in range(resolvers.MAX_RESOLVERS + 4):
        verify_oidc_token(token(), config=replace(config, jwks_uri=f"https://issuer.example/{index}"))
    assert len(resolvers._resolvers) == resolvers.MAX_RESOLVERS
    state.keys *= resolvers.MAX_KEYS + 1
    with pytest.raises(OIDCError):
        verify_oidc_token(token(), config=config)
