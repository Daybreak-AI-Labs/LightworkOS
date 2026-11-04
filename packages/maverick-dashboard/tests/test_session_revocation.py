"""Per-principal session/bearer revocation: revoke_principal bumps a
monotonic epoch; any credential whose iat predates it is rejected."""
from __future__ import annotations

import math

import pytest
from maverick_dashboard import session_revocation as sr


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_unrevoked_principal_allows_everything():
    assert sr.revocation_epoch("alice") == 0.0
    assert sr.is_revoked("alice", issued_at=1.0) is False
    assert sr.is_revoked("alice", issued_at=None) is False


def test_revoke_rejects_older_allows_newer():
    sr.revoke_principal("bob", at=100.0)
    assert sr.revocation_epoch("bob") == 100.0
    assert sr.is_revoked("bob", issued_at=99.0) is True       # issued before epoch
    assert sr.is_revoked("bob", issued_at=100.0) is False     # at/after epoch is ok
    assert sr.is_revoked("bob", issued_at=None) is True       # no iat under epoch -> revoked


def test_epoch_is_monotonic():
    sr.revoke_principal("carol", at=200.0)
    sr.revoke_principal("carol", at=150.0)  # stale write -> must not move backwards
    assert sr.revocation_epoch("carol") == 200.0


def test_blank_principal_is_noop():
    sr.revoke_principal("")
    assert sr.revocation_epoch("") == 0.0


def test_garbage_iat_treated_as_revoked():
    sr.revoke_principal("dave", at=100.0)
    assert sr.is_revoked("dave", issued_at="not-a-number") is True
    assert sr.is_revoked("dave", issued_at=math.nan) is True
    assert sr.is_revoked("dave", issued_at=math.inf) is True


def test_absent_store_is_not_an_error():
    # No revocations yet: a genuinely-absent store is empty, not corrupt.
    assert sr.revocation_epoch("nobody") == 0.0
    assert sr.is_revoked("nobody", issued_at=1.0) is False


def test_corrupt_store_fails_closed():
    # A store that EXISTS but is unreadable JSON must NOT silently un-revoke the
    # whole population -- is_revoked fails CLOSED (revoked) on a damaged store.
    sr._path().parent.mkdir(parents=True, exist_ok=True)
    sr._path().write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(sr.RevocationStoreError):
        sr.revocation_epoch("eve")
    assert sr.is_revoked("eve", issued_at=2.0) is True


@pytest.mark.parametrize(
    "content",
    ["[]", '{"eve":NaN}', '{"eve":100,"eve":0}', '{"eve":-1}'],
)
def test_parseable_but_untrusted_store_fails_closed(content):
    sr._path().parent.mkdir(parents=True, exist_ok=True)
    sr._path().write_text(content, encoding="utf-8")
    with pytest.raises(sr.RevocationStoreError):
        sr.revocation_epoch("eve")
    assert sr.is_revoked("eve", issued_at=1000.0) is True


@pytest.mark.parametrize("epoch", [math.nan, math.inf, -math.inf, 0.0])
def test_revoke_rejects_nonfinite_or_nonpositive_epoch(epoch):
    with pytest.raises(ValueError):
        sr.revoke_principal("eve", at=epoch)
