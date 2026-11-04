"""Environment hygiene for injected audit signing keys."""
from __future__ import annotations

import os

import pytest
from maverick.audit import signing


def test_injected_key_env_is_consumed_even_without_crypto(monkeypatch):
    monkeypatch.setattr(
        signing, "_INJECTED_KEYPAIR_CACHE", signing._INJECTED_KEYPAIR_UNREAD
    )
    monkeypatch.setattr(signing, "_have_crypto", lambda: False)
    monkeypatch.setenv(signing._SIGNING_KEY_ENV, "00" * 32)

    with pytest.raises(ValueError):
        signing._injected_keypair()
    assert signing._SIGNING_KEY_ENV not in os.environ
    with pytest.raises(ValueError):
        signing._injected_keypair()
