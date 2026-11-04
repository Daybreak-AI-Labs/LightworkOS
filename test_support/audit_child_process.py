"""Provide a test-owned audit signer to spawned native-workflow workers."""
from __future__ import annotations

import os
import secrets
from functools import partial

_FIXTURE_ENV = "LIGHTWORK_TEST_NATIVE_AUDIT_SIGNER"


def configure_test_audit_signer(monkeypatch):
    """Create a disposable signer owned solely by the current test."""
    from maverick.audit import signing

    key = secrets.token_hex(32)
    monkeypatch.setenv(_FIXTURE_ENV, key)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", key)
    signing._reset_injected_keypair_cache()


def _run_with_test_signer(target, key, *args, **kwargs):
    from maverick.audit import signing

    os.environ["MAVERICK_AUDIT_SIGNING_KEY"] = key
    signing._reset_injected_keypair_cache()
    return target(*args, **kwargs)


def audit_signing_target(target):
    """Return a spawn-safe target bound to this fixture's disposable key."""
    key = os.environ.get(_FIXTURE_ENV, "")
    if len(key) != 64:
        raise RuntimeError("native test audit signer is not configured")
    return partial(_run_with_test_signer, target, key)
