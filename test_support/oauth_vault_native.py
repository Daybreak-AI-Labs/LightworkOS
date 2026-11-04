"""Encrypted vault operation importable by spawned test children."""
from __future__ import annotations

import time

from maverick.oauth_vault import OAuthVault


def _operate(operation, ready, loaded, release, results, provider):
    from maverick.tenant import kms
    kms._clear_cache()
    vault = OAuthVault("synthetic-tenant")
    original = vault._load

    def gated_load():
        value = original()
        loaded.put(provider)
        if not release.wait(15):
            raise RuntimeError("test release timeout")
        return value

    vault._load = gated_load
    ready.set()
    try:
        if operation == "put":
            vault.put(provider, {"access_token": f"synthetic-{provider}"})
        elif operation == "refresh":
            def refresh(record):
                results.put(("refresh", record["refresh_token"]))
                return {"access_token": "synthetic-new", "refresh_token": "synthetic-rotated",
                        "expires_at": time.time() + 3600}
            token = vault.access_token("provider", refresher=refresh)
            results.put(("token", token))
        else:
            vault.delete("provider")
        results.put(("done", provider))
    except BaseException as exc:
        results.put(("error", type(exc).__name__))
