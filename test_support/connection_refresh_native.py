"""Connection refresh helpers importable by spawned test children."""
from __future__ import annotations

from maverick import config, connections
from maverick import connection_oauth as oauth
from maverick.paths import tenant_scope

OWNER = "user:owner"


def _renew():
    with tenant_scope(tenant="tenant-a"):
        return oauth.renew(connections.get_connection("evidence"), actor=OWNER)


def _process_renew(entered, release, counter, results, *, crash=""):
    """Spawned child uses the same on-disk sealed store and native file locks."""
    import os

    config.reset_config_cache()

    def post(*args):
        with counter.get_lock():
            counter.value += 1
        entered.set()
        if crash == "pending":
            os._exit(17)
        if not release.wait(15):
            raise TimeoutError("test release did not arrive")
        return {"access_token": "process-fixture-token", "expires_in": 3600}

    def identity(*args, **_identity_inputs):
        if crash == "consumed":
            os._exit(18)
        return {"provider": "google", "subject": "fixture-account", "display_name": "Fixture",
                "email": "fixture@example.test", "email_verified": True, "hosted_domain": "example.test"}

    oauth._post_token = post
    oauth._provider_identity = identity
    try:
        result = _renew()
        results.put(("ready", result["revision"]))
    except Exception as exc:
        results.put(("error", type(exc).__name__))
