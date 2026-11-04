"""The suite must not inherit an AI provider from the host it runs on.

``config.any_provider_configured`` reads every provider credential and base-URL
variable. A host whose agent proxy set ``ANTHROPIC_BASE_URL`` (and no key) made
six tests fail that assume a fresh install -- doctor's red "not set" row, the
dashboard's degraded ``/healthz``, the base-URL predicate -- because those tests
unset only the API-key names. The repo-root ``conftest.py`` now drops the host's
values once at session start; these tests pin that contract.
"""
from __future__ import annotations

import os

from test_support.provider_env import HOST_PROVIDER_ENV_VARS, scrub_host_provider_env


def test_scrub_list_covers_every_provider_variable_the_kernel_reads():
    from maverick.config import PROVIDER_BASE_URL_ENV_VARS, PROVIDER_CREDENTIAL_ENV_VARS

    kernel_reads = set(PROVIDER_CREDENTIAL_ENV_VARS) | set(PROVIDER_BASE_URL_ENV_VARS)
    missing = kernel_reads - set(HOST_PROVIDER_ENV_VARS)
    assert not missing, (
        f"add {sorted(missing)} to test_support/provider_env.py -- the root conftest "
        "cannot import maverick.config before it redirects HOME, so the list is kept by hand"
    )


def test_session_starts_without_a_host_provider():
    present = [name for name in HOST_PROVIDER_ENV_VARS if name in os.environ]
    assert not present, (
        f"{present} reached the test session from the host -- the root conftest "
        "scrub did not run before this test"
    )


def test_scrub_removes_only_the_listed_names():
    env = {
        "ANTHROPIC_BASE_URL": "https://proxy.invalid",
        "OPENAI_API_KEY": "not-a-real-key",  # pragma: allowlist secret
        "HOME": "/h",
        "PATH": "/bin",
    }
    removed = scrub_host_provider_env(env)
    assert sorted(removed) == ["ANTHROPIC_BASE_URL", "OPENAI_API_KEY"]
    assert env == {"HOME": "/h", "PATH": "/bin"}
