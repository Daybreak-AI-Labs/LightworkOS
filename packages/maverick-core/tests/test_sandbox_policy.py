"""Sandbox backend enterprise gate.

The 'local' backend runs shell=True on the host with no isolation. Under
enterprise mode (or an explicit require-container opt-in) build_sandbox must
refuse it fail-closed instead of silently running untrusted agent code on the
host. Off by default, so single-tenant/dev keeps the (warned) local backend.
"""
from __future__ import annotations

import pytest
from maverick.sandbox import SandboxPolicyError, build_sandbox


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for v in ("MAVERICK_ENTERPRISE", "MAVERICK_REQUIRE_CONTAINER_BACKEND",
              "MAVERICK_SUPPRESS_SANDBOX_WARNING"):
        monkeypatch.delenv(v, raising=False)


def test_local_allowed_by_default():
    # No policy active -> local backend is built (with a one-time warning).
    sb = build_sandbox(backend="local")
    assert sb is not None


def test_local_refused_when_require_container_and_no_runtime(monkeypatch):
    # require-container active AND no docker/podman on PATH -> fail closed
    # (never silently run on the host).
    monkeypatch.setenv("MAVERICK_REQUIRE_CONTAINER_BACKEND", "1")
    monkeypatch.setattr("maverick.sandbox._default_container_backend", lambda: None)
    with pytest.raises(SandboxPolicyError):
        build_sandbox(backend="local")


def test_local_refused_under_enterprise_mode_and_no_runtime(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr("maverick.sandbox._default_container_backend", lambda: None)
    with pytest.raises(SandboxPolicyError):
        build_sandbox(backend="local")


def test_local_autoselects_container_when_runtime_available(monkeypatch):
    # Container-default under enterprise: when a container runtime IS available,
    # 'local' is upgraded to it instead of failing closed. build_sandbox must not
    # raise the policy error (a missing docker *daemon* may raise a different
    # error at construct time -- that's fine, just not SandboxPolicyError).
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr("maverick.sandbox._default_container_backend", lambda: "docker")
    try:
        sb = build_sandbox(backend="local")
        assert sb is not None
    except SandboxPolicyError:
        pytest.fail("local should auto-upgrade to the available container backend")
    except Exception:
        pass  # docker daemon not present in this env -> non-policy error is OK


def test_unknown_backend_refused_when_require_container(monkeypatch):
    # Regression: the gate must also catch the degrade-to-local path. A typo'd
    # backend name matched no known backend and would otherwise fall through to
    # an unsandboxed host LocalBackend -- the exact fail-open the gate prevents.
    monkeypatch.setenv("MAVERICK_REQUIRE_CONTAINER_BACKEND", "1")
    with pytest.raises(SandboxPolicyError):
        build_sandbox(backend="dcoker")  # typo for "docker"


def test_unknown_backend_still_degrades_to_local_without_policy():
    # With no policy active, an unrecognized backend keeps the documented
    # warn-and-degrade behavior (the refusal applies only to require-container).
    sb = build_sandbox(backend="dcoker")
    assert sb is not None


def test_container_backend_not_refused_by_policy(monkeypatch):
    # The gate refuses ONLY 'local'. A container backend must not trip it; in an
    # env without a Docker daemon build_sandbox may raise a different error
    # (docker unavailable) -- that's fine, it just must not be SandboxPolicyError.
    monkeypatch.setenv("MAVERICK_REQUIRE_CONTAINER_BACKEND", "1")
    try:
        build_sandbox(backend="docker")
    except SandboxPolicyError:
        pytest.fail("docker backend wrongly refused by the local-only policy gate")
    except Exception:
        pass  # e.g. Docker daemon not installed in this environment
