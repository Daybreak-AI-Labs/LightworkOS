"""Principal helpers never silently canonicalize an upstream identity."""
from __future__ import annotations

from types import SimpleNamespace

import maverick_dashboard.auth as auth
from maverick.oidc import VerifiedPrincipal
from starlette.requests import Request


def _request_for(sub: str) -> Request:
    request = Request({"type": "http", "method": "GET", "path": "/"})
    request.state.principal = VerifiedPrincipal(
        sub=sub,
        issuer="https://issuer.example",
        audience="lightwork",
        claims={"sub": sub},
    )
    return request


def test_trailing_space_subjects_stay_distinct_for_ownership_and_execution(
    monkeypatch,
):
    # OIDC rejects edge whitespace at its trust boundary. This downstream
    # defense-in-depth test ensures an alternate/future principal source still
    # cannot trigger an identity collision in owner or execution helpers.
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda _principal: False)
    alice = _request_for("alice")
    alice_space = _request_for("alice ")
    plain_goal = SimpleNamespace(id=1, owner="user:alice")
    spaced_goal = SimpleNamespace(id=2, owner="user:alice ")

    assert auth.caller_principal(alice) == "user:alice"
    assert auth.caller_principal(alice_space) == "user:alice "
    assert auth.execution_user_id_from_request(alice) == "alice"
    assert auth.execution_user_id_from_request(alice_space) == "alice "

    assert auth.can_access_goal(alice, plain_goal) is True
    assert auth.can_access_goal(alice, spaced_goal) is False
    assert auth.can_access_goal(alice_space, plain_goal) is False
    assert auth.can_access_goal(alice_space, spaced_goal) is True


def test_tenant_pin_keeps_exact_verified_principal(monkeypatch):
    pins: list[str] = []
    monkeypatch.setattr("maverick.paths.tenant_by_user_enabled", lambda: True)
    monkeypatch.setattr(
        "maverick.paths.set_tenant", lambda tenant: pins.append(tenant) or object(),
    )
    request = _request_for("alice ")

    auth._pin_tenant_from_principal(request, request.state.principal)

    assert pins == ["api:user:alice "]
