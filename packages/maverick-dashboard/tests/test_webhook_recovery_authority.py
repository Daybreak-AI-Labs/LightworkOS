"""The webhook "new attempt" review re-checks every kind of caller."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException


def test_an_api_key_revoked_during_the_review_cannot_carry_it_through(monkeypatch):
    # Sessions, invitations and proxy sign-ins were re-verified inside the
    # fresh check; an API key reused the principal from the start of the request.
    from maverick_dashboard import auth, webhooks_api

    checked = []
    monkeypatch.setattr(webhooks_api, "require_global_permission", lambda request, permission: None)
    monkeypatch.setattr(auth, "_api_key_bearer", lambda request: "lw_key")

    def revoked(request, token):
        checked.append(token)
        raise HTTPException(401, "This access key was revoked.")

    monkeypatch.setattr(auth, "_authenticate_api_key", revoked)
    request = SimpleNamespace(state=SimpleNamespace(
        principal=SimpleNamespace(principal="user:ops", claims={"via": "api_key"})))
    with pytest.raises(HTTPException) as refused:
        webhooks_api._recovery_authority(request)
    assert refused.value.status_code == 401 and checked == ["lw_key"]
