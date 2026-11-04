"""Durable-write identities retain the same authenticated/local boundary."""
from __future__ import annotations

import hashlib

import pytest
from fastapi import HTTPException
from maverick_dashboard.request_identity import request_actor, request_identity
from starlette.requests import Request


def _request(token: str = "") -> Request:
    headers = [(b"authorization", token.encode())] if token else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


def test_token_identity_cannot_fall_back_to_local_when_auth_is_configured():
    def identity(_request):
        return None

    def token():
        return "dashboard-secret"
    assert request_identity(_request("Bearer dashboard-secret"), caller=identity,
                            dashboard_token=token, auth_off=lambda: True) == "auth:dashboard-token"
    with pytest.raises(HTTPException) as error:
        request_identity(_request("Bearer wrong"), caller=identity,
                         dashboard_token=token, auth_off=lambda: True)
    assert error.value.status_code == 401


def test_actor_is_attributable_and_bounded():
    principal = "user:" + "x" * 300
    actor = request_actor(_request(), identity=lambda _request: principal)
    assert len(actor) == 255
    assert actor.endswith("#sha256:" + hashlib.sha256(principal.encode()).hexdigest())
    assert request_actor(_request(), identity=lambda _request: None) == "local:dashboard"
