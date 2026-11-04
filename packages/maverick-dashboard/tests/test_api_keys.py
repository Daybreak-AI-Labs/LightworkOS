"""Personal / service-account API keys: scopes, expiry, rotation, revocation.

Hermetic like the other dashboard tests: OIDC is simulated by mapping
``Bearer <name>`` to ``user:<name>`` (no PyJWT, no network); the key store,
RBAC roster and audit log live under a per-test ``MAVERICK_HOME``.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_DASHBOARD_ADMINS",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_DASHBOARD_API_KEYS",
                 "MAVERICK_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    import maverick.audit.writer as aw
    aw._default = None
    aw._defaults.clear()
    from maverick_dashboard import api_keys, auth
    api_keys._last_used_written.clear()
    auth._break_glass_last_audit[0] = None
    yield
    config.reset_config_cache()
    aw._default = None
    aw._defaults.clear()


def _client() -> TestClient:
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)


def _sign_in_map(monkeypatch):
    """``Bearer <name>`` -> ``user:<name>`` (the OIDC path, without PyJWT)."""
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _verify(token, **_kw):
        return VerifiedPrincipal(sub=token, issuer="https://issuer.example",
                                 audience="maverick", claims={"sub": token})

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _as(name: str) -> dict:
    return {"Authorization": f"Bearer {name}"}


def _key(secret: str) -> dict:
    return {"Authorization": f"Bearer {secret}"}


def _reviewed(client, headers, action, key_id=None, **body):
    """A key change the way Access keys makes it: the complete review first
    (access_key_requests_api), then the sealed review confirmed. A refusal at
    either step is returned as it is."""
    context = client.get("/api/v1/access-key-requests", headers=headers)
    if context.status_code != 200:
        return context
    request = {"context": context.json()["context"], "action": action, **body}
    if key_id is not None:
        request["key_id"] = key_id
    review = client.post("/api/v1/access-key-requests/review", json=request, headers=headers)
    if review.status_code != 200:
        return review
    path = "/api/v1/api-keys" + (f"/{key_id}/{action}" if key_id is not None else "")
    return client.post(path, json={"token": review.json()["token"], "confirmed": True}, headers=headers)


def _create(client, who, **body):
    payload = {"label": "nightly report", "scopes": ["tasks:read"]}
    payload.update(body)
    return _reviewed(client, _as(who), "create", **payload)


def _change(client, who, key_id, action):
    return _reviewed(client, _as(who), action, key_id)


# ---- create / list / use ----------------------------------------------------

def test_create_shows_secret_once_and_stores_only_its_hash(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import api_keys, rbac
    rbac.set_role("user:alice", "operator")
    c = _client()

    r = _create(c, "alice", scopes=["tasks:read", "tasks:write"])
    assert r.status_code == 201, r.text
    body = r.json()
    secret = body["secret"]
    assert secret.startswith("lwk_") and len(secret) > 40
    assert "A new key is shown once" in body["notice"]  # the secret is shown once
    assert body["key"]["prefix"] == secret[:12]
    assert body["key"]["scopes"] == ["tasks:read", "tasks:write"]
    assert body["key"]["owner"] == "user:alice"
    # Only the digest is on disk; never the secret, never the prefix beyond display.
    raw = api_keys.store_path().read_text()
    assert secret not in raw
    assert hashlib.sha256(secret.encode()).hexdigest() in raw

    listed = c.get("/api/v1/api-keys", headers=_as("alice")).json()
    assert [k["id"] for k in listed["keys"]] == [body["key"]["id"]]
    assert "secret" not in listed["keys"][0]
    assert listed["keys"][0]["status"] == "active"
    # ~90 days by default.
    assert abs(listed["keys"][0]["expires_at"] - (time.time() + 90 * 86400)) < 120


def test_key_authenticates_as_its_owner_and_records_last_use(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    secret = _create(c, "alice").json()["secret"]

    r = c.get("/api/v1/account/me", headers=_key(secret))
    assert r.status_code == 200, r.text
    assert r.json()["signed_in"] is True
    # A read-only key: view yes, operate no -- even though Alice may operate.
    allowed = {a["label"]: a["allowed"] for a in r.json()["abilities"]}
    assert allowed["See work and results"] and not allowed["Start and run tasks"]

    listed = c.get("/api/v1/api-keys", headers=_as("alice")).json()["keys"][0]
    assert listed["last_used_at"] is not None
    assert listed["last_used_ip"] == "testclient"


def test_last_used_write_is_rate_limited(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import api_keys, rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    secret = _create(c, "alice").json()["secret"]
    writes = []
    real_write = api_keys._write
    monkeypatch.setattr(api_keys, "_write", lambda data: (writes.append(1), real_write(data)))
    for _ in range(5):
        assert c.get("/api/v1/account/me", headers=_key(secret)).status_code == 200
    assert len(writes) == 1


def test_unknown_key_is_refused_and_never_falls_back_to_ambient_identity(monkeypatch):
    _sign_in_map(monkeypatch)
    c = _client()
    r = c.get("/api/v1/account/me", headers=_key("lwk_" + "x" * 43))
    assert r.status_code == 401
    assert r.json()["detail"] == "This API key is not recognised."


# ---- scopes -----------------------------------------------------------------

def test_read_scope_cannot_call_a_write_route_or_an_admin_route(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    rbac.set_role("user:alice", "admin")
    c = _client()
    secret = _create(c, "alice", scopes=["tasks:read"]).json()["secret"]

    # Alice herself may operate ...
    assert c.post("/api/v1/graph/rebuild", headers=_as("alice")).status_code != 403
    # ... but her read-only key may not, and the message says why.
    r = c.post("/api/v1/graph/rebuild", headers=_key(secret))
    assert r.status_code == 403
    assert "does not have a scope" in r.json()["detail"]
    r = c.get("/api/v1/service-accounts", headers=_key(secret))
    assert r.status_code == 403
    # Reading still works.
    assert c.get("/api/v1/account/me", headers=_key(secret)).status_code == 200


def test_write_scope_allows_the_write_route(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    secret = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    assert c.post("/api/v1/graph/rebuild", headers=_key(secret)).status_code != 403


def test_task_and_approval_scopes_do_not_cross_authorize(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    c = _client()
    task_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    approval_key = _create(c, "alice", scopes=["approvals:decide"]).json()["secret"]
    both_key = _create(c, "alice", scopes=["tasks:write", "approvals:decide"]).json()["secret"]

    assert c.post("/api/v1/graph/rebuild", headers=_key(task_key)).status_code != 403
    assert c.post("/api/v1/graph/rebuild", headers=_key(approval_key)).status_code == 403
    assert c.get("/api/v1/approvals", headers=_key(task_key)).status_code == 403
    assert c.get("/api/v1/approvals", headers=_key(approval_key)).status_code == 200
    assert c.get("/approvals", headers=_key(task_key)).status_code == 403
    assert c.get("/approvals", headers=_key(approval_key)).status_code == 200
    # Queue claim and vote are action gates, even without a matching approval.
    for suffix in ("claim", "approve"):
        path = f"/api/v1/approvals/424242/{suffix}"
        assert c.post(path, headers=_key(task_key)).status_code == 403
        assert c.post(path, headers=_key(approval_key)).status_code == 404
    assert c.get("/api/v1/approvals", headers=_key(both_key)).status_code == 200
    assert c.post("/api/v1/graph/rebuild", headers=_key(both_key)).status_code != 403


def test_flow_decision_authority_uses_approval_scope_off_queue(monkeypatch):
    _sign_in_map(monkeypatch)
    from fastapi import HTTPException, Request
    from maverick_dashboard import auth, rbac
    from maverick_dashboard.approval_authority import require_approval_authority

    rbac.set_role("user:alice", "operator")
    c = _client()
    task_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    approval_key = _create(c, "alice", scopes=["approvals:decide"]).json()["secret"]

    def request_for(secret):
        request = Request({"type": "http", "method": "POST",
                           "path": "/api/v1/flows/runs/run-1/resume", "headers": [],
                           "client": ("testclient", 1234)})
        request.state.principal = auth._authenticate_api_key(request, secret)
        return request

    with pytest.raises(HTTPException) as denied:
        require_approval_authority(
            request_for(task_key), action="flow.approval.decide", resource="run-1",
        )
    assert denied.value.status_code == 403
    authority = require_approval_authority(
        request_for(approval_key), action="flow.approval.decide", resource="run-1",
    )
    assert authority.action == "flow.approval.decide"


def test_task_key_cannot_read_approval_cards_through_other_pages(monkeypatch, tmp_path):
    _sign_in_map(monkeypatch)
    from fastapi import Request
    from maverick.world_model import WorldModel
    from maverick_dashboard import auth, rbac
    from maverick_dashboard.content_access import can_read_approval

    rbac.set_role("user:alice", "operator")
    c = _client()
    task_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    approval_key = _create(c, "alice", scopes=["approvals:decide"]).json()["secret"]
    world = WorldModel(tmp_path / "world.db")
    approval = world.get_approval(world.create_approval(
        "reviewed change", requested_by="user:alice", detail="private approval card",
    ))

    def request_for(secret):
        request = Request({"type": "http", "method": "GET", "path": "/oversight",
                           "headers": [], "client": ("testclient", 1234)})
        request.state.principal = auth._authenticate_api_key(request, secret)
        return request

    assert not can_read_approval(request_for(task_key), approval, world)
    assert can_read_approval(request_for(approval_key), approval, world)


def test_task_key_cannot_make_domain_review_decisions(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    c = _client()
    task_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    decisions = (
        ("/api/v1/security/evidence/missing/decision",
         {"decision": "approved", "rationale": "Reviewed", "expected_revision": 1}),
        ("/api/v1/security/vendors/missing/decision",
         {"decision": "approved", "rationale": "Reviewed", "expected_revision": 1}),
        ("/api/v1/consent/decisions", {"profile_id": "profile", "purpose_id": "purpose"}),
        ("/api/v1/content-access/missing/decision",
         {"decision": "approve", "expected_revision": 1}),
    )
    for path, body in decisions:
        response = c.post(path, json=body, headers=_key(task_key))
        assert response.status_code == 403, (path, response.text)
        assert "does not have a scope" in response.json()["detail"]


def test_admin_scope_keeps_both_actions_and_owner_demotion_caps_approval(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "admin")
    rbac.set_role("user:bob", "operator")
    c = _client()
    admin_key = _create(c, "alice", scopes=["admin"]).json()["secret"]
    approval_key = _create(c, "bob", scopes=["approvals:decide"]).json()["secret"]

    assert c.get("/api/v1/approvals", headers=_key(admin_key)).status_code == 200
    assert c.post("/api/v1/graph/rebuild", headers=_key(admin_key)).status_code != 403
    assert c.get("/api/v1/approvals", headers=_key(approval_key)).status_code == 200
    rbac.set_role("user:bob", "viewer")
    assert c.get("/api/v1/approvals", headers=_key(approval_key)).status_code == 403


def test_key_cannot_exceed_owner_role(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:vic", "viewer")
    c = _client()
    r = _create(c, "vic", scopes=["tasks:read", "tasks:write"])
    # The review refuses it before anything is minted (422, plain words).
    assert r.status_code == 422
    assert "never do more than" in r.json()["detail"]
    # The page only offers the scopes the role allows.
    assert c.get("/api/v1/api-keys", headers=_as("vic")).json()["scopes_available"] == ["tasks:read"]


def test_demoting_the_owner_shrinks_the_key(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    secret = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    assert c.post("/api/v1/graph/rebuild", headers=_key(secret)).status_code != 403
    rbac.set_role("user:alice", "viewer")
    assert c.post("/api/v1/graph/rebuild", headers=_key(secret)).status_code == 403


# ---- rotation / expiry / revocation ------------------------------------------

def _age(key_id: str, **fields):
    from maverick_dashboard import api_keys
    with api_keys._locked(api_keys.store_path()):
        data = api_keys._load()
        data["keys"][key_id].update(fields)
        api_keys._write(data)


def test_rotate_keeps_old_key_for_the_grace_period_then_stops_it(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    first = _create(c, "alice", scopes=["tasks:read"]).json()
    old_secret, old_id = first["secret"], first["key"]["id"]

    r = _change(c, "alice", old_id, "rotate")
    assert r.status_code == 200, r.text
    new_secret, new_key = r.json()["secret"], r.json()["key"]
    assert new_secret != old_secret and new_key["rotated_from"] == old_id
    assert new_key["scopes"] == ["tasks:read"] and new_key["label"] == "nightly report"
    # Both work during the grace period.
    assert c.get("/api/v1/account/me", headers=_key(old_secret)).status_code == 200
    assert c.get("/api/v1/account/me", headers=_key(new_secret)).status_code == 200
    listed = {k["id"]: k for k in c.get("/api/v1/api-keys", headers=_as("alice")).json()["keys"]}
    assert listed[old_id]["status"] == "rotating"
    assert abs(listed[old_id]["grace_until"] - (time.time() + 24 * 3600)) < 120
    # Grace over: the old key stops with a plain message; the new one goes on.
    _age(old_id, grace_until=time.time() - 1)
    r = c.get("/api/v1/account/me", headers=_key(old_secret))
    assert r.status_code == 401
    assert "rotated" in r.json()["detail"]
    assert c.get("/api/v1/account/me", headers=_key(new_secret)).status_code == 200
    # A rotated-out key cannot be rotated again.
    stale = _change(c, "alice", old_id, "rotate")
    assert stale.status_code == 409 and "no longer supports this change" in stale.json()["detail"]


def test_expired_key_fails_with_a_plain_message_and_the_page_warns_before(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    made = _create(c, "alice", expires_in_days=3).json()
    listed = c.get("/api/v1/api-keys", headers=_as("alice")).json()
    assert listed["expiring_soon"] == [made["key"]["id"]]
    assert listed["keys"][0]["status"] == "expiring"

    _age(made["key"]["id"], expires_at=time.time() - 1)
    r = c.get("/api/v1/account/me", headers=_key(made["secret"]))
    assert r.status_code == 401
    assert r.json()["detail"].startswith("This API key has expired.")


def test_expiry_is_capped_by_the_installation_maximum(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    r = _create(c, "alice", expires_in_days=400)
    # The review refuses both before anything is minted (422).
    assert r.status_code == 422 and "at most 365 days" in r.json()["detail"]
    assert _create(c, "alice", expires_in_days=0).status_code == 422


def test_revoke_stops_the_key_at_once_and_others_cannot_touch_it(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    rbac.set_role("user:bob", "operator")
    c = _client()
    made = _create(c, "alice").json()
    key_id = made["key"]["id"]
    # Bob cannot see, revoke or rotate Alice's key (404: no existence oracle).
    assert c.get("/api/v1/api-keys", headers=_as("bob")).json()["keys"] == []
    assert _change(c, "bob", key_id, "revoke").status_code == 404
    assert _change(c, "bob", key_id, "rotate").status_code == 404

    r = _change(c, "alice", key_id, "revoke")
    # A revocation issues no secret; its record names the current key.
    assert r.status_code == 200 and r.json()["current_key"]["status"] == "revoked"
    r = c.get("/api/v1/account/me", headers=_key(made["secret"]))
    assert r.status_code == 401 and r.json()["detail"] == "This API key was revoked."


def test_a_key_can_list_its_owner_s_keys(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    secret = _create(c, "alice").json()["secret"]
    # The key acts as Alice on the keys API too (view scope).
    assert c.get("/api/v1/api-keys", headers=_key(secret)).status_code == 200


def test_api_key_cannot_mint_rotate_or_revoke_credentials(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    rbac.set_role("user:alice", "admin")
    c = _client()
    read_key = _create(c, "alice", scopes=["tasks:read"]).json()
    admin_key = _create(c, "alice", scopes=["admin"]).json()
    account = c.post("/api/v1/service-accounts",
                     json={"name": "existing-sync", "role": "viewer"},
                     headers=_as("alice"))
    assert account.status_code == 201

    for bearer in (read_key["secret"], admin_key["secret"]):
        headers = _key(bearer)
        assert c.get("/api/v1/api-keys", headers=headers).status_code == 200
        assert c.get("/account/api-keys", headers=headers).status_code == 403
        assert c.post("/api/v1/api-keys",
                      json={"label": "elevated", "scopes": ["admin"]},
                      headers=headers).status_code == 403
        assert c.post(f"/api/v1/api-keys/{admin_key['key']['id']}/rotate",
                      headers=headers).status_code == 403
        assert c.post(f"/api/v1/api-keys/{admin_key['key']['id']}/revoke",
                      headers=headers).status_code == 403
        assert c.post("/api/v1/service-accounts", json={"name": "new-sync", "role": "viewer"},
                      headers=headers).status_code == 403
        assert c.post("/api/v1/service-accounts/existing-sync/disable",
                      headers=headers).status_code == 403

    # The signed-in owner still manages and rotates keys in the product.
    assert len(c.get("/api/v1/api-keys", headers=_as("alice")).json()["keys"]) == 2
    assert rbac.get_stored_role("user:svc:existing-sync") == "viewer"
    assert _change(c, "alice", admin_key['key']['id'], "rotate").status_code == 200


# ---- service accounts -------------------------------------------------------

def test_admin_creates_service_account_which_holds_keys_but_cannot_sign_in(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    rbac.set_role("user:alice", "operator")
    c = _client()

    # Only administrators.
    assert c.post("/api/v1/service-accounts", json={"name": "billing-sync", "role": "operator"},
                  headers=_as("alice")).status_code == 403
    r = c.post("/api/v1/service-accounts",
               json={"name": "billing-sync", "role": "operator", "description": "Posts invoices"},
               headers=_as("root"))
    assert r.status_code == 201, r.text
    account = r.json()["service_account"]
    assert account["principal"] == "user:svc:billing-sync"
    assert rbac.get_stored_role("user:svc:billing-sync") == "operator"
    assert c.post("/api/v1/service-accounts", json={"name": "billing-sync", "role": "viewer"},
                  headers=_as("root")).status_code == 400

    # A key for it, minted by the admin, acts as the account within its role.
    r = _create(c, "root", owner="user:svc:billing-sync", scopes=["tasks:write"])
    assert r.status_code == 201, r.text
    secret = r.json()["secret"]
    me = c.get("/api/v1/account/me", headers=_key(secret))
    assert me.status_code == 200 and me.json()["signed_in"] is True
    assert c.get("/api/v1/api-keys", headers=_key(secret)).json()["you"] == "user:svc:billing-sync"
    # An admin scope is more than the account's operator role.
    assert _create(c, "root", owner="user:svc:billing-sync", scopes=["admin"]).status_code == 422
    # A non-admin cannot mint for it.
    assert _create(c, "alice", owner="user:svc:billing-sync").status_code == 403

    # The subject can never sign in interactively, even if an IdP issued it.
    assert c.get("/api/v1/account/me", headers=_as("svc:billing-sync")).status_code == 401

    # Admin overview lists the account and every key.
    overview = c.get("/api/v1/api-keys?all=1", headers=_as("root")).json()
    assert overview["showing_everyone"] and overview["service_accounts"][0]["slug"] == "billing-sync"
    assert overview["service_accounts"][0]["keys"][0]["scopes"] == ["tasks:write"]

    # Disabling revokes all of its keys and removes the role.
    r = c.post("/api/v1/service-accounts/billing-sync/disable", headers=_as("root"))
    assert r.status_code == 200 and r.json()["service_account"]["disabled_at"]
    assert c.get("/api/v1/account/me", headers=_key(secret)).status_code == 401
    assert rbac.get_stored_role("user:svc:billing-sync") is None
    gone = _create(c, "root", owner="user:svc:billing-sync")
    assert gone.status_code == 409 and "no longer available" in gone.json()["detail"]


# ---- static token / break-glass ---------------------------------------------

def test_static_token_still_works_and_is_audited_as_break_glass(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-break-glass-token-for-tests")  # pragma: allowlist secret
    rows = []
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", lambda kind, **payload: rows.append((kind, payload)) or True)
    c = _client()
    tok = {"Authorization": "Bearer static-break-glass-token-for-tests"}
    assert c.get("/api/v1/account/me", headers=tok).status_code == 200
    assert c.get("/api/v1/account/me", headers=tok).status_code == 200
    assert _reviewed(c, tok, "create", label="recovery", scopes=["tasks:read"]).status_code == 201
    kinds = [getattr(k, "value", k) for k, _p in rows]
    assert kinds.count("break_glass_token_used") == 1  # rate-limited
    payload = next(p for k, p in rows if getattr(k, "value", k) == "break_glass_token_used")
    assert payload["path"] == "/api/v1/account/me"
    # A wrong bearer that is not a key is still refused.
    assert c.get("/api/v1/account/me", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_settings_page_warns_while_the_static_token_is_set(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-break-glass-token-for-tests")  # pragma: allowlist secret
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: True)
    c = _client()
    page = c.get("/settings", headers={"Authorization": "Bearer static-break-glass-token-for-tests"})
    assert page.status_code == 200
    assert "shared server access token is set" in page.text
    assert 'href="/account/api-keys"' in page.text


def test_key_reaches_a_remote_caller_in_no_token_mode(monkeypatch):
    """Without a static token the dashboard is loopback-only; a key is an
    explicit credential the local operator minted, so it may come from
    another computer (and still fails closed when wrong)."""
    from maverick_dashboard import api_keys
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: True)
    key, secret = api_keys.create_key(label="remote script", scopes=["tasks:read"],
                                      owner="user:local", created_by="user:local")
    from maverick_dashboard.app import app
    remote = TestClient(app, base_url="http://127.0.0.1", client=("203.0.113.9", 4321))
    assert remote.get("/api/v1/account/me").status_code == 401
    assert remote.get("/api/v1/account/me", headers=_key("lwk_" + "y" * 43)).status_code == 401
    r = remote.get("/api/v1/api-keys", headers=_key(secret))
    assert r.status_code == 200, r.text
    assert r.json()["you"] == "user:local"


# ---- hygiene ----------------------------------------------------------------

def test_secrets_scrubber_redacts_keys():
    from maverick.secrets import scrub
    text = "using lwk_" + "A1b2C3d4" * 6 + " for the report"
    assert "lwk_" not in scrub(text) and "REDACTED" in scrub(text)
    assert "lwk_" not in scrub("Authorization: Bearer lwk_" + "z" * 43)


def test_disabled_setting_turns_the_feature_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_API_KEYS", "0")
    c = _client()
    assert c.get("/api/v1/api-keys").status_code == 404
    # The page stays reachable and says the feature is off: its controls read
    # ``enabled`` from the review catalog and stay disabled.
    assert c.get("/account/api-keys").status_code == 200
    assert c.get("/api/v1/access-key-requests").json()["enabled"] is False
    from maverick_dashboard import api_keys
    with pytest.raises(api_keys.ApiKeyError):
        api_keys.create_key(label="x", scopes=["tasks:read"], owner="user:local", created_by="")


def test_page_renders_for_a_signed_in_person(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "viewer")
    page = _client().get("/account/api-keys", headers=_as("alice"))
    assert page.status_code == 200
    assert "Copy this key now. You won't see it again." in page.text


def test_corrupt_store_refuses_every_key(monkeypatch, tmp_path):
    from maverick_dashboard import api_keys
    api_keys.store_path().write_text("{not json")
    verified, reason = api_keys.verify("lwk_" + "q" * 43)
    assert verified is None and "unavailable" in reason
    data = json.dumps({"keys": {"k": {"id": "k", "label": "x"}}, "service_accounts": {}})
    api_keys.store_path().write_text(data)
    assert api_keys.verify("lwk_" + "q" * 43)[0] is None


# ---- personal-state mutators honour the key's scopes -------------------------

def test_read_only_key_cannot_change_the_owner_s_personal_state(monkeypatch):
    """A tasks:read key could mint a chat link code (a sign-in for the owner's
    role) or point the owner's daily summary at another address, because the
    personal pages only asked for the view floor."""
    _sign_in_map(monkeypatch)
    from maverick import channel_identities, user_preferences
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    read_key = _create(c, "alice", scopes=["tasks:read"]).json()["secret"]

    def post(path, headers, **data):
        return c.post(path, data=data, headers=headers, follow_redirects=False)

    refused = [
        post("/me/channels/link-code", _key(read_key), channel="slack"),
        post("/me/preferences", _key(read_key), time_zone="UTC", digest_hour=8,
             email="attacker@example.com", digest_enabled="on"),
        post("/me/channels/unlink", _key(read_key), channel="slack", external_id="U1"),
        post("/me/digest/send-now", _key(read_key)),
        c.put("/api/v1/workspace/active-tenant", json={"tenant_id": None}, headers=_key(read_key)),
    ]
    assert [r.status_code for r in refused] == [403] * 5, [r.text for r in refused]
    assert all("does not have a scope" in r.json()["detail"] for r in refused)
    # Nothing was issued or saved on the owner's account.
    assert user_preferences.get_preferences("user:alice")["email"] == ""
    assert channel_identities.principal_for("slack", "U_ATTACKER") is None

    # Reading the same page still works for the read-only key.
    assert c.get("/api/v1/me/work", headers=_key(read_key)).status_code == 200


def test_write_key_and_the_signed_in_owner_still_use_personal_state(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick import user_preferences
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    write_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    both_key = _create(c, "alice", scopes=["tasks:write", "approvals:decide"]).json()["secret"]

    def post(path, headers, **data):
        return c.post(path, data=data, headers=headers, follow_redirects=False)

    # The signed-in owner (no key) is unchanged, whatever the role floor.
    assert post("/me/channels/link-code", _as("alice"), channel="slack").status_code == 200
    saved = post("/me/preferences", _as("alice"), time_zone="UTC", digest_hour=9,
                 email="alice@example.com", digest_enabled="on")
    assert saved.status_code == 303
    assert user_preferences.get_preferences("user:alice")["digest_hour"] == 9

    # A write-scope key may adjust preferences and the workspace picker ...
    saved = post("/me/preferences", _key(write_key), time_zone="UTC", digest_hour=10,
                 email="alice@example.com", digest_enabled="on")
    assert saved.status_code == 303
    assert user_preferences.get_preferences("user:alice")["digest_hour"] == 10
    assert c.put("/api/v1/workspace/active-tenant", json={"tenant_id": None},
                 headers=_key(write_key)).status_code == 200
    # ... but a chat link lets the chat account both start tasks and decide
    # approvals, so a key needs both of those scopes to mint its code.
    refused = post("/me/channels/link-code", _key(write_key), channel="slack")
    assert refused.status_code == 403
    assert post("/me/channels/link-code", _key(both_key), channel="slack").status_code == 200


# ---- mount prefix --------------------------------------------------------------

def test_key_scope_is_chosen_from_the_route_not_the_mount_prefix(monkeypatch):
    """Behind a mount prefix the request path still starts with it; the scope a
    key needs must come from the route inside the application."""
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    from maverick_dashboard.app import app

    rbac.set_role("user:alice", "operator")
    plain = _client()
    task_key = _create(plain, "alice", scopes=["tasks:write"]).json()["secret"]
    approval_key = _create(plain, "alice", scopes=["approvals:decide"]).json()["secret"]
    mounted = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, root_path="/lw")

    # Same answers as the unprefixed paths in the scope test above.
    assert mounted.get("/lw/api/v1/approvals", headers=_key(task_key)).status_code == 403
    assert mounted.get("/lw/api/v1/approvals", headers=_key(approval_key)).status_code == 200
    assert mounted.post("/lw/api/v1/approvals/424242/approve", headers=_key(task_key)).status_code == 403
    assert mounted.post("/lw/api/v1/approvals/424242/approve", headers=_key(approval_key)).status_code == 404


# ---- pack editing honours key scopes -------------------------------------------

def test_read_key_of_a_pinned_admin_cannot_use_the_pack_editing_routes(monkeypatch, tmp_path):
    _sign_in_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    from maverick_dashboard import rbac
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    rbac.set_role("user:alice", "admin")
    c = _client()
    read_key = _create(c, "alice", scopes=["tasks:read"]).json()["secret"]
    write_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    admin_key = _create(c, "alice", scopes=["settings:write"]).json()["secret"]

    routes = (
        ("/api/v1/agents/finance_ap/validate", {}),
        ("/api/v1/agents/finance_ap/publish-check", {}),
        ("/api/v1/agents/finance_ap/override", {}),
        ("/api/v1/agents/finance_ap/graduate", {"expected_generation": "0" * 64}),
        ("/api/v1/roles/writer/override", {}),
    )
    for path, body in routes:
        for secret in (read_key, write_key):
            refused = c.post(path, json=body, headers=_key(secret))
            assert refused.status_code == 403, (path, refused.status_code, refused.text)
            assert "does not have a scope" in refused.json()["detail"]
        # A key with an administrator scope still reaches the route's own logic,
        # as does the pinned admin signed in.
        assert c.post(path, json=body, headers=_key(admin_key)).status_code != 403, path
        assert c.post(path, json=body, headers=_as("alice")).status_code != 403, path


# ---- break-glass audit window ---------------------------------------------------

def test_break_glass_requests_keep_failing_while_their_audit_is_refused(monkeypatch):
    """The hourly window must start only once a row was written; otherwise the
    first request fails and every later one is admitted unaudited."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-break-glass-token-for-tests")  # pragma: allowlist secret
    import maverick.audit as audit_pkg
    from maverick.audit import AuditRefused
    rows = []
    refuse = {"on": True}

    def audit_event(kind, **payload):
        if refuse["on"]:
            raise AuditRefused("custody unavailable")
        rows.append(kind)
        return True

    monkeypatch.setattr(audit_pkg, "audit_event", audit_event)
    from maverick_dashboard.app import app
    c = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, raise_server_exceptions=False)
    tok = {"Authorization": "Bearer static-break-glass-token-for-tests"}

    codes = [c.get("/api/v1/account/me", headers=tok).status_code for _ in range(4)]
    assert all(code >= 400 for code in codes), codes
    assert rows == []

    refuse["on"] = False
    assert c.get("/api/v1/account/me", headers=tok).status_code == 200
    assert c.get("/api/v1/account/me", headers=tok).status_code == 200
    assert len(rows) == 1  # written once, then rate-limited for the hour


def test_break_glass_requests_keep_failing_while_their_audit_is_not_written(monkeypatch):
    """An unwritable audit sink makes ``audit_event`` return False instead of
    raising. No row exists, so the request fails and the window stays shut."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-break-glass-token-for-tests")  # pragma: allowlist secret
    import maverick.audit as audit_pkg
    attempts = []
    written = {"ok": False}

    def audit_event(kind, **payload):
        if getattr(kind, "value", kind) == "break_glass_token_used":
            attempts.append(written["ok"])
        return written["ok"]

    monkeypatch.setattr(audit_pkg, "audit_event", audit_event)
    from maverick_dashboard.app import app
    c = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, raise_server_exceptions=False)
    tok = {"Authorization": "Bearer static-break-glass-token-for-tests"}

    codes = [c.get("/api/v1/account/me", headers=tok).status_code for _ in range(3)]
    assert codes == [503, 503, 503], codes
    assert attempts == [False, False, False]  # every request tried to record itself

    written["ok"] = True
    assert c.get("/api/v1/account/me", headers=tok).status_code == 200
    assert c.get("/api/v1/account/me", headers=tok).status_code == 200
    assert attempts == [False, False, False, True]  # then rate-limited for the hour


# ---- a key bound to a workspace fails closed ------------------------------------

def _workspace_key(monkeypatch, secret_scopes=("tasks:read",)):
    """Alice (an operator, not a global admin) is a member of workspace ``acme``
    and holds a key bound to it."""
    _sign_in_map(monkeypatch)
    from maverick.tenant import registry
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    registry.create_tenant("acme")
    rbac.set_tenant_role("acme", "user:alice", "operator")
    c = _client()
    created = _create(c, "alice", scopes=list(secret_scopes), workspace="acme")
    assert created.status_code == 201, created.text
    return c, created.json()["secret"]


def test_key_bound_to_a_workspace_stops_working_when_the_workspace_is_paused(monkeypatch):
    c, secret = _workspace_key(monkeypatch)
    from maverick.tenant import registry
    # A route with no permission call of its own, so only the pin can refuse it.
    assert c.get("/api/v1/flywheel", headers=_key(secret)).status_code == 200

    registry.suspend_tenant("acme")
    refused = c.get("/api/v1/flywheel", headers=_key(secret))
    assert refused.status_code == 403, refused.text
    assert "workspace" in refused.json()["detail"].lower()
    # The owner's own browser session still falls back to the default workspace.
    assert c.get("/api/v1/flywheel", headers=_as("alice")).status_code == 200


def test_key_bound_to_a_workspace_stops_working_when_its_owner_leaves(monkeypatch):
    c, secret = _workspace_key(monkeypatch)
    from maverick_dashboard import rbac
    assert c.get("/api/v1/flywheel", headers=_key(secret)).status_code == 200

    rbac.remove_tenant_role("acme", "user:alice")
    refused = c.get("/api/v1/flywheel", headers=_key(secret))
    assert refused.status_code == 403, refused.text
    assert c.get("/api/v1/account/me", headers=_key(secret)).status_code == 403


# ---- service account role and key store stay in step -----------------------------

def _refuse_audit_kind(monkeypatch, kind_name):
    """Refuse only one audit kind; every other row is written as usual."""
    import maverick.audit as audit_pkg
    real = audit_pkg.audit_event

    def audit_event(kind, **payload):
        if kind == getattr(audit_pkg.EventKind, kind_name):
            raise audit_pkg.AuditRefused("custody unavailable")
        return real(kind, **payload)

    monkeypatch.setattr(audit_pkg, "audit_event", audit_event)


def test_refused_service_account_audit_leaves_no_role_behind(monkeypatch):
    from maverick.audit import AuditRefused
    from maverick_dashboard import api_keys, rbac
    _refuse_audit_kind(monkeypatch, "SERVICE_ACCOUNT_CHANGED")

    with pytest.raises(AuditRefused):
        api_keys.create_service_account("billing", "admin", actor="user:root")

    assert api_keys.list_service_accounts() == []
    # No orphan admin-role principal for an account that does not exist.
    assert rbac.get_stored_role("user:svc:billing") is None
    assert "user:svc:billing" not in rbac.list_users()


def test_service_account_creation_still_assigns_the_role(monkeypatch):
    from maverick_dashboard import api_keys, rbac
    account = api_keys.create_service_account("billing", "operator", actor="user:root")
    assert account.principal == "user:svc:billing"
    assert rbac.get_stored_role("user:svc:billing") == "operator"
    assert [a.slug for a in api_keys.list_service_accounts()] == ["billing"]


def test_disable_service_account_retry_finishes_a_failed_role_removal(monkeypatch):
    from maverick_dashboard import api_keys, rbac
    api_keys.create_service_account("billing", "operator", actor="user:root")
    real_remove = rbac.remove_user
    failing = {"on": True}

    def remove_user(principal, **kwargs):
        if failing["on"]:
            raise OSError("roster unavailable")
        return real_remove(principal, **kwargs)

    monkeypatch.setattr(rbac, "remove_user", remove_user)
    with pytest.raises(OSError):
        api_keys.disable_service_account("billing", actor="user:root")
    # The account is already off, but its role is still on the roster.
    assert api_keys.get_service_account("billing").disabled_at is not None
    assert rbac.get_stored_role("user:svc:billing") == "operator"

    failing["on"] = False
    api_keys.disable_service_account("billing", actor="user:root")
    assert rbac.get_stored_role("user:svc:billing") is None


# ---- a damaged store fails closed, whatever the damage ---------------------------

def _damaged_store(*, scopes=None, action=None, state=None):
    key = {"id": "k1", "label": "x", "owner": "user:alice", "prefix": "lwk_abcd",
           "secret_sha256": "0" * 64, "scopes": scopes if scopes is not None else ["tasks:read"],
           "workspace": "", "created_at": 1.0, "expires_at": 2.0, "created_by": "",
           "last_used_at": None, "last_used_ip": "", "revoked_at": None, "grace_until": None,
           "replaced_by": "", "rotated_from": ""}
    request = {"operation": "a" * 32, "actor": "user:alice", "context": "b" * 64,
               "binding": "c" * 64, "action": action or "create",
               "state": state or "started", "key_id": "", "recorded_at": 1.0}
    return {"keys": {"k1": key}, "service_accounts": {}, "issuance_requests": {"a" * 32: request}}


@pytest.mark.parametrize("damage", [
    {"scopes": [["tasks:read"]]},
    {"scopes": [{"tasks:read": 1}]},
    {"action": ["create"]},
    {"action": {"create": True}},
    {"state": ["started"]},
])
def test_unhashable_damage_in_the_store_is_a_store_error_not_a_crash(damage):
    from maverick_dashboard import api_keys
    api_keys.store_path().write_text(json.dumps(_damaged_store(**damage)))

    with pytest.raises(api_keys.ApiKeyStoreError):
        api_keys.list_keys()
    verified, reason = api_keys.verify("lwk_" + "q" * 43)
    assert verified is None and "unavailable" in reason


def test_damaged_store_answers_401_for_a_key_and_503_for_the_listing(monkeypatch):
    _sign_in_map(monkeypatch)
    from maverick_dashboard import api_keys, rbac
    rbac.set_role("user:alice", "operator")
    api_keys.store_path().write_text(json.dumps(_damaged_store(scopes=[["tasks:read"]])))
    from maverick_dashboard.app import app
    c = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, raise_server_exceptions=False)

    keyed = c.get("/api/v1/account/me", headers=_key("lwk_" + "q" * 43))
    assert keyed.status_code == 401 and "unavailable" in keyed.json()["detail"]
    listing = c.get("/api/v1/api-keys", headers=_as("alice"))
    assert listing.status_code == 503, listing.text


def test_read_only_key_cannot_write_the_owner_s_preferences_or_alert_settings(monkeypatch):
    """The saved choices (display, chat defaults, alert muting, pinned pages, the
    sidebar layout) belong to the owner's account, so a key needs a write scope."""
    _sign_in_map(monkeypatch)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")
    c = _client()
    read_key = _create(c, "alice", scopes=["tasks:read"]).json()["secret"]
    write_key = _create(c, "alice", scopes=["tasks:write"]).json()["secret"]
    ctx = "x" * 64
    routes = [
        ("/api/v1/preferences", {"expected_revision": "0" * 64, "context": ctx, "changes": {}}),
        ("/api/v1/preferences/original", {"expected_revision": "0" * 64, "context": ctx, "changes": {},
                                          "operation_id": "a" * 32}),
        ("/api/v1/preferences/display", {"key": "theme", "value": "dark", "context": ctx}),
        ("/api/v1/preferences/profile/import", {"profile": {}}),
        ("/api/v1/navigation/pins", {"op": "add", "href": "/overview", "context": ctx}),
        ("/api/v1/navigation/recent", {"path": "/overview", "context": ctx}),
        ("/api/v1/notifications/personal/preferences",
         {"context": ctx, "expected_revision": "0" * 64, "preferences": {}}),
        ("/api/v1/notifications/personal/seen", {"context": ctx, "item_id": "0" * 64}),
        ("/api/v1/notifications/personal/mute", {"context": ctx, "item_id": "0" * 64, "scope": "task"}),
        ("/api/v1/notifications/personal/unmute", {"context": ctx, "scope": "task", "key": "1"}),
    ]
    for path, body in routes:
        refused = c.post(path, json=body, headers=_key(read_key))
        assert refused.status_code == 403, (path, refused.status_code, refused.text)
        assert "does not have a scope" in refused.json()["detail"], path
        # The same call with a write scope, or by the signed-in owner, is judged on its merits.
        for headers in (_key(write_key), _as("alice")):
            answered = c.post(path, json=body, headers=headers)
            assert answered.status_code != 403 or "does not have a scope" not in answered.text, path
    refused = c.post("/navigation/areas", data={"op": "up", "area": "Work", "context": ctx},
                     headers=_key(read_key), follow_redirects=False)
    assert refused.status_code == 403 and "does not have a scope" in refused.json()["detail"]


def test_the_page_title_is_words_and_its_script_loads_once():
    # A script tag sat in the title block, which the layout puts inside
    # <title>: the browser tab and screen readers showed the tag as text.
    import re

    page = _client().get("/account/api-keys")
    assert page.status_code == 200
    title = re.search(r"<title>(.*?)</title>", page.text, re.DOTALL).group(1)
    assert title.strip() == "Access keys · Lightwork"
    assert page.text.count("lightwork-access-key-requests.js") == 1


def test_workspace_only_owner_key_tracks_saved_selection(monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.tenant import registry
    from maverick_dashboard import api_keys, rbac, workspace_tenants

    registry.create_tenant("acme")
    rbac.set_tenant_role("acme", "user:alice", "operator")
    workspace_tenants.set_selection("user:alice", "acme")
    with tenant_scope(tenant="acme"):
        _, secret = api_keys.create_key(label="integration", scopes=["tasks:read"],
                                        owner="user:alice", created_by="user:alice")
    verified, reason = api_keys.verify(secret)
    assert verified is not None, reason
    assert "view" in verified.permissions
    workspace_tenants.set_selection("user:alice", None)
    assert api_keys.verify(secret)[0] is None


def test_unreadable_group_policy_cannot_grant_root_view(monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import auth, rbac, scim_groups

    registry.create_tenant("acme")
    rbac.set_tenant_role("acme", "user:alice", "viewer")
    def broken(_name):
        raise scim_groups.GroupAccessPolicyError("unavailable")
    monkeypatch.setattr(scim_groups, "_ci_mapping", broken)
    assert auth.global_role_for_principal("user:alice") is None
