"""Approvals decided from Microsoft Teams use the dashboard's own decision path,
and the Channels page manages Teams settings, connection tests and links."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from test_support.channel_review import channel_review_token

FAKE_SECRET = "not-a-real-secret"  # pragma: allowlist secret
APP_ID = "0f0f0f0f-1111-2222-3333-444444444444"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import integration_readiness, rbac
    rbac.set_role("user:alice", "operator")
    integration_readiness._clear_for_testing()
    dash_app._world_cache.clear()
    yield
    integration_readiness._clear_for_testing()
    config.reset_config_cache()


def _world():
    from maverick_dashboard._shared import _world
    return _world()


def _card(*, expires_at=None):
    from maverick.approval_cards import build_approval_card
    return build_approval_card(
        action="email.send", summary="Email invoice 42 to the customer", target_label="Invoice 42",
        target={"invoice": 42}, parameters={"to": "customer@example.com"},
        parameter_summary=["Email invoice 42 once"], actor="user:bob", workspace="local",
        role="operator", authority_versions={"role_revision": "r1"}, input_versions={"v": "1"},
        credential_versions={"state": "resolved_again_at_execution"},
        budget={"currency": "USD", "maximum": 1.0},
        expires_at=expires_at if expires_at is not None else time.time() + 600,
        known_effects=["The customer receives the email"], unresolved_assumptions=[],
        before="Not sent", after="Sent", irreversible=True)


def _approval(risk="medium", *, card=None, requested_by="user:bob", **kw):
    from maverick.approval_cards import encode_approval_detail
    card = card or _card()
    aid = _world().create_approval("email.send", risk=risk, scope="customer 42",
                                   detail=encode_approval_detail(card), provenance="consent",
                                   requested_by=requested_by, **kw)
    return aid, card["binding_sha256"]


def _decide(**kw):
    from maverick_dashboard.approval_decisions import decide_from_channel
    base = dict(principal="user:alice", channel="teams", channel_user="aad-1")
    base.update(kw)
    return decide_from_channel(**base)


def test_channel_decision_is_recorded_and_audited_like_the_dashboard(monkeypatch):
    from maverick import audit
    seen = []
    real = audit.audit_event

    def spy(kind, **fields):
        seen.append((kind, fields))
        return real(kind, **fields)
    monkeypatch.setattr("maverick.audit.audit_event", spy)
    aid, binding = _approval()
    result = _decide(approval_id=aid, status="approved", binding=binding)
    assert result["status"] == "approved" and result["effective"] is True
    assert result["decided_by"] == "user:alice" and result["audit"] == "delivered"
    state = _world().approval_state(aid)
    assert state["status"] == "approved" and state["effective"] is True
    assert _world().get_approval(aid).decided_by == "user:alice"
    kinds = [(k, f) for k, f in seen if f.get("channel") == "teams"]
    assert kinds and kinds[-1][1]["action"] == "approval_decided_via_channel"
    assert kinds[-1][1]["decision"] == "approved" and kinds[-1][1]["approval_id"] == aid


def test_high_and_critical_need_confirmation_and_acknowledgement(monkeypatch):
    from maverick import audit
    from maverick_dashboard.approval_decisions import ApprovalDecisionRefused
    seen = []
    real = audit.audit_event

    def spy(kind, **fields):
        seen.append(fields)
        return real(kind, **fields)
    monkeypatch.setattr("maverick.audit.audit_event", spy)
    ack = {"acknowledged": True}
    for risk in ("high", "critical"):
        aid, binding = _approval(risk, undoable=True)
        with pytest.raises(ApprovalDecisionRefused, match="Confirm it") as exc:
            _decide(approval_id=aid, status="approved", binding=binding)
        assert exc.value.status_code == 428
        # The second card alone is not enough: the same acknowledgement rule as
        # the Approvals page applies (and the typed word for critical risk).
        with pytest.raises(ApprovalDecisionRefused, match="Confirm you have read") as exc:
            _decide(approval_id=aid, status="approved", binding=binding, confirmed=True)
        assert exc.value.status_code == 422
        if risk == "critical":
            with pytest.raises(ApprovalDecisionRefused, match="Type APPROVE"):
                _decide(approval_id=aid, status="approved", binding=binding, confirmed=True,
                        acknowledgement=ack)
        assert _world().approval_state(aid)["status"] == "pending"
        result = _decide(approval_id=aid, status="approved", binding=binding, confirmed=True,
                         acknowledgement={**ack, "confirmation": "approve"})
        assert result["status"] == "approved" and result["undo_seconds"] == 30
        confirmation = [f for f in seen if f.get("action") == "approval_confirmation"][-1]
        assert confirmation["approval_id"] == aid and confirmation["channel"] == "teams"
        assert confirmation["typed_confirmation"] is (risk == "critical")
    # Rejecting never needs the second step.
    aid, binding = _approval("critical")
    assert _decide(approval_id=aid, status="denied", binding="")["status"] == "denied"
    # Off by configuration: the confirm card is still shown, the rule is not.
    monkeypatch.setenv("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT", "0")
    aid, binding = _approval("high")
    assert _decide(approval_id=aid, status="approved", binding=binding,
                   confirmed=True)["status"] == "approved"


def test_undo_from_chat_uses_the_shared_undo_and_audits_it(monkeypatch):
    from maverick import audit
    from maverick_dashboard.approval_decisions import ApprovalDecisionRefused, undo_from_channel
    aid, binding = _approval(undoable=True)
    with pytest.raises(ApprovalDecisionRefused, match="no decision to undo"):
        undo_from_channel(approval_id=aid, principal="user:alice", channel="teams")
    first = _decide(approval_id=aid, status="approved", binding=binding)
    seen = []
    real = audit.audit_event

    def spy(kind, **fields):
        seen.append(fields)
        return real(kind, **fields)
    monkeypatch.setattr("maverick.audit.audit_event", spy)
    # The kernel's WorldModel.undo_approval_decision does the work: the request
    # is pending again and the next decision is a new signed audit round.
    result = undo_from_channel(approval_id=aid, principal="user:alice", channel="teams",
                               channel_user="aad-1")
    assert result == {"status": "pending", "previous_status": "approved", "undone_by": "user:alice",
                      "approval_id": aid}
    assert _world().approval_state(aid)["status"] == "pending"
    undone = [f for f in seen if f.get("action") == "approval_decision_undone"][-1]
    assert undone["channel"] == "teams" and undone["previously_decided_by"] == "user:alice"
    assert undone["channel_user"] == "aad-1"
    second = _decide(approval_id=aid, status="approved", binding=binding)
    assert second["status"] == "approved" and second["decision_id"] != first["decision_id"]
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "0")
    with pytest.raises(ApprovalDecisionRefused, match="Too late"):
        undo_from_channel(approval_id=aid, principal="user:alice", channel="teams")
    assert _world().approval_state(aid)["status"] == "approved"


def test_expired_stale_and_decided_cards_are_refused():
    from maverick_dashboard.approval_decisions import ApprovalDecisionRefused
    aid, binding = _approval(card=_card(expires_at=time.time() - 5))
    with pytest.raises(ApprovalDecisionRefused, match="expired"):
        _decide(approval_id=aid, status="approved", binding=binding)
    aid, binding = _approval()
    with pytest.raises(ApprovalDecisionRefused, match="card changed"):
        _decide(approval_id=aid, status="approved", binding="0" * 64)
    _decide(approval_id=aid, status="approved", binding=binding)
    with pytest.raises(ApprovalDecisionRefused, match="already decided") as exc:
        _decide(approval_id=aid, status="approved", binding=binding)
    assert exc.value.status_code == 404
    with pytest.raises(ApprovalDecisionRefused, match="already decided"):
        _decide(approval_id=999999, status="denied", binding="")


def test_segregation_of_duties_and_permissions_hold_for_chat():
    from maverick_dashboard import rbac
    from maverick_dashboard.approval_decisions import ApprovalDecisionRefused
    aid, binding = _approval(requested_by="user:alice", approvals_required=2)
    with pytest.raises(ApprovalDecisionRefused, match="requester can't approve"):
        _decide(approval_id=aid, status="approved", binding=binding)
    rbac.set_role("user:viewer", "viewer", actor="user:admin")
    with pytest.raises(ApprovalDecisionRefused, match="operator role") as exc:
        _decide(approval_id=aid, status="approved", binding=binding, principal="user:viewer")
    assert exc.value.status_code == 403
    with pytest.raises(ApprovalDecisionRefused, match="isn't linked"):
        _decide(approval_id=aid, status="approved", binding=binding, principal="")


def test_settings_changes_are_never_decided_from_chat():
    from maverick_dashboard import settings_quorum
    from maverick_dashboard.approval_decisions import ApprovalDecisionRefused
    aid = _world().create_approval(settings_quorum.ACTION, risk="high", scope="settings",
                                   detail="change", provenance=settings_quorum.PROVENANCE)
    with pytest.raises(ApprovalDecisionRefused, match="dashboard"):
        _decide(approval_id=aid, status="approved", binding="")


def test_send_back_from_chat_supersedes_with_the_note(monkeypatch):
    from maverick import audit
    from maverick_dashboard.approval_decisions import send_back_from_channel
    seen = []
    real = audit.audit_event

    def spy(kind, **fields):
        seen.append(fields)
        return real(kind, **fields)
    monkeypatch.setattr("maverick.audit.audit_event", spy)
    aid, binding = _approval()
    result = send_back_from_channel(approval_id=aid, principal="user:alice", channel="teams",
                                    rationale="  Which   customer? ")
    assert result["status"] == "superseded" and result["rationale"] == "Which customer?"
    assert _world().approval_state(aid)["status"] == "denied"
    revision = [f for f in seen if f.get("action") == "approval_revision_requested"][0]
    assert revision["superseded_binding_sha256"] == binding and revision["channel"] == "teams"


def test_approval_view_matches_the_queue_projection():
    from maverick_dashboard.approval_decisions import approval_view
    aid, binding = _approval("high")
    view = approval_view(aid)
    assert view["approval"]["risk"] == "high" and view["approval"]["scope"] == "customer 42"
    assert view["card"]["binding_sha256"] == binding and view["card_status"] == "current"
    aid, _ = _approval(card=_card(expires_at=time.time() - 5))
    assert approval_view(aid)["card"] is None and approval_view(aid)["card_status"] == "expired"
    assert approval_view(424242) is None


def test_dashboard_routes_still_use_the_shared_functions():
    # Local dashboard credentials have no employee identity and may decide
    # only unowned approval content; a named request needs a reviewed grant.
    aid, binding = _approval(requested_by="")
    client = TestClient(_app(), base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    r = client.post(f"/api/v1/approvals/{aid}/approve",
                    headers={"X-Lightwork-Approval-Binding": binding})
    assert r.status_code == 204
    assert _world().approval_state(aid)["status"] == "approved"


def _app():
    from maverick_dashboard.app import app
    return app


# --------------------------------------------------------- Channels page

class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


def _save_teams(client):
    r = client.post("/channels/save", data={"channel": "teams", "enabled": "on", "app_id": APP_ID,
                                              "review_token": channel_review_token(client),
                                              # A chat app with nobody permitted is refused before any
                                              # network test, so the connection test names one person.
                                              "allowed_users": "12345678-abcd-abcd-abcd-1234567890ab", "confirm_people": "yes",
                                              "app_password": FAKE_SECRET, "tenant_id": TENANT},
                    follow_redirects=False)
    assert r.status_code == 303, r.text
    from maverick import config
    config.reset_config_cache()


def test_channels_page_tests_the_teams_connection(monkeypatch):
    from maverick_dashboard import channel_check_api
    client = TestClient(_app(), base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    _save_teams(client)
    page = client.get("/channels").text
    assert "Microsoft Teams" in page and "People linked to Teams" in page and "App ID" in page
    posts = []
    monkeypatch.setattr(channel_check_api, "_post",
                        lambda url, **kw: posts.append((url, kw)) or _Resp(200, {"access_token": "t", "expires_in": 60}))
    r = client.post("/channels/test", data={"channel": "teams"}, follow_redirects=False)
    assert "saved=tested" in r.headers["location"]
    url, kw = posts[0]
    assert url == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert kw["data"]["client_id"] == APP_ID and kw["data"]["scope"] == "https://api.botframework.com/.default"
    monkeypatch.setattr(channel_check_api, "_post",
                        lambda url, **kw: _Resp(401, {"error": "invalid_client"}))
    r = client.post("/channels/test", data={"channel": "teams"}, follow_redirects=False)
    assert "saved=test_failed" in r.headers["location"]
    from maverick_dashboard import integration_readiness
    receipt = integration_readiness._RECEIPTS[("channel", "teams")]
    assert "app secret" in receipt["detail"] and FAKE_SECRET not in receipt["detail"]


def test_channels_page_links_teams_accounts(monkeypatch):
    from maverick import teams_identity
    client = TestClient(_app(), base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    r = client.post("/channels/teams/link", data={"teams_id": "Alice@Example.com", "principal": "alice",
                                                  "approver": "on"}, follow_redirects=False)
    assert r.status_code == 303 and "saved=linked" in r.headers["location"]
    assert teams_identity.link_for("alice@example.com")["approver"] is True
    page = client.get("/channels?saved=linked").text
    assert "alice@example.com" in page and "Teams account linked." in page
    assert client.post("/channels/teams/link", data={"teams_id": "bad id!", "principal": "x"}).status_code == 422
    r = client.post("/channels/teams/link-code", data={"principal": "user:carol"}, follow_redirects=False)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    import re

    code = re.search(r"One-time code:</strong> <code>([A-Za-z0-9]+)</code>", r.text).group(1)
    assert "One-time code" in r.text
    assert code not in client.get(f"/channels?saved=link_code&code={code}").text
    assert teams_identity.redeem_link_code(code, "carol-object-id") == "user:carol"
    r = client.post("/channels/teams/unlink", data={"teams_id": "alice@example.com"}, follow_redirects=False)
    assert "saved=unlinked" in r.headers["location"] and teams_identity.link_for("alice@example.com") is None
    # Same-origin + admin only.
    assert TestClient(_app(), base_url="http://127.0.0.1").post("/channels/teams/link", data={"teams_id": "a@b.c", "principal": "x"}).status_code == 403


def test_teams_settings_are_in_the_catalog():
    from maverick_dashboard import settings_catalog as catalog
    assert "channels.teams.allowed_users" in catalog.BY_ID
    assert catalog.BY_ID["channels.teams.approvals_enabled"].control == "toggle"
    assert catalog.BY_ID["channels.teams.allowed_tenants"].control == "list"


def test_an_expired_request_never_shows_its_stored_envelope_as_plain_detail():
    from maverick.approval_cards import APPROVAL_DETAIL_PREFIX
    from maverick_dashboard.approval_decisions import approval_view

    aid, _ = _approval(card=_card(expires_at=time.time() - 5))
    detail = approval_view(aid)["approval"]["detail"]
    assert APPROVAL_DETAIL_PREFIX not in detail and "Email invoice 42" not in detail
    assert "decide-by time has passed" in detail
