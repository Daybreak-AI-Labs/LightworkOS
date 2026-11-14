"""Microsoft Teams adapter: Bot Connector JWT verification, activity parsing,
replies through a fake transport, Adaptive Cards, approval invokes through the
shared decision path, identity linking and config.

No Teams tenant is used: the JWT tests sign with a locally generated RSA key
and serve its public half as the JWKS document; every HTTP call goes through a
recorded fake transport."""
from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

fastapi = pytest.importorskip("fastapi")
jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from maverick_channels import teams as teams_mod  # noqa: E402
from maverick_channels.teams import (  # noqa: E402
    BOT_ISSUER,
    SigningKeys,
    TeamsAuthError,
    TeamsChannel,
    channel_config,
    explain_token_failure,
    parse_activity,
    token_endpoint,
    verify_bot_token,
)

APP_ID = "0f0f0f0f-1111-2222-3333-444444444444"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AAD_USER = "12345678-abcd-abcd-abcd-1234567890ab"
SERVICE_URL = "https://smba.trafficmanager.net/emea/"
FAKE_SECRET = "not-a-real-secret"  # pragma: allowlist secret


# ---------------------------------------------------------------- helpers

@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key, kid="k1", endorsements=("msteams",)) -> dict:
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public.update({"kid": kid, "use": "sig", "alg": "RS256",
                   "endorsements": list(endorsements)})
    return {"keys": [public]}


def _pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _token(key, *, aud=APP_ID, iss=BOT_ISSUER, exp_delta=3600, kid="k1", alg="RS256",
           serviceurl=SERVICE_URL, **extra) -> str:
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "exp": now + exp_delta, "iat": now, "nbf": now - 10,
              "serviceurl": serviceurl, **extra}
    return jwt.encode(claims, _pem(key), algorithm=alg, headers={"kid": kid})


class FakeTransport:
    """Records every outbound call and answers from a queue or defaults."""

    def __init__(self):
        self.calls = []
        self.responses = {}

    async def __call__(self, method, url, *, headers=None, json_body=None, data=None, timeout=30.0):
        self.calls.append({"method": method, "url": url, "headers": headers or {},
                           "json": json_body, "data": data})
        if "/oauth2/v2.0/token" in url:
            return self.responses.get("token", (200, {"access_token": "tok-1", "expires_in": 3600}))
        return self.responses.get((method, url.split("/v3/")[-1]), (201, {"id": "act-777"}))


class FakeDecisions:
    """Stands in for maverick_dashboard.approval_decisions."""

    class ApprovalDecisionRefused(Exception):
        def __init__(self, detail, status_code=409):
            super().__init__(detail)
            self.detail, self.status_code = detail, status_code

    def __init__(self, risk="medium", card=True, status="pending"):
        self.calls = []
        self.risk, self.card_present, self.status = risk, card, status
        self.refuse = None
        self.eligible = {"user:alice", "user:bob"}

    def eligible_approvers(self, world, approval):
        return set(self.eligible)

    def approval_view(self, approval_id):
        card = None
        if self.card_present:
            card = {"summary": "Send the invoice", "binding_sha256": "b" * 64,
                    "target": {"label": "Invoice 42"}, "authority": {"actor": "user:bob", "role": "operator"},
                    "expires_at": time.time() + 600, "budget": {"currency": "USD", "maximum": 12.5},
                    "parameters": {"summary": ["Email invoice 42 to the customer"]},
                    "preview": {"before": "Not sent", "after": "Sent"},
                    "consequences": {"irreversible": True, "known_effects": ["The customer gets the email"],
                                     "unresolved_assumptions": []}}
        return {"approval": {"id": approval_id, "action": "email.send", "risk": self.risk,
                             "scope": "customer 42", "detail": "", "status": self.status},
                "card": card, "card_status": "current", "source_label": None}

    def decide_from_channel(self, **kw):
        self.calls.append(("decide", kw))
        if self.refuse:
            raise self.refuse
        self.status = kw["status"]
        return {"status": kw["status"], "effective": True, "decided_by": kw["principal"],
                "risk": self.risk, "audit": "delivered", "approvals_required": 1, "approved_count": 1,
                "undo_seconds": 30, "decided_at": time.time()}

    def undo_from_channel(self, **kw):
        self.calls.append(("undo", kw))
        if self.refuse:
            raise self.refuse
        self.status = "pending"
        return {"status": "pending", "previous_status": "approved", "undone_by": kw["principal"]}

    def send_back_from_channel(self, **kw):
        self.calls.append(("send_back", kw))
        return {"status": "superseded", "effective": True, "decided_by": kw["principal"],
                "risk": self.risk, "audit": "delivered", "rationale": kw["rationale"]}


class _FakeWorld:
    def get_approval(self, approval_id):
        return {"id": approval_id}


@pytest.fixture(autouse=True)
def _approval_world(monkeypatch):
    monkeypatch.setattr(teams_mod, "_approval_world", _FakeWorld)


def _channel(rsa_key, monkeypatch=None, **overrides):
    transport = FakeTransport()
    kw = dict(handler=AsyncMock(return_value="the reply"), app_id=APP_ID, app_password=FAKE_SECRET,
              tenant_id=TENANT, allowed_user_ids=[AAD_USER], approvals_enabled=True,
              transport=transport, keys=SigningKeys(jwks=_jwks(rsa_key)), decisions=FakeDecisions())
    kw.update(overrides)
    ch = TeamsChannel(**kw)
    ch.transport = transport
    return ch


def _claim_ok(monkeypatch):
    wm = MagicMock()
    wm.is_processed_message.return_value = False
    wm.mark_message_processed.return_value = True
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    return wm


def _message(text="hello agent", *, conversation_type="personal", entities=None, activity_id="m1",
             conversation_id="a:conv1", aad=AAD_USER, tenant=TENANT):
    return {"type": "message", "channelId": "msteams", "id": activity_id,
            "serviceUrl": SERVICE_URL, "text": text,
            "from": {"id": "29:user-scoped", "aadObjectId": aad, "name": "Alice"},
            "recipient": {"id": f"28:{APP_ID}", "name": "Lightwork"},
            "conversation": {"id": conversation_id, "conversationType": conversation_type},
            "channelData": {"tenant": {"id": tenant}}, "entities": entities or []}


def _invoke(verb, *, approval_id=7, risk="medium", question="", reply_to="card-1"):
    data = {"approval_id": approval_id, "binding": "b" * 64, "risk": risk}
    if question:
        data["question"] = question
    activity = _message("", activity_id="inv-1")
    activity.update({"type": "invoke", "name": "adaptiveCard/action", "replyToId": reply_to,
                     "value": {"action": {"type": "Action.Execute", "verb": verb, "data": data}}})
    return activity


def _post(ch, rsa_key, activity, *, token=None):
    client = TestClient(ch._app)
    return client.post("/webhook/teams", content=json.dumps(activity).encode(),
                       headers={"Authorization": "Bearer " + (token or _token(rsa_key))})


# ------------------------------------------------------------ JWT checks

def test_valid_connector_token_verifies(rsa_key):
    keys = SigningKeys(jwks=_jwks(rsa_key))
    claims = verify_bot_token(_token(rsa_key), app_id=APP_ID, keys=keys)
    assert claims["aud"] == APP_ID and claims["iss"] == BOT_ISSUER


@pytest.mark.parametrize("kwargs, reason", [
    ({"aud": "some-other-app"}, "audience"),
    ({"exp_delta": -3600}, "expired"),
    ({"iss": "https://evil.example"}, "issuer"),
])
def test_bad_claims_fail_closed(rsa_key, kwargs, reason):
    keys = SigningKeys(jwks=_jwks(rsa_key))
    with pytest.raises(TeamsAuthError, match=reason):
        verify_bot_token(_token(rsa_key, **kwargs), app_id=APP_ID, keys=keys)


def test_unknown_key_refreshes_once_then_refuses(rsa_key):
    fetches = []

    def fetch(url):
        fetches.append(url)
        return {"jwks_uri": "https://login.botframework.com/v1/.well-known/keys"} \
            if url.endswith("openidconfiguration") else _jwks(rsa_key, kid="k1")

    keys = SigningKeys(fetch_json=fetch)
    # Cold start: metadata + keys are fetched once and the token verifies.
    verify_bot_token(_token(rsa_key), app_id=APP_ID, keys=keys)
    assert len(fetches) == 2
    # A token signed under an unknown kid is refused; the cooldown stops a
    # refresh storm driven by attacker-chosen kids.
    with pytest.raises(TeamsAuthError):
        verify_bot_token(_token(rsa_key, kid="rotated"), app_id=APP_ID, keys=keys)
    with pytest.raises(TeamsAuthError):
        verify_bot_token(_token(rsa_key, kid="rotated-again"), app_id=APP_ID, keys=keys)
    assert len(fetches) == 2


def test_symmetric_algorithm_and_other_key_are_refused(rsa_key):
    keys = SigningKeys(jwks=_jwks(rsa_key))
    hs = jwt.encode({"iss": BOT_ISSUER, "aud": APP_ID, "exp": int(time.time()) + 60},
                    "shared", algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(TeamsAuthError, match="algorithm"):
        verify_bot_token(hs, app_id=APP_ID, keys=keys)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(TeamsAuthError, match="signature"):
        verify_bot_token(_token(other), app_id=APP_ID, keys=keys)


def test_webhook_refuses_missing_or_bad_token(rsa_key):
    ch = _channel(rsa_key)
    client = TestClient(ch._app)
    assert client.post("/webhook/teams", json=_message()).status_code == 403
    assert _post(ch, rsa_key, _message(), token=_token(rsa_key, aud="x")).status_code == 403
    # The token names the service URL it was issued for; an activity pointing
    # elsewhere is refused before anything is sent there.
    bad = _message()
    bad["serviceUrl"] = "https://attacker.example/"
    assert _post(ch, rsa_key, bad).status_code == 403
    assert not ch.handler.await_count


def test_webhook_requires_teams_channel_endorsement_and_service_url(rsa_key):
    ch = _channel(rsa_key)
    direct_line = _message("link FAKECODE")
    direct_line["channelId"] = "directline"
    assert _post(ch, rsa_key, direct_line).status_code == 403
    assert not ch.handler.await_count

    no_endorsement = _channel(rsa_key, keys=SigningKeys(jwks=_jwks(rsa_key, endorsements=())))
    assert _post(no_endorsement, rsa_key, _message()).status_code == 403
    assert not no_endorsement.handler.await_count

    missing_service_claim = _token(rsa_key, serviceurl="")
    assert _post(ch, rsa_key, _message(), token=missing_service_claim).status_code == 403
    assert not ch.handler.await_count


def test_preupgrade_teams_receipt_authority_is_legacy_only(rsa_key, monkeypatch):
    from maverick import oidc
    from maverick_channels.base import IncomingMessage

    ch = _channel(rsa_key)
    old_message = IncomingMessage(user_id="a:conv1", sender_id=AAD_USER,
                                  channel="teams", text="question")
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: False)
    assert ch._authorized(old_message, APP_ID)
    assert not ch._authorized(old_message, "another installation")
    ch.allowed_user_ids.clear()
    assert not ch._authorized(old_message, APP_ID)
    ch.allowed_user_ids.add(AAD_USER)
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    assert not ch._authorized(old_message, APP_ID)


# ------------------------------------------------------ activity parsing

def test_parse_personal_and_channel_messages():
    personal = parse_activity(_message("  do the thing "), bot_id=f"28:{APP_ID}")
    assert personal.kind == "message" and personal.text == "do the thing"
    assert personal.conversation_type == "personal" and personal.principal_key == AAD_USER
    assert personal.tenant_id == TENANT and personal.service_url == SERVICE_URL

    entities = [{"type": "mention", "text": "<at>Lightwork</at>",
                 "mentioned": {"id": f"28:{APP_ID}", "name": "Lightwork"}},
                {"type": "mention", "text": "<at>Bob</at>", "mentioned": {"id": "29:bob", "name": "Bob"}}]
    channel = parse_activity(_message("<at>Lightwork</at> summarise this for <at>Bob</at> &amp; me",
                                      conversation_type="channel", entities=entities),
                             bot_id=f"28:{APP_ID}")
    assert channel.conversation_type == "channel"
    assert channel.text == "summarise this for Bob & me"


def test_parse_conversation_update_and_ignored_types():
    added = {"type": "conversationUpdate", "channelId": "msteams", "serviceUrl": SERVICE_URL,
             "recipient": {"id": f"28:{APP_ID}"}, "membersAdded": [{"id": f"28:{APP_ID}"}],
             "conversation": {"id": "c1"}, "channelData": {"tenant": {"id": TENANT}}}
    parsed = parse_activity(added, bot_id=f"28:{APP_ID}")
    assert parsed.kind == "conversationUpdate" and parsed.bot_added is True
    assert parse_activity({"type": "typing"}, bot_id="28:x") is None
    assert parse_activity([1, 2], bot_id="28:x") is None


# ------------------------------------------------------ messages -> work

def test_message_becomes_work_and_reply_goes_to_the_thread(rsa_key, monkeypatch):
    ch = _channel(rsa_key)
    _claim_ok(monkeypatch)
    r = _post(ch, rsa_key, _message("write the weekly summary"))
    assert r.status_code == 200
    ch.handler.assert_awaited_once()
    msg = ch.handler.await_args.args[0]
    assert msg.channel == "teams" and msg.text == "write the weekly summary"
    assert msg.user_id == "a:conv1" and msg.sender_id == AAD_USER and msg.message_id == "m1"
    assert msg.provider_tenant_id == TENANT and msg.provider_sender_id == AAD_USER
    from maverick_channels.delivery import _digest
    assert msg._verified_channel_account_sha256 == _digest(APP_ID)
    token_call, reply = ch.transport.calls
    assert token_call["url"] == token_endpoint(TENANT)
    assert token_call["data"]["scope"] == "https://api.botframework.com/.default"
    assert FAKE_SECRET not in json.dumps(reply)
    assert reply["method"] == "POST"
    assert reply["url"] == SERVICE_URL.rstrip("/") + "/v3/conversations/a%3Aconv1/activities/m1"
    assert reply["headers"]["Authorization"] == "Bearer tok-1"
    assert reply["json"]["text"] == "the reply"


def test_channel_message_strips_mention_and_ignores_unknown_sender(rsa_key, monkeypatch):
    ch = _channel(rsa_key)
    _claim_ok(monkeypatch)
    entities = [{"type": "mention", "text": "<at>Lightwork</at>",
                 "mentioned": {"id": f"28:{APP_ID}", "name": "Lightwork"}}]
    _post(ch, rsa_key, _message("<at>Lightwork</at> plan the launch", conversation_type="channel",
                                entities=entities, conversation_id="19:thread@thread.tacv2"))
    assert ch.handler.await_args.args[0].text == "plan the launch"
    ch.handler.reset_mock()
    ch.transport.calls.clear()
    assert _post(ch, rsa_key, _message("hi", aad="99999999-0000-0000-0000-000000000000",
                                       activity_id="m2")).status_code == 200
    assert not ch.handler.await_count and not ch.transport.calls
    assert _post(ch, rsa_key, _message("hi", tenant="other-tenant", activity_id="m3")).status_code == 200
    assert not ch.handler.await_count


def test_without_company_sign_in_a_sender_with_no_entra_id_is_answered(rsa_key, monkeypatch):
    # The allowlist admits the bot-scoped id when the activity carries no
    # aadObjectId, but intake compared it with an empty sender id and refused
    # (503), so Teams redelivered the message forever.
    ch = _channel(rsa_key, allowed_user_ids=["29:user-scoped"])
    _claim_ok(monkeypatch)
    assert _post(ch, rsa_key, _message("plan the launch", aad="", activity_id="bot-scoped")).status_code == 200
    assert ch.handler.await_args.args[0].text == "plan the launch"


def test_a_signing_key_fetch_failure_is_a_refusal_not_a_server_error(rsa_key):
    # Network errors, error statuses and malformed keys escaped as 500s.
    def unreachable(url):
        raise ConnectionError("login.botframework.com timed out")

    with pytest.raises(TeamsAuthError, match="could not be fetched"):
        verify_bot_token(_token(rsa_key), app_id=APP_ID, keys=SigningKeys(fetch_json=unreachable))
    broken = SigningKeys(jwks={"keys": [{"kid": "k1", "kty": "RSA", "n": "not-a-modulus", "e": "AQAB"}]})
    with pytest.raises(TeamsAuthError, match="unusable"):
        verify_bot_token(_token(rsa_key, kid="k1"), app_id=APP_ID, keys=broken)
    ch = _channel(rsa_key, keys=SigningKeys(fetch_json=unreachable))
    assert _post(ch, rsa_key, _message("hello", activity_id="keys-down")).status_code == 403
    ch.handler.assert_not_called()


def test_handler_error_reply_is_redacted(rsa_key, monkeypatch):
    secret = "boom token=sk-SECRET"  # pragma: allowlist secret
    ch = _channel(rsa_key, handler=AsyncMock(side_effect=RuntimeError(secret)))
    _claim_ok(monkeypatch)
    _post(ch, rsa_key, _message("x", activity_id="m9"))
    sent = ch.transport.calls[-1]["json"]["text"]
    assert "sk-SECRET" not in sent and sent == "⚠ An internal error occurred."


def test_oidc_teams_ingress_requires_aad_identity_and_current_tenant(rsa_key, monkeypatch):
    from maverick import oidc

    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    ch = _channel(rsa_key, allowed_user_ids=["29:user-scoped", AAD_USER])
    assert _post(ch, rsa_key, _message(aad="", activity_id="no-aad")).status_code == 200
    ch.handler.assert_not_called()
    assert _post(ch, rsa_key, _message(tenant="ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee",
                                      activity_id="other-tenant")).status_code == 200
    ch.handler.assert_not_called()
    assert _post(ch, rsa_key, _message(activity_id="valid-aad")).status_code == 200
    ch.handler.assert_awaited_once()


def test_welcome_on_bot_added(rsa_key):
    ch = _channel(rsa_key)
    added = {"type": "conversationUpdate", "channelId": "msteams",
             "serviceUrl": SERVICE_URL, "id": "u1",
             "recipient": {"id": f"28:{APP_ID}"}, "membersAdded": [{"id": f"28:{APP_ID}"}],
             "from": {"id": "29:x"}, "conversation": {"id": "c1"},
             "channelData": {"tenant": {"id": TENANT}}}
    assert _post(ch, rsa_key, added).status_code == 200
    assert "Send me a task" in ch.transport.calls[-1]["json"]["text"]


def test_rejected_reply_is_not_retried_blindly(rsa_key):
    ch = _channel(rsa_key)
    ch.transport.responses["token"] = (401, {"error": "invalid_client"})
    with pytest.raises(teams_mod.DeliveryNotSent, match="app secret"):
        import asyncio
        asyncio.run(ch.send("a:conv1", "hello"))


def test_long_reply_is_chunked_and_multiline_reply_is_a_card(rsa_key):
    import asyncio
    ch = _channel(rsa_key)
    asyncio.run(ch.send("a:conv1", "x" * 9000))
    posts = [c for c in ch.transport.calls if c["method"] == "POST" and "/activities" in c["url"]]
    assert len(posts) == 3 and all(len(p["json"]["text"]) <= 4000 for p in posts)
    ch.transport.calls.clear()
    asyncio.run(ch.send("a:conv1", "Line one\nLine two"))
    body = ch.transport.calls[-1]["json"]
    assert body["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert "Line one" in json.dumps(body)


# --------------------------------------------------------------- cards

def test_approval_card_mirrors_the_dashboard_card():
    from maverick_channels.teams_cards import approval_card, confirm_card

    view = FakeDecisions(risk="high").approval_view(7)
    card = approval_card(view["approval"], view["card"])
    text = json.dumps(card)
    for needle in ("What it changes", "Invoice 42", "Requested by", "Decide by", "Spending",
                   "Up to $12.50", "What it will do", "Email invoice 42", "Before", "After",
                   "Can't be undone", "Open questions", "Risk: High", "decision is yours"):
        assert needle in text, needle
    verbs = [a.get("verb") for a in card["actions"]]
    assert verbs[:2] == ["approve", "reject"]
    assert card["actions"][2]["type"] == "Action.ShowCard"
    assert card["actions"][2]["card"]["actions"][0]["verb"] == "ask"
    assert card["actions"][0]["data"] == {"approval_id": 7, "binding": "b" * 64, "risk": "high"}
    confirm = confirm_card(view["approval"], binding="b" * 64)
    assert confirm["actions"][0]["verb"] == "approve_confirm" and "high risk" in json.dumps(confirm)
    decided = approval_card(view["approval"], view["card"], decided={
        "status": "approved", "decided_by": "user:alice", "audit": "delivered"})
    assert "actions" not in decided and "Approved by user:alice" in json.dumps(decided)


def test_legacy_card_has_no_approve_button():
    from maverick_channels.teams_cards import approval_card

    view = FakeDecisions(card=False).approval_view(3)
    card = approval_card(view["approval"], None)
    assert [a.get("verb") for a in card["actions"] if a.get("verb")] == ["reject"]
    assert "missing the details" in json.dumps(card)


# ------------------------------------------------------------- invokes

def _link(principal="user:alice", approver=True):
    from maverick import teams_identity
    teams_identity.link(AAD_USER, principal, approver=approver, actor="user:admin")


def test_invoke_approve_goes_through_the_shared_decision_and_updates_the_card(rsa_key, monkeypatch):
    _link()
    ch = _channel(rsa_key)
    r = _post(ch, rsa_key, _invoke("approve"))
    assert r.status_code == 200
    body = r.json()
    assert body["statusCode"] == 200 and body["type"] == "application/vnd.microsoft.card.adaptive"
    assert "Approved by user:alice" in json.dumps(body["value"])
    kind, kw = ch._decisions.calls[0]
    assert kind == "decide" and kw["status"] == "approved" and kw["principal"] == "user:alice"
    assert kw["channel"] == "teams" and kw["binding"] == "b" * 64 and kw["confirmed"] is False
    put = [c for c in ch.transport.calls if c["method"] == "PUT"][0]
    assert put["url"].endswith("/v3/conversations/a%3Aconv1/activities/card-1")
    assert "Approved by user:alice" in json.dumps(put["json"])


def test_invoke_high_risk_needs_a_second_confirm_card(rsa_key):
    _link()
    ch = _channel(rsa_key, decisions=FakeDecisions(risk="critical"))
    first = _post(ch, rsa_key, _invoke("approve", risk="critical")).json()
    assert first["type"] == "application/vnd.microsoft.card.adaptive"
    assert first["value"]["actions"][0]["verb"] == "approve_confirm"
    assert not ch._decisions.calls
    # Critical risk also asks for the typed word, like the Approvals page.
    assert any(item.get("id") == "acknowledged" for item in first["value"]["body"])
    assert any(item.get("id") == "confirmation" for item in first["value"]["body"])
    confirm = _invoke("approve_confirm", risk="critical")
    confirm["value"]["action"]["data"].update({"acknowledged": "true", "confirmation": "APPROVE"})
    second = _post(ch, rsa_key, confirm).json()
    assert "Approved by" in json.dumps(second["value"])
    kw = ch._decisions.calls[0][1]
    assert kw["confirmed"] is True
    assert kw["acknowledgement"] == {"acknowledged": True, "confirmation": "APPROVE"}


def test_decided_card_offers_undo_and_undo_restores_the_card(rsa_key):
    _link()
    ch = _channel(rsa_key)
    decided = _post(ch, rsa_key, _invoke("approve")).json()["value"]
    assert decided["actions"][0]["verb"] == "undo" and "undo this for 30 seconds" in json.dumps(decided)
    restored = _post(ch, rsa_key, _invoke("undo")).json()
    kind, kw = ch._decisions.calls[-1]
    assert kind == "undo" and kw["principal"] == "user:alice" and kw["channel"] == "teams"
    verbs = [a.get("verb") for a in restored["value"]["actions"]]
    assert verbs[:2] == ["approve", "reject"] and "was undone" in json.dumps(restored["value"])
    put = [c for c in ch.transport.calls if c["method"] == "PUT"][-1]
    assert "was undone" in json.dumps(put["json"])
    ch._decisions.refuse = FakeDecisions.ApprovalDecisionRefused("Too late to undo: the agent has already been told")
    assert "Too late" in _post(ch, rsa_key, _invoke("undo")).json()["value"]


def test_invoke_reject_and_ask(rsa_key):
    _link()
    ch = _channel(rsa_key)
    _post(ch, rsa_key, _invoke("reject"))
    assert ch._decisions.calls[-1][1]["status"] == "denied"
    ch = _channel(rsa_key)  # a fresh pending request for the question path
    r = _post(ch, rsa_key, _invoke("ask", question="Which customer?")).json()
    kind, kw = ch._decisions.calls[-1]
    assert kind == "send_back" and kw["rationale"] == "Which customer?"
    assert "Sent back for changes" in json.dumps(r["value"])


def test_invoke_refusals_are_plain_messages(rsa_key):
    _link()
    decisions = FakeDecisions()
    decisions.refuse = FakeDecisions.ApprovalDecisionRefused("the approval expired; request a fresh review")
    ch = _channel(rsa_key, decisions=decisions)
    r = _post(ch, rsa_key, _invoke("approve")).json()
    assert r["type"] == "application/vnd.microsoft.activity.message" and "expired" in r["value"]
    already = _channel(rsa_key, decisions=FakeDecisions(status="approved"))
    r = _post(already, rsa_key, _invoke("approve")).json()
    assert "already decided" in r["value"]
    off = _channel(rsa_key, approvals_enabled=False)
    assert "turned off" in _post(off, rsa_key, _invoke("approve")).json()["value"]


def test_invoke_needs_the_dashboards_role_and_content_access(rsa_key):
    """A linked person who could not open the request on the Approvals page
    (no operate role, or no access to its content) gets no card for it, so
    changing the number in the payload cannot read another request."""
    _link(principal="user:mallory")
    ch = _channel(rsa_key)
    for verb in ("cancel", "approve", "reject", "undo"):
        r = _post(ch, rsa_key, _invoke(verb, approval_id=99)).json()
        assert r["type"] == "application/vnd.microsoft.activity.message"
        assert "can't open this request" in r["value"] and "email.send" not in json.dumps(r)
    assert not ch._decisions.calls
    ch._decisions.eligible = {"user:mallory"}
    r = _post(ch, rsa_key, _invoke("cancel", approval_id=99)).json()
    assert r["type"] == "application/vnd.microsoft.card.adaptive"


def test_invoke_from_unlinked_account_is_refused(rsa_key):
    from maverick import teams_identity
    teams_identity.unlink(AAD_USER)
    ch = _channel(rsa_key)
    r = _post(ch, rsa_key, _invoke("approve")).json()
    assert "isn't linked" in r["value"] and not ch._decisions.calls


# ------------------------------------------------------ identity linking

def test_link_code_flow_in_chat(rsa_key, monkeypatch):
    from maverick import teams_identity
    teams_identity.unlink(AAD_USER)
    code = teams_identity.issue_link_code("user:carol", approver=True, actor="user:admin")
    ch = _channel(rsa_key)
    _claim_ok(monkeypatch)
    _post(ch, rsa_key, _message(f"link {code.lower()}", activity_id="l1"))
    assert "now linked to user:carol" in ch.transport.calls[-1]["json"]["text"]
    assert not ch.handler.await_count  # a link command never becomes a goal
    link = teams_identity.link_for(AAD_USER)
    assert link["principal"] == "user:carol" and link["approver"] is True
    assert link["conversation"]["conversation_id"] == "a:conv1"
    # One-time: a second use fails.
    _post(ch, rsa_key, _message(f"link {code}", activity_id="l2"))
    assert "isn't valid" in ch.transport.calls[-1]["json"]["text"]


def test_identity_store_lookups_and_validation():
    from maverick import teams_identity
    teams_identity.link(" ALICE@Example.com ", "alice", approver=False)
    assert teams_identity.principal_for("alice@example.com") == "user:alice"
    assert teams_identity.principal_for("nobody@example.com") is None
    with pytest.raises(teams_identity.TeamsIdentityError):
        teams_identity.link("bad id!", "user:x")
    with pytest.raises(teams_identity.TeamsIdentityError):
        teams_identity.link(AAD_USER, "")
    rows = {row["teams_id"]: row for row in teams_identity.list_links()}
    assert rows["alice@example.com"]["approver"] is False
    assert teams_identity.unlink("alice@example.com") is True


# ------------------------------------------------------ proactive posting

def test_post_approval_to_linked_users(monkeypatch):
    from maverick import teams_identity
    teams_identity.link(AAD_USER, "user:alice", approver=True)
    teams_identity.remember_conversation(AAD_USER, {"service_url": SERVICE_URL, "conversation_id": "a:conv1",
                                                    "tenant_id": TENANT, "user_id": "29:x"})
    teams_identity.link("bob@example.com", "user:bob", approver=True)
    teams_identity.link("carol@example.com", "user:carol", approver=False)
    transport = FakeTransport()
    transport.responses[("POST", "conversations")] = (201, {"id": "a:new-chat"})
    cfg = {"enabled": True, "approvals_enabled": True, "app_id": APP_ID, "app_password": FAKE_SECRET,
           "tenant_id": TENANT}
    posted = teams_mod.post_approval_to_linked_users(7, cfg=cfg, transport=transport, decisions=FakeDecisions())
    urls = [c["url"] for c in transport.calls if c["method"] == "POST" and "/v3/" in c["url"]]
    assert urls[0].endswith("/v3/conversations/a%3Aconv1/activities")
    assert urls[1].endswith("/v3/conversations") and urls[2].endswith("/v3/conversations/a%3Anew-chat/activities")
    create = [c for c in transport.calls if c["url"].endswith("/v3/conversations")][0]["json"]
    assert create["members"] == [{"id": "bob@example.com"}] and create["tenantId"] == TENANT
    assert len(posted) == 2  # carol is not an approver
    assert teams_mod.post_approval_to_linked_users(7, cfg={**cfg, "approvals_enabled": False},
                                                   transport=transport) == []


def test_approval_card_is_not_posted_to_a_link_the_dashboard_rule_excludes():
    """A demoted or deprovisioned approver link must not receive the card."""
    from maverick import teams_identity
    teams_identity.link(AAD_USER, "user:alice", approver=True)
    teams_identity.remember_conversation(AAD_USER, {"service_url": SERVICE_URL, "conversation_id": "a:conv1",
                                                    "tenant_id": TENANT, "user_id": "29:x"})
    teams_identity.link("dave@example.com", "user:dave", approver=True)
    transport = FakeTransport()
    cfg = {"enabled": True, "approvals_enabled": True, "app_id": APP_ID, "app_password": FAKE_SECRET,
           "tenant_id": TENANT}
    decisions = FakeDecisions()
    decisions.eligible = {"user:alice"}
    assert len(teams_mod.post_approval_to_linked_users(7, cfg=cfg, transport=transport, decisions=decisions)) == 1
    assert not any("dave" in json.dumps(c.get("json")) for c in transport.calls)
    decisions.eligible = set()
    transport.calls.clear()
    assert teams_mod.post_approval_to_linked_users(7, cfg=cfg, transport=transport, decisions=decisions) == []
    assert transport.calls == []


def test_approval_notify_hook_is_gated_and_skips_settings(monkeypatch):
    from maverick import approval_notify
    started = []
    monkeypatch.setattr(approval_notify.threading, "Thread",
                        lambda **kw: started.append(kw) or MagicMock())
    monkeypatch.setattr(approval_notify, "teams_approvals_enabled", lambda cfg=None: True)
    approval_notify.approval_created(1, provenance="settings_quorum")
    assert not started
    approval_notify.approval_created(2, provenance="consent")
    assert started and started[0]["daemon"] is True


# --------------------------------------------------------------- config

def test_channel_config_round_trip(monkeypatch):
    monkeypatch.delenv("TEAMS_APP_PASSWORD", raising=False)
    cfg = channel_config({"enabled": "true", "app_id": APP_ID, "app_password": FAKE_SECRET,
                          "tenant_id": TENANT.upper(), "allowed_users": [AAD_USER],
                          "approvals_enabled": True, "port": "8791"})
    assert cfg["enabled"] and cfg["app_password"] == FAKE_SECRET and cfg["tenant_id"] == TENANT
    assert cfg["allowed_users"] == {AAD_USER} and cfg["approvals_enabled"] and cfg["port"] == 8791
    monkeypatch.setenv("TEAMS_APP_PASSWORD", "from-the-server")  # pragma: allowlist secret
    assert channel_config({"app_password": "saved"})["app_password"] == "from-the-server"  # pragma: allowlist secret
    assert token_endpoint("") == "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"
    assert token_endpoint(TENANT) == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


def test_construction_is_fail_closed(rsa_key):
    with pytest.raises(ValueError, match="allowed_tenants"):
        TeamsChannel(handler=AsyncMock(), app_id=APP_ID, app_password="x", allowed_user_ids=[AAD_USER])
    with pytest.raises(ValueError, match="TEAMS_ALLOWED_USERS"):
        TeamsChannel(handler=AsyncMock(), app_id=APP_ID, app_password="x", tenant_id=TENANT,
                     allowed_user_ids=[])
    with pytest.raises(ValueError, match="credentials"):
        TeamsChannel(handler=AsyncMock(), app_id="", app_password="x", tenant_id=TENANT)


def test_token_failures_are_explained_plainly():
    assert "app secret" in explain_token_failure(401, {"error": "invalid_client"})
    assert "tenant" in explain_token_failure(400, {"error": "unauthorized_client",
                                                   "error_description": "AADSTS700016: ..."})
    assert "server error" in explain_token_failure(503, {})


# ----------------------------------------- reply delivery, sign-in and cards

def test_a_throttled_reply_was_not_sent_and_can_be_retried_but_a_server_error_is_unknown(rsa_key):
    import asyncio
    ch = _channel(rsa_key)
    key = ("POST", "conversations/a%3Aconv1/activities")
    ch.transport.responses[key] = (429, {})
    with pytest.raises(teams_mod.DeliveryNotSent, match="throttling"):
        asyncio.run(ch.send("a:conv1", "hello"))
    ch.transport.responses[key] = (503, {})
    with pytest.raises(teams_mod.DeliveryUnknown):
        asyncio.run(ch.send("a:conv1", "hello"))


def test_a_multiline_reply_keeps_its_lines_and_paragraphs_on_the_card():
    from maverick_channels.teams_cards import result_card
    card = result_card("Summary\n\n- a\n- b\r\n```\ncode\n```")
    blocks = [b for b in card["body"] if b["type"] == "TextBlock"]
    assert [b["text"] for b in blocks] == ["Lightwork", "Summary", "- a", "- b", r"\`\`\`", "code", r"\`\`\`"]
    assert blocks[2].get("spacing") == "medium"                 # the blank line before the list
    assert blocks[3].get("spacing") is None


def test_a_reply_of_many_short_lines_is_sent_as_text_when_its_card_would_be_too_large(rsa_key):
    import asyncio
    import json

    from maverick_channels.teams_cards import MAX_MESSAGE_BYTES
    ch = _channel(rsa_key)
    asyncio.run(ch.send("a:conv1", "Summary\n- a\n- b"))
    short = "\n".join("x" for _ in range(2000))           # within the 4000-character reply limit
    asyncio.run(ch.send("a:conv1", short))
    sent = [c["json"] for c in ch.transport.calls if c["url"].endswith("/activities")]
    assert sent[0]["attachments"][0]["content"]["body"][1]["text"] == "Summary"
    assert "attachments" not in sent[1] and sent[1]["text"] == short
    assert sent[1]["textFormat"] == "markdown"
    assert all(len(json.dumps(body).encode("utf-16-le")) <= MAX_MESSAGE_BYTES for body in sent)


def test_only_a_link_code_is_a_link_attempt_and_never_under_company_sign_in(rsa_key, monkeypatch):
    import asyncio

    from maverick import oidc, teams_identity
    ch = _channel(rsa_key)
    parsed = parse_activity(_message("link pricing"), bot_id=ch.connector.bot_id)
    assert asyncio.run(ch._maybe_link(parsed)) is None         # a request that begins with "link"
    teams_identity.unlink(AAD_USER)
    code = teams_identity.issue_link_code("user:carol", approver=False, actor="user:admin")
    parsed = parse_activity(_message(f"link {code}"), bot_id=ch.connector.bot_id)
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    assert asyncio.run(ch._maybe_link(parsed)) is None         # the legacy store is not trusted
    assert teams_identity.principal_for(AAD_USER) is None
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: False)
    assert "now linked to user:carol" in asyncio.run(ch._maybe_link(parsed))


def test_approval_cards_are_not_posted_to_legacy_links_under_company_sign_in(monkeypatch):
    from maverick import oidc, teams_identity
    teams_identity.link(AAD_USER, "user:alice", approver=True)
    teams_identity.remember_conversation(AAD_USER, {"service_url": SERVICE_URL, "conversation_id": "a:conv1",
                                                    "tenant_id": TENANT, "user_id": "29:x"})
    transport = FakeTransport()
    cfg = {"enabled": True, "approvals_enabled": True, "app_id": APP_ID, "app_password": FAKE_SECRET,
           "tenant_id": TENANT}
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    assert teams_mod.post_approval_to_linked_users(7, cfg=cfg, transport=transport, decisions=FakeDecisions()) == []
    assert transport.calls == []                                # nothing about the request left the server
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: False)
    assert len(teams_mod.post_approval_to_linked_users(7, cfg=cfg, transport=transport,
                                                       decisions=FakeDecisions())) == 1


def test_a_risk_recorded_with_capitals_still_needs_the_second_confirmation(rsa_key):
    _link()
    ch = _channel(rsa_key, decisions=FakeDecisions(risk="High"))
    first = _post(ch, rsa_key, _invoke("approve", risk="High")).json()
    assert first["value"]["actions"][0]["verb"] == "approve_confirm"
    assert not ch._decisions.calls


def test_a_slow_in_place_card_update_cannot_make_the_invoke_answer_late(rsa_key, monkeypatch):
    import asyncio
    _link()

    class Slow(FakeTransport):
        async def __call__(self, method, url, **kwargs):
            if method == "PUT":
                await asyncio.sleep(5)
            return await super().__call__(method, url, **kwargs)

    ch = _channel(rsa_key, transport=Slow())
    monkeypatch.setattr(teams_mod, "_INVOKE_UPDATE_SECONDS", 0.05)
    started = time.monotonic()
    response = _post(ch, rsa_key, _invoke("approve"))
    assert response.status_code == 200 and "Approved by user:alice" in json.dumps(response.json()["value"])
    assert time.monotonic() - started < 2.5
