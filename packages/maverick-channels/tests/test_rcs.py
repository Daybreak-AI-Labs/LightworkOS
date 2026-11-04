"""RCS Business Messaging adapter: client-token verification (query param,
header, and the {clientToken, secret} validation handshake), Pub/Sub
envelope decoding, MSISDN allowlist, durable execution claims held on
unknown failure, and outbound agentMessages calls authed by a service-account
Bearer token (google-auth faked via sys.modules)."""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from maverick_channels.rcs import RcsChannel  # noqa: E402

TOKEN = "client-token-123"
SENDER = "+14155551234"
AGENT = "maverick_rbm_agent"
SA_PATH = "/etc/maverick/rbm-sa.json"
RBM_SCOPE = "https://www.googleapis.com/auth/rcsbusinessmessaging"


def _channel(**overrides):
    kw = dict(
        handler=AsyncMock(return_value="the reply"),
        agent_id=AGENT,
        service_account_json=SA_PATH,
        webhook_token=TOKEN,
        allowed_user_ids=[SENDER],
    )
    kw.update(overrides)
    return RcsChannel(**kw)


def _event(sender=SENDER, text="hello agent", msg_id="rbm-msg-1"):
    event = {"senderPhoneNumber": sender, "messageId": msg_id,
             "sendTime": "2026-06-10T00:00:00Z"}
    if text is not None:
        event["text"] = text
    return event


def _envelope(event):
    """Pub/Sub-style push envelope; the outer messageId is the pubsub id and
    must NOT be confused with the RBM messageId inside the decoded data."""
    data = base64.b64encode(json.dumps(event).encode()).decode()
    return {"message": {"data": data, "messageId": "pubsub-outer-1"}}


def _claim_ok(monkeypatch):
    """Most tests are not about dedup; provide an available claim store."""
    wm = MagicMock()
    wm.is_processed_message.return_value = False
    wm.mark_message_processed.return_value = True
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    return wm


# -- inbound -----------------------------------------------------------------

def test_token_verified_inbound_drives_handler_and_replies(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", params={"clientToken": TOKEN},
                    json=_envelope(_event()))

    assert r.status_code == 200
    ch.handler.assert_awaited_once()
    msg = ch.handler.await_args.args[0]
    assert msg.user_id == SENDER and msg.text == "hello agent"
    assert msg.channel == "rcs" and msg.message_id == "rbm-msg-1"
    ch.send.assert_awaited_once_with(SENDER, "the reply")


def test_direct_json_event_accepted(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", params={"clientToken": TOKEN}, json=_event())

    assert r.status_code == 200
    ch.handler.assert_awaited_once()
    assert ch.handler.await_args.args[0].text == "hello agent"


def test_token_accepted_from_header(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", headers={"clientToken": TOKEN},
                    json=_envelope(_event()))

    assert r.status_code == 200
    ch.handler.assert_awaited_once()


def test_bad_client_token_403():
    ch = _channel()
    client = TestClient(ch._app)

    wrong = client.post("/webhook/rcs", params={"clientToken": "wrong"},
                        json=_envelope(_event()))
    missing = client.post("/webhook/rcs", json=_envelope(_event()))

    assert wrong.status_code == 403 and missing.status_code == 403
    assert not ch.handler.await_count


def test_bad_client_token_rejected_before_json_parse(monkeypatch):
    ch = _channel()
    client = TestClient(ch._app)

    def fail_json(*args, **kwargs):
        raise AssertionError("request.json() must not run before token validation")

    monkeypatch.setattr(fastapi.Request, "json", fail_json)

    wrong = client.post("/webhook/rcs", params={"clientToken": "wrong"},
                        json=_envelope(_event()))

    assert wrong.status_code == 403
    assert not ch.handler.await_count


def test_body_token_handshake_rejects_oversized_body():
    ch = _channel()
    client = TestClient(ch._app)

    r = client.post(
        "/webhook/rcs",
        content=b"{" + (b" " * 4096) + b"}",
        headers={"content-type": "application/json"},
    )

    assert r.status_code == 413
    assert not ch.handler.await_count


def test_body_token_handshake_refuses_a_lone_surrogate_token():
    # JSON can carry a lone surrogate (\ud800); it is a wrong token, not a 500.
    ch = _channel()
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", content=b'{"secret": "s", "clientToken": "\\ud800"}',
                    headers={"content-type": "application/json"})

    assert r.status_code == 403
    assert not ch.handler.await_count


def test_unlisted_msisdn_ignored(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", params={"clientToken": TOKEN},
                    json=_envelope(_event(sender="+19998887777")))

    assert r.status_code == 200          # Google still gets its 200
    assert not ch.handler.await_count    # but nothing ran
    assert not ch.send.await_count


def test_non_text_event_ignored(monkeypatch):
    """Suggestion responses / receipts are acked and dropped: text only."""
    ch = _channel()
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)

    event = _event(text=None)
    event["suggestionResponse"] = {"postbackData": "yes", "text": "Yes"}
    r = client.post("/webhook/rcs", params={"clientToken": TOKEN},
                    json=_envelope(event))

    assert r.status_code == 200
    assert not ch.handler.await_count


def test_validation_handshake_echoes_secret():
    ch = _channel()
    client = TestClient(ch._app)

    ok = client.post("/webhook/rcs", json={"clientToken": TOKEN, "secret": "echo-me"})
    assert ok.status_code == 200 and ok.json() == {"secret": "echo-me"}

    bad = client.post("/webhook/rcs", json={"clientToken": "wrong", "secret": "x"})
    assert bad.status_code == 403
    assert not ch.handler.await_count


def test_get_verification_echoes_secret():
    ch = _channel()
    client = TestClient(ch._app)

    ok = client.get("/webhook/rcs", params={"clientToken": TOKEN, "secret": "abc"})
    assert ok.status_code == 200 and ok.json() == {"secret": "abc"}

    bad = client.get("/webhook/rcs", params={"clientToken": "wrong", "secret": "abc"})
    assert bad.status_code == 403


def test_dedup_claim_skips_redelivery(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    wm = MagicMock()
    wm.is_processed_message.return_value = True
    wm.mark_message_processed.return_value = False  # already claimed
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", params={"clientToken": TOKEN},
                    json=_envelope(_event()))

    assert r.status_code == 200
    wm.is_processed_message.assert_called_with("rcs", "rbm-msg-1")
    wm.mark_message_processed.assert_not_called()
    assert not ch.handler.await_count


def test_claim_store_failure_is_retryable_and_never_runs_handler(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    monkeypatch.setattr(
        "maverick.world_model.open_world",
        MagicMock(side_effect=RuntimeError("claim store offline")),
    )
    client = TestClient(ch._app)

    r = client.post(
        "/webhook/rcs", params={"clientToken": TOKEN}, json=_envelope(_event())
    )

    assert r.status_code == 503
    assert not ch.handler.await_count
    assert not ch.send.await_count


def test_claim_remains_held_on_unknown_handler_failure(monkeypatch):
    ch = _channel(handler=AsyncMock(side_effect=RuntimeError("boom")))
    ch.send = AsyncMock()
    wm = MagicMock()
    wm.is_processed_message.return_value = False
    wm.mark_message_processed.return_value = True
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    client = TestClient(ch._app)

    r = client.post("/webhook/rcs", params={"clientToken": TOKEN},
                    json=_envelope(_event()))

    assert r.status_code == 200
    wm.release_processed_message.assert_not_called()
    from maverick_channels.delivery import DeliveryJournal
    row = DeliveryJournal().get(r.json()["receipt"])
    assert row["execution"] == "execution_unknown"
    client.post("/webhook/rcs", params={"clientToken": TOKEN}, json=_envelope(_event()))
    ch.handler.assert_awaited_once()
    # An error report still goes back to the sender (whatsapp_cloud parity), but
    # it's GENERIC -- the raw exception text ("boom") could carry a secret and
    # must not be reflected to the remote user (it's logged server-side instead).
    ch.send.assert_awaited_once()
    sent = ch.send.await_args.args[1]
    assert "boom" not in sent
    assert "error" in sent.lower()


# -- outbound ------------------------------------------------------------------

class _FakeCreds:
    def __init__(self):
        self.token = None
        self.valid = False
        self.refreshes = 0

    def refresh(self, request):
        self.refreshes += 1
        self.token = "sa-token"
        self.valid = True


def _install_google_auth(monkeypatch, creds):
    transport_requests = types.ModuleType("google.auth.transport.requests")
    transport_requests.Request = lambda: "auth-request"
    transport = types.ModuleType("google.auth.transport")
    transport.requests = transport_requests
    gauth = types.ModuleType("google.auth")
    gauth.load_credentials_from_file = MagicMock(return_value=(creds, "project-id"))
    gauth.transport = transport
    google_mod = types.ModuleType("google")
    google_mod.auth = gauth
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.auth", gauth)
    monkeypatch.setitem(sys.modules, "google.auth.transport", transport)
    monkeypatch.setitem(sys.modules, "google.auth.transport.requests", transport_requests)
    return gauth


def _install_httpx(monkeypatch, sent):
    class _Resp:
        status_code = 200
        text = ""

    class _Client:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, params=None, headers=None, json=None):
            sent.append({"url": url, "params": params, "headers": headers,
                         "json": json})
            return _Resp()

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(AsyncClient=_Client))


def test_send_posts_agent_message_with_sa_token(monkeypatch):
    ch = _channel()
    creds = _FakeCreds()
    gauth = _install_google_auth(monkeypatch, creds)
    sent = []
    _install_httpx(monkeypatch, sent)

    asyncio.run(ch.send(SENDER, "pong"))

    gauth.load_credentials_from_file.assert_called_once_with(
        SA_PATH, scopes=[RBM_SCOPE],
    )
    assert creds.refreshes == 1
    call = sent[0]
    assert call["url"].endswith(f"/v1/phones/{SENDER}/agentMessages")
    assert call["params"]["agentId"] == AGENT
    assert call["params"]["messageId"]  # RBM requires an agent-generated id
    assert call["headers"]["Authorization"] == "Bearer sa-token"
    assert call["json"] == {"contentMessage": {"text": "pong"}}

    # Second send: credentials are cached and still valid -> no re-load,
    # no re-refresh.
    asyncio.run(ch.send(SENDER, "again"))
    assert gauth.load_credentials_from_file.call_count == 1
    assert creds.refreshes == 1


def test_long_sends_chunked(monkeypatch):
    ch = _channel()
    _install_google_auth(monkeypatch, _FakeCreds())
    sent = []
    _install_httpx(monkeypatch, sent)

    asyncio.run(ch.send(SENDER, "x" * 5000))

    chunks = [c["json"]["contentMessage"]["text"] for c in sent]
    assert [len(c) for c in chunks] == [2000, 2000, 1000]
    assert "".join(chunks) == "x" * 5000
    # Each chunk is a distinct RBM message.
    assert len({c["params"]["messageId"] for c in sent}) == 3


def test_send_missing_google_auth_raises_importerror(monkeypatch):
    ch = _channel()
    for name in ("google", "google.auth", "google.auth.transport",
                 "google.auth.transport.requests"):
        monkeypatch.setitem(sys.modules, name, None)  # force ImportError
    with pytest.raises(ImportError, match=r"maverick-channels\[rcs\]"):
        asyncio.run(ch.send(SENDER, "hi"))


# -- construction is fail-closed ------------------------------------------------

def test_missing_credentials_raise(monkeypatch):
    for var in ("RCS_AGENT_ID", "RCS_SERVICE_ACCOUNT_JSON", "RCS_WEBHOOK_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValueError, match="credentials missing"):
        _channel(agent_id=None, service_account_json=None, webhook_token=None)


def test_missing_allowlist_raises(monkeypatch):
    monkeypatch.delenv("RCS_ALLOWED_USER_IDS", raising=False)
    with pytest.raises(ValueError, match="ALLOWED_USER_IDS"):
        _channel(allowed_user_ids=None)
