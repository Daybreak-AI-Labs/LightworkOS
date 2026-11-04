"""WhatsApp Cloud API adapter: verification handshake, HMAC-signed events,
sender allowlist, dedup claim, and outbound Graph calls."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from maverick_channels.whatsapp_cloud import WhatsAppCloudChannel  # noqa: E402

APP_SECRET = "app-secret"
VERIFY_TOKEN = "verify-me"
SENDER = "15551234567"


def _channel(monkeypatch=None, **overrides):
    kw = dict(
        handler=AsyncMock(return_value="the reply"),
        access_token="EAAG-token",
        phone_number_id="1112223334445",
        verify_token=VERIFY_TOKEN,
        app_secret=APP_SECRET,
        allowed_user_ids=[SENDER],
    )
    kw.update(overrides)
    return WhatsAppCloudChannel(**kw)


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(APP_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _event(sender=SENDER, text="hello agent", msg_id="wamid.X1"):
    return {
        "entry": [{"changes": [{"value": {"messages": [
            {"type": "text", "from": sender, "id": msg_id, "text": {"body": text}},
        ]}}]}],
    }


def _claim_ok(monkeypatch):
    """Most tests are not about dedup; provide an available claim store."""
    wm = MagicMock()
    wm.is_processed_message.return_value = False
    wm.mark_message_processed.return_value = True
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    return wm


def test_verification_handshake():
    ch = _channel()
    client = TestClient(ch._app)
    r = client.get("/webhook/whatsapp-cloud", params={
        "hub.mode": "subscribe", "hub.verify_token": VERIFY_TOKEN,
        "hub.challenge": "12345",
    })
    assert r.status_code == 200 and r.text == "12345"
    bad = client.get("/webhook/whatsapp-cloud", params={
        "hub.mode": "subscribe", "hub.verify_token": "wrong", "hub.challenge": "x",
    })
    assert bad.status_code == 403


def test_signed_message_drives_handler_and_replies(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)
    body = json.dumps(_event()).encode()
    r = client.post("/webhook/whatsapp-cloud", content=body,
                    headers={"X-Hub-Signature-256": _sign(body)})
    assert r.status_code == 200
    ch.handler.assert_awaited_once()
    msg = ch.handler.await_args.args[0]
    assert msg.user_id == SENDER and msg.text == "hello agent"
    assert msg.channel == "whatsapp_cloud" and msg.message_id == "wamid.X1"
    ch.send.assert_awaited_once_with(SENDER, "the reply")


def test_handler_exception_reply_is_redacted(monkeypatch):
    # On a handler error the user must get a generic message, NOT the raw
    # exception text -- it can carry a credential / internal path. Every other
    # channel redacts, and whatsapp_cloud must not forward f"error: {e}".
    secret = "boom token=sk-SECRET path=/etc/passwd"  # pragma: allowlist secret
    ch = _channel(handler=AsyncMock(side_effect=RuntimeError(secret)))
    ch.send = AsyncMock()
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)
    body = json.dumps(_event()).encode()
    r = client.post("/webhook/whatsapp-cloud", content=body,
                    headers={"X-Hub-Signature-256": _sign(body)})
    assert r.status_code == 200
    ch.send.assert_awaited_once()
    sent = ch.send.await_args.args[1]
    assert secret not in sent and "sk-SECRET" not in sent
    assert sent == "⚠ An internal error occurred."


def test_bad_signature_403():
    ch = _channel()
    client = TestClient(ch._app)
    body = json.dumps(_event()).encode()
    r = client.post("/webhook/whatsapp-cloud", content=body,
                    headers={"X-Hub-Signature-256": "sha256=" + "0" * 64})
    assert r.status_code == 403
    assert not ch.handler.await_count


def test_malformed_auth_values_fail_closed():
    ch = _channel()
    client = TestClient(ch._app)

    verify = client.get("/webhook/whatsapp-cloud", params={
        "hub.mode": "subscribe", "hub.verify_token": "wroñg", "hub.challenge": "x",
    })
    assert verify.status_code == 403

    body = json.dumps(_event()).encode()
    assert not ch._signature_ok(body, "sha256=" + "é" * 64)
    assert not ch.handler.await_count


def test_unlisted_sender_ignored(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    client = TestClient(ch._app)
    body = json.dumps(_event(sender="19998887777")).encode()
    r = client.post("/webhook/whatsapp-cloud", content=body,
                    headers={"X-Hub-Signature-256": _sign(body)})
    assert r.status_code == 200          # Meta still gets its 200
    assert not ch.handler.await_count    # but nothing ran
    assert not ch.send.await_count


def test_dedup_claim_skips_redelivery(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    wm = MagicMock()
    wm.is_processed_message.return_value = True
    wm.mark_message_processed.return_value = False  # already claimed
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    client = TestClient(ch._app)
    body = json.dumps(_event()).encode()
    r = client.post("/webhook/whatsapp-cloud", content=body,
                    headers={"X-Hub-Signature-256": _sign(body)})
    assert r.status_code == 200
    wm.is_processed_message.assert_called_with("whatsapp_cloud", "wamid.X1")
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
    body = json.dumps(_event()).encode()

    r = client.post(
        "/webhook/whatsapp-cloud",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body)},
    )

    assert r.status_code == 503
    assert not ch.handler.await_count
    assert not ch.send.await_count


def test_send_posts_to_graph(monkeypatch):
    ch = _channel()
    sent = []

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"messages": [{"id": "fixture-response-id"}]}

    class _Client:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent.append((url, headers, json))
            return _Resp()

    import sys
    import types
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(AsyncClient=_Client))
    import asyncio
    asyncio.run(ch.send(SENDER, "pong"))
    url, headers, payload = sent[0]
    assert url.endswith("/1112223334445/messages")
    assert headers["Authorization"] == "Bearer EAAG-token"
    assert payload == {"messaging_product": "whatsapp", "to": SENDER,
                       "type": "text", "text": {"body": "pong"}}


def test_long_replies_chunked(monkeypatch):
    ch = _channel()
    sent = []

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"messages": [{"id": "fixture-response-id"}]}

    class _Client:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent.append(json["text"]["body"])
            return _Resp()

    import sys
    import types
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(AsyncClient=_Client))
    import asyncio
    asyncio.run(ch.send(SENDER, "x" * 9000))
    assert len(sent) == 3 and sum(len(s) for s in sent) == 9000


def test_missing_credentials_raise():
    with pytest.raises(ValueError, match="credentials missing"):
        _channel(app_secret=None, access_token=None)


def test_missing_allowlist_raises(monkeypatch):
    monkeypatch.delenv("WHATSAPP_CLOUD_ALLOWED_USER_IDS", raising=False)
    with pytest.raises(ValueError, match="ALLOWED_USER_IDS"):
        _channel(allowed_user_ids=None)


@pytest.mark.parametrize("body", [
    b"[1,2,3]",                                          # top-level JSON array
    b'"juststring"',                                     # top-level JSON string
    b"5",                                                # top-level int
    b'{"entry":"x"}',                                    # entry not a list
    b'{"entry":5}',                                      # entry a truthy non-iterable
    b'{"entry":[1]}',                                    # entry item not a dict
    b'{"entry":[{"changes":"x"}]}',                      # changes not a list
    b'{"entry":[{"changes":5}]}',                        # changes a truthy non-iterable
    b'{"entry":[{"changes":[{"value":"x"}]}]}',          # value not a dict
    b'{"entry":[{"changes":[{"value":{"messages":5}}]}]}',  # messages non-iterable
    b'{"entry":[{"changes":[{"value":{"messages":["x",null]}}]}]}',  # message not a dict
])
def test_hostile_body_shapes_do_not_500(body):
    # A signed-but-misshapen body (Meta status updates, or anything that passes
    # the HMAC) must NOT raise out of the webhook handler. _extract_messages
    # type-guards every nesting level; the handler returns a clean 200.
    ch = _channel()
    client = TestClient(ch._app)
    r = client.post(
        "/webhook/whatsapp-cloud", content=body,
        headers={"X-Hub-Signature-256": _sign(body)},
    )
    assert r.status_code == 200


def test_extract_messages_ignores_junk_keeps_valid():
    valid = _event(text="hi")
    assert WhatsAppCloudChannel._extract_messages(valid)[0]["text"]["body"] == "hi"
    # Junk shapes flatten to nothing rather than raising.
    for junk in (None, "x", 5, [], {"entry": [None, "x", {"changes": [5]}]}):
        assert WhatsAppCloudChannel._extract_messages(junk) == []


def test_handler_exception_returns_generic_reply(monkeypatch):
    # A handler error must NOT echo the raw exception (paths/detail) to the
    # external sender; a generic message goes out and the detail is only logged.
    ch = _channel()
    ch.send = AsyncMock()
    ch.handler = AsyncMock(side_effect=RuntimeError("/srv/secret/path leaked!"))
    _claim_ok(monkeypatch)
    client = TestClient(ch._app)
    body = json.dumps(_event()).encode()
    r = client.post("/webhook/whatsapp-cloud", content=body,
                    headers={"X-Hub-Signature-256": _sign(body)})
    assert r.status_code == 200
    ch.send.assert_awaited_once()
    sent_text = ch.send.await_args.args[1]
    assert sent_text == "⚠ An internal error occurred."
    assert "secret" not in sent_text and "/srv" not in sent_text  # no leak
