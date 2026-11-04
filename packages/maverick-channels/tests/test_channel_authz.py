"""Sender-authorization contract for every inbound channel.

Each channel must refuse to run the agent for a sender that isn't on an
explicit allowlist. Before this, slack/signal/matrix/imessage had no
allowlist at all, so any stranger who could reach the bot could drive
the swarm and burn the operator's API budget. These tests pin the
fail-closed behaviour so it can't silently regress.

Channels with optional third-party SDKs (slack_sdk, matrix-nio) can only
be constructed where the SDK is installed, so those cases skip cleanly
on a bare CI runner. The shared gate (``is_allowed`` / ``normalize_allowlist``)
is dependency-free and always exercised.
"""
from __future__ import annotations

import pytest
from maverick_channels.base import is_allowed, normalize_allowlist


async def _noop(_):
    return ""


# --- shared gate -----------------------------------------------------------

def test_is_allowed_denies_unknown_and_anonymous():
    allow = {"alice", "bob"}
    assert is_allowed("alice", allow) is True
    assert is_allowed("carol", allow) is False
    # Missing / sentinel ids never pass, even against a populated allowlist.
    assert is_allowed("", allow) is False
    assert is_allowed(None, allow) is False
    assert is_allowed("anonymous", allow) is False


def test_is_allowed_empty_allowlist_denies_everyone():
    # An empty allowlist is deny-all, never allow-all.
    assert is_allowed("alice", set()) is False


def test_normalize_allowlist_from_arg_and_env(monkeypatch):
    assert normalize_allowlist({"a", " b "}, "X_ALLOWED") == {"a", "b"}
    monkeypatch.setenv("X_ALLOWED", "u1, u2 ,, u3")
    assert normalize_allowlist(None, "X_ALLOWED") == {"u1", "u2", "u3"}
    monkeypatch.delenv("X_ALLOWED", raising=False)
    assert normalize_allowlist(None, "X_ALLOWED") == set()


# --- per-channel: construction is fail-closed ------------------------------

def test_signal_requires_allowlist():
    from maverick_channels.signal import SignalChannel
    with pytest.raises(ValueError, match="SIGNAL_ALLOWED_USER_IDS"):
        SignalChannel(
            handler=_noop, phone_number="+12345550199", allowed_user_ids=set(),
        )


def test_signal_stores_allowlist_and_denies_non_member():
    from maverick_channels.signal import SignalChannel
    # Pass an existing path so construction gets past the signal-cli probe.
    chan = SignalChannel(
        handler=_noop,
        phone_number="+12345550199",
        signal_cli_path="/bin/sh",
        allowed_user_ids={"+12345550100"},
    )
    assert is_allowed("+12345550100", chan.allowed_user_ids) is True
    assert is_allowed("+19998887777", chan.allowed_user_ids) is False


def test_slack_requires_allowlist():
    slack = pytest.importorskip("maverick_channels.slack")
    if not slack._HAVE_SLACK:
        pytest.skip("slack_sdk not installed")
    with pytest.raises(ValueError, match="SLACK_ALLOWED_USER_IDS"):
        slack.SlackChannel(
            handler=_noop, app_token="xapp-x", bot_token="xoxb-x",
            allowed_user_ids=set(),
        )


def test_matrix_requires_allowlist():
    matrix = pytest.importorskip("maverick_channels.matrix")
    if not matrix._HAVE_MATRIX:
        pytest.skip("matrix-nio not installed")
    with pytest.raises(ValueError, match="MATRIX_ALLOWED_USER_IDS"):
        matrix.MatrixChannel(
            handler=_noop, homeserver="https://matrix.org",
            user_id="@me:matrix.org", access_token="tok",
            allowed_user_ids=set(),
        )


# --- sms / whatsapp: per-sender allowlist (Twilio) -------------------------
#
# A valid X-Twilio-Signature only proves Twilio relayed the POST, not that
# the *sender* is authorized -- and a Twilio number is reachable by anyone on
# the PSTN. These channels were the two missed by the first allowlist pass;
# pin the fail-closed behaviour at both construction and the webhook path.

def _have_twilio() -> bool:
    try:
        import fastapi  # noqa: F401
        import twilio  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_sms_requires_allowlist():
    from maverick_channels.sms import SMSChannel
    with pytest.raises(ValueError, match="SMS_ALLOWED_USER_IDS"):
        SMSChannel(
            handler=_noop, account_sid="ACx", auth_token="tok",
            from_number="+15550000", allowed_user_ids=set(),
        )


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_whatsapp_requires_allowlist():
    from maverick_channels.whatsapp import WhatsAppChannel
    with pytest.raises(ValueError, match="WHATSAPP_ALLOWED_USER_IDS"):
        WhatsAppChannel(
            handler=_noop, account_sid="ACx", auth_token="tok",
            from_number="whatsapp:+15550000", allowed_user_ids=set(),
        )


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_sms_webhook_rejects_unauthorized_sender():
    """End-to-end: a signature-valid POST from a non-allowlisted number is
    refused (403) and never reaches the handler; an allowlisted number runs."""
    from fastapi.testclient import TestClient
    from maverick_channels.sms import SMSChannel

    seen = []

    async def _handler(msg):
        seen.append(msg.user_id)
        return "ran"

    chan = SMSChannel(
        handler=_handler, account_sid="ACx", auth_token="tok",
        from_number="+15550000", allowed_user_ids={"+12025550111"},
    )
    # Isolate the sender-allowlist gate from Twilio signature checking.
    chan._validator.validate = lambda *a, **k: True

    async def _send(_uid, _text):
        return None

    chan.send = _send
    client = TestClient(chan._app)

    def _post(frm):
        return client.post(
            "/webhook/sms",
            data={"From": frm, "Body": "hi", "MessageSid": "SM-auth-fixture"},
        )

    resp = _post("+19998887777")  # stranger
    assert resp.status_code == 403
    assert seen == []

    resp = _post("+12025550111")  # allowlisted owner
    assert resp.status_code == 200
    assert seen == ["+12025550111"]


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_whatsapp_webhook_rejects_unauthorized_sender():
    from fastapi.testclient import TestClient
    from maverick_channels.whatsapp import WhatsAppChannel

    seen = []

    async def _handler(msg):
        seen.append(msg.user_id)
        return "ran"

    chan = WhatsAppChannel(
        handler=_handler, account_sid="ACx", auth_token="tok",
        from_number="whatsapp:+15550000",
        allowed_user_ids={"whatsapp:+12025550111"},
    )
    chan._validator.validate = lambda *a, **k: True

    async def _send(_uid, _text):
        return None

    chan.send = _send
    client = TestClient(chan._app)

    def _post(frm):
        return client.post(
            "/webhook/whatsapp",
            data={"From": frm, "Body": "hi", "MessageSid": "WA-auth-fixture"},
        )

    resp = _post("whatsapp:+19998887777")
    assert resp.status_code == 403
    assert seen == []

    resp = _post("whatsapp:+12025550111")
    assert resp.status_code == 200
    assert seen == ["whatsapp:+12025550111"]


# --- sms / whatsapp: dedup-before-send (no double-spend on send failure) ---
#
# The budget-spending handler runs the full swarm. If we only marked the
# MessageSid processed AFTER the outbound send, a transient send failure would
# 500, Twilio would retry, and the whole goal would re-run -- double budget
# spend. So the MessageSid is marked processed immediately after the handler
# succeeds, BEFORE the send, and a send failure never returns 500.


class _FakeWorldModel:
    """Models the atomic dedup-claim API without touching a real DB.

    ``marked`` tracks the SIDs *currently* claimed: a claim adds, a release
    removes. ``mark_message_processed`` returns True on first claim / False on
    a duplicate, mirroring the real INSERT-under-UNIQUE-constraint behavior the
    channels now rely on (claim-first dedup)."""

    instances: list = []

    def __init__(self, _path=None):
        self.processed: set[tuple[str, str]] = set()
        self.marked: list[tuple[str, str]] = []
        _FakeWorldModel.instances.append(self)

    def is_processed_message(self, channel, external_id) -> bool:
        return (channel, external_id) in self.processed

    def mark_message_processed(self, channel, external_id, goal_id=None) -> bool:
        key = (channel, external_id)
        if key in self.processed:
            return False  # already claimed -> caller no-ops
        self.processed.add(key)
        self.marked.append(key)
        return True

    def release_processed_message(self, channel, external_id) -> None:
        key = (channel, external_id)
        self.processed.discard(key)
        if key in self.marked:
            self.marked.remove(key)


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_sms_marks_processed_before_send_and_survives_send_failure(monkeypatch):
    import maverick.world_model as _wm
    from fastapi.testclient import TestClient
    from maverick_channels.sms import SMSChannel

    _FakeWorldModel.instances = []
    monkeypatch.setattr(_wm, "WorldModel", _FakeWorldModel)

    ran = []

    async def _handler(msg):
        ran.append(msg.user_id)
        return "ok"

    chan = SMSChannel(
        handler=_handler, account_sid="ACx", auth_token="tok",
        from_number="+15550000", allowed_user_ids={"+12025550111"},
    )
    chan._validator.validate = lambda *a, **k: True

    async def _send_fails(_uid, _text):
        raise RuntimeError("twilio 503")

    chan.send = _send_fails
    client = TestClient(chan._app)

    resp = client.post(
        "/webhook/sms",
        data={"From": "+12025550111", "Body": "hi", "MessageSid": "SM123"},
    )
    # Send failed, but the goal already ran: must NOT 500 (Twilio would retry
    # and re-run the swarm). And the MessageSid is marked processed.
    assert resp.status_code == 200
    assert ran == ["+12025550111"]
    wm = _FakeWorldModel.instances[-1]
    receipt_id = resp.headers["X-Lightwork-Receipt"]
    assert ("delivery:sms", receipt_id) in wm.marked
    from maverick_channels.delivery import DeliveryJournal
    assert DeliveryJournal().get(receipt_id)["delivery"] == "delivery_unknown"
    client.post("/webhook/sms", data={"From": "+12025550111", "Body": "hi", "MessageSid": "SM123"})
    assert ran == ["+12025550111"]


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_sms_does_not_mark_processed_on_handler_failure(monkeypatch):
    import maverick.world_model as _wm
    from fastapi.testclient import TestClient
    from maverick_channels.sms import SMSChannel

    _FakeWorldModel.instances = []
    monkeypatch.setattr(_wm, "WorldModel", _FakeWorldModel)

    async def _handler(_msg):
        raise RuntimeError("handler boom")

    chan = SMSChannel(
        handler=_handler, account_sid="ACx", auth_token="tok",
        from_number="+15550000", allowed_user_ids={"+12025550111"},
    )
    chan._validator.validate = lambda *a, **k: True

    async def _send(_uid, _text):
        return None

    chan.send = _send
    client = TestClient(chan._app)

    resp = client.post(
        "/webhook/sms",
        data={"From": "+12025550111", "Body": "hi", "MessageSid": "SM999"},
    )
    assert resp.status_code == 200
    # Handler raised, so the message must be left UNmarked -- Twilio's retry
    # re-processes it rather than silently losing the goal.
    wm = _FakeWorldModel.instances[-1]
    assert ("sms", "SM999") not in wm.marked


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
def test_whatsapp_marks_processed_before_send_and_survives_send_failure(monkeypatch):
    import maverick.world_model as _wm
    from fastapi.testclient import TestClient
    from maverick_channels.whatsapp import WhatsAppChannel

    _FakeWorldModel.instances = []
    monkeypatch.setattr(_wm, "WorldModel", _FakeWorldModel)

    ran = []

    async def _handler(msg):
        ran.append(msg.user_id)
        return "ok"

    chan = WhatsAppChannel(
        handler=_handler, account_sid="ACx", auth_token="tok",
        from_number="whatsapp:+15550000",
        allowed_user_ids={"whatsapp:+12025550111"},
    )
    chan._validator.validate = lambda *a, **k: True

    async def _send_fails(_uid, _text):
        raise RuntimeError("twilio 503")

    chan.send = _send_fails
    client = TestClient(chan._app)

    resp = client.post(
        "/webhook/whatsapp",
        data={"From": "whatsapp:+12025550111", "Body": "hi", "MessageSid": "WA123"},
    )
    assert resp.status_code == 200
    assert ran == ["whatsapp:+12025550111"]
    wm = _FakeWorldModel.instances[-1]
    receipt_id = resp.headers["X-Lightwork-Receipt"]
    assert ("delivery:whatsapp", receipt_id) in wm.marked
    from maverick_channels.delivery import DeliveryJournal
    assert DeliveryJournal().get(receipt_id)["delivery"] == "delivery_unknown"
    client.post("/webhook/whatsapp", data={"From": "whatsapp:+12025550111", "Body": "hi", "MessageSid": "WA123"})
    assert ran == ["whatsapp:+12025550111"]


# --- telegram: chat allowlist must not authorize every group member --------


def _have_telegram() -> bool:
    try:
        import telegram  # noqa: F401
        return True
    except ImportError:
        return False


class _FakeUser:
    def __init__(self, uid):
        self.id = uid


class _FakeChat:
    def __init__(self, cid, ctype):
        self.id = cid
        self.type = ctype


class _FakeUpdate:
    def __init__(self, user_id, chat_id, chat_type):
        self.effective_user = _FakeUser(user_id) if user_id is not None else None
        self.effective_chat = _FakeChat(chat_id, chat_type)


@pytest.mark.skipif(not _have_telegram(), reason="python-telegram-bot not installed")
def test_telegram_group_requires_allowlisted_sender():
    from maverick_channels.telegram import TelegramChannel

    chan = TelegramChannel(
        handler=_noop,
        token="test-token",
        allowed_user_ids={"111"},
        allowed_chat_ids={"-1009998887777"},
    )
    group = "-1009998887777"
    # Allowlisted sender in the allowlisted group: authorized.
    assert chan._is_authorized(_FakeUpdate("111", group, "supergroup")) is True
    # A DIFFERENT group member (sender not allowlisted) must NOT be authorized
    # just because the chat is allowlisted -- this was the bug.
    assert chan._is_authorized(_FakeUpdate("222", group, "supergroup")) is False
    # Anonymous group admin / channel post (no sender): denied.
    assert chan._is_authorized(_FakeUpdate(None, group, "supergroup")) is False


@pytest.mark.skipif(not _have_telegram(), reason="python-telegram-bot not installed")
def test_telegram_private_chat_allowlist_authorizes():
    from maverick_channels.telegram import TelegramChannel

    # Chat-only allowlist for a PRIVATE chat is fine: one sender == one chat.
    chan = TelegramChannel(
        handler=_noop, token="test-token", allowed_chat_ids={"555"},
    )
    assert chan._is_authorized(_FakeUpdate("555", "555", "private")) is True
    # But the same chat allowlist must not authorize a group with chat id 777.
    assert chan._is_authorized(_FakeUpdate("777", "777", "supergroup")) is False


# --- voice: per-caller allowlist (launch-hardening) ------------------------

def _have_voice_deps() -> bool:
    try:
        import fastapi  # noqa: F401
        import httpx  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _have_voice_deps(), reason="fastapi+httpx not installed")
def test_voice_allowlist_blocks_unauthorized_caller(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_channels.voice import VoiceChannel

    seen = []

    async def _handler(msg):
        seen.append(msg.user_id)
        return "ran"

    monkeypatch.setenv("VAPI_WEBHOOK_TOKEN", "voice-secret")
    chan = VoiceChannel(_handler, api_key="vapi-test-key", assistant_id="fixture-assistant",
                        allowed_callers=["+12025550111"])
    client = TestClient(chan._app)
    hdr = {"Authorization": "Bearer voice-secret"}

    def _post(number):
        return client.post("/webhook/voice", headers=hdr, json={
            "message": {"type": "tool-calls", "call": {"id": "call1", "assistantId": "fixture-assistant",
                        "customer": {"number": number}}, "toolCallList": [{"id": "event1", "name": "lightwork_request",
                        "parameters": {"request": "hi"}}]},
        })

    # Unauthorized caller: rejected, handler never runs.
    resp = _post("+19998887777")
    assert resp.status_code == 403
    assert "not permitted" in resp.json()["detail"].lower()
    assert seen == []

    # Authorized caller: handler runs.
    resp = _post("+12025550111")
    assert resp.status_code == 200
    assert resp.json() == {"results": [{"name": "lightwork_request", "toolCallId": "event1", "result": "ran"}]}
    assert seen == ["+12025550111"]


@pytest.mark.skipif(not _have_voice_deps(), reason="fastapi+httpx not installed")
def test_voice_without_allowlist_refuses_authenticated_caller(monkeypatch):
    """The webhook bearer authenticates the provider, not its phone caller."""
    from fastapi.testclient import TestClient
    from maverick_channels.voice import VoiceChannel

    seen = []

    async def _handler(message):
        seen.append(message)
        return "ran"

    monkeypatch.setenv("VAPI_WEBHOOK_TOKEN", "voice-secret")
    monkeypatch.delenv("VOICE_ALLOWED_CALLERS", raising=False)
    chan = VoiceChannel(_handler, api_key="vapi-test-key")
    client = TestClient(chan._app)
    resp = client.post("/webhook/voice", headers={"Authorization": "Bearer voice-secret"}, json={
        "message": {"type": "transcript", "role": "user", "transcript": "hi", "id": "event1"},
        "call": {"id": "call1", "customer": {"number": "+19998887777"}},
    })
    assert resp.status_code == 403
    assert resp.json()["detail"] == "voice caller list is not configured"
    assert seen == []


@pytest.mark.skipif(not _have_voice_deps(), reason="fastapi+httpx not installed")
@pytest.mark.parametrize("number", [None, "", "202-555-0111", "+012025550111", "+12025550111 "])
def test_voice_refuses_missing_or_noncanonical_number_even_with_valid_bearer(monkeypatch, number):
    from fastapi.testclient import TestClient
    from maverick_channels.voice import VoiceChannel

    seen = []

    async def _handler(message):
        seen.append(message)
        return "ran"

    monkeypatch.setenv("VAPI_WEBHOOK_TOKEN", "voice-secret")
    chan = VoiceChannel(_handler, api_key="vapi-test-key", assistant_id="fixture-assistant", allowed_callers=["+12025550111"])
    call = {"id": "call1", "assistantId": "fixture-assistant", "customer": {}}
    if number is not None:
        call["customer"]["number"] = number
    resp = TestClient(chan._app).post("/webhook/voice", headers={"Authorization": "Bearer voice-secret"},
        json={"message": {"type": "tool-calls", "call": call, "toolCallList": [
              {"id": "event1", "name": "lightwork_request", "parameters": {"request": "hi"}}]}})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "This caller number is not permitted to start work."
    assert seen == []


# --- channel allowlist helpers ---

def test_channel_allowlist_helpers():
    base = pytest.importorskip("maverick_channels.base")
    al = base.normalize_allowlist(["a", "b ", " "], "X_UNUSED")
    assert al == {"a", "b"}
    assert base.is_allowed("a", al) is True
    assert base.is_allowed("z", al) is False
    assert base.is_allowed("", al) is False
    # "anonymous" must never satisfy an allowlist.
    assert base.is_allowed("anonymous", {"anonymous"}) is False


def test_email_channel_requires_allowlist(monkeypatch):
    mod = pytest.importorskip("maverick_channels.email")
    monkeypatch.delenv("EMAIL_ALLOWED_USER_IDS", raising=False)
    with pytest.raises(ValueError):
        mod.EmailChannel(
            handler=lambda m: "", imap_host="h", imap_user="u",
            imap_password="p", smtp_host="s", smtp_user="u", smtp_password="p",
        )
