"""Inbound channels must dedup a retried webhook ATOMICALLY.

Twilio resends the same MessageSid within ~15s when a handler is slow. The old
code did is_processed_message() (check) -> handler (slow goal) -> mark (after),
so two retries racing a slow handler both passed the check and ran the goal
twice -- a double-spend (duplicate API cost). The handler now CLAIMS the
MessageSid up front via mark_message_processed()'s atomic return value, so a
racing retry is a no-op.
"""
from __future__ import annotations

import pytest


def test_dedup_helpers_use_canonical_backend_and_ownership_close(monkeypatch):
    import maverick.world_model as world_model
    from maverick_channels.base import (
        claim_processed_message,
        release_processed_message,
    )

    calls = []

    class _World:
        def mark_message_processed(self, channel, external_id):
            calls.append(("claim", channel, external_id))
            return True

        def release_processed_message(self, channel, external_id):
            calls.append(("release", channel, external_id))

    worlds = [_World(), _World()]
    closed = []
    monkeypatch.setattr(world_model, "open_world", lambda: worlds.pop(0))
    monkeypatch.setattr(
        world_model, "close_world_if_owned", lambda candidate: closed.append(candidate)
    )

    assert claim_processed_message("sms", "SM1") is True
    release_processed_message("sms", "SM1")

    assert calls == [("claim", "sms", "SM1"), ("release", "sms", "SM1")]
    assert len(closed) == 2


def _have_twilio() -> bool:
    try:
        import fastapi  # noqa: F401
        import twilio  # noqa: F401
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
@pytest.mark.parametrize("channel,module,path,frm,sid", [
    ("sms", "maverick_channels.sms", "/webhook/sms",
     "+12025550111", "SMdup"),
    ("whatsapp", "maverick_channels.whatsapp", "/webhook/whatsapp",
     "whatsapp:+12025550111", "WAdup"),
])
def test_webhook_claims_sid_before_running_handler(
    tmp_path, monkeypatch, channel, module, path, frm, sid,
):
    """The SID is claimed BEFORE the handler runs, so a Twilio retry that
    races a still-running handler is deduped. A check-then-mark order would
    leave the SID unmarked until after the handler (a double-spend window)."""
    import importlib

    import maverick.world_model as wm_mod
    from fastapi.testclient import TestClient
    monkeypatch.setattr(wm_mod, "DEFAULT_DB", tmp_path / "world.db")

    mod = importlib.import_module(module)
    Channel = mod.SMSChannel if channel == "sms" else mod.WhatsAppChannel

    ran: list[str] = []
    claimed_when_handler_ran: list[bool] = []

    async def _handler(msg):
        # A concurrent Twilio retry arriving *now* must already see the SID as
        # claimed -- i.e. the claim happened before us. (Old code: still False.)
        from maverick_channels.delivery import DeliveryJournal
        receipt = DeliveryJournal().store.list(limit=2)[0]
        with wm_mod.WorldModel(wm_mod.DEFAULT_DB) as wm:
            claimed_when_handler_ran.append(
                receipt["execution"] == "execution_started_unconfirmed"
                and wm.is_processed_message("delivery:" + channel, receipt["id"])
            )
        ran.append(msg.text)
        return "ok"

    chan = Channel(
        handler=_handler, account_sid="ACx", auth_token="tok",
        from_number=("whatsapp:+15550000" if channel == "whatsapp" else "+15550000"),
        allowed_user_ids={frm},
    )
    chan._validator.validate = lambda *a, **k: True  # bypass Twilio signature

    async def _send(_uid, _text):
        return None
    chan.send = _send

    client = TestClient(chan._app)

    def _post():
        return client.post(path, data={"From": frm, "Body": "hi", "MessageSid": sid})

    assert _post().status_code == 200
    assert ran == ["hi"]
    # Claimed before the handler ran -> a racing retry would no-op.
    assert claimed_when_handler_ran == [True]

    # An actual Twilio resend of the same SID is now a no-op (no second run).
    assert _post().status_code == 200
    assert ran == ["hi"]


@pytest.mark.skipif(not _have_twilio(), reason="fastapi+twilio not installed")
@pytest.mark.parametrize("channel,module,path,frm,sid", [
    ("sms", "maverick_channels.sms", "/webhook/sms",
     "+12025550111", "SMclaimdown"),
    ("whatsapp", "maverick_channels.whatsapp", "/webhook/whatsapp",
     "whatsapp:+12025550111", "WAclaimdown"),
])
def test_webhook_claim_store_failure_is_retryable_and_never_runs_handler(
    monkeypatch, channel, module, path, frm, sid,
):
    import importlib

    import maverick.world_model as world_model
    from fastapi.testclient import TestClient

    mod = importlib.import_module(module)
    Channel = mod.SMSChannel if channel == "sms" else mod.WhatsAppChannel
    ran = []

    async def _handler(msg):
        ran.append(msg.text)
        return "must not run"

    chan = Channel(
        handler=_handler,
        account_sid="ACx",
        auth_token="tok",
        from_number=("whatsapp:+15550000" if channel == "whatsapp" else "+15550000"),
        allowed_user_ids={frm},
    )
    chan._validator.validate = lambda *a, **k: True

    def _claim_store_down():
        raise RuntimeError("claim store offline")

    monkeypatch.setattr(world_model, "open_world", _claim_store_down)
    response = TestClient(chan._app).post(
        path, data={"From": frm, "Body": "hi", "MessageSid": sid}
    )

    assert response.status_code == 503
    assert ran == []
