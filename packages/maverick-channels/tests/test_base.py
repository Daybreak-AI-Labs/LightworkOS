"""Channel base contract tests."""
from __future__ import annotations

from maverick_channels import Channel, Handler, IncomingMessage


def test_incoming_message_defaults():
    m = IncomingMessage(user_id="123", text="hello", channel="test")
    assert m.user_id == "123"
    assert m.text == "hello"
    assert m.channel == "test"
    assert m.attachments == []
    assert m.raw is None


def test_handler_type_exported():
    # Type alias; just confirm it's reachable.
    assert Handler is not None


def test_channel_is_abstract():
    # Channel is an ABC; subclasses must implement start/send/stop.
    import abc
    assert issubclass(Channel, abc.ABC) or hasattr(Channel, "__abstractmethods__")


# --- public_url_for: reconstruct the URL Twilio actually signed ------------


class _FakeURL:
    def __init__(self, path: str, full: str):
        self.path = path
        self._full = full

    def __str__(self) -> str:
        return self._full


class _FakeRequest:
    def __init__(self, path: str, full: str, headers: dict[str, str]):
        self.url = _FakeURL(path, full)
        self.headers = headers


def test_public_url_for_uses_forwarded_headers():
    from maverick_channels.base import public_url_for

    # Behind a reverse proxy: request.url is the loopback URL, but Twilio
    # signed the public https URL reconstructed from the X-Forwarded-* headers.
    req = _FakeRequest(
        path="/webhook/sms",
        full="http://127.0.0.1:8766/webhook/sms",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "bot.example.com"},
    )
    assert public_url_for(req) == "https://bot.example.com/webhook/sms"


def test_public_url_for_prefers_configured_base(monkeypatch):
    from maverick_channels.base import public_url_for

    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://configured.example.com/")
    req = _FakeRequest(
        path="/webhook/whatsapp",
        full="http://127.0.0.1:8765/webhook/whatsapp",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ignored.example.com"},
    )
    assert public_url_for(req) == "https://configured.example.com/webhook/whatsapp"


def test_public_url_for_reads_the_dashboard_setting(monkeypatch):
    from maverick_channels.base import public_url_for

    monkeypatch.delenv("MAVERICK_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"channels": {"public_base_url": "https://set.example.com/"}})
    req = _FakeRequest(path="/webhook/sms", full="http://127.0.0.1:8766/webhook/sms",
                       headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "proxy.example.com"})
    assert public_url_for(req) == "https://set.example.com/webhook/sms"
    monkeypatch.setenv("MAVERICK_PUBLIC_BASE_URL", "https://env.example.com")
    assert public_url_for(req) == "https://env.example.com/webhook/sms"  # the environment wins


def test_public_url_for_falls_back_to_raw_url(monkeypatch):
    from maverick_channels.base import public_url_for

    monkeypatch.delenv("MAVERICK_PUBLIC_BASE_URL", raising=False)
    # Direct bind, no proxy headers: fall back to the raw request URL.
    req = _FakeRequest(
        path="/webhook/sms",
        full="https://direct.example.com/webhook/sms",
        headers={},
    )
    assert public_url_for(req) == "https://direct.example.com/webhook/sms"


# --- backoff_delay: poll loops slow down on repeated upstream failures -----


def test_backoff_delay_no_errors_is_base_interval():
    from maverick_channels.base import backoff_delay

    assert backoff_delay(30.0, 0) == 30.0
    assert backoff_delay(30.0, -1) == 30.0  # defensive: never below base


def test_backoff_delay_doubles_per_consecutive_error():
    from maverick_channels.base import backoff_delay

    assert backoff_delay(30.0, 1) == 60.0
    assert backoff_delay(30.0, 2) == 120.0
    assert backoff_delay(30.0, 3) == 240.0


def test_backoff_delay_is_capped():
    from maverick_channels.base import backoff_delay

    # A persistently failing upstream tops out at the cap, not 2**n forever.
    assert backoff_delay(30.0, 50) == 300.0
    assert backoff_delay(10.0, 100, cap=120.0) == 120.0


def test_backoff_delay_handles_extremely_long_outages():
    from maverick_channels.base import backoff_delay

    assert backoff_delay(30.0, 1024) == 300.0
    assert backoff_delay(30.0, 10**100) == 300.0
    assert backoff_delay(0.0, 10**100) == 0.0


def test_backoff_delay_preserves_small_intervals_before_the_cap():
    import math

    from maverick_channels.base import backoff_delay

    assert backoff_delay(1e-310, 1024) == math.ldexp(1e-310, 1024)


def test_incoming_message_principal_id_prefers_sender_id():
    room_msg = IncomingMessage(
        user_id="CROOM", text="hello", channel="slack", sender_id="UALICE",
    )
    assert room_msg.principal_id == "UALICE"

    direct_msg = IncomingMessage(user_id="123", text="hello", channel="sms")
    assert direct_msg.principal_id == "123"


def test_incoming_message_truncates_oversized_text(monkeypatch):
    monkeypatch.setenv("MAVERICK_MAX_INBOUND_CHARS", "100")
    # Re-evaluate the cap (it's read per-construction).
    from maverick_channels.base import IncomingMessage
    big = "x" * 5000
    msg = IncomingMessage(user_id="u", text=big, channel="test")
    assert len(msg.text) < 5000
    assert "truncated by Lightwork inbound cap" in msg.text


def test_incoming_message_cap_disabled_with_zero(monkeypatch):
    monkeypatch.setenv("MAVERICK_MAX_INBOUND_CHARS", "0")
    from maverick_channels.base import IncomingMessage
    big = "y" * 5000
    msg = IncomingMessage(user_id="u", text=big, channel="test")
    assert msg.text == big  # cap disabled


def test_incoming_message_short_text_untouched(monkeypatch):
    monkeypatch.delenv("MAVERICK_MAX_INBOUND_CHARS", raising=False)
    from maverick_channels.base import IncomingMessage
    msg = IncomingMessage(user_id="u", text="hello", channel="test")
    assert msg.text == "hello"
