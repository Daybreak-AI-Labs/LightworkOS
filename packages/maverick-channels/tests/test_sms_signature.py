"""SMS Twilio webhook signature verification smoke test.

Critical security property: SMSChannel._handle_webhook must reject
requests with a bad X-Twilio-Signature with 403 before invoking the
agent handler. Without this, anyone with the webhook URL can spoof an
inbound SMS and drive the swarm.

We can't easily run the full FastAPI handler in unit tests because the
twilio + fastapi deps may not be installed in CI. We instead assert the
*shape* of the channel: that it constructs a RequestValidator and wires
the webhook route.
"""
from __future__ import annotations

import pytest


def _have_deps() -> bool:
    try:
        import fastapi  # noqa: F401
        import twilio  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _have_deps(), reason="fastapi+twilio not installed")
def test_sms_channel_constructs_validator():
    from maverick_channels.sms import SMSChannel

    async def _noop(_):
        return ""

    chan = SMSChannel(
        handler=_noop,
        account_sid="ACtest",
        auth_token="tokentoken",
        from_number="+15551234",
        allowed_user_ids={"+15550001111"},
    )
    # RequestValidator must be wired in.
    assert chan._validator is not None
    # FastAPI route exists.
    routes = [r.path for r in chan._app.routes if hasattr(r, "path")]
    assert "/webhook/sms" in routes


@pytest.mark.skipif(not _have_deps(), reason="fastapi+twilio not installed")
def test_sms_channel_rejects_missing_creds():
    """Constructing without creds must raise so a half-configured channel
    can't accidentally accept webhooks."""
    from maverick_channels.sms import SMSChannel

    async def _noop(_):
        return ""

    with pytest.raises(ValueError, match="Twilio credentials"):
        SMSChannel(handler=_noop, account_sid=None, auth_token=None, from_number=None)
