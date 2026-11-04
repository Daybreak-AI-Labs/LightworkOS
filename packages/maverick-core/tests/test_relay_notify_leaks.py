"""Regressions: relay destination hijack + webhook-URL log leak."""
from __future__ import annotations

import logging
import sys

from maverick import notifications
from maverick.relay_reference import Relay, RelayConfig

# --- relay: inbound context must not override deliver_to / goal --------------

def test_relay_context_cannot_hijack_destination_or_goal():
    captured: dict = {}

    def fake_starter(url, payload, *, secret=None):
        captured["payload"] = payload
        return "handle-1"

    cfg = RelayConfig(
        secondary_channel="trusted-channel",
        long_task_pattern=".*",       # everything is a long task here
        require_inbound_auth=False,
    )
    relay = Relay(
        config=cfg,
        sync_handler=lambda text, context: "quick",
        starter=fake_starter,
        deliver=lambda ch, result, context=None: None,
    )

    # Inbound context tries to redirect the result and decouple the goal.
    relay.handle(
        "run a long background task",
        context={"deliver_to": "attacker-channel", "goal": "evil", "source": "x"},
    )

    p = captured["payload"]
    assert p["deliver_to"] == "trusted-channel"     # NOT attacker-channel
    assert p["goal"] == "run a long background task"  # NOT "evil"


# --- notifications: a failed Slack/Discord POST must not log the secret URL --

def test_slack_failure_does_not_log_webhook_url(monkeypatch, caplog):
    secret_url = "https://hooks.slack.com/services/T00/B00/XXXXSECRETXXXX"  # pragma: allowlist secret

    class _FakeHTTPX:
        @staticmethod
        def post(url, *a, **k):
            # httpx embeds the request URL in the exception string.
            raise RuntimeError(f"ConnectError to {url}")

    monkeypatch.setitem(sys.modules, "httpx", _FakeHTTPX)
    with caplog.at_level(logging.WARNING, logger="maverick.notifications"):
        ok = notifications._send_slack("title", "body", secret_url)
    assert ok is False
    blob = " ".join(r.getMessage() for r in caplog.records)
    assert secret_url not in blob
    assert "SECRET" not in blob
