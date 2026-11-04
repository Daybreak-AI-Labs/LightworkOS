"""Channel robustness and outbound reply hygiene.

1. Signal: the outbound reply send runs inside the receive loop's try/except,
   so a send failure (signal-cli's stdin breaks when the daemon dies or
   restarts, which is exactly when sends fail) does not propagate out of
   start() and kill the whole channel, as with email/sms/whatsapp.

2. Error-text leakage: a channel never reflects the raw exception text back
   to the remote user (``f"⚠ error: {e}"``), which can carry a credential or
   internal path. The detail is logged; the user gets a generic message
   (matching slack/signal). Voice is the representative case here.
"""
from __future__ import annotations

import asyncio
import json

import pytest

# --- fix 1: a Signal send failure must not kill the receive loop -----------

class _FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""

    async def read(self, size):
        return await self.readline()


class _FakeProc:
    pid = 4242
    returncode = None

    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = _FakeStdout([])
        self.stdin = None

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -1

    async def wait(self):
        return self.returncode


def test_signal_send_failure_does_not_kill_loop(monkeypatch):
    from maverick_channels.signal import SignalChannel

    async def _noop(_):
        return "reply"

    chan = SignalChannel(
        handler=_noop,
        phone_number="+12345550199",
        signal_cli_path="/bin/sh",
        allowed_user_ids={"+12345550100"},
    )

    line = json.dumps({
        "method": "receive",
        "params": {"envelope": {
            "source": "+12345550100",
            "dataMessage": {"message": "hello", "timestamp": 123},
        }},
    }).encode() + b"\n"

    async def _fake_create(*a, **k):
        return _FakeProc(_FakeStdout([line, b""]))  # one message, then EOF

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create)

    sent: list = []

    async def _boom(user_id, text):
        sent.append((user_id, text))
        raise BrokenPipeError("signal-cli stdin closed")

    monkeypatch.setattr(chan, "send", _boom)

    async def _reply(_msg):
        return "the reply"

    monkeypatch.setattr(chan, "handler", _reply)

    # The send raises, but start() must swallow it, keep looping, hit EOF, and
    # return -- not propagate the BrokenPipeError out of the channel.
    asyncio.run(chan.start())
    assert sent and sent[0][0] == "+12345550100"


# --- fix 2: handler errors are not reflected to the remote user ------------

def test_voice_handler_error_is_generic_not_leaked(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_channels.voice import VoiceChannel

    secret = "sk-do-not-leak-9876"  # pragma: allowlist secret

    async def _raises(_):
        raise RuntimeError(f"db connect failed token={secret}")

    monkeypatch.setenv("VAPI_WEBHOOK_TOKEN", "voice-secret")  # pragma: allowlist secret
    chan = VoiceChannel(handler=_raises, api_key="vapi-test-key", assistant_id="fixture-assistant",
                        allowed_callers=["+12025550111"])
    client = TestClient(chan._app)
    resp = client.post(
        "/webhook/voice",
        json={"message": {"type": "tool-calls", "call": {"id": "call1", "assistantId": "fixture-assistant",
              "customer": {"number": "+12025550111"}}, "toolCallList": [
              {"id": "event1", "name": "lightwork_request", "parameters": {"request": "hi"}}]}},
        headers={"Authorization": "Bearer voice-secret"},
    )
    assert resp.status_code == 200
    body = resp.json()["results"][0]["result"]
    assert secret not in body
    assert "no confirmed result" in body.lower()  # Explicit uncertainty, no raw detail.


# --- fix 3: outbound egress hygiene (mentions / empty / self-loop) ---------

def _signal_chan(monkeypatch, line: bytes):
    from maverick_channels.signal import SignalChannel

    async def _noop(_):
        return "reply"

    chan = SignalChannel(
        handler=_noop, phone_number="+12345550199",
        signal_cli_path="/bin/sh", allowed_user_ids={"+12345550199", "+12345550100"},
    )

    async def _fake_create(*a, **k):
        return _FakeProc(_FakeStdout([line, b""]))

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_create)
    return chan


def _receive(source: str) -> bytes:
    return json.dumps({
        "method": "receive",
        "params": {"envelope": {
            "source": source, "dataMessage": {"message": "hello", "timestamp": 123},
        }},
    }).encode() + b"\n"


def test_signal_ignores_its_own_number(monkeypatch):
    # signal-cli echoes our own outbound back as a receive. Even with the bot's
    # own number on the allowlist (a self-DM setup), it must not re-dispatch --
    # otherwise every reply loops forever.
    chan = _signal_chan(monkeypatch, _receive("+12345550199"))  # == phone_number
    dispatched = []
    monkeypatch.setattr(chan, "handler",
                        lambda m: dispatched.append(m) or "x")
    asyncio.run(chan.start())
    assert dispatched == []  # own message never reached the agent


def test_signal_empty_reply_is_not_sent(monkeypatch):
    chan = _signal_chan(monkeypatch, _receive("+12345550100"))
    sent = []
    monkeypatch.setattr(chan, "send",
                        lambda u, t: sent.append((u, t)))

    async def _empty(_):
        return ""

    monkeypatch.setattr(chan, "handler", _empty)
    asyncio.run(chan.start())
    assert sent == []  # action-only goal -> nothing pushed to Signal


def test_matrix_empty_reply_is_not_sent(monkeypatch):
    from maverick_channels.matrix import MatrixChannel

    chan = MatrixChannel.__new__(MatrixChannel)  # bypass __init__ (needs nio)
    chan.user_id = "@bot:hs"
    chan.homeserver = "https://hs"
    chan.allowed_user_ids = {"@user:hs"}
    chan._start_ts_ms = None
    sent = []

    async def _send(room, text):
        sent.append((room, text))

    chan.send = _send

    async def _empty(_):
        return ""

    chan.handler = _empty

    room = type("R", (), {"room_id": "!r:hs"})()
    event = type("E", (), {
        "sender": "@user:hs", "body": "hi", "server_timestamp": 1, "event_id": "$event1",
    })()
    asyncio.run(chan._on_message(room, event))
    assert sent == []  # blank m.text event never posted to the room


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
