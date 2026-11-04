"""The self-hosted relay (deploy/relay/relay.py) must sign requests exactly the
way maverick.webhooks verifies them — otherwise every forwarded request 403s.
This loads the standalone relay module by path and checks the round-trip.
"""
from __future__ import annotations

import http.client
import importlib.util
import threading
import time
from pathlib import Path

import pytest
from maverick.webhooks import verify_signature

_RELAY = (
    Path(__file__).resolve().parents[3] / "deploy" / "relay" / "relay.py"
)


def _load_relay():
    spec = importlib.util.spec_from_file_location("maverick_relay", _RELAY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.skipif(not _RELAY.exists(), reason="relay reference not present")
def test_relay_signature_is_accepted_by_webhooks():
    relay = _load_relay()
    secret = "shared-secret"  # pragma: allowlist secret
    body = b'{"title": "do the thing"}'
    ts = str(int(time.time()))
    sig = relay.sign(body, secret, ts)
    assert sig.startswith("sha256=")
    # The receiver must accept it (timestamp-bound, within freshness window).
    assert verify_signature(body, sig, secret, timestamp=ts) is True


@pytest.mark.skipif(not _RELAY.exists(), reason="relay reference not present")
def test_relay_signature_rejects_tamper():
    relay = _load_relay()
    secret = "shared-secret"  # pragma: allowlist secret
    ts = str(int(time.time()))
    sig = relay.sign(b'{"title": "a"}', secret, ts)
    # A different body under the same signature must fail.
    assert verify_signature(b'{"title": "b"}', sig, secret, timestamp=ts) is False


@pytest.mark.skipif(not _RELAY.exists(), reason="relay reference not present")
def test_relay_requires_caller_token_to_start(monkeypatch):
    monkeypatch.setenv("MAVERICK_RELAY_SECRET", "shared-secret")
    monkeypatch.delenv("MAVERICK_RELAY_TOKEN", raising=False)
    relay = _load_relay()

    with pytest.raises(SystemExit, match="MAVERICK_RELAY_TOKEN"):
        relay.main()


@pytest.mark.skipif(not _RELAY.exists(), reason="relay reference not present")
def test_relay_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("MAVERICK_RELAY_HOST", raising=False)
    relay = _load_relay()

    assert relay.HOST == "127.0.0.1"


@pytest.mark.skipif(not _RELAY.exists(), reason="relay reference not present")
def test_relay_refuses_a_non_ascii_bearer_with_401(monkeypatch):
    # http.server decodes headers as latin-1, so a caller can send accented
    # text: that is a wrong token (401), not a dropped connection.
    monkeypatch.setenv("MAVERICK_RELAY_TOKEN", "caller-token")  # pragma: allowlist secret
    relay = _load_relay()
    server = relay.ThreadingHTTPServer(("127.0.0.1", 0), relay.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_address[1], timeout=10,
        )
        connection.request(
            "POST", "/relay", body=b"{}",
            headers={"Authorization": "Bearer jeton-\u00e9", "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 401
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
