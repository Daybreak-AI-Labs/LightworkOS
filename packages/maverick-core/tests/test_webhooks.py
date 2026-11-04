"""Tests for outbound webhooks (maverick.webhooks)."""
from __future__ import annotations

# ---------- webhooks ----------

def test_webhooks_no_urls_no_op():
    from maverick.webhooks import fire
    # Pass empty urls explicitly to bypass config lookup.
    n = fire("test_event", {"x": 1}, urls=[], secret=None)
    assert n == 0


def test_webhooks_signature_round_trip():
    """verify_signature accepts the signature fire() would produce."""
    from maverick.webhooks import _sign, verify_signature
    body = b'{"hello": "world"}'
    sig = _sign(body, "secret-key")
    assert sig.startswith("sha256=")
    assert verify_signature(body, sig, "secret-key") is True
    assert verify_signature(body, sig, "wrong-key") is False
    assert verify_signature(body, "garbage", "secret-key") is False


def test_webhooks_fires_per_url(monkeypatch):
    """fire() submits one POST per URL configured."""
    from maverick import webhooks
    posted: list[str] = []

    def _fake_post(url, body, headers, timeout):
        posted.append(url)

    monkeypatch.setattr(webhooks, "_post", _fake_post)
    # Wait for threadpool to drain by submitting then joining.
    n = webhooks.fire(
        "goal_finished",
        {"goal_id": 1, "status": "succeeded"},
        urls=["https://a.example", "https://b.example"],
        secret=None,
    )
    # Drain the pool.
    exec_ = webhooks._get_executor()
    exec_.shutdown(wait=True)
    # Reset for downstream tests so they get a fresh pool.
    webhooks._executor = None
    assert n == 2
    assert sorted(posted) == ["https://a.example", "https://b.example"]


def test_webhooks_timestamped_signature_replay_window():
    """A timestamped signature is rejected once the timestamp falls outside the
    max-age window (replay defence) but accepted while fresh."""
    import time

    from maverick.webhooks import _sign, verify_signature
    body = b'{"event": "x"}'
    fresh = str(int(time.time()))
    sig = _sign(body, "k", timestamp=fresh)
    # fresh -> accepted
    assert verify_signature(body, sig, "k", timestamp=fresh, max_age=300) is True
    # stale -> rejected even though the HMAC matches the (stale) timestamp
    stale = str(int(time.time()) - 10_000)
    stale_sig = _sign(body, "k", timestamp=stale)
    assert verify_signature(body, stale_sig, "k", timestamp=stale, max_age=300) is False
    # a captured fresh signature replayed with a tampered timestamp -> rejected
    assert verify_signature(body, sig, "k", timestamp=stale, max_age=300) is False


def test_webhooks_outbound_post_blocks_ssrf(monkeypatch):
    """_post routes through the SSRF guard: a loopback/metadata target makes no
    outbound request."""
    import httpx
    from maverick import webhooks
    posted: list[str] = []

    def _spy(self, url, **kw):  # pragma: no cover - must not run for blocked host
        posted.append(str(url))

        class _R:
            status_code = 200
            text = ""

        return _R()

    monkeypatch.setattr(httpx.Client, "post", _spy)
    for url in (
        "http://127.0.0.1:8765/internal",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ):
        webhooks._post(url, b"{}", {}, 5.0)
    assert posted == []


def test_webhooks_outbound_post_allows_public(monkeypatch):
    """A public outbound target still fires through the guard."""
    import httpx
    from maverick import webhooks
    posted: list[str] = []

    def _spy(self, url, **kw):
        posted.append(str(url))

        class _R:
            status_code = 200
            text = ""

        return _R()

    monkeypatch.setattr(httpx.Client, "post", _spy)
    # Literal public IP -> deterministic offline (no DNS).
    webhooks._post("http://93.184.216.34/wh", b"{}", {}, 5.0)
    assert posted == ["http://93.184.216.34/wh"]
