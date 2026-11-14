"""http_fetch streams with a hard byte cap.

Regression: _run_fetch used ``client.request()`` + ``resp.content[:max_bytes]``,
which buffered the ENTIRE body into memory before slicing -- ``max_bytes``
bounded the returned text but not the download, so a model-supplied URL to a
multi-GB / endless body could exhaust memory. It now streams and stops after
``max_bytes``.
"""
from __future__ import annotations


class _StreamResp:
    """Minimal stand-in for an httpx streaming response."""

    def __init__(self, chunks, *, content_type="text/plain"):
        self._chunks = chunks
        self.status_code = 200
        self.reason_phrase = "OK"
        self.encoding = "utf-8"
        self.url = "https://example.com/"
        self.headers = {"content-type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_bytes(self, chunk_size=None):  # httpx signature
        yield from self._chunks


class _StreamClient:
    def __init__(self, resp):
        self._resp = resp

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def stream(self, *a, **k):
        return self._resp


def _fetch(resp, monkeypatch, **args):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # offline: no DNS
    monkeypatch.setenv("MAVERICK_FETCH_NO_SCAN", "1")  # deterministic output
    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "safe_client", lambda url, **kw: _StreamClient(resp))
    from maverick.tools.http_fetch import http_fetch
    return http_fetch().fn({"url": "https://example.com/", "render": "raw", **args})


def test_body_truncated_to_max_bytes(monkeypatch):
    # 10 KiB available, cap at 4 KiB -> only 4 KiB returned, marked truncated.
    chunks = [b"Z" * 1024 for _ in range(10)]
    out = _fetch(_StreamResp(chunks), monkeypatch, max_bytes=4096)
    assert out.count("Z") == 4096  # 'Z' appears nowhere in the header
    assert "4096+ bytes" in out  # the '+' flags truncation


def test_streaming_stops_early_and_does_not_drain_endless_body(monkeypatch):
    # An endless generator: the old resp.content path would buffer forever.
    # The cap must stop reading after it's crossed, not after exhaustion.
    consumed = {"n": 0}

    def endless():
        while True:
            consumed["n"] += 1
            yield b"Y" * 1024

    out = _fetch(_StreamResp(endless()), monkeypatch, max_bytes=2048)
    assert consumed["n"] <= 4  # ~2 chunks to cross 2 KiB, not unbounded
    assert "HTTP 200 OK" in out
    assert "2048+ bytes" in out


def test_small_body_not_truncated(monkeypatch):
    # Under the cap: full body returned, no '+' truncation marker.
    out = _fetch(_StreamResp([b"hello world"]), monkeypatch, max_bytes=200_000)
    assert "hello world" in out
    assert "11 bytes" in out
    assert "11+ bytes" not in out


def test_trickled_body_stops_at_the_overall_deadline_and_redirects_are_reported(monkeypatch):
    # The 30 s httpx timeout bounds each read only; a server that trickles a
    # byte inside it held the call for up to max_bytes reads. A 3xx was
    # returned with no Location, so the caller could not follow it.
    import itertools

    import maverick.tools.http_fetch as hf

    clock = itertools.count(0.0, 10.0)
    monkeypatch.setattr(hf.time, "monotonic", lambda: next(clock))
    out = _fetch(_StreamResp([b"a"] * 50), monkeypatch)
    # What arrived is kept (an approved POST's response must not be lost),
    # marked as cut off by the deadline.
    assert out.startswith("HTTP 200") and "body cut off: not finished within 30s" in out.splitlines()[0]
    assert 0 < out.count("a") < 50

    monkeypatch.setattr(hf.time, "monotonic", lambda: 0.0)
    moved = _StreamResp([b""])
    moved.status_code, moved.reason_phrase = 301, "Moved\x1b[2J" + "x" * 500
    moved.headers["location"] = "https://www.example.com/"
    out = _fetch(moved, monkeypatch)
    assert "Redirect location (not followed): https://www.example.com/" in out
    assert "\x1b" not in out.splitlines()[0] and len(out.splitlines()[0]) < 200
