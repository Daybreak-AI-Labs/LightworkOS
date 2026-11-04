"""openapi_runner bounds model/user-supplied HTTP bodies (DoS guard).

``safe_client`` only validates the host -- it does not cap the response size.
``r.text`` would buffer the entire body into memory before parsing/truncating,
so a spec/endpoint URL pointing at an endless body could exhaust memory.
``_load_spec`` and ``_op_call`` stream with a hard byte ceiling (mirroring ``http_fetch._stream_fetch``). These tests prove only the
capped prefix is ever read off the wire.
"""
from __future__ import annotations

import contextlib
import json

import pytest
from maverick.tools import openapi_runner as oar


class _FakeStream:
    """Mimics httpx's streaming response context.

    ``iter_bytes`` yields fixed-size chunks from an *unbounded* generator,
    recording how many bytes were actually pulled. A correct (capped) reader
    stops well before the whole (notionally infinite) body is consumed.
    """

    def __init__(self, chunk: bytes, total_chunks: int, counter: list[int]):
        self._chunk = chunk
        self._total = total_chunks
        self._counter = counter
        self.status_code = 200
        self.encoding = "utf-8"

    def raise_for_status(self):
        return None

    def iter_bytes(self):
        for _ in range(self._total):
            self._counter[0] += len(self._chunk)
            yield self._chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeClient:
    def __init__(self, chunk: bytes, total_chunks: int, counter: list[int]):
        self._chunk = chunk
        self._total = total_chunks
        self._counter = counter

    def stream(self, method, url, **kwargs):
        return _FakeStream(self._chunk, self._total, self._counter)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_safe_client(monkeypatch, chunk, total_chunks, counter):
    @contextlib.contextmanager
    def fake_safe_client(url, **kwargs):
        yield _FakeClient(chunk, total_chunks, counter)

    # _load_spec / _op_call import safe_client locally from ._ssrf, so patch
    # it at the source.
    from maverick.tools import _ssrf
    monkeypatch.setattr(_ssrf, "safe_client", fake_safe_client)


def test_spec_fetch_stops_at_byte_cap(monkeypatch):
    counter = [0]
    # 1 KB chunks; a "huge" body of 1 GB worth of chunks. A capped reader must
    # never pull anywhere near that.
    chunk = b"x" * 1024
    _patch_safe_client(monkeypatch, chunk, total_chunks=1_000_000, counter=counter)
    monkeypatch.setattr(oar, "_SPEC_MAX_BYTES", 50_000)
    oar._spec_cache.clear()

    # Body is a run of 'x' -> not valid JSON, and as YAML it parses to a plain
    # string (not a dict), so _load_spec rejects it as missing 'paths'. The
    # parse outcome is incidental; what matters is how MUCH was read.
    with pytest.raises(RuntimeError):
        oar._load_spec("https://example.com/spec.json")

    # Read at most the cap plus one final chunk (the chunk that crossed it).
    assert counter[0] <= 50_000 + len(chunk)
    assert counter[0] < 1024 * 1024  # nowhere near the full body


def test_call_response_stops_at_byte_cap(monkeypatch):
    counter = [0]
    chunk = b"y" * 1024
    _patch_safe_client(monkeypatch, chunk, total_chunks=1_000_000, counter=counter)
    monkeypatch.setattr(oar, "_CALL_MAX_BYTES", 40_000)

    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://example.com"}],
        "paths": {"/big": {"get": {"operationId": "getBig"}}},
    }
    monkeypatch.setattr(oar, "_load_spec", lambda src, workdir=None: spec)

    out = oar._op_call("https://example.com/spec.json", "getBig", None, None, None, None)

    assert out.startswith("HTTP 200")
    assert "(truncated)" in out  # display slice still applies
    assert counter[0] <= 40_000 + len(chunk)
    assert counter[0] < 1024 * 1024


def test_spec_within_cap_parses_normally(monkeypatch):
    counter = [0]
    spec_obj = {"openapi": "3.0.0", "paths": {}}
    body = json.dumps(spec_obj).encode("utf-8")
    _patch_safe_client(monkeypatch, body, total_chunks=1, counter=counter)
    monkeypatch.setattr(oar, "_SPEC_MAX_BYTES", 10_000_000)
    oar._spec_cache.clear()

    loaded = oar._load_spec("https://example.com/ok.json")
    assert loaded == spec_obj
