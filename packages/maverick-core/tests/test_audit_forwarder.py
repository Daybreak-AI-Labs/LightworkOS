"""SIEM forwarder: push rendered audit lines to tcp/udp/http collectors."""
from __future__ import annotations

import email.message
import io
import json
import logging
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from datetime import datetime, timezone

import pytest
from maverick.audit import forwarder


def test_parse_dest_schemes():
    assert forwarder.parse_dest("tcp://h:514") == ("tcp", "h", 514, "")
    assert forwarder.parse_dest("udp://h:514") == ("udp", "h", 514, "")
    s, h, p, url = forwarder.parse_dest("https://siem.example/services/collector/raw")
    assert (s, h, p) == ("https", "siem.example", 443)
    assert url == "https://siem.example/services/collector/raw"
    assert forwarder.parse_dest("http://h/path")[2] == 80  # default port


@pytest.mark.parametrize("bad", [
    "ftp://h:1", "tcp://h", "udp://nohost", "https://", "not-a-uri",
])
def test_parse_dest_rejects_bad(bad):
    with pytest.raises(ValueError):
        forwarder.parse_dest(bad)


def test_forward_tcp_delivers_newline_framed_lines():
    received: list[bytes] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept():
        conn, _ = srv.accept()
        with conn:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                received.append(chunk)

    t = threading.Thread(target=_accept)
    t.start()
    n = forwarder.forward(["a", "b", "c"], f"tcp://127.0.0.1:{port}")
    t.join(timeout=5)
    srv.close()
    assert n == 3
    assert b"".join(received) == b"a\nb\nc\n"


def test_forward_udp_one_datagram_per_event():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    port = srv.getsockname()[1]

    n = forwarder.forward(["x", "y"], f"udp://127.0.0.1:{port}")
    assert n == 2
    got = {srv.recvfrom(1024)[0] for _ in range(2)}
    srv.close()
    assert got == {b"x\n", b"y\n"}


def test_forward_udp_rejects_oversized_event_without_truncating():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(0.2)
    port = srv.getsockname()[1]

    try:
        with pytest.raises(ValueError, match="exceeds UDP payload limit"):
            forwarder.forward(["x" * forwarder._UDP_MAX], f"udp://127.0.0.1:{port}")
        with pytest.raises(TimeoutError):
            srv.recvfrom(1024)
    finally:
        srv.close()


def test_forward_udp_ipv6_destination():
    # IPv6 collectors must work too (regression: family was hardcoded AF_INET).
    import socket as _s
    if not _s.has_ipv6:
        pytest.skip("no IPv6 on this host")
    try:
        srv = _s.socket(_s.AF_INET6, _s.SOCK_DGRAM)
        srv.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback unavailable in this environment")
    try:
        srv.settimeout(5)
        port = srv.getsockname()[1]
        n = forwarder.forward(["z"], f"udp://[::1]:{port}")
        assert n == 1
        assert srv.recvfrom(1024)[0] == b"z\n"
    finally:
        srv.close()


def test_forward_http_posts_batch_with_token(monkeypatch):
    captured = {}

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["auth"] = req.get_header("Authorization")
        return _Resp()

    monkeypatch.setenv("MAVERICK_SIEM_TOKEN", "hec-token")
    monkeypatch.delenv("MAVERICK_SECRETS_BACKEND", raising=False)
    monkeypatch.setattr(forwarder, "_open_vendor", _fake_urlopen)

    n = forwarder.forward(["e1", "e2"], "https://siem.example/raw")
    assert n == 2
    assert captured["body"] == b"e1\ne2\n"
    assert captured["auth"] == "Bearer hec-token"
    assert captured["url"] == "https://siem.example/raw"


def test_forward_http_streams_bounded_batches(monkeypatch):
    bodies: list[bytes] = []
    yielded = 0

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _lines():
        nonlocal yielded
        for line in ("aa", "bb", "cc"):
            yielded += 1
            yield line

    def _fake_urlopen(req, timeout=None):
        bodies.append(req.data)
        if len(bodies) == 1:
            assert yielded < 3
        return _Resp()

    monkeypatch.setattr(forwarder, "_HTTP_BATCH_MAX", 6)
    monkeypatch.setattr(forwarder, "_open_vendor", _fake_urlopen)

    assert forwarder.forward(_lines(), "https://siem.example/raw") == 3
    assert bodies == [b"aa\nbb\n", b"cc\n"]


def test_forward_http_raises_on_5xx(monkeypatch):
    class _Resp:
        status = 503
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(forwarder, "_open_vendor", lambda req, timeout=None: _Resp())
    with pytest.raises(RuntimeError, match="503"):
        forwarder.forward(["e1"], "https://siem.example/raw")


def test_forward_http_empty_batch_sends_nothing(monkeypatch):
    def _boom(*a, **k):  # pragma: no cover -- must not be called
        raise AssertionError("urlopen called for empty batch")

    monkeypatch.setattr(forwarder, "_open_vendor", _boom)
    assert forwarder.forward([], "https://siem.example/raw") == 0


# --- Datadog and Microsoft Sentinel destinations -----------------------------

_DD_KEY = "dd-api-key-test-0123456789abcdef"  # pragma: allowlist secret - fake key
_SENTINEL_HOST = "my-dce-5kyl.eastus-1.ingest.monitor.azure.com"
_SENTINEL_DCR = "dcr-000a00a000a00000a000000aa000a0aa"
_SENTINEL_TENANT = "11111111-2222-3333-4444-555555555555"
_SENTINEL_CLIENT = "66666666-7777-8888-9999-000000000000"
_SENTINEL_SECRET = "sentinel-client-secret-test-0123456789"  # pragma: allowlist secret - fake
_SENTINEL_DEST = f"sentinel://{_SENTINEL_HOST}/{_SENTINEL_DCR}/Custom-MaverickAudit"


@pytest.fixture
def vendor_env(monkeypatch):
    """Keep vendor destinations away from host config, the secret backend and token cache."""
    monkeypatch.delenv("MAVERICK_SECRETS_BACKEND", raising=False)
    for name in ("MAVERICK_DATADOG_API_KEY", "MAVERICK_SENTINEL_TENANT_ID",
                 "MAVERICK_SENTINEL_CLIENT_ID", "MAVERICK_SENTINEL_CLIENT_SECRET",
                 "MAVERICK_SIEM_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(forwarder, "_audit_config", lambda key: None)
    monkeypatch.setattr(forwarder, "_sentinel_tokens", {})
    return monkeypatch


def _record_posts(monkeypatch):
    calls = []

    def _fake(url, body, headers, timeout, label):
        calls.append({"url": url, "body": body, "headers": dict(headers), "label": label})
        return b""

    monkeypatch.setattr(forwarder, "_https_post", _fake)
    return calls


def _sentinel_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_SENTINEL_TENANT_ID", _SENTINEL_TENANT)
    monkeypatch.setenv("MAVERICK_SENTINEL_CLIENT_ID", _SENTINEL_CLIENT)
    monkeypatch.setenv("MAVERICK_SENTINEL_CLIENT_SECRET", _SENTINEL_SECRET)


def _sentinel_fake(monkeypatch, *, lifetime=3600):
    """Fake the Entra token endpoint and the DCR ingestion endpoint."""
    seen = {"tokens": [], "ingest": []}

    def _fake(url, body, headers, timeout, label):
        if url.startswith("https://login.microsoftonline.com/"):
            seen["tokens"].append({"url": url, "body": body, "headers": dict(headers)})
            token = f"tok-{len(seen['tokens'])}"
            return json.dumps({"token_type": "Bearer", "expires_in": lifetime,
                               "access_token": token}).encode()
        seen["ingest"].append({"url": url, "body": body, "headers": dict(headers), "label": label})
        return b""

    monkeypatch.setattr(forwarder, "_https_post", _fake)
    return seen


@pytest.mark.parametrize("dest,host", [
    ("datadog://datadoghq.com", "http-intake.logs.datadoghq.com"),
    ("datadog://datadoghq.eu", "http-intake.logs.datadoghq.eu"),
    ("datadog://us3.datadoghq.com", "http-intake.logs.us3.datadoghq.com"),
    ("datadog://ddog-gov.com", "http-intake.logs.ddog-gov.com"),
])
def test_parse_dest_datadog_site_maps_to_intake_host(dest, host):
    assert forwarder.parse_dest(dest) == ("datadog", host, 443, f"https://{host}/api/v2/logs")


@pytest.mark.parametrize("bad", [
    "datadog://", "datadog://example.com", "datadog://datadoghq.com.evil.example",
    "datadog://datadoghq.com:443", "datadog://datadoghq.com/api/v2/logs",
    "datadog://datadoghq.com?x=1", "datadog://key-in-uri@datadoghq.com",
])
def test_parse_dest_rejects_bad_datadog_without_echoing_uri(bad):
    with pytest.raises(ValueError) as info:
        forwarder.parse_dest(bad)
    assert "key-in-uri" not in str(info.value)


def test_parse_dest_sentinel_builds_logs_ingestion_url():
    assert forwarder.parse_dest(_SENTINEL_DEST) == (
        "sentinel", _SENTINEL_HOST, 443,
        f"https://{_SENTINEL_HOST}/dataCollectionRules/{_SENTINEL_DCR}"
        "/streams/Custom-MaverickAudit?api-version=2023-01-01",
    )


@pytest.mark.parametrize("bad", [
    "sentinel://", f"sentinel://evil.example.com/{_SENTINEL_DCR}/Custom-T",
    f"sentinel://monitor.azure.com/{_SENTINEL_DCR}/Custom-T",
    f"sentinel://{_SENTINEL_HOST}:443/{_SENTINEL_DCR}/Custom-T",
    f"sentinel://{_SENTINEL_HOST}/dcr-short/Custom-T",
    f"sentinel://{_SENTINEL_HOST}/{_SENTINEL_DCR}/Microsoft-Table",
    f"sentinel://{_SENTINEL_HOST}/{_SENTINEL_DCR}/Custom-T/extra",
    f"sentinel://{_SENTINEL_HOST}/{_SENTINEL_DCR}",
    f"sentinel://{_SENTINEL_HOST}/{_SENTINEL_DCR}/Custom-T?x=1",
    f"sentinel://user@{_SENTINEL_HOST}/{_SENTINEL_DCR}/Custom-T",
])
def test_parse_dest_rejects_bad_sentinel(bad):
    with pytest.raises(ValueError):
        forwarder.parse_dest(bad)


def test_parse_dest_unsupported_scheme_lists_vendor_schemes():
    with pytest.raises(ValueError, match="datadog, sentinel"):
        forwarder.parse_dest("ftp://h:1")


@pytest.mark.parametrize("site,intake", [
    ("datadoghq.com", "http-intake.logs.datadoghq.com"),
    ("datadoghq.eu", "http-intake.logs.datadoghq.eu"),
    ("us3.datadoghq.com", "http-intake.logs.us3.datadoghq.com"),
])
def test_datadog_posts_json_array_with_key_header_per_site(vendor_env, site, intake):
    calls = _record_posts(vendor_env)
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)
    assert forwarder.forward(["a", "b"], f"datadog://{site}") == 2
    (call,) = calls
    assert call["url"] == f"https://{intake}/api/v2/logs"
    assert call["headers"]["DD-API-KEY"] == _DD_KEY
    assert call["headers"]["Content-Type"] == "application/json"
    assert json.loads(call["body"]) == [
        {"ddsource": "lightwork", "service": "lightwork-audit", "message": "a"},
        {"ddsource": "lightwork", "service": "lightwork-audit", "message": "b"},
    ]


def test_datadog_key_falls_back_to_audit_config(vendor_env):
    calls = _record_posts(vendor_env)
    vendor_env.setattr(forwarder, "_audit_config",
                       lambda key: _DD_KEY if key == "datadog_api_key" else None)
    forwarder.forward(["a"], "datadog://datadoghq.com")
    assert calls[0]["headers"]["DD-API-KEY"] == _DD_KEY


def test_datadog_documented_limits_are_the_batch_bounds():
    # Datadog send-logs reference: 1000 entries per array, 5MB per payload, 1MB per
    # log. The reference does not define MB, so the smaller decimal reading is used.
    assert (forwarder._DATADOG_MAX_ENTRIES, forwarder._DATADOG_MAX_BODY,
            forwarder._DATADOG_MAX_LOG) == (1000, 5_000_000, 1_000_000)


def test_datadog_batches_at_entry_limit(vendor_env):
    calls = _record_posts(vendor_env)
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)
    lines = [f"e{i}" for i in range(1001)]
    assert forwarder.forward(lines, "datadog://datadoghq.com") == 1001
    assert [len(json.loads(c["body"])) for c in calls] == [1000, 1]


def test_datadog_batches_before_body_byte_limit(vendor_env):
    calls = _record_posts(vendor_env)
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)
    line = "x" * 10
    one = len(forwarder._datadog_entry(line))
    limit = 2 + 2 * one + 1  # brackets + two entries + the comma between them
    vendor_env.setattr(forwarder, "_DATADOG_MAX_BODY", limit)
    assert forwarder.forward([line] * 5, "datadog://datadoghq.com") == 5
    assert [len(json.loads(c["body"])) for c in calls] == [2, 2, 1]
    assert all(len(c["body"]) <= limit for c in calls)


def test_datadog_log_limit_is_one_million_bytes_and_refuses_one_more(vendor_env):
    calls = _record_posts(vendor_env)
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)
    room = forwarder._DATADOG_MAX_LOG - len(forwarder._datadog_entry(""))
    assert len(forwarder._datadog_entry("x" * room)) == 1_000_000
    assert forwarder.forward(["x" * room], "datadog://datadoghq.com") == 1
    with pytest.raises(ValueError, match="Datadog"):
        forwarder.forward(["x" * (room + 1)], "datadog://datadoghq.com")
    assert len(calls) == 1


def test_datadog_failure_names_destination_and_never_the_key(vendor_env, caplog):
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)

    def _refuse(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    vendor_env.setattr(forwarder, "_open_vendor", _refuse)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RuntimeError) as info:
            forwarder.forward(["a"], "datadog://datadoghq.com")
    message = str(info.value)
    assert "Datadog" in message and "403" in message
    assert _DD_KEY not in message and _DD_KEY not in repr(info.value)
    assert _DD_KEY not in caplog.text


def test_datadog_transport_error_names_destination_and_never_the_key(vendor_env):
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)

    def _unreachable(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    vendor_env.setattr(forwarder, "_open_vendor", _unreachable)
    with pytest.raises(RuntimeError, match="Datadog") as info:
        forwarder.forward(["a"], "datadog://datadoghq.com")
    assert _DD_KEY not in str(info.value)


def test_https_post_refuses_plaintext_url_before_any_request(vendor_env):
    def _boom(*args, **kwargs):  # pragma: no cover -- must not be called
        raise AssertionError("network used for a plaintext URL")

    vendor_env.setattr(forwarder, "_open_vendor", _boom)
    with pytest.raises(RuntimeError, match="TLS"):
        forwarder._https_post("http://intake.example/api", b"[]", {}, 5.0, "Datadog log intake")


def _no_network(monkeypatch):
    """Fail loudly if a test ever reaches a socket; header errors must come first."""
    def _connect(self):  # pragma: no cover -- must not be called
        raise AssertionError("network used for a request that should not be built")

    monkeypatch.setattr("http.client.HTTPSConnection.connect", _connect)


@pytest.mark.parametrize("value", [
    "dd-key-part\nline-two", "dd-key-part\rline-two", "dd-key-part\x00line-two",
    "dd-key-part line-two",
])
def test_https_post_refuses_non_ascii_header_without_echoing_it(vendor_env, value):
    # http.client's ValueError (or UnicodeEncodeError) quotes the whole header value,
    # so the value must be refused before urllib ever builds the request.
    _no_network(vendor_env)
    with pytest.raises(RuntimeError, match="Datadog log intake") as info:
        forwarder._https_post("https://http-intake.logs.datadoghq.com/api/v2/logs", b"[]",
                              {"DD-API-KEY": value}, 5.0, "Datadog log intake")
    assert "dd-key-part" not in str(info.value) and "line-two" not in str(info.value)
    assert info.value.__context__ is None


def _scripted_https(monkeypatch, *replies):
    """Answer successive https requests with (status, location) replies; record each request.

    A plaintext http request raises, so a test fails if a credential is ever sent over http.
    """
    seen = []

    def _https_open(self, req):
        seen.append(("https", req.full_url, req.get_header("Dd-api-key")))
        status, location = replies[len(seen) - 1]
        headers = email.message.Message()
        if location:
            headers["Location"] = location
        resp = urllib.response.addinfourl(io.BytesIO(b"ok"), headers, req.full_url, status)
        resp.msg = "OK" if status == 200 else "Redirect"
        return resp

    def _http_open(self, req):  # pragma: no cover -- must not be called
        seen.append(("http", req.full_url, req.get_header("Dd-api-key")))
        raise AssertionError("plaintext request sent")

    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", _https_open)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", _http_open)
    return seen


_DD_URL = "https://http-intake.logs.datadoghq.com/api/v2/logs"


@pytest.mark.parametrize("status", [301, 302, 307])
@pytest.mark.parametrize("location", [
    "http://collector.example.net/api/v2/logs",   # plaintext: the key must not leave
    "https://collector.example.net/api/v2/logs",  # another host
    "/api/v2/logs-moved",                         # same origin: still not followed
])
def test_vendor_redirects_are_reported_not_followed(vendor_env, status, location):
    # urllib would resend every custom header to the redirect target, and on 301-303
    # would resend the POST body as a GET. A redirect is therefore an HTTP error.
    seen = _scripted_https(vendor_env, (status, location), (200, None))
    with pytest.raises(RuntimeError, match=f"returned HTTP {status}") as info:
        forwarder._https_post(_DD_URL, b"[]", {"DD-API-KEY": _DD_KEY}, 5.0,
                              "Datadog log intake")
    assert seen == [("https", _DD_URL, _DD_KEY)]
    assert _DD_KEY not in str(info.value)


def test_datadog_key_with_line_break_is_refused_without_echoing_it(vendor_env, caplog):
    _no_network(vendor_env)
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", "dd-api-key-line-one\ndd-api-key-line-two")
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RuntimeError, match="Datadog") as info:
            forwarder.forward(["a"], "datadog://datadoghq.com")
    for text in (str(info.value), repr(info.value), caplog.text):
        assert "line-one" not in text and "line-two" not in text
    assert info.value.__context__ is None


def test_sentinel_documented_limits_are_the_batch_bounds():
    # Logs Ingestion API: 1MB per call and 64KB per field value; Azure truncates a
    # longer field. The service limits do not define the unit, so the decimal reading.
    assert (forwarder._SENTINEL_MAX_BODY, forwarder._SENTINEL_MAX_FIELD) == (1_000_000, 64_000)


def test_sentinel_token_is_fetched_once_and_refreshed_after_expiry(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env, lifetime=3600)
    now = [1000.0]
    vendor_env.setattr(forwarder, "_clock", lambda: now[0])
    vendor_env.setattr(forwarder, "_SENTINEL_MAX_BODY", 200)  # force several batches
    lines = [json.dumps({"ts": 1786700000.0, "n": i}) for i in range(6)]
    assert forwarder.forward(lines, _SENTINEL_DEST) == 6
    assert len(seen["tokens"]) == 1
    assert len(seen["ingest"]) > 1
    assert {c["headers"]["Authorization"] for c in seen["ingest"]} == {"Bearer tok-1"}
    # Inside the five-minute refresh margin the cached token is still reused.
    now[0] = 1000.0 + 3600 - 300 - 1
    forwarder.forward(lines[:1], _SENTINEL_DEST)
    assert len(seen["tokens"]) == 1
    # Past the margin a new token is fetched once and used.
    now[0] = 1000.0 + 3600 - 300 + 1
    forwarder.forward(lines[:1], _SENTINEL_DEST)
    assert len(seen["tokens"]) == 2
    assert seen["ingest"][-1]["headers"]["Authorization"] == "Bearer tok-2"


def test_sentinel_token_request_uses_client_credentials_over_tls(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env)
    forwarder.forward([json.dumps({"ts": 1786700000.0})], _SENTINEL_DEST)
    (token,) = seen["tokens"]
    assert token["url"] == f"https://login.microsoftonline.com/{_SENTINEL_TENANT}/oauth2/v2.0/token"
    assert token["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert urllib.parse.parse_qs(token["body"].decode()) == {
        "grant_type": ["client_credentials"],
        "client_id": [_SENTINEL_CLIENT],
        "client_secret": [_SENTINEL_SECRET],
        "scope": ["https://monitor.azure.com/.default"],
    }


def test_sentinel_ingestion_request_targets_dcr_stream_with_bearer(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env)
    forwarder.forward(["plain text line"], _SENTINEL_DEST)
    (post,) = seen["ingest"]
    assert post["url"] == (f"https://{_SENTINEL_HOST}/dataCollectionRules/{_SENTINEL_DCR}"
                           "/streams/Custom-MaverickAudit?api-version=2023-01-01")
    assert post["headers"]["Authorization"] == "Bearer tok-1"
    assert post["headers"]["Content-Type"] == "application/json"
    assert "Sentinel" in post["label"]


def test_sentinel_rows_carry_event_time_or_now_and_the_raw_line(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env)
    audit_line = json.dumps({"ts": 1786700000.5, "kind": "halt"}, separators=(",", ":"))
    cef_line = "CEF:0|Maverick|audit|1|halt|halt|9|"
    before = datetime.now(timezone.utc)
    assert forwarder.forward([audit_line, cef_line], _SENTINEL_DEST) == 2
    after = datetime.now(timezone.utc)
    rows = json.loads(seen["ingest"][0]["body"])
    assert rows[0] == {"TimeGenerated": "2026-08-14T09:33:20.500Z", "RawData": audit_line}
    assert set(rows[1]) == {"TimeGenerated", "RawData"} and rows[1]["RawData"] == cef_line
    stamped = datetime.fromisoformat(rows[1]["TimeGenerated"].replace("Z", "+00:00"))
    # The row carries millisecond precision, so compare at that precision.
    floor = before.replace(microsecond=before.microsecond // 1000 * 1000)
    assert floor <= stamped <= after


def test_sentinel_batches_at_one_million_byte_default(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env)
    big = "y" * 60_000  # 60 kB rows: the batch is cut before the row that would exceed 1,000,000 bytes
    per_row = len(forwarder._sentinel_row(big)) + 1  # a row plus the comma that joins it
    fit = (1_000_000 - 1) // per_row  # two brackets and n-1 commas: 1 + n * per_row bytes
    assert forwarder.forward([big] * (fit + 1), _SENTINEL_DEST) == fit + 1
    assert [len(json.loads(c["body"])) for c in seen["ingest"]] == [fit, 1]
    assert all(len(c["body"]) <= 1_000_000 for c in seen["ingest"])


def test_sentinel_refuses_field_over_64000_bytes_before_sending(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env)
    with pytest.raises(ValueError, match="Sentinel"):
        forwarder.forward(["ok", "x" * 64_001], _SENTINEL_DEST)
    assert seen["tokens"] == [] and seen["ingest"] == []


def test_sentinel_accepts_field_at_64000_byte_limit(vendor_env):
    _sentinel_env(vendor_env)
    seen = _sentinel_fake(vendor_env)
    assert forwarder.forward(["x" * 64_000], _SENTINEL_DEST) == 1
    assert len(seen["ingest"]) == 1


def test_sentinel_names_missing_settings_without_sending(vendor_env):
    seen = _sentinel_fake(vendor_env)
    with pytest.raises(RuntimeError) as info:
        forwarder.forward(["a"], _SENTINEL_DEST)
    assert "MAVERICK_SENTINEL_TENANT_ID" in str(info.value)
    assert seen["tokens"] == [] and seen["ingest"] == []


def test_sentinel_settings_fall_back_to_audit_config(vendor_env):
    seen = _sentinel_fake(vendor_env)
    stored = {"sentinel_tenant_id": _SENTINEL_TENANT, "sentinel_client_id": _SENTINEL_CLIENT,
              "sentinel_client_secret": _SENTINEL_SECRET}
    vendor_env.setattr(forwarder, "_audit_config", stored.get)
    forwarder.forward(["a"], _SENTINEL_DEST)
    assert seen["tokens"][0]["url"].startswith(f"https://login.microsoftonline.com/{_SENTINEL_TENANT}/")


def test_sentinel_rejects_malformed_tenant_before_any_request(vendor_env):
    _sentinel_env(vendor_env)
    vendor_env.setenv("MAVERICK_SENTINEL_TENANT_ID", "evil.example/../x")
    seen = _sentinel_fake(vendor_env)
    with pytest.raises(RuntimeError, match="tenant or client ID"):
        forwarder.forward(["a"], _SENTINEL_DEST)
    assert seen["tokens"] == [] and seen["ingest"] == []


def test_sentinel_sign_in_failure_names_destination_and_never_the_secret(vendor_env, caplog):
    _sentinel_env(vendor_env)

    def _refuse(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    vendor_env.setattr(forwarder, "_open_vendor", _refuse)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RuntimeError) as info:
            forwarder.forward(["a"], _SENTINEL_DEST)
    message = str(info.value)
    assert "Sentinel" in message and "401" in message
    assert _SENTINEL_SECRET not in message and _SENTINEL_SECRET not in repr(info.value)
    assert _SENTINEL_SECRET not in caplog.text


def test_vendor_destinations_send_nothing_for_empty_input(vendor_env):
    _sentinel_env(vendor_env)
    vendor_env.setenv("MAVERICK_DATADOG_API_KEY", _DD_KEY)
    calls = _record_posts(vendor_env)
    assert forwarder.forward([], "datadog://datadoghq.com") == 0
    assert forwarder.forward([], _SENTINEL_DEST) == 0
    assert calls == []


def test_generic_http_collector_redirect_is_not_followed(monkeypatch):
    # Following a 302 would resend the bearer to the new location as a
    # body-less GET and count the dropped batch as shipped.
    monkeypatch.setenv("MAVERICK_SIEM_TOKEN", "hec-token")
    monkeypatch.delenv("MAVERICK_SECRETS_BACKEND", raising=False)
    seen = _scripted_https(monkeypatch, (302, "https://other.example.net/raw"), (200, None))
    with pytest.raises(urllib.error.HTTPError):
        forwarder.forward(["e1"], "https://siem.example/raw")
    assert [url for _, url, _ in seen] == ["https://siem.example/raw"]
