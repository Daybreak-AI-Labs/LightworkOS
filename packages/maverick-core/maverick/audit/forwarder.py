"""Push audit events to a SIEM endpoint.

The pull-based ``maverick audit export`` re-emits the tamper-evident log as
JSONL/CEF to a file or stdout; this module is the *push* counterpart, shipping
those same rendered lines to a network collector so a SIEM ingests them without
a cron job scraping files off the box.

Destination schemes, parsed from a single URI so one ``--to`` flag /
``[audit] siem_dest`` knob covers them:

  - ``tcp://host:port`` -- newline-framed syslog/TCP (Splunk, rsyslog, Vector).
  - ``udp://host:port`` -- one datagram per event (classic syslog/UDP).
  - ``http://...`` / ``https://...`` -- bounded POST batches whose bodies are
    newline-delimited (Splunk HEC ``/raw``, Sumo, an HTTP collector). A bearer
    from ``MAVERICK_SIEM_TOKEN`` (via the secret provider) is sent as
    ``Authorization`` when set.
  - ``datadog://<site>`` -- Datadog Logs intake for a documented site (for
    example ``datadoghq.com`` or ``datadoghq.eu``). Each line becomes one log
    with fixed ``ddsource``/``service``; the API key comes from
    ``MAVERICK_DATADOG_API_KEY`` or ``[audit] datadog_api_key``, never the URI.
  - ``sentinel://<dce-host>/<dcr-immutable-id>/Custom-<stream>`` -- Azure
    Monitor Logs Ingestion API for Microsoft Sentinel. Each line becomes
    ``{"TimeGenerated", "RawData"}``, so the DCR stream must declare those two
    columns. The Entra client-credentials token comes from
    ``MAVERICK_SENTINEL_TENANT_ID`` / ``_CLIENT_ID`` / ``_CLIENT_SECRET`` (or
    the matching ``[audit]`` keys) and is cached until shortly before expiry.
    Azure public cloud only.

Vendor schemes are TLS-only with no plaintext variant, and only documented
vendor hosts are accepted, so a key or token never leaves for an arbitrary host.

Read-only with respect to the audit log: it only consumes already-rendered
event lines. Returns the count shipped. Best-effort framing, explicit errors --
a transport failure raises so the CLI exits non-zero (a SIEM gap is a
compliance event, not something to swallow).
"""
from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

log = logging.getLogger(__name__)

_SUPPORTED = ("tcp", "udp", "http", "https", "datadog", "sentinel")
# Maximum UDP payload size for IPv4. Oversized events must fail loudly instead
# of being truncated and counted as successfully forwarded.
_UDP_MAX = 65507
_HTTP_BATCH_MAX = 1024 * 1024
# Datadog Logs intake (send-logs reference): 1000 entries and 5MB per request,
# 1MB per log. Datadog truncates a larger log, so it is refused here instead. The
# reference does not say whether MB is 10^6 or 2^20 bytes; the smaller reading is
# used, so a log that Datadog would truncate under either reading is never sent.
_DATADOG_MAX_ENTRIES = 1000
_DATADOG_MAX_BODY = 5_000_000
_DATADOG_MAX_LOG = 1_000_000
# The intake host is ``http-intake.logs.<site>``; only these sites are accepted.
_DATADOG_SITES = frozenset({
    "datadoghq.com", "datadoghq.eu", "us3.datadoghq.com", "us5.datadoghq.com",
    "ap1.datadoghq.com", "ap2.datadoghq.com", "uk1.datadoghq.com",
    "ddog-gov.com", "us2.ddog-gov.com",
})
# Azure Monitor Logs Ingestion API: 1MB per call and 64KB per field value. Azure
# truncates a longer field, so such a line is refused instead of being counted as
# sent. The service limits do not define the unit; the smaller decimal reading is used.
_SENTINEL_MAX_BODY = 1_000_000
_SENTINEL_MAX_FIELD = 64_000
_SENTINEL_API_VERSION = "2023-01-01"
_SENTINEL_SCOPE = "https://monitor.azure.com/.default"
# A cached Microsoft Entra token is replaced this long before it expires.
_TOKEN_REFRESH_MARGIN = 300.0
_DCE_HOST_RE = re.compile(r"[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.monitor\.azure\.com")
_DCR_ID_RE = re.compile(r"dcr-[0-9a-fA-F]{32}")
_STREAM_RE = re.compile(r"Custom-[A-Za-z0-9_]{1,200}")
_AZURE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,254}")
_HEADER_VALUE_RE = re.compile(r"[ -~]*")
_clock: Callable[[], float] = time.monotonic
_sentinel_tokens: dict[tuple[str, str], tuple[str, float]] = {}
_sentinel_token_lock = threading.Lock()


def parse_dest(dest: str) -> tuple[str, str, int, str]:
    """Validate a destination URI -> ``(scheme, host, port, url)``.

    ``url`` is empty for tcp/udp, the destination itself for http(s), and the
    vendor ingestion URL built from the URI for datadog/sentinel.

    Raises ``ValueError`` on an unsupported scheme or a missing host/port for a
    socket scheme, so a typo in config fails loudly at startup instead of
    silently dropping audit traffic.
    """
    u = urlparse((dest or "").strip())
    scheme = (u.scheme or "").lower()
    if scheme not in _SUPPORTED:
        raise ValueError(
            f"unsupported SIEM destination scheme {scheme!r} "
            f"(expected one of {', '.join(_SUPPORTED)})"
        )
    if scheme in ("tcp", "udp"):
        if not u.hostname or not u.port:
            raise ValueError(f"{scheme} destination needs host:port (got {dest!r})")
        return scheme, u.hostname, int(u.port), ""
    if scheme == "datadog":
        return _parse_datadog(u)
    if scheme == "sentinel":
        return _parse_sentinel(u)
    if not u.hostname:
        raise ValueError(f"http(s) destination needs a host (got {dest!r})")
    return scheme, u.hostname, int(u.port or (443 if scheme == "https" else 80)), dest


def _parse_datadog(u) -> tuple[str, str, int, str]:
    # Vendor errors do not echo the URI: a key pasted into it must not be logged.
    if u.netloc.lower() not in _DATADOG_SITES or u.path or u.query or u.fragment:
        raise ValueError(
            "datadog destination must be datadog://<site> with one of: "
            + ", ".join(sorted(_DATADOG_SITES)))
    host = f"http-intake.logs.{u.netloc.lower()}"
    return "datadog", host, 443, f"https://{host}/api/v2/logs"


def _parse_sentinel(u) -> tuple[str, str, int, str]:
    host = u.hostname or ""
    segments = u.path.split("/")
    if (u.netloc.lower() != host or not _DCE_HOST_RE.fullmatch(host) or len(segments) != 3
            or not _DCR_ID_RE.fullmatch(segments[1]) or not _STREAM_RE.fullmatch(segments[2])
            or u.query or u.fragment):
        raise ValueError(
            "sentinel destination must be sentinel://<data-collection-endpoint-host>"
            "/<dcr-immutable-id>/Custom-<stream> on an Azure Monitor host (*.monitor.azure.com)")
    return ("sentinel", host, 443,
            f"https://{host}/dataCollectionRules/{segments[1]}/streams/{segments[2]}"
            f"?api-version={_SENTINEL_API_VERSION}")


def _audit_secret(env: str, key: str) -> str | None:
    """A deployment secret: the environment (or secret provider) first, then ``[audit] <key>``."""
    try:
        from ..secret_provider import get_secret
        tok = get_secret(env)
    # failure-policy: best_effort
    except Exception:  # pragma: no cover -- never block forwarding on token lookup
        tok = None
    if not tok:
        # The sealed ``[audit]`` value from the dashboard's All settings.
        value = _audit_config(key)
        tok = value if isinstance(value, str) else None
    return tok.strip() if tok else None


def _siem_token() -> str | None:
    return _audit_secret("MAVERICK_SIEM_TOKEN", "siem_token")


def _audit_config(key: str) -> object:
    try:
        from ..config import load_config
        return ((load_config() or {}).get("audit") or {}).get(key)
    # An unreadable config means no saved token and no plaintext opt-in, so
    # forwarding stays authenticated or refused.
    except Exception:  # failure-policy: best_effort
        return None


def _insecure_siem_allowed() -> bool:
    """Opt-in escape hatch for plaintext SIEM transport on a trusted segment."""
    import os
    raw = os.environ.get("MAVERICK_SIEM_ALLOW_INSECURE", "").strip().lower()
    if raw:
        return raw in ("1", "true", "yes", "on")
    return _audit_config("siem_allow_insecure") is True


def _send_tcp(host: str, port: int, lines: Iterable[str], timeout: float) -> int:
    n = 0
    with socket.create_connection((host, port), timeout=timeout) as sock:
        for line in lines:
            sock.sendall((line + "\n").encode("utf-8"))
            n += 1
    return n


def _send_udp(host: str, port: int, lines: Iterable[str], timeout: float) -> int:
    # Resolve the family (AF_INET vs AF_INET6) instead of hardcoding IPv4, so an
    # IPv6 syslog collector (udp://[::1]:514) works like the tcp/http paths do.
    family, _, _, _, sockaddr = socket.getaddrinfo(
        host, port, 0, socket.SOCK_DGRAM)[0]
    n = 0
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for line in lines:
            payload = (line + "\n").encode("utf-8")
            if len(payload) > _UDP_MAX:
                raise ValueError(
                    "rendered audit event exceeds UDP payload limit "
                    f"({_UDP_MAX} bytes); use tcp:// or http(s)://"
                )
            sock.sendto(payload, sockaddr)
            n += 1
    return n


def _post_http_batch(url: str, body: bytes, timeout: float) -> None:
    import urllib.request

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    token = _siem_token()
    if token:
        # Don't send the SIEM bearer in cleartext: a credential over http://
        # is sniffable. Refuse unless the operator explicitly accepts the risk
        # (e.g. a TLS-terminating sidecar on a trusted segment).
        if url.lower().startswith("http://") and not _insecure_siem_allowed():
            raise RuntimeError(
                "refusing to send the SIEM bearer token over plaintext http://; "
                "use https:// or set MAVERICK_SIEM_ALLOW_INSECURE=1 to override")
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme validated
        code = getattr(resp, "status", None) or resp.getcode()
    if not (200 <= int(code) < 300):
        raise RuntimeError(f"SIEM HTTP collector returned {code}")


def _send_http(url: str, lines: Iterable[str], timeout: float) -> int:
    n = 0
    batch = bytearray()
    for line in lines:
        payload = (line + "\n").encode("utf-8")
        if batch and len(batch) + len(payload) > _HTTP_BATCH_MAX:
            _post_http_batch(url, bytes(batch), timeout)
            batch.clear()
        batch.extend(payload)
        n += 1
        if len(batch) >= _HTTP_BATCH_MAX:
            _post_http_batch(url, bytes(batch), timeout)
            batch.clear()
    if batch:
        _post_http_batch(url, bytes(batch), timeout)
    return n


def _open_vendor(req, timeout: float):
    """Open a vendor request without following any redirect.

    urllib would resend every custom header (the Datadog key, the Entra token) to
    the redirect target, and on 301-303 would resend the POST body as a GET, so a
    batch could be dropped while still counted as sent. The vendor endpoints do not
    redirect, so a 3xx is returned as an HTTP error instead.
    """
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None  # urllib then raises HTTPError for the 3xx status

    return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)


def _https_post(url: str, body: bytes, headers: dict[str, str], timeout: float,
                label: str) -> bytes:
    """POST over TLS to a vendor destination and return the response body.

    ``label`` names the destination in errors. Errors never carry the request
    headers and suppress the urllib chain, so a key or token cannot reach a log
    line or an exception.
    """
    import urllib.error
    import urllib.request

    if urlparse(url).scheme != "https":
        raise RuntimeError(f"{label}: refusing to send to a non-TLS URL")
    for value in headers.values():
        # http.client quotes an invalid header value in its ValueError, which would
        # print the key or token. Refuse anything but printable ASCII before urllib sees it.
        if not _HEADER_VALUE_RE.fullmatch(value):
            raise RuntimeError(f"{label}: a request header is not plain ASCII text; "
                               "check the credential for stray characters")
    req = urllib.request.Request(url, data=body, method="POST")
    for name, value in headers.items():
        req.add_header(name, value)
    try:
        with _open_vendor(req, timeout) as resp:  # https only, redirects refused
            code = getattr(resp, "status", None) or resp.getcode()
            payload = resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{label} returned HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"{label} could not be reached ({type(exc).__name__})") from None
    if not (200 <= int(code) < 300):
        raise RuntimeError(f"{label} returned HTTP {code}")
    return payload


def _json_array_batches(
    lines: Iterable[str],
    encode: Callable[[str], bytes],
    max_items: int | None,
    max_bytes: int,
) -> Iterator[tuple[bytes, int]]:
    """Yield ``(json_array_body, item_count)`` batches that respect both limits.

    A batch is cut before the item that would exceed either limit. An item that
    cannot fit a body on its own raises instead of being sent.
    """
    items: list[bytes] = []
    size = 2  # the enclosing brackets
    for line in lines:
        item = encode(line)
        if items and ((max_items is not None and len(items) >= max_items)
                      or size + len(item) + 1 > max_bytes):
            yield b"[" + b",".join(items) + b"]", len(items)
            items, size = [], 2
        cost = len(item) + (1 if items else 0)  # the comma before every item but the first
        if size + cost > max_bytes:
            raise ValueError("rendered audit event does not fit one vendor request")
        items.append(item)
        size += cost
    if items:
        yield b"[" + b",".join(items) + b"]", len(items)


def _datadog_entry(line: str) -> bytes:
    # ASCII-only JSON, so the size checked here is the size sent.
    entry = json.dumps({"ddsource": "lightwork", "service": "lightwork-audit", "message": line},
                       separators=(",", ":")).encode("ascii")
    if len(entry) > _DATADOG_MAX_LOG:
        raise ValueError("rendered audit event exceeds Datadog's 1,000,000-byte per-log limit; "
                         "Datadog would truncate it")
    return entry


def _send_datadog(url: str, lines: Iterable[str], timeout: float) -> int:
    key = _audit_secret("MAVERICK_DATADOG_API_KEY", "datadog_api_key")
    if not key:
        raise RuntimeError("Datadog destination needs an API key: set MAVERICK_DATADOG_API_KEY "
                           "or [audit] datadog_api_key")
    n = 0
    for body, count in _json_array_batches(lines, _datadog_entry,
                                           _DATADOG_MAX_ENTRIES, _DATADOG_MAX_BODY):
        _https_post(url, body, {"Content-Type": "application/json", "DD-API-KEY": key},
                    timeout, "Datadog log intake")
        n += count
    return n


def _event_time(line: str) -> str:
    """ISO 8601 UTC time from a JSON audit line's ``ts`` (epoch seconds), else now."""
    try:
        ts = json.loads(line).get("ts")
    except (ValueError, AttributeError):  # CEF lines, or JSON that is not an object
        ts = None
    stamp = None
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        try:
            stamp = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            stamp = None
    return ((stamp or datetime.now(timezone.utc))
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def _sentinel_row(line: str) -> bytes:
    if len(line.encode("utf-8", "surrogatepass")) > _SENTINEL_MAX_FIELD:
        raise ValueError("rendered audit event exceeds Sentinel's 64,000-byte field limit; "
                         "Azure would truncate it")
    row = {"TimeGenerated": _event_time(line), "RawData": line}
    return json.dumps(row, separators=(",", ":")).encode("ascii")


def _sentinel_credentials() -> tuple[str, str, str]:
    tenant = _audit_secret("MAVERICK_SENTINEL_TENANT_ID", "sentinel_tenant_id")
    client_id = _audit_secret("MAVERICK_SENTINEL_CLIENT_ID", "sentinel_client_id")
    secret = _audit_secret("MAVERICK_SENTINEL_CLIENT_SECRET", "sentinel_client_secret")
    if not (tenant and client_id and secret):
        raise RuntimeError(
            "Sentinel destination needs MAVERICK_SENTINEL_TENANT_ID, MAVERICK_SENTINEL_CLIENT_ID "
            "and MAVERICK_SENTINEL_CLIENT_SECRET (or the matching [audit] settings)")
    if not (_AZURE_ID_RE.fullmatch(tenant) and _AZURE_ID_RE.fullmatch(client_id)):
        raise RuntimeError("Sentinel tenant or client ID is malformed")
    return tenant, client_id, secret


def _sentinel_access_token(tenant: str, client_id: str, secret: str, timeout: float) -> str:
    """A Microsoft Entra client-credentials token, fetched once and reused until near expiry."""
    key = (tenant, client_id)
    with _sentinel_token_lock:
        now = _clock()
        cached = _sentinel_tokens.get(key)
        if cached is not None and now < cached[1]:
            return cached[0]
        body = urlencode({"grant_type": "client_credentials", "client_id": client_id,
                          "client_secret": secret, "scope": _SENTINEL_SCOPE}).encode("ascii")
        raw = _https_post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                          body, {"Content-Type": "application/x-www-form-urlencoded"},
                          timeout, "Sentinel sign-in (Microsoft Entra)")
        try:
            reply = json.loads(raw)
            token = reply["access_token"]
            lifetime = float(reply.get("expires_in", 0))
            if not isinstance(token, str) or not token:
                raise ValueError("empty access token")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise RuntimeError("Sentinel sign-in returned no usable access token") from None
        _sentinel_tokens[key] = (token, now + max(lifetime - _TOKEN_REFRESH_MARGIN, 0.0))
        return token


def _send_sentinel(url: str, lines: Iterable[str], timeout: float) -> int:
    tenant, client_id, secret = _sentinel_credentials()
    n = 0
    for body, count in _json_array_batches(lines, _sentinel_row, None, _SENTINEL_MAX_BODY):
        token = _sentinel_access_token(tenant, client_id, secret, timeout)
        _https_post(url, body, {"Content-Type": "application/json",
                                "Authorization": f"Bearer {token}"},
                    timeout, "Sentinel (Azure Monitor Logs Ingestion)")
        n += count
    return n


def forward(lines: Iterable[str], dest: str, *, timeout: float = 10.0) -> int:
    """Ship already-rendered audit lines to ``dest``; return the count sent.

    ``lines`` is any iterable of strings (e.g. ``to_jsonl``/``to_cef`` over
    ``iter_audit_events``). Raises on an unsupported/ malformed destination or a
    transport error so the caller can surface the gap.
    """
    scheme, host, port, url = parse_dest(dest)
    if scheme in ("tcp", "udp", "http"):
        log.warning(
            "SIEM destination uses plaintext %s://; audit events cross the "
            "network unencrypted -- prefer https:// or a TLS tunnel.", scheme)
    if scheme == "tcp":
        return _send_tcp(host, port, lines, timeout)
    if scheme == "udp":
        return _send_udp(host, port, lines, timeout)
    if scheme == "datadog":
        return _send_datadog(url, lines, timeout)
    if scheme == "sentinel":
        return _send_sentinel(url, lines, timeout)
    return _send_http(url, lines, timeout)


__all__ = ["forward", "parse_dest"]
