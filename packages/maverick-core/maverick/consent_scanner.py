"""Deployable, privacy-bounded web tracker scanner.

The scanner is intentionally separated from the consent receipt authority.
It visits only privacy-owner-enrolled properties, retains metadata rather than
page contents or cookie/storage values, quarantines every discovery as
``unknown``, and never converts absence of findings into a completeness claim.

``PlaywrightPageCollector`` is the production browser seam.  The coordinator
accepts an injected collector so admission, privacy, traversal, and failure
semantics can be tested without network access or a browser installation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import queue
import re
import secrets
import select
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse, urlunparse

SCAN_REPORT_SCHEMA = "lightwork.consent-tracker-scan-report.v1"
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_RESOURCE_TYPES = frozenset(
    {"script", "image", "xhr", "fetch", "media", "font", "websocket", "other"}
)
_MAX_START_URLS = 128
_MAX_ALLOWED_ORIGINS = 128
_MAX_LINKS_PER_PAGE = 2_000
_MAX_COOKIE_METADATA = 2_000
_MAX_STORAGE_KEYS = 2_000
_MAX_ERRORS = 100
_SOCKS_ALLOWED_PORTS = frozenset({80, 443})
_SOCKS_DNS_TIMEOUT_SECONDS = 5.0
_SOCKS_HANDSHAKE_TIMEOUT_SECONDS = 5.0
_SOCKS_MAX_RESOLVER_THREADS = 32
_SOCKS_MAX_CONNECTIONS = 64
_SOCKS_MAX_ADDRESSES = 64


class ConsentScannerError(RuntimeError):
    """Base scanner error."""


class ConsentScannerConfigError(ConsentScannerError):
    """The scanner is not explicitly enabled."""


class ConsentScannerValidationError(ConsentScannerError, ValueError):
    """A scanner request is unsafe or outside the closed contract."""


class ConsentScannerUnavailable(ConsentScannerError):
    """The browser collector cannot run in this deployment."""


def enabled() -> bool:
    """Return true only when consent and its scanner subsystem are enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("consent_preferences")
    if not isinstance(section, Mapping) or section.get("enable") is not True:
        return False
    scanner = section.get("scanner")
    return isinstance(scanner, Mapping) and scanner.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise ConsentScannerConfigError(
            "consent scanner is disabled; enable [consent_preferences] and "
            "[consent_preferences.scanner] explicitly"
        )


def _canonical(value: object) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentScannerValidationError("scanner data must be finite JSON") from exc
    if len(payload) > 2 * 1_024 * 1_024:
        raise ConsentScannerValidationError("scanner report exceeds the 2 MiB bound")
    return payload


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ref(value: object, field: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise ConsentScannerValidationError(f"{field} must be an opaque identifier")
    return value


def _positive_int(value: object, field: str, lower: int, upper: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not lower <= value <= upper
    ):
        raise ConsentScannerValidationError(
            f"{field} must be an integer between {lower} and {upper}"
        )
    return value


def _finite_time(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsentScannerValidationError(f"{field} must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ConsentScannerValidationError(f"{field} must be a finite timestamp")
    return result


def _host(value: object) -> str:
    if not isinstance(value, str):
        raise ConsentScannerValidationError("origin host is required")
    candidate = value.strip().rstrip(".").lower()
    if not _HOST_RE.fullmatch(candidate):
        raise ConsentScannerValidationError("origin host is invalid")
    return candidate


def _origin(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise ConsentScannerValidationError("allowed origin is invalid")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ConsentScannerValidationError("allowed origin is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise ConsentScannerValidationError(
            "allowed origins must be exact HTTPS origins without credentials or paths"
        )
    host = _host(parsed.hostname)
    return f"https://{host}" if port is None else f"https://{host}:{port}"


def _navigation_url(value: object, origins: frozenset[str]) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4_096:
        raise ConsentScannerValidationError("scan URL is invalid")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ConsentScannerValidationError("scan URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise ConsentScannerValidationError(
            "scan URLs must be HTTPS and cannot contain credentials or fragments"
        )
    host = _host(parsed.hostname)
    origin = f"https://{host}" if port is None else f"https://{host}:{port}"
    if origin not in origins:
        raise ConsentScannerValidationError("scan URL is outside enrolled property origins")
    path = parsed.path or "/"
    return urlunparse(("https", parsed.netloc.lower(), path, "", parsed.query, ""))


def _public_host(host: str) -> bool:
    from .tools.http_fetch import is_blocked_host

    return not is_blocked_host(host)


@dataclass(frozen=True)
class ScanLimits:
    max_pages: int = 100
    max_depth: int = 4
    page_timeout_seconds: int = 30
    max_network_events: int = 5_000
    settle_milliseconds: int = 1_000

    def validated(self) -> ScanLimits:
        return ScanLimits(
            max_pages=_positive_int(self.max_pages, "max_pages", 1, 10_000),
            max_depth=_positive_int(self.max_depth, "max_depth", 0, 20),
            page_timeout_seconds=_positive_int(
                self.page_timeout_seconds, "page_timeout_seconds", 1, 300
            ),
            max_network_events=_positive_int(
                self.max_network_events, "max_network_events", 1, 100_000
            ),
            settle_milliseconds=_positive_int(
                self.settle_milliseconds, "settle_milliseconds", 0, 30_000
            ),
        )


_LIMIT_BOUNDS = {
    "max_pages": (1, 10_000),
    "max_depth": (0, 20),
    "page_timeout_seconds": (1, 300),
    "max_network_events": (1, 100_000),
}


def scan_limit_settings(config: Mapping[str, Any] | None = None) -> dict[str, int]:
    """The installation's scan limits from ``[consent_preferences.scanner]``.

    Each of ``max_pages``, ``max_depth``, ``page_timeout_seconds`` and
    ``max_network_events`` is both the default for a new scan and a cap no
    scan may exceed. ``interval_seconds`` is the shortest time between
    scheduled scans (and the default for a schedule that names none). Only
    keys that are set are returned; unset keeps each scan's own value.
    """
    if config is None:
        from .config import load_config

        config = load_config() or {}
    consent = config.get("consent_preferences") if isinstance(config, Mapping) else None
    section = consent.get("scanner") if isinstance(consent, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    bounds = {**_LIMIT_BOUNDS, "interval_seconds": (300, 2_592_000)}
    selected: dict[str, int] = {}
    for key, (lower, upper) in bounds.items():
        if key in section:
            try:
                selected[key] = _positive_int(section[key], f"scanner {key}", lower, upper)
            except ConsentScannerValidationError as exc:
                raise ConsentScannerConfigError(str(exc)) from exc
    return selected


def default_scan_limits(settings: Mapping[str, int] | None = None) -> ScanLimits:
    """Scan limits for a scan that names none: the installation's, else built-in."""
    chosen = scan_limit_settings() if settings is None else settings
    return ScanLimits(**{k: v for k, v in chosen.items() if k in _LIMIT_BOUNDS})


def capped_scan_limits(
    limits: ScanLimits, settings: Mapping[str, int] | None = None
) -> ScanLimits:
    """``limits`` lowered to the installation's caps (never raised)."""
    chosen = scan_limit_settings() if settings is None else settings
    values = asdict(limits.validated())
    for key in _LIMIT_BOUNDS:
        if key in chosen:
            values[key] = min(values[key], chosen[key])
    return ScanLimits(**values)


@dataclass(frozen=True)
class NetworkMetadata:
    url: str
    resource_type: str


@dataclass(frozen=True)
class CookieMetadata:
    domain: str
    name: str
    secure: bool
    http_only: bool
    same_site: str
    expires: float | None = None


@dataclass(frozen=True)
class PageCapture:
    final_url: str
    links: tuple[str, ...]
    network: tuple[NetworkMetadata, ...]
    cookies: tuple[CookieMetadata, ...]
    storage_keys: tuple[str, ...]
    network_truncated: bool = False


class PageCollector(Protocol):
    def capture(
        self,
        url: str,
        *,
        navigation_hosts: frozenset[str],
        limits: ScanLimits,
        auth_secret_ref: str | None,
    ) -> PageCapture: ...


HostResolver = Callable[[str, int], Sequence[str]]
PinnedConnector = Callable[[str, int, float], socket.socket]


def _system_resolver(host: str, port: int) -> tuple[str, ...]:
    """Resolve once and return only the literal addresses from that answer."""

    rows = socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return tuple(str(row[4][0]) for row in rows)


def _strict_public_ip(value: str) -> bool:
    """Reject every non-global or specially scoped address, without overrides."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_multicast
        and not address.is_unspecified
    )


def _connect_literal_ip(ip: str, port: int, timeout: float) -> socket.socket:
    """Open a socket to an IP literal, never asking the OS to resolve it again."""

    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    upstream = socket.socket(family, socket.SOCK_STREAM)
    upstream.settimeout(timeout)
    target: tuple[Any, ...]
    if family == socket.AF_INET6:
        target = (address.compressed, port, 0, 0)
    else:
        target = (address.compressed, port)
    try:
        upstream.connect(target)
    except Exception:
        upstream.close()
        raise
    return upstream


class _SocksRequestRejected(Exception):
    """Internal control flow for a closed SOCKS request."""


class _PinnedSocksProxy:
    """Bounded loopback SOCKS5 proxy that pins every admitted TCP connection.

    Chromium sends the original hostname in its SOCKS5 CONNECT request.  This
    proxy resolves that name exactly once, rejects the entire answer when any
    address is non-public, and connects to one validated IP literal.  TLS SNI,
    certificate verification, HTTP ``Host``, and WebSocket host handling remain
    browser-owned because the tunnel never rewrites application bytes.
    """

    def __init__(
        self,
        *,
        resolver: HostResolver = _system_resolver,
        connector: PinnedConnector = _connect_literal_ip,
        dns_timeout_seconds: float = _SOCKS_DNS_TIMEOUT_SECONDS,
        connect_timeout_seconds: float = 15.0,
        idle_timeout_seconds: float = 60.0,
        authorize_host: Callable[[str, int], bool] | None = None,
    ) -> None:
        self._authorize_host = authorize_host
        self._resolver = resolver
        self._connector = connector
        self._dns_timeout = max(0.1, min(float(dns_timeout_seconds), 30.0))
        self._connect_timeout = max(0.1, min(float(connect_timeout_seconds), 30.0))
        self._idle_timeout = max(1.0, min(float(idle_timeout_seconds), 330.0))
        self._stop = threading.Event()
        self._connections = threading.BoundedSemaphore(_SOCKS_MAX_CONNECTIONS)
        self._resolver_slots = threading.BoundedSemaphore(
            _SOCKS_MAX_RESOLVER_THREADS
        )
        self._active: set[socket.socket] = set()
        self._active_lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._port: int | None = None

    @property
    def server_url(self) -> str:
        if self._port is None:
            raise RuntimeError("pinned browser proxy is not running")
        return f"socks5://127.0.0.1:{self._port}"

    def __enter__(self) -> _PinnedSocksProxy:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(_SOCKS_MAX_CONNECTIONS)
            listener.settimeout(0.25)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self._port = int(listener.getsockname()[1])
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="consent-scan-egress",
            daemon=True,
        )
        self._accept_thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        self._listener = None
        self._port = None
        if listener is not None:
            self._close_socket(listener)
        with self._active_lock:
            active = tuple(self._active)
        for sock in active:
            self._close_socket(sock)
        thread = self._accept_thread
        self._accept_thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def _track(self, sock: socket.socket) -> None:
        with self._active_lock:
            self._active.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._active_lock:
            self._active.discard(sock)

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                client, _peer = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if self._stop.is_set() or not self._connections.acquire(blocking=False):
                self._close_socket(client)
                continue
            self._track(client)
            threading.Thread(
                target=self._run_client,
                args=(client,),
                name="consent-scan-egress-client",
                daemon=True,
            ).start()

    def _run_client(self, client: socket.socket) -> None:
        try:
            self._handle_client(client)
        finally:
            self._untrack(client)
            self._close_socket(client)
            self._connections.release()

    @staticmethod
    def _receive_exact(client: socket.socket, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            chunk = client.recv(count - len(chunks))
            if not chunk:
                raise _SocksRequestRejected
            chunks.extend(chunk)
        return bytes(chunks)

    @staticmethod
    def _reply(client: socket.socket, code: int) -> None:
        client.sendall(b"\x05" + bytes((code,)) + b"\x00\x01\x00\x00\x00\x00\x00\x00")

    @classmethod
    def _reject(cls, client: socket.socket, code: int) -> None:
        try:
            cls._reply(client, code)
        except OSError:
            pass
        raise _SocksRequestRejected

    @classmethod
    def _read_request(cls, client: socket.socket) -> tuple[str, int]:
        version, method_count = cls._receive_exact(client, 2)
        if version != 5 or not 1 <= method_count <= 32:
            raise _SocksRequestRejected
        methods = cls._receive_exact(client, method_count)
        if 0 not in methods:
            client.sendall(b"\x05\xff")
            raise _SocksRequestRejected
        client.sendall(b"\x05\x00")

        version, command, reserved, address_type = cls._receive_exact(client, 4)
        if version != 5 or reserved != 0:
            cls._reject(client, 1)
        if command != 1:
            cls._reject(client, 7)
        try:
            if address_type == 1:
                host = str(ipaddress.ip_address(cls._receive_exact(client, 4)))
            elif address_type == 3:
                length = cls._receive_exact(client, 1)[0]
                if not 1 <= length <= 253:
                    cls._reject(client, 8)
                host = _host(cls._receive_exact(client, length).decode("ascii"))
            elif address_type == 4:
                host = str(ipaddress.ip_address(cls._receive_exact(client, 16)))
            else:
                cls._reject(client, 8)
        except (ConsentScannerValidationError, UnicodeError, ValueError):
            cls._reject(client, 8)
        port = struct.unpack("!H", cls._receive_exact(client, 2))[0]
        if port not in _SOCKS_ALLOWED_PORTS:
            cls._reject(client, 2)
        return host, port

    def _resolve_once(self, host: str, port: int) -> tuple[str, ...]:
        if not self._resolver_slots.acquire(blocking=False):
            raise _SocksRequestRejected
        result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                addresses: object = self._resolver(host, port)
                item = (True, addresses)
            except Exception as exc:
                item = (False, exc)
            try:
                result.put_nowait(item)
            except queue.Full:
                pass
            finally:
                self._resolver_slots.release()

        threading.Thread(
            target=resolve,
            name="consent-scan-egress-dns",
            daemon=True,
        ).start()
        try:
            succeeded, payload = result.get(timeout=self._dns_timeout)
        except queue.Empty as exc:
            raise _SocksRequestRejected from exc
        if not succeeded or isinstance(payload, (str, bytes)):
            raise _SocksRequestRejected
        if not isinstance(payload, Sequence) or not 1 <= len(payload) <= _SOCKS_MAX_ADDRESSES:
            raise _SocksRequestRejected
        addresses: list[str] = []
        for value in payload:
            if not isinstance(value, str) or not _strict_public_ip(value):
                raise _SocksRequestRejected
            normalized = ipaddress.ip_address(value).compressed
            if normalized not in addresses:
                addresses.append(normalized)
        if not addresses:
            raise _SocksRequestRejected
        return tuple(addresses)

    def _pin_target(self, host: str, port: int) -> str:
        if port not in _SOCKS_ALLOWED_PORTS:
            raise _SocksRequestRejected
        try:
            literal = ipaddress.ip_address(host).compressed
        except ValueError:
            name = _host(host)
            return self._resolve_once(name, port)[0]
        if not _strict_public_ip(literal):
            raise _SocksRequestRejected
        return literal

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(_SOCKS_HANDSHAKE_TIMEOUT_SECONDS)
            host, port = self._read_request(client)
            if self._authorize_host is not None:
                try:
                    allowed = self._authorize_host(host, port)
                except Exception:
                    allowed = False
                if not allowed:
                    self._reject(client, 2)
            try:
                pinned_ip = self._pin_target(host, port)
            except _SocksRequestRejected:
                self._reject(client, 2)
            try:
                upstream = self._connector(
                    pinned_ip,
                    port,
                    self._connect_timeout,
                )
            except Exception:
                self._reject(client, 5)
            self._track(upstream)
            self._reply(client, 0)
            client.settimeout(min(self._idle_timeout, 30.0))
            upstream.settimeout(min(self._idle_timeout, 30.0))
            self._relay(client, upstream)
        except (_SocksRequestRejected, OSError, ValueError):
            return
        finally:
            if upstream is not None:
                self._untrack(upstream)
                self._close_socket(upstream)

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        deadline = time.monotonic() + self._idle_timeout
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            readable, _writable, _failed = select.select(
                (client, upstream),
                (),
                (),
                min(0.5, remaining),
            )
            if not readable:
                continue
            for source in readable:
                chunk = source.recv(64 * 1_024)
                if not chunk:
                    return
                target = upstream if source is client else client
                target.sendall(chunk)
                deadline = time.monotonic() + self._idle_timeout


class PlaywrightPageCollector:
    """Fresh-context Chromium collector with per-request SSRF controls."""

    def __init__(
        self,
        *,
        storage_state_resolver: Callable[[str], str | Mapping[str, Any]] | None = None,
        host_is_public: Callable[[str], bool] = _public_host,
        host_resolver: HostResolver = _system_resolver,
    ) -> None:
        self._storage_state_resolver = storage_state_resolver
        self._host_is_public = host_is_public
        self._host_resolver = host_resolver

    @staticmethod
    def _browser_launch_options(proxy_url: str) -> dict[str, Any]:
        return {
            "headless": True,
            "proxy": {
                "server": proxy_url,
                # Chromium otherwise has implicit loopback bypass rules.  The
                # SOCKS listener itself is still reached by its explicit IP.
                "bypass": "<-loopback>",
            },
            "args": [
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-domain-reliability",
                # A SOCKS CONNECT exposes the destination only once. Avoid
                # HTTP/2 origin coalescing that may reuse the encrypted tunnel
                # for a different authority without a new proxy authorization.
                "--disable-http2",
                "--disable-quic",
                "--disable-sync",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                "--metrics-recording-only",
                "--no-first-run",
                "--proxy-bypass-list=<-loopback>",
            ],
        }

    def _storage_state(self, auth_secret_ref: str | None) -> object | None:
        if auth_secret_ref is None:
            return None
        if self._storage_state_resolver is None:
            raise ConsentScannerUnavailable(
                "authenticated scan requested without a credential-owning resolver"
            )
        try:
            state = self._storage_state_resolver(auth_secret_ref)
        except Exception as exc:
            raise ConsentScannerUnavailable(
                "authenticated scan state could not be resolved"
            ) from exc
        if not isinstance(state, (str, Mapping)):
            raise ConsentScannerUnavailable("authenticated scan state is invalid")
        return state

    def _admit_request(self, url: str, *, navigation: bool, hosts: frozenset[str]) -> bool:
        try:
            parsed = urlparse(url)
            host = _host(parsed.hostname)
            port = parsed.port
        except (ConsentScannerValidationError, ValueError, TypeError):
            return False
        default_port = {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(
            parsed.scheme
        )
        if default_port is None or parsed.username or parsed.password:
            return False
        if port not in {None, default_port} or not self._host_is_public(host):
            return False
        return not navigation or host in hosts

    def capture(
        self,
        url: str,
        *,
        navigation_hosts: frozenset[str],
        limits: ScanLimits,
        auth_secret_ref: str | None,
    ) -> PageCapture:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ConsentScannerUnavailable(
                "Playwright is required; install maverick-agent[browser] and Chromium"
            ) from exc

        network: list[NetworkMetadata] = []
        truncated = False
        storage_state = self._storage_state(auth_secret_ref)
        try:
            idle_timeout = (
                limits.page_timeout_seconds + limits.settle_milliseconds / 1_000 + 5
            )
            with _PinnedSocksProxy(
                resolver=self._host_resolver,
                connect_timeout_seconds=min(limits.page_timeout_seconds, 30),
                idle_timeout_seconds=idle_timeout,
            ) as egress_proxy, sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    **self._browser_launch_options(egress_proxy.server_url)
                )
                try:
                    context = browser.new_context(
                        accept_downloads=False,
                        ignore_https_errors=False,
                        java_script_enabled=True,
                        permissions=[],
                        service_workers="block",
                        storage_state=storage_state,
                    )
                    try:
                        page = context.new_page()

                        def route_request(route, request) -> None:
                            nonlocal truncated
                            navigation = bool(request.is_navigation_request())
                            if not self._admit_request(
                                request.url,
                                navigation=navigation,
                                hosts=navigation_hosts,
                            ):
                                route.abort("blockedbyclient")
                                return
                            # The document URL is represented by the page hash below;
                            # treating it as a tracker would create one false finding
                            # for every successfully visited page.
                            if navigation:
                                route.continue_()
                                return
                            if len(network) >= limits.max_network_events:
                                truncated = True
                                route.abort("blockedbyclient")
                                return
                            resource_type = str(request.resource_type or "other").lower()
                            if resource_type not in _RESOURCE_TYPES:
                                resource_type = "other"
                            network.append(NetworkMetadata(request.url, resource_type))
                            route.continue_()

                        context.route("**/*", route_request)
                        page.goto(
                            url,
                            timeout=limits.page_timeout_seconds * 1_000,
                            wait_until="domcontentloaded",
                        )
                        if limits.settle_milliseconds:
                            page.wait_for_timeout(limits.settle_milliseconds)
                        final_url = str(page.url)
                        final_host = _host(urlparse(final_url).hostname)
                        if final_host not in navigation_hosts:
                            raise ConsentScannerValidationError(
                                "navigation redirected outside enrolled property origins"
                            )
                        raw_links = page.eval_on_selector_all(
                            "a[href]",
                            "nodes => nodes.slice(0, 2000).map(node => node.href)",
                        )
                        if not isinstance(raw_links, (list, tuple)):
                            raw_links = []
                        links = tuple(
                            item
                            for item in raw_links[:_MAX_LINKS_PER_PAGE]
                            if isinstance(item, str)
                        )
                        raw_storage = page.evaluate(
                            "() => Object.keys(window.localStorage).slice(0, 2000)"
                        )
                        if not isinstance(raw_storage, (list, tuple)):
                            raw_storage = []
                        storage_keys = tuple(
                            item
                            for item in raw_storage[:_MAX_STORAGE_KEYS]
                            if isinstance(item, str) and len(item) <= 512
                        )
                        cookie_rows = context.cookies()
                        cookies = tuple(
                            CookieMetadata(
                                domain=str(row.get("domain", "")).lstrip(".").lower(),
                                name=str(row.get("name", ""))[:512],
                                secure=bool(row.get("secure")),
                                http_only=bool(row.get("httpOnly")),
                                same_site=str(row.get("sameSite", ""))[:32],
                                expires=(
                                    float(row["expires"])
                                    if isinstance(row.get("expires"), (int, float))
                                    and float(row["expires"]) > 0
                                    else None
                                ),
                            )
                            for row in cookie_rows[:_MAX_COOKIE_METADATA]
                            if isinstance(row, Mapping)
                            and isinstance(row.get("name"), str)
                            and row.get("name")
                        )
                        return PageCapture(
                            final_url=final_url,
                            links=links,
                            network=tuple(network),
                            cookies=cookies,
                            storage_keys=storage_keys,
                            network_truncated=truncated,
                        )
                    finally:
                        context.close()
                finally:
                    browser.close()
        except ConsentScannerError:
            raise
        except Exception as exc:
            raise ConsentScannerUnavailable("browser page capture failed") from exc


@dataclass(frozen=True)
class ScanFinding:
    finding_id: str
    kind: str
    tracker_key: str
    source_page_sha256: str
    host: str
    path_sha256: str | None
    resource_type: str | None
    name_sha256: str | None
    first_party: bool
    classification: str
    evidence_sha256: str


@dataclass(frozen=True)
class ScanReport:
    schema: str
    run_id: str
    tenant_sha256: str
    property_id: str
    started_at: float
    completed_at: float
    pages_attempted: int
    pages_captured: int
    page_sha256: tuple[str, ...]
    findings: tuple[ScanFinding, ...]
    errors: tuple[dict[str, str], ...]
    truncated: bool
    complete: bool
    report_sha256: str


class ConsentScanner:
    """Bounded breadth-first scanner that never stores page or identifier values."""

    def __init__(
        self,
        collector: PageCollector,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] | None = None,
        host_is_public: Callable[[str], bool] = _public_host,
    ) -> None:
        self._collector = collector
        self._clock = clock
        self._id_factory = id_factory or (lambda: secrets.token_hex(12))
        self._host_is_public = host_is_public

    @staticmethod
    def _network_finding(
        event: NetworkMetadata,
        *,
        source_page_sha256: str,
        first_party_hosts: frozenset[str],
    ) -> ScanFinding | None:
        try:
            parsed = urlparse(event.url)
            host = _host(parsed.hostname)
        except (ConsentScannerValidationError, ValueError, TypeError):
            return None
        path_sha = _digest_text(parsed.path or "/")
        tracker_key = _digest_text(f"network:{host}:{path_sha}:{event.resource_type}")
        body = {
            "kind": "network",
            "tracker_key": tracker_key,
            "source_page_sha256": source_page_sha256,
            "host": host,
            "path_sha256": path_sha,
            "resource_type": event.resource_type,
            "first_party": host in first_party_hosts,
            "classification": "unknown",
        }
        return ScanFinding(
            finding_id=f"CSF-{tracker_key[:24]}",
            kind="network",
            tracker_key=tracker_key,
            source_page_sha256=source_page_sha256,
            host=host,
            path_sha256=path_sha,
            resource_type=event.resource_type,
            name_sha256=None,
            first_party=host in first_party_hosts,
            classification="unknown",
            evidence_sha256=_sha256(body),
        )

    @staticmethod
    def _cookie_finding(
        cookie: CookieMetadata,
        *,
        source_page_sha256: str,
        first_party_hosts: frozenset[str],
    ) -> ScanFinding | None:
        try:
            host = _host(cookie.domain)
        except ConsentScannerValidationError:
            return None
        name_sha = _digest_text(cookie.name)
        tracker_key = _digest_text(f"cookie:{host}:{name_sha}")
        body = {
            "kind": "cookie",
            "tracker_key": tracker_key,
            "source_page_sha256": source_page_sha256,
            "host": host,
            "name_sha256": name_sha,
            "secure": cookie.secure,
            "http_only": cookie.http_only,
            "same_site": cookie.same_site,
            "expires": cookie.expires,
            "first_party": host in first_party_hosts,
            "classification": "unknown",
        }
        return ScanFinding(
            finding_id=f"CSF-{tracker_key[:24]}",
            kind="cookie",
            tracker_key=tracker_key,
            source_page_sha256=source_page_sha256,
            host=host,
            path_sha256=None,
            resource_type=None,
            name_sha256=name_sha,
            first_party=host in first_party_hosts,
            classification="unknown",
            evidence_sha256=_sha256(body),
        )

    @staticmethod
    def _storage_finding(key: str, *, source_page_sha256: str, host: str) -> ScanFinding:
        name_sha = _digest_text(key)
        tracker_key = _digest_text(f"storage:{host}:{name_sha}")
        body = {
            "kind": "storage",
            "tracker_key": tracker_key,
            "source_page_sha256": source_page_sha256,
            "host": host,
            "name_sha256": name_sha,
            "first_party": True,
            "classification": "unknown",
        }
        return ScanFinding(
            finding_id=f"CSF-{tracker_key[:24]}",
            kind="storage",
            tracker_key=tracker_key,
            source_page_sha256=source_page_sha256,
            host=host,
            path_sha256=None,
            resource_type=None,
            name_sha256=name_sha,
            first_party=True,
            classification="unknown",
            evidence_sha256=_sha256(body),
        )

    def scan(  # noqa: C901
        self,
        tenant_id: str,
        property_id: str,
        start_urls: Sequence[str],
        allowed_origins: Sequence[str],
        *,
        limits: ScanLimits | None = None,
        auth_secret_ref: str | None = None,
        authenticated_scan_consent: bool = False,
    ) -> ScanReport:
        require_enabled()
        tenant = _ref(tenant_id, "tenant_id")
        property_ref = _ref(property_id, "property_id")
        if not 1 <= len(allowed_origins) <= _MAX_ALLOWED_ORIGINS:
            raise ConsentScannerValidationError("allowed_origins count is invalid")
        origins = frozenset(_origin(value) for value in allowed_origins)
        hosts = frozenset(_host(urlparse(value).hostname) for value in origins)
        if any(not self._host_is_public(host) for host in hosts):
            raise ConsentScannerValidationError(
                "enrolled property origins must resolve only to public addresses"
            )
        if not 1 <= len(start_urls) <= _MAX_START_URLS:
            raise ConsentScannerValidationError("start_urls count is invalid")
        seeds = tuple(_navigation_url(value, origins) for value in start_urls)
        scan_limits = capped_scan_limits(limits or default_scan_limits())
        if auth_secret_ref is not None:
            _ref(auth_secret_ref, "auth_secret_ref")
            if authenticated_scan_consent is not True:
                raise ConsentScannerValidationError(
                    "authenticated scans require explicit privacy-owner consent"
                )
        elif authenticated_scan_consent:
            raise ConsentScannerValidationError(
                "authenticated scan consent cannot be set without a secret reference"
            )

        started = _finite_time(self._clock(), "clock")
        run_id = f"CSR-{_ref(self._id_factory(), 'run entropy')}"
        queue: deque[tuple[str, int]] = deque((url, 0) for url in seeds)
        queued = set(seeds)
        captured_urls: set[str] = set()
        page_hashes: list[str] = []
        findings_by_key: dict[str, ScanFinding] = {}
        errors: list[dict[str, str]] = []
        attempted = 0
        truncated = False

        while queue and attempted < scan_limits.max_pages:
            url, depth = queue.popleft()
            attempted += 1
            try:
                capture = self._collector.capture(
                    url,
                    navigation_hosts=hosts,
                    limits=scan_limits,
                    auth_secret_ref=auth_secret_ref,
                )
                final_url = _navigation_url(capture.final_url, origins)
                page_sha = _digest_text(final_url)
                captured_urls.add(final_url)
                page_hashes.append(page_sha)
                truncated = truncated or capture.network_truncated
                for event in capture.network[: scan_limits.max_network_events]:
                    finding = self._network_finding(
                        event,
                        source_page_sha256=page_sha,
                        first_party_hosts=hosts,
                    )
                    if finding is not None:
                        findings_by_key.setdefault(finding.tracker_key, finding)
                for cookie in capture.cookies[:_MAX_COOKIE_METADATA]:
                    finding = self._cookie_finding(
                        cookie,
                        source_page_sha256=page_sha,
                        first_party_hosts=hosts,
                    )
                    if finding is not None:
                        findings_by_key.setdefault(finding.tracker_key, finding)
                final_host = _host(urlparse(final_url).hostname)
                for key in capture.storage_keys[:_MAX_STORAGE_KEYS]:
                    if not isinstance(key, str) or not 1 <= len(key) <= 512:
                        continue
                    finding = self._storage_finding(
                        key,
                        source_page_sha256=page_sha,
                        host=final_host,
                    )
                    findings_by_key.setdefault(finding.tracker_key, finding)
                if depth < scan_limits.max_depth:
                    for link in capture.links[:_MAX_LINKS_PER_PAGE]:
                        try:
                            candidate = _navigation_url(urljoin(final_url, link), origins)
                        except ConsentScannerValidationError:
                            continue
                        if candidate not in queued and candidate not in captured_urls:
                            queue.append((candidate, depth + 1))
                            queued.add(candidate)
            except Exception as exc:
                if len(errors) < _MAX_ERRORS:
                    errors.append(
                        {
                            "page_sha256": _digest_text(url),
                            "error_code": type(exc).__name__,
                        }
                    )

        if queue:
            truncated = True
        completed = _finite_time(self._clock(), "clock")
        ordered_findings = tuple(
            findings_by_key[key] for key in sorted(findings_by_key)
        )
        body = {
            "schema": SCAN_REPORT_SCHEMA,
            "run_id": run_id,
            "tenant_sha256": _digest_text(tenant),
            "property_id": property_ref,
            "started_at": started,
            "completed_at": completed,
            "pages_attempted": attempted,
            "pages_captured": len(captured_urls),
            "page_sha256": sorted(set(page_hashes)),
            "findings": [asdict(item) for item in ordered_findings],
            "errors": errors,
            "truncated": truncated,
            "complete": not truncated and not errors,
        }
        return ScanReport(
            schema=SCAN_REPORT_SCHEMA,
            run_id=run_id,
            tenant_sha256=body["tenant_sha256"],
            property_id=property_ref,
            started_at=started,
            completed_at=completed,
            pages_attempted=attempted,
            pages_captured=len(captured_urls),
            page_sha256=tuple(body["page_sha256"]),
            findings=ordered_findings,
            errors=tuple(errors),
            truncated=truncated,
            complete=not truncated and not errors,
            report_sha256=_sha256(body),
        )


__all__ = [
    "CookieMetadata",
    "ConsentScanner",
    "ConsentScannerConfigError",
    "ConsentScannerError",
    "ConsentScannerUnavailable",
    "ConsentScannerValidationError",
    "NetworkMetadata",
    "PageCapture",
    "PageCollector",
    "PlaywrightPageCollector",
    "SCAN_REPORT_SCHEMA",
    "ScanFinding",
    "ScanLimits",
    "capped_scan_limits",
    "default_scan_limits",
    "scan_limit_settings",
    "ScanReport",
    "enabled",
    "require_enabled",
]
