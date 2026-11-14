"""SSRF-safe HTTP fetching: resolve once, validate, pin the connection.

Every tool that fetches a model/user-supplied URL used to do this::

    if is_blocked_host(parsed.hostname): reject
    httpx.get(url)              # <-- httpx re-resolves the name here

That is a DNS-rebinding TOCTOU: a hostile resolver can answer with a
public IP for the validation lookup and then ``127.0.0.1`` /
``169.254.169.254`` for the connection lookup, slipping past the guard.

This module closes the window. ``resolve_pinned_ip`` resolves the host
**once**, requires *every* returned address to be public, and returns the
IP. ``safe_client`` / ``safe_get`` then connect to that exact IP via a
transport that rewrites only the connection target, leaving the ``Host``
header and TLS SNI / certificate verification bound to the original
hostname. There is no second resolution, so there is nothing to rebind.

Honors ``MAVERICK_FETCH_ALLOW_PRIVATE=1`` (skips the public-only check but
still pins the resolved IP), matching the existing guard's escape hatch.

Redirects are NOT followed by default: a 3xx to a fresh host would not be
pinned, so callers must keep ``follow_redirects=False`` and re-validate
each hop themselves.
"""
from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import os
import socket
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:  # pragma: no cover
    import httpx


class BlockedHost(Exception):
    """Raised when a URL's host won't resolve or resolves to a non-public IP."""


class BlockedAddress(BlockedHost, ValueError):
    """A host that resolves to a private/internal address.

    Also a ``ValueError``, so callers of the urllib guard
    (``http_fetch.guarded_urlopen``) that catch ``ValueError`` keep working,
    while callers that tell "inside the network" apart catch ``BlockedHost``."""


_scoped_private_hosts: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "maverick_scoped_private_hosts",
    default=frozenset(),
)


def _normalized_host(host: str) -> str:
    normalized = str(host or "").lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        return normalized


@contextlib.contextmanager
def allow_private_hosts(hosts: Iterable[str]) -> Iterator[None]:
    """Temporarily admit exact loopback IP literals in the current context.

    This is narrower than the process-global on-prem escape hatch: it propagates
    through ``asyncio.to_thread`` but not into concurrent request contexts, and
    cannot authorize a hostname that DNS could rebind or a private network range.
    It exists for exact loopback endpoints an operator approved, such as a
    local model server or a partner test estate.
    """
    normalized: set[str] = set()
    for raw in hosts:
        host = _normalized_host(raw)
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("scoped private hosts must be loopback IP literals") from exc
        if not address.is_loopback:
            raise ValueError("scoped private hosts must be loopback IP literals")
        normalized.add(host)
    if not normalized:
        raise ValueError("at least one loopback host is required")
    token = _scoped_private_hosts.set(frozenset(normalized))
    try:
        yield
    finally:
        _scoped_private_hosts.reset(token)


# Shared address space (RFC 6598, carrier-grade NAT). ``ipaddress`` calls it
# neither private nor global, yet clouds serve internal endpoints from it --
# Alibaba Cloud's metadata service is 100.100.100.200.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


def address_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address a guarded fetch must never connect to."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.version == 4 and ip in _SHARED_ADDRESS_SPACE)
        # Deprecated IPv6 site-local fec0::/10 is neither private nor
        # reserved to ``ipaddress``, but it is never a public destination.
        or (ip.version == 6 and ip.is_site_local)
        or address_is_always_blocked(ip)
    )


def _ip_is_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable address -> refuse
    return address_is_blocked(ip)


# Cloud platform endpoints that do not sit in a link-local range: Alibaba
# Cloud serves instance credentials from a shared-address-space literal, AWS
# serves IMDS over IPv6 from a unique-local literal, and Azure's WireServer is
# a host-only endpoint in public address space.
_ALWAYS_BLOCKED_LITERALS = frozenset({
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("168.63.129.16"),
})
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address carries (mapped, 6to4 or NAT64)."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def address_is_always_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for addresses the private-network override must NOT open.

    "Let agents read addresses inside your network" means RFC 1918, loopback
    and shared address space (an intranet, a dev server, a Tailscale peer).
    It never means the cloud metadata service (169.254.169.254 on AWS, Azure,
    GCP, OCI and DigitalOcean; fe80:: and fd00:ec2::254 on IPv6, also when
    carried inside a mapped, 6to4 or NAT64 IPv6 address), Azure's WireServer,
    site-local, multicast, reserved or unspecified addresses: one toggled setting must not turn every
    prompt-injectable tool into an instance-credential client.
    """
    if ip.version == 6:
        embedded = _embedded_ipv4(ip)
        if embedded is not None and address_is_always_blocked(embedded):
            return True
    if ip.is_loopback:  # ::1 sits in ::/8, which ipaddress calls reserved
        return False
    return (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (ip.version == 6 and ip.is_site_local)
        or ip in _ALWAYS_BLOCKED_LITERALS
    )


def _ip_is_always_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return address_is_always_blocked(ip)


def allow_private() -> bool:
    """``MAVERICK_FETCH_ALLOW_PRIVATE`` when set, else ``[tools]
    fetch_allow_private`` (Settings > All settings). Off unless exactly "1"."""
    raw = os.environ.get("MAVERICK_FETCH_ALLOW_PRIVATE")
    if raw is not None and raw.strip():
        return raw == "1"
    try:
        from ..env_setting import env_or_config

        return env_or_config("MAVERICK_FETCH_ALLOW_PRIVATE", "tools", "fetch_allow_private") == "1"
    except Exception:  # an unreadable configuration never opens the guard
        return False


def _allow_private() -> bool:
    return allow_private()


def _host_header(parsed: Any, host: str) -> str:
    """``Host`` value for ``parsed``: IPv6 literals bracketed, an invalid port
    refused as ``BlockedHost`` (``urlparse`` raises a bare ``ValueError``)."""
    try:
        port = parsed.port
    except ValueError as exc:
        raise BlockedHost(f"invalid port in URL for {host!r}") from exc
    name = f"[{host}]" if ":" in host else host
    return name if not port else f"{name}:{port}"


def resolve_pinned_ip(host: str, *, require_public: bool = False) -> str:
    """Resolve ``host`` once and return a single IP to connect to.

    Requires *every* resolved address to be public (so a resolver can't
    smuggle a private IP alongside a public one). Raises ``BlockedHost`` on
    a resolution failure or any non-public address. ``require_public`` ignores
    private-network overrides for callers that must never reach an internal IP.
    """
    if not host:
        raise BlockedHost("missing host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise BlockedHost(f"cannot resolve {host!r}: {e}") from e
    ips = [info[4][0] for info in infos if info[4]]
    if not ips:
        raise BlockedHost(f"no addresses for {host!r}")
    normalized_host = _normalized_host(host)
    scoped_private = normalized_host in _scoped_private_hosts.get()
    if require_public or (not scoped_private and not _allow_private()):
        for ip in ips:
            if _ip_is_blocked(ip):
                raise BlockedHost(
                    f"{host!r} resolves to non-public address {ip}"
                )
    elif not scoped_private:
        # The private-network override: still never the metadata service.
        for ip in ips:
            if _ip_is_always_blocked(ip):
                raise BlockedHost(
                    f"{host!r} resolves to {ip}, which stays blocked even when "
                    "private addresses are allowed (link-local, metadata, "
                    "multicast, reserved or unspecified)"
                )
    elif scoped_private:
        expected = ipaddress.ip_address(normalized_host)
        for ip in ips:
            try:
                actual = ipaddress.ip_address(ip)
            except ValueError as exc:
                raise BlockedHost(f"invalid address for scoped host {host!r}") from exc
            if actual != expected or not actual.is_loopback:
                raise BlockedHost(
                    f"scoped host {host!r} resolved outside its exact loopback literal"
                )
    return ips[0]


def _request_host_matches(request: Any, host: str) -> bool:
    """True if ``request``'s host reconciles with the validated/pinned ``host``.

    httpx decodes an IDN host to Unicode in ``url.host`` while ``urlparse`` keeps
    the original (often punycode) form, so a naive ``url.host == host`` skips the
    pin for IDN hosts -- reopening the DNS-rebinding TOCTOU. Match either the
    Unicode or the ASCII/punycode (``raw_host``) form so a legitimate IDN host is
    still recognized and pinned, and anything that doesn't reconcile is refused."""
    candidates = {request.url.host}
    try:
        raw = request.url.raw_host
        if raw:
            candidates.add(raw.decode("ascii"))
    except Exception:
        pass
    return host in candidates


class _PinnedTransport:
    """httpx transport wrapper that connects to a pre-validated IP.

    Rewrites the request's connection host to ``ip`` while restoring the
    original ``Host`` header and setting ``sni_hostname`` so TLS SNI and
    certificate hostname verification stay bound to the real host.
    """

    def __init__(self, host: str, host_header: str, ip: str, inner: Any):
        self._host = host
        self._host_header = host_header
        self._ip = ip
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not _request_host_matches(request, self._host):
            # Host doesn't reconcile with the validated/pinned host -- refuse
            # rather than let the inner transport re-resolve an unvalidated name.
            raise BlockedHost(
                f"unpinned host {request.url.host!r} != validated {self._host!r}")
        # Check the original hostname on every request before rewriting it to
        # the pinned address. The process-wide guard remains defense in depth.
        from ..egress_guard import _check

        _check(str(request.url))
        request.headers["Host"] = self._host_header
        request.extensions = {**request.extensions, "sni_hostname": self._host}
        request.url = request.url.copy_with(host=self._ip)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> _PinnedTransport:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def safe_client(
    url: str, *, attempt_deadline=None, require_public: bool = False,
    **client_kwargs: Any,
) -> httpx.Client:
    """Return an ``httpx.Client`` pinned to a validated public IP for ``url``.

    Raises ``BlockedHost`` if the scheme is not http/https or the host
    resolves to a non-public address. ``require_public`` keeps that rule even
    if private-network fetching is enabled. Redirects remain disabled.
    """
    import httpx

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedHost(f"scheme {parsed.scheme!r} not allowed")
    from ..egress_guard import _check

    _check(url)
    host = parsed.hostname or ""
    ip = resolve_pinned_ip(host, require_public=require_public)
    host_header = _host_header(parsed, host)
    if attempt_deadline is None:
        inner = httpx.HTTPTransport()
    else:
        from ._bounded_http import DeadlineHTTPTransport
        # The existing resolver remains synchronous. If DNS consumed the
        # deadline, constructing this transport refuses before any HTTP I/O.
        inner = DeadlineHTTPTransport(attempt_deadline)
    transport = _PinnedTransport(host, host_header, ip, inner)
    client_kwargs.setdefault("follow_redirects", False)
    client_kwargs["transport"] = transport
    return httpx.Client(**client_kwargs)


def safe_get(url: str, **kwargs: Any) -> httpx.Response:
    """SSRF-safe ``httpx.get``: validates + pins the host, then fetches.

    Splits httpx ``Client`` kwargs (timeout, headers, verify, ...) from
    request kwargs (params, ...). Raises ``BlockedHost`` on a non-public
    host. Always uses ``follow_redirects=False``.
    """
    timeout = kwargs.pop("timeout", 30.0)
    headers = kwargs.pop("headers", None)
    verify = kwargs.pop("verify", True)
    # Drop any caller-supplied follow_redirects: a per-request True would
    # override the safe client's redirect-disabled default and let a 3xx escape
    # to an unpinned/unvalidated host -- the exact SSRF this helper prevents.
    kwargs.pop("follow_redirects", None)
    with safe_client(url, timeout=timeout, verify=verify) as client:
        return client.get(url, headers=headers, **kwargs)


class _AsyncPinnedTransport:
    """Async mirror of ``_PinnedTransport`` for ``httpx.AsyncClient``.

    Same contract: rewrite the connection host to the pre-validated IP while
    restoring the original ``Host`` header and TLS SNI, so there is no second
    name resolution to rebind.
    """

    def __init__(self, host: str, host_header: str, ip: str, inner: Any):
        self._host = host
        self._host_header = host_header
        self._ip = ip
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not _request_host_matches(request, self._host):
            raise BlockedHost(
                f"unpinned host {request.url.host!r} != validated {self._host!r}")
        from ..egress_guard import _check

        _check(str(request.url))
        request.headers["Host"] = self._host_header
        request.extensions = {**request.extensions, "sni_hostname": self._host}
        request.url = request.url.copy_with(host=self._ip)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> _AsyncPinnedTransport:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


def pinned_async_transport(url: str) -> _AsyncPinnedTransport:
    """An ``httpx`` async transport pinned to ``url``'s validated public IP.

    For a client that builds its own ``httpx.AsyncClient`` (pass it as
    ``transport=``): the host is resolved and checked once, here, and every
    request connects to that IP with ``Host`` and TLS SNI kept as the name.
    Raises ``BlockedHost`` like :func:`safe_async_client`."""
    import httpx

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedHost(f"scheme {parsed.scheme!r} not allowed")
    from ..egress_guard import _check

    _check(url)
    host = parsed.hostname or ""
    ip = resolve_pinned_ip(host)
    host_header = _host_header(parsed, host)
    return _AsyncPinnedTransport(host, host_header, ip, httpx.AsyncHTTPTransport())


def safe_async_client(url: str, **client_kwargs: Any) -> httpx.AsyncClient:
    """Async counterpart of ``safe_client``: an ``httpx.AsyncClient`` pinned
    to a validated public IP for ``url``.

    Raises ``BlockedHost`` if the scheme is not http/https or the host
    resolves to a non-public address. ``follow_redirects`` defaults to
    ``False`` -- a 3xx to a fresh host would not be pinned.
    """
    import httpx

    transport = pinned_async_transport(url)
    client_kwargs.setdefault("follow_redirects", False)
    client_kwargs["transport"] = transport
    return httpx.AsyncClient(**client_kwargs)


__all__ = [
    "BlockedAddress",
    "BlockedHost",
    "address_is_blocked",
    "allow_private",
    "allow_private_hosts",
    "pinned_async_transport",
    "resolve_pinned_ip",
    "safe_client",
    "safe_async_client",
    "safe_get",
]
