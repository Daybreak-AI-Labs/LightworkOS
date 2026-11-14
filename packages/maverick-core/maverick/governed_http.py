"""Explicit one-hop HTTP boundary for first-party integrations.

This complements the process-wide egress guard, which remains necessary for
third-party libraries and for integrations that have not migrated. Callers
must validate initial model-supplied destinations and pin their DNS separately
where needed. This module enforces tenant and enterprise egress policy, and
the redirect helper additionally validates and pins network redirect targets.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from typing import Any
from urllib.parse import urlsplit


def _absolute_http_target(url: Any) -> str:
    """Require the destination whose host will actually be admitted."""
    target = str(url)
    try:
        parsed = urlsplit(target)
        valid_target = parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        valid_target = False
    if not valid_target:
        raise ValueError("governed requests require an absolute HTTP URL")
    return target


def admit_client_request(client: Any, url: Any) -> None:
    """Admit a network-capable owned-client request without taking ownership.

    A configured HTTPX MockTransport/ASGI/WSGI transport is in-process and is
    exempt, exactly as in the process-wide guard. Unknown client/transport
    shapes are treated as network-capable. Callers must disable redirects or
    provide a per-hop boundary, and retain their own timeout and cleanup.
    """
    import httpx

    from .egress_guard import _check, _reaches_the_network

    target = _absolute_http_target(url)
    try:
        probe = httpx.Request("GET", target)
    except Exception:  # failure-policy: fail_closed -- an unknown adapter may use the network
        _check(target)
        return
    if _reaches_the_network(client, probe):
        _check(target)


def guarded_sender(send: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap an existing HTTP operation while preserving its arguments.

    Acquiring the sender at the call site preserves client configuration and
    test adapters; the policy check always precedes the delegated effect.
    """
    def guarded(url: str, *args: Any, **kwargs: Any) -> Any:
        # A bound HTTPX client can enable redirects on the client itself, so
        # the absence of a per-request flag does not imply a one-hop request.
        # Require an explicit False override in that case. Injected senders
        # must themselves honor the same one-hop contract.
        follow_redirects = kwargs.get("follow_redirects")
        owner = getattr(send, "__self__", None)
        if (follow_redirects or kwargs.get("allow_redirects", False)
                or (follow_redirects is not False
                    and getattr(owner, "follow_redirects", False) is True)):
            raise ValueError("governed requests must validate each redirect hop")
        # A relative path can inherit a bound client's base_url after this
        # check. Require an absolute HTTP URL so admission sees the real host.
        target = _absolute_http_target(url)
        from .egress_guard import _check

        _check(target)
        return send(url, *args, **kwargs)

    return guarded


def guarded_redirect_get(
    send: Callable[..., Any], *, require_https: bool = False,
) -> Callable[..., Any]:
    """Follow GET redirects with a policy decision before every HTTP hop.

    HTTPX builds each next request. Redirects reuse the original client's
    transport configuration and strip credentials on an origin change. Each
    network redirect is checked under the private-network setting, and a
    direct one is pinned to the checked address before sending.
    """
    def guarded(url: str, *args: Any, **kwargs: Any) -> Any:
        if require_https and urlsplit(str(url)).scheme.lower() != "https":
            raise ValueError("HTTPS is required for this request")
        options = dict(kwargs)
        options["follow_redirects"] = False
        response = guarded_sender(send)(url, *args, **options)
        if getattr(response, "status_code", None) not in (301, 302, 303, 307, 308):
            return response
        next_request = getattr(response, "next_request", None)
        if next_request is None:
            return response

        import httpx

        history = []
        owner = getattr(send, "__self__", None)
        # Bound clients retain their actual CA, client certificate, proxies,
        # mounts and custom transport. Top-level httpx.get passes these options
        # to a short-lived client, so preserve them for its redirect client.
        if owner is not None and callable(getattr(owner, "send", None)):
            context = nullcontext(owner)
        else:
            client_options = {key: options[key] for key in ("verify", "cert", "proxy", "trust_env") if key in options}
            context = httpx.Client(cookies=response.cookies, follow_redirects=False,
                                   timeout=options.get("timeout", 5.0), **client_options)
        with context as client:
            while next_request is not None:
                if len(history) >= 20:
                    response.close()
                    raise httpx.TooManyRedirects(
                        "Exceeded maximum allowed redirects.", request=next_request,
                    )
                if next_request.method != "GET":
                    response.close()
                    raise ValueError("redirect helper only follows GET requests")
                if require_https and next_request.url.scheme.lower() != "https":
                    response.close()
                    raise ValueError("HTTPS is required for every redirect")
                try:
                    previous = response.request.url
                    target = next_request.url
                    if (previous.scheme, previous.host, previous.port) != (target.scheme, target.host, target.port):
                        # Keep only ordinary representation/transport headers.
                        # Credential header names are not enumerable (API keys,
                        # signed headers and vendor tokens all occur in practice).
                        # HTTPX already removed the source Cookie header and
                        # rebuilt it from cookies scoped to the destination.
                        allowed = {"accept", "accept-encoding", "accept-language", "cache-control",
                                   "connection", "cookie", "host", "user-agent"}
                        for header in list(next_request.headers):
                            if header.lower() not in allowed:
                                del next_request.headers[header]
                    following = _send_pinned_redirect(client, next_request)
                except BaseException:
                    response.close()
                    raise
                history.append(response)
                response.close()
                response = following
                next_request = response.next_request
        response.history = history
        return response

    return guarded


def _proxy_carries(transport: Any) -> bool:
    """Whether a standard HTTPX transport hands each request to a proxy."""
    import httpcore
    import httpx

    if type(transport) is not httpx.HTTPTransport:
        return False
    pool = transport._pool
    return (type(pool) in (httpcore.HTTPProxy, httpcore.SOCKSProxy)
            or getattr(pool, "_proxy", None) is not None)


def _check_proxied_destination(host: str) -> None:
    """Apply the address policy to a hop whose proxy resolves the name.

    IP literals and names this host can resolve get the same check as a direct
    hop, including the private-network setting. A name that does not resolve
    here is left to the proxy, which chooses its address.
    """
    import socket

    from .tools import _ssrf

    try:
        socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return
    _ssrf.resolve_pinned_ip(host)


def _send_pinned_redirect(client: Any, request: Any) -> Any:
    """Pin a redirect in an isolated pool with the caller's transport settings.

    A proxied hop sends the hostname to the proxy, as the initial request
    does, after the same address check; only direct hops are pinned.
    """
    import httpx

    from .egress_guard import _check, _reaches_the_network
    from .tools._ssrf import _host_header, _PinnedTransport, resolve_pinned_ip

    _check(str(request.url))
    if not _reaches_the_network(client, request):
        return client.send(request, follow_redirects=False, auth=None)
    host = request.url.raw_host.decode("ascii")
    selected = client._transport_for_url(request.url)
    if _proxy_carries(selected):
        _check_proxied_destination(host)
        return client.send(request, follow_redirects=False, auth=None)
    ip = resolve_pinned_ip(host)
    inner = _isolated_redirect_transport(selected, host=host)

    class IsolatedPinnedTransport(_PinnedTransport):
        def handle_request(self, request):
            original = request.url
            try:
                return super().handle_request(request)
            finally:
                # HTTPX resolves relative Location headers after transport
                # return; that base must remain the original hostname.
                request.url = original

    transport = IsolatedPinnedTransport(host, _host_header(urlsplit(str(request.url)), host), ip, inner)
    with httpx.Client(transport=transport, cookies=client.cookies,
                      event_hooks=client.event_hooks, follow_redirects=False) as pinned:
        response = pinned.send(request, follow_redirects=False, auth=None)
        client.cookies.extract_cookies(response)
        return response


class _RedirectTlsStream:
    """Keep proxy and origin certificate identities on their own TLS layers."""

    def __init__(self, stream: Any, tls_hosts: tuple[str, ...]) -> None:
        self._stream, self._tls_hosts = stream, tls_hosts

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        del server_hostname  # Pool URLs contain the pin, not the TLS identity.
        if not self._tls_hosts:
            raise ValueError("unexpected TLS layer in pinned redirect")
        stream = self._stream.start_tls(ssl_context=ssl_context,
                                        server_hostname=self._tls_hosts[0], timeout=timeout)
        return _RedirectTlsStream(stream, self._tls_hosts[1:])


class _RedirectTlsBackend:
    """Wrap new streams only; the original backend and pools remain untouched."""

    def __init__(self, backend: Any, tls_hosts: tuple[str, ...]) -> None:
        self._backend, self._tls_hosts = backend, tls_hosts

    def __getattr__(self, name: str) -> Any:
        return getattr(self._backend, name)

    def connect_tcp(self, *args, **kwargs):
        return _RedirectTlsStream(self._backend.connect_tcp(*args, **kwargs), self._tls_hosts)

    def connect_unix_socket(self, *args, **kwargs):
        return _RedirectTlsStream(self._backend.connect_unix_socket(*args, **kwargs), self._tls_hosts)


def _isolated_redirect_transport(transport: Any, *, host: str) -> Any:
    """Copy configuration, never connections, from a standard HTTPX transport.

    Rewriting two HTTPS origins to the same pinned IP collapses httpcore's
    pool key. Reusing that pool could send the second hostname over a TLS
    connection verified only for the first. Each redirect needs its own pool.
    """
    import copy

    import httpcore
    import httpx

    if type(transport) is not httpx.HTTPTransport:
        raise ValueError("cannot safely isolate this network redirect transport")
    pool = transport._pool
    if type(pool) not in (httpcore.ConnectionPool, httpcore.HTTPProxy, httpcore.SOCKSProxy):
        raise ValueError("cannot safely isolate this network redirect connection pool")
    if type(pool) is httpcore.ConnectionPool and pool._proxy is not None:
        raise ValueError("cannot safely isolate this custom proxy redirect configuration")
    tls_hosts = (host,)
    if type(pool) is httpcore.HTTPProxy and pool._proxy_url.scheme == b"https":
        tls_hosts = (pool._proxy_url.host.decode("ascii"), host)
    # HTTPX retains the original CA and client certificate in this SSLContext.
    # Preserve its proxy/TLS/network settings while constructing empty pool
    # state; neither the caller's connections nor its locks are shared.
    options = {name: getattr(pool, "_" + name) for name in (
        "ssl_context", "max_connections", "max_keepalive_connections",
        "keepalive_expiry", "http1", "http2", "retries", "network_backend",
    )}
    if type(pool) is httpcore.SOCKSProxy:
        options.update(proxy_url=pool._proxy_url, proxy_auth=pool._proxy_auth)
    else:
        options.update((name, getattr(pool, "_" + name)) for name in (
            "local_address", "uds", "socket_options",
        ))
        if type(pool) is httpcore.HTTPProxy:
            options.update(proxy_url=pool._proxy_url, proxy_headers=list(pool._proxy_headers),
                           proxy_ssl_context=pool._proxy_ssl_context)
        else:
            options["proxy"] = pool._proxy
    isolated = copy.copy(transport)
    # CONNECT/SOCKS must address the pinned IP, but httpcore's tunnel TLS
    # paths do not all honor sni_hostname. Bind each TLS layer explicitly,
    # passing the original SSLContext through with verification unchanged.
    options["network_backend"] = _RedirectTlsBackend(pool._network_backend, tls_hosts)
    isolated._pool = type(pool)(**options)
    return isolated


class GuardedClient:
    """Apply the one-hop boundary to a caller-owned HTTPX client.

    Context entry and exit are delegated to the underlying client. Operations
    that need a different signature or streaming ownership are refused until
    they have a dedicated governed adapter; they never silently bypass policy.
    """

    _METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
    _UNSUPPORTED = frozenset({"request", "send", "stream"})

    def __init__(self, client: Any) -> None:
        self._client = client

    def __enter__(self) -> GuardedClient:
        entered = self._client.__enter__()
        return self if entered is self._client else GuardedClient(entered)

    def __exit__(self, *exc: Any) -> Any:
        return self._client.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        if name in self._UNSUPPORTED:
            raise AttributeError(f"governed client does not support {name}; use an explicit transport")
        value = getattr(self._client, name)
        if name in self._METHODS:
            return guarded_sender(value)
        return value


def request(
    method: str,
    url: str,
    *,
    send: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> Any:
    """Send one governed request, without retries or implicit redirects.

    ``send`` allows a caller to supply an HTTP operation for tests or a
    platform-specific adapter. It receives the URL and the unchanged keyword
    arguments only after the live egress policy has admitted that URL.
    """
    if send is None:
        import httpx

        send = getattr(httpx, method.lower())
    return guarded_sender(send)(url, **kwargs)
