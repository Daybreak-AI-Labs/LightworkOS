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
    network redirect is checked and pinned to a public address before sending.
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


def _send_pinned_redirect(client: Any, request: Any) -> Any:
    """Borrow the selected transport without mutating or closing its owner."""
    import httpx

    from .egress_guard import _check, _reaches_the_network
    from .tools._ssrf import _host_header, _PinnedTransport, resolve_pinned_ip

    _check(str(request.url))
    if not _reaches_the_network(client, request):
        return client.send(request, follow_redirects=False, auth=None)
    host = request.url.host
    ip = resolve_pinned_ip(host, require_public=True)
    inner = client._transport_for_url(request.url)

    class BorrowedPinnedTransport(_PinnedTransport):
        def handle_request(self, request):
            original = request.url
            try:
                return super().handle_request(request)
            finally:
                # HTTPX resolves relative Location headers after transport
                # return; that base must remain the original hostname.
                request.url = original

        def close(self):
            pass  # The caller owns the underlying transport and connection pool.

    transport = BorrowedPinnedTransport(host, _host_header(urlsplit(str(request.url)), host), ip, inner)
    with httpx.Client(transport=transport, cookies=client.cookies,
                      event_hooks=client.event_hooks, follow_redirects=False) as pinned:
        response = pinned.send(request, follow_redirects=False, auth=None)
        client.cookies.extract_cookies(response)
        return response


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
