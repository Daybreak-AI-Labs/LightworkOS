"""Explicit one-hop HTTP boundary for first-party integrations.

This complements the process-wide egress guard, which remains necessary for
third-party libraries and for integrations that have not migrated. Callers
must validate model-supplied destinations and pin DNS separately where needed;
this module enforces tenant and enterprise egress policy, not SSRF policy.
"""
from __future__ import annotations

from collections.abc import Callable
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

    HTTPX builds each next request, including its URL, cookies, headers and
    cross-origin credential stripping. The original sender is used for the
    first hop; subsequent requests use one client with redirects disabled so
    this boundary can check each prepared destination before sending it.
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

        from .egress_guard import _check

        history = []
        # Carry cookies set on the initial response into the redirect client.
        # Its subsequent responses update the same jar through HTTPX itself.
        with httpx.Client(
            cookies=response.cookies,
            follow_redirects=False,
            timeout=options.get("timeout", 5.0),
        ) as client:
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
                    _check(str(next_request.url))
                except BaseException:
                    response.close()
                    raise
                history.append(response)
                response.close()
                response = client.send(next_request, follow_redirects=False)
                next_request = response.next_request
        response.history = history
        return response

    return guarded


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
