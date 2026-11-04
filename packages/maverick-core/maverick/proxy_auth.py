"""Reverse-proxy SSO: trust a forwarded identity header from a trusted upstream.

The standard, low-risk way to put browser SSO in front of an internal service:
a proxy (oauth2-proxy, your IdP's, an ALB OAuth listener, ...) authenticates the
user and forwards their identity in a request header (e.g. ``X-Forwarded-User``).
Lightwork maps that value to a ``user:<id>`` principal that drops straight into
the capability/role + tenant model -- no hand-rolled OAuth flow to own.

SECURITY: a forwarded header is trivially spoofable by a *direct* client, so it
is honored ONLY when the request's network peer is a trusted upstream. The peer
must be pinned via ``trusted_proxies``; an unpinned deployment refuses the
header unless the operator explicitly opts into loopback trust with
``[auth.proxy] trust_loopback = true`` (off by default, since a bare loopback
peer can't be told from any other co-located process). The operator MUST also
(a) make the proxy the only ingress to the dashboard and (b) configure the
proxy to strip any client-supplied copy of the header. Default-off; opt-in via
``[auth.proxy] enabled`` / ``MAVERICK_PROXY_AUTH``.
"""
from __future__ import annotations

import ipaddress
import logging
import os

from ._envparse import coerce_bool, is_truthy

_DEFAULT_HEADER = "X-Forwarded-User"
# The proxy normally shares the host, so loopback is the safe default peer.
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})

log = logging.getLogger(__name__)


def _section() -> dict:
    try:
        from .config import load_config
        return ((load_config() or {}).get("auth") or {}).get("proxy") or {}
    except Exception:
        return {}


def proxy_auth_enabled() -> bool:
    """Opt-in, off by default: ``MAVERICK_PROXY_AUTH`` or ``[auth.proxy] enabled``."""
    env = os.environ.get("MAVERICK_PROXY_AUTH", "").strip().lower()
    if env:
        return is_truthy(env)
    return coerce_bool(_section().get("enabled"))


def proxy_header_name() -> str:
    """The forwarded-identity header to read (default ``X-Forwarded-User``)."""
    name = (
        os.environ.get("MAVERICK_PROXY_AUTH_HEADER")
        or str(_section().get("header") or "")
    ).strip()
    return name or _DEFAULT_HEADER


def _trust_loopback_fallback() -> bool:
    """Whether to trust loopback peers when ``trusted_proxies`` is unset.

    OFF unless the operator EXPLICITLY opts in with ``[auth.proxy]
    trust_loopback = true``. Trusting loopback by IP alone can't tell the real
    proxy from ANY other co-located loopback process -- a sidecar, another
    container in the pod's network namespace, or an SSRF pivot to 127.0.0.1 --
    each of which could then spoof ``X-Forwarded-User: admin``. So an unpinned
    deployment refuses the forwarded header in EVERY mode (enterprise included,
    which already failed closed); to accept it the operator must either pin
    ``trusted_proxies`` or set ``trust_loopback = true``.
    """
    return coerce_bool(_section().get("trust_loopback"))


def _normalized_peer(client_host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse ``client_host`` as an IP, collapsing an IPv4-mapped IPv6 form
    (``::ffff:10.0.0.5``, what a dual-stack listener reports for an IPv4 peer)
    down to its IPv4 address so it compares equal to a plain ``10.0.0.5`` pin."""
    try:
        addr = ipaddress.ip_address(client_host)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return mapped
    return addr


def _parse_trusted_networks(
    trusted: list | tuple,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse each ``trusted_proxies`` entry as a host or CIDR network.

    An unparsable entry is dropped with a loud warning rather than silently
    matching nothing (fail-closed) or crashing the request path.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in trusted:
        text = str(entry).strip()
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            log.warning(
                "proxy_auth: [auth.proxy] trusted_proxies entry %r is not a "
                "valid IP address or CIDR network; ignoring it", text,
            )
    return networks


def proxy_trusts(client_host: str | None) -> bool:
    """True iff a request from ``client_host`` may carry the identity header.

    A configured ``[auth.proxy] trusted_proxies = ["10.0.0.5", ...]`` is the
    secure form (the exact proxy peer, or a CIDR range for a proxy pool /
    load balancer, is pinned). With no pin, loopback is trusted only when the
    operator explicitly opted in with ``[auth.proxy] trust_loopback = true``
    (see :func:`_trust_loopback_fallback` -- OFF by default in every mode).
    An empty/unknown peer is never trusted.
    """
    if not client_host:
        return False
    trusted = _section().get("trusted_proxies")
    if isinstance(trusted, (list, tuple)) and trusted:
        peer = _normalized_peer(client_host)
        if peer is None:
            return False
        return any(peer in network for network in _parse_trusted_networks(trusted))
    return _trust_loopback_fallback() and client_host in _LOOPBACK


def warn_if_untrusted_proxy_config() -> None:
    """Loudly warn at startup when reverse-proxy SSO is enabled but no upstream
    is trusted: neither ``trusted_proxies`` pinned nor ``trust_loopback``
    explicitly set. In that state the forwarded identity header is refused from
    every peer (secure, but proxy auth is effectively non-functional and login
    via the proxy will fail) -- the operator almost certainly meant to pin the
    proxy. No-op when proxy auth is off or a peer is already configured.
    """
    if not proxy_auth_enabled():
        return
    section = _section()
    trusted = section.get("trusted_proxies")
    if isinstance(trusted, (list, tuple)) and trusted:
        return
    if section.get("trust_loopback") is not None:
        return
    log.warning(
        "reverse-proxy SSO ([auth.proxy] enabled) is on but no upstream is "
        "trusted: pin [auth.proxy] trusted_proxies to your proxy's peer "
        "address, or set [auth.proxy] trust_loopback = true if the proxy shares "
        "this host. Until then the forwarded identity header is refused from "
        "every peer and login via the proxy will fail.",
    )


def uvicorn_launch_kwargs() -> dict:
    """Extra ``uvicorn.run()`` kwargs the dashboard's own auth model requires.

    ``proxy_trusts()`` and the loopback-only-serving gate both key off
    ``request.client.host`` -- the real, unspoofable network peer. uvicorn's
    ``ProxyHeadersMiddleware`` (installed by default: ``proxy_headers=True``,
    ``forwarded_allow_ips`` defaulting to ``127.0.0.1`` or ``FORWARDED_ALLOW_IPS``)
    rewrites that same scope value from ``X-Forwarded-For`` for any peer it
    trusts, in place, with the original peer unrecoverable afterward. With
    reverse-proxy SSO enabled that reopens exactly the co-located-loopback
    identity spoof ``trust_loopback=false`` exists to close (any loopback
    peer -- a sidecar, another pod-network container, an SSRF pivot -- can
    send ``X-Forwarded-For: <pinned-proxy-ip>`` and be treated as coming from
    the pinned proxy), and independently breaks the documented pinned-loopback-
    proxy setup outright (the real client's rewritten address never matches
    the pin). Disabling proxy-header rewriting is correct rather than trying
    to make ``forwarded_allow_ips`` match ``trusted_proxies``: once uvicorn
    trusts a peer it substitutes the *forwarded* address for it, which is the
    opposite of what a peer-identity check needs.
    """
    # Rate limits and anonymous local-access checks also require the true peer
    # even when proxy SSO is disabled. Forwarded addresses are interpreted
    # separately only after the peer matches the configured trusted proxies.
    return {"proxy_headers": False}


def principal_from_proxy(value: str):
    """Map a forwarded identity value to a :class:`maverick.oidc.VerifiedPrincipal`.

    ``principal`` is ``user:<value>`` so it matches the OIDC/``[role_assignments]``
    conventions; ``claims`` records that this identity came via the proxy (not a
    signed ID token) so downstream code can tell them apart.
    """
    from .oidc import VerifiedPrincipal, validate_subject
    subject = validate_subject(value)
    return VerifiedPrincipal(
        sub=subject, issuer="proxy", audience="", claims={"via": "proxy"},
    )


__all__ = [
    "proxy_auth_enabled",
    "proxy_header_name",
    "proxy_trusts",
    "warn_if_untrusted_proxy_config",
    "principal_from_proxy",
    "uvicorn_launch_kwargs",
]
