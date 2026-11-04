"""Allowed network addresses for the dashboard ("IP allowlist").

Reads ``[auth.ip_allowlist]`` through :func:`maverick.config.get_ip_allowlist`
(the ``"auth"`` / ``"ip_allowlist"`` tables; keys ``"cidrs"`` and
``"workspace_cidrs"``; the environment's ``MAVERICK_IP_ALLOWLIST`` wins). An
empty list allows every address, so existing installations are unchanged.

Two checkpoints:

* the installation list (``cidrs``) is enforced by the app's HTTP middleware
  before any sign-in runs, for every path except the liveness/readiness
  probes;
* the workspace list (``workspace_cidrs``) is enforced in the authentication
  dependency once the caller's workspace is pinned, so a workspace's own
  ``config.toml`` overlay narrows access for its members.

The client address is taken from the socket peer. Only when that peer is one
of the operator's pinned ``[auth.proxy] trusted_proxies`` does the
``X-Forwarded-For`` chain count, walked from the right past every trusted hop
to the first address a trusted proxy did not vouch for. A header from an
unpinned peer is ignored, so a direct caller cannot choose its own address.

Fail closed: an entry that does not parse matches nothing, and a policy that
cannot be read allows only the computer Lightwork runs on.
"""
from __future__ import annotations

import ipaddress
import logging

log = logging.getLogger(__name__)

BLOCKED_MESSAGE = (
    "This network address isn't allowed to use Lightwork. Ask an administrator "
    "to add it to the allowed addresses."
)
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class PolicyUnreadable(RuntimeError):
    """The allowlist could not be read; callers allow only loopback."""


def parse_address(host: str | None) -> _Address | None:
    """Parse a peer or forwarded address (IPv4-mapped IPv6 collapses to IPv4;
    ``testclient`` is Starlette's in-process peer and reads as loopback)."""
    text = str(host or "").strip()
    if text in {"testclient", "localhost"}:
        return ipaddress.ip_address("127.0.0.1")
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def parse_networks(entries: list | tuple) -> tuple[list[_Network], list[str]]:
    """``(networks, rejected)``: every entry parsed strictly; a bad one is
    reported, never silently widened or dropped into "allow all"."""
    networks: list[_Network] = []
    rejected: list[str] = []
    for entry in entries or ():
        text = str(entry).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            rejected.append(text)
    return networks, rejected


def _peer_is_trusted_proxy(host: str) -> bool:
    try:
        from maverick.proxy_auth import proxy_trusts

        return bool(host) and proxy_trusts(host)
    except Exception:
        return False


def client_ip(request) -> _Address | None:
    """The real client address, proxy-aware only behind a pinned proxy."""
    peer_host = request.client.host if getattr(request, "client", None) else ""
    peer = parse_address(peer_host)
    if peer is None or not _peer_is_trusted_proxy(peer_host):
        return peer
    forwarded = request.headers.get("x-forwarded-for", "") or ""
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    # Walk right to left: each hop was appended by the proxy that received
    # it, so the first hop no trusted proxy vouches for is the client.
    current = peer
    for hop in reversed(hops):
        addr = parse_address(hop)
        if addr is None:
            # A garbled chain cannot name the client; keep the last good hop.
            break
        current = addr
        if not _peer_is_trusted_proxy(str(addr)):
            break
    return current


def _policy() -> dict:
    from maverick.config import config_source_errors, get_ip_allowlist

    # get_ip_allowlist() reads the merged config, so the active tenant's overlay
    # is a source of this list too: an unreadable overlay must not drop it.
    if config_source_errors(include_tenant=True):
        raise PolicyUnreadable("ip allowlist policy unreadable")
    policy = get_ip_allowlist()
    # The load can be what finds the source unreadable: check again after it.
    if config_source_errors(include_tenant=True):
        raise PolicyUnreadable("ip allowlist policy unreadable")
    return policy


def address_allowed(addr: _Address | None, entries: list | tuple) -> bool:
    """Whether ``addr`` is inside one of ``entries`` (empty list: everyone)."""
    networks, rejected = parse_networks(entries)
    if rejected:
        log.warning("ip_allowlist: ignoring entries that are not addresses or ranges: %s",
                    ", ".join(rejected))
    if not networks and not rejected:
        return True
    if addr is None:
        return False
    return any(addr in network for network in networks)


def installation_allows(request) -> bool:
    """The installation list, checked before sign-in."""
    addr = client_ip(request)
    try:
        entries = _policy()["cidrs"]
    except Exception:
        return addr is not None and addr.is_loopback
    return address_allowed(addr, entries)


def workspace_allows(request) -> bool:
    """The list for the pinned workspace (its config overlay is active now)."""
    addr = client_ip(request)
    try:
        from maverick.config import config_source_errors, get_ip_allowlist

        # The workspace overlay is a source too: unreadable means loopback only.
        # Checked again after the load, which is what first reads a fresh overlay.
        if config_source_errors(include_tenant=True):
            raise PolicyUnreadable("workspace ip allowlist policy unreadable")
        policy = get_ip_allowlist()
        if config_source_errors(include_tenant=True):
            raise PolicyUnreadable("workspace ip allowlist policy unreadable")
        entries = policy["workspace_cidrs"]
    except Exception:
        return addr is not None and addr.is_loopback
    return address_allowed(addr, entries)


def configured() -> bool:
    """Whether any allowlist is set (for the settings page's state line)."""
    try:
        policy = _policy()
    except Exception:
        return True
    return bool(policy["cidrs"] or policy["workspace_cidrs"])


__all__ = [
    "BLOCKED_MESSAGE",
    "PolicyUnreadable",
    "address_allowed",
    "client_ip",
    "configured",
    "installation_allows",
    "parse_address",
    "parse_networks",
    "workspace_allows",
]
