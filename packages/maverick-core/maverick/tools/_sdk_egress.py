"""Egress policy for tools whose client library the egress guard does not wrap.

``egress_guard`` enforces ``[enterprise] allowed_hosts`` on httpx, requests and
urllib. botocore talks through urllib3 directly and pymongo through raw
sockets, so the AWS and MongoDB tools must check the endpoint they are about
to reach themselves. The check is the one the HTTP tools get: the enterprise
allow-list, then the tenant/tool egress policy and the network posture. A
policy that cannot be evaluated refuses the request.
"""
from __future__ import annotations

from urllib.parse import urlsplit


def sdk_egress_denial(tool: str, url: str) -> str | None:
    """Return why ``tool`` may not reach ``url``, or None when it may."""
    from ..enterprise import enterprise_egress_denial

    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".") if isinstance(url, str) else ""
    except ValueError:
        host = ""
    if not host:
        return f"{tool}: could not tell which host {url!r} names, so the request was not sent"
    if denial := enterprise_egress_denial(url, tool=tool):
        return denial
    try:
        from ..tenant.egress import egress_allowed

        allowed = egress_allowed(tool, host)
    except Exception as exc:  # noqa: BLE001 -- an unreadable policy must not allow all
        return (f"{tool}: the egress policy could not be evaluated "
                f"({type(exc).__name__}), so the request to {host!r} was not sent")
    if not allowed:
        return f"{tool}: egress policy does not allow {host!r}; the request was not sent"
    return None


def require_sdk_egress(tool: str, url: str) -> None:
    """Raise ``RuntimeError`` with the reason when ``tool`` may not reach ``url``."""
    if denial := sdk_egress_denial(tool, url):
        raise RuntimeError(denial)


__all__ = ["require_sdk_egress", "sdk_egress_denial"]
