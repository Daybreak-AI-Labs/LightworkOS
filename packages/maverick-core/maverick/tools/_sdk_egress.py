"""Egress policy for tools whose client library the egress guard does not wrap.

``egress_guard`` enforces ``[enterprise] allowed_hosts`` on httpx, requests and
urllib. botocore talks through urllib3 directly and pymongo through raw
sockets, so the AWS and MongoDB tools must check the endpoint they are about
to reach themselves. The check is the one the HTTP tools get: the enterprise
allow-list, then the tenant/tool egress policy and the network posture. A
policy that cannot be evaluated refuses the request.
"""
from __future__ import annotations

import os
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
    try:
        denial = enterprise_egress_denial(url, tool=tool)
    except Exception as exc:  # noqa: BLE001 -- e.g. an unreadable config
        return (f"{tool}: the network policy could not be read ({type(exc).__name__}: {exc}), "
                f"so the request to {host!r} was not sent")
    if denial:
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


def egress_restricted(tool: str) -> bool:
    """Whether any egress policy limits ``tool`` to particular hosts.

    Asks the same layers as :func:`sdk_egress_denial` about a host no policy
    can list (``.invalid`` is reserved). True when that host would be refused,
    or when the policy cannot be read.
    """
    probe = "egress-probe.invalid"
    try:
        from ..enterprise import egress_permitted
        from ..tenant.egress import egress_allowed

        return not (egress_permitted(f"https://{probe}/") and egress_allowed(tool, probe))
    except Exception:  # noqa: BLE001 -- unreadable policy: treat as restricted
        return True


def aws_client(tool: str, service: str, *, resource: bool = False, config=None):
    """Build a boto3 client (or resource) only after its endpoint is allowed.

    botocore resolves credentials while it creates a client, and providers
    such as instance metadata, container credentials, STS assume-role and SSO
    make network requests. So the endpoint is decided first on a probe client
    given static placeholder keys (no credential provider runs and endpoint
    resolution is local), the policy is checked, and only then is the real
    client built with the normal credential chain.
    """
    import boto3

    kwargs = {
        "endpoint_url": os.environ.get("AWS_ENDPOINT_URL") or None,
        "region_name": os.environ.get("AWS_REGION") or None,
    }
    if config is not None:
        kwargs["config"] = config
    probe = boto3.client(service, aws_access_key_id="egress-probe",
                         aws_secret_access_key="egress-probe", **kwargs)
    require_sdk_egress(tool, probe.meta.endpoint_url)
    if resource:
        return boto3.resource(service, **kwargs)
    return boto3.client(service, **kwargs)


__all__ = ["aws_client", "egress_restricted", "require_sdk_egress", "sdk_egress_denial"]
