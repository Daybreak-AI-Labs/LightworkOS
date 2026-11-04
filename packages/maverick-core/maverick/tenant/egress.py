"""Per-tenant egress policy plane.

:mod:`maverick.sandbox.network_policy` restricts egress **per tool**. This adds a
plane **per tenant** that applies to *every* tool a tenant's agents run, so one
tenant can't reach another tenant's resources or a cloud metadata endpoint
regardless of which tool makes the call. The two compose with **AND**: a host is
reachable only if it passes *both* the tenant plane and the per-tool policy.

Config:

    [egress]                       # default plane (all tenants without an override)
    deny  = ["169.254.169.254"]    # block cloud metadata for everyone
    allow = []                     # empty = allow-all (after deny)

    [tenancy.egress.acme]          # per-tenant override (wins over [egress])
    allow = ["api.acme.com", "*.acme-internal.net"]
    deny  = ["*"]

Resolution: ``[tenancy.egress.<tenant>]`` if present, else ``[egress]``, else
empty (allow-all — unchanged default). ``host_allowed`` is the pure decision
(deny wins; non-empty allow restricts), unit-tested in isolation.
"""
from __future__ import annotations

from ..sandbox.network_policy import _matches
from ..sandbox.network_policy import host_allowed as _tool_host_allowed


def _resolve_tenant(tenant: str | None) -> str | None:
    if tenant == "__active__":
        from ..paths import current_tenant_id
        return current_tenant_id()
    return tenant


def load_tenant_egress(tenant: str | None = "__active__") -> dict:
    """The egress plane for ``tenant``: the per-tenant override or the default."""
    try:
        from ..config import load_config
        cfg = load_config() or {}
    except Exception:  # pragma: no cover -- config never blocks egress
        return {}
    tid = _resolve_tenant(tenant)
    if tid:
        per = ((cfg.get("tenancy", {}) or {}).get("egress", {}) or {}).get(tid)
        if isinstance(per, dict):
            return per
    default = cfg.get("egress", {}) or {}
    return default if isinstance(default, dict) else {}


def host_allowed(host: str, *, tenant: str | None = "__active__", policy: dict | None = None) -> bool:
    """True iff the tenant plane permits egress to ``host``.

    Deny wins; a non-empty ``allow`` list restricts to it; no policy = allow-all.
    """
    pol = policy if policy is not None else load_tenant_egress(tenant)
    if not isinstance(pol, dict):
        return True
    if _matches(host, pol.get("deny")):
        return False
    allow = pol.get("allow")
    if allow:
        return _matches(host, allow)
    return True


def egress_allowed(tool: str, host: str, *, tenant: str | None = "__active__") -> bool:
    """Compose the per-tenant plane AND the per-tool policy: ``host`` is reachable
    by ``tool`` only if both layers allow it -- and the network posture
    (``[security] network_policy``) permits it: ``deny-all`` refuses every
    host, ``allowlist`` only hosts on an approved list."""
    from ..sandbox.network_policy import load_policy, network_posture

    posture = network_posture()
    if posture == "deny-all":
        return False
    if posture == "allowlist":
        rule = (load_policy() or {}).get(tool) or {}
        tool_list = rule.get("allow_egress") if isinstance(rule, dict) else None
        tenant_list = (load_tenant_egress(tenant) or {}).get("allow")
        if not (tool_list and _matches(host, tool_list)) and not (
                tenant_list and _matches(host, tenant_list)):
            return False
    return host_allowed(host, tenant=tenant) and _tool_host_allowed(tool, host)


def describe(tenant: str | None = "__active__") -> str:
    """Human summary of the tenant's egress plane."""
    pol = load_tenant_egress(tenant)
    if not pol:
        return "tenant egress: unrestricted"
    parts = []
    if pol.get("allow"):
        parts.append(f"allow={list(pol['allow'])}")
    if pol.get("deny"):
        parts.append(f"deny={list(pol['deny'])}")
    return "tenant egress: " + (", ".join(parts) or "unrestricted")


__all__ = ["load_tenant_egress", "host_allowed", "egress_allowed", "describe"]
