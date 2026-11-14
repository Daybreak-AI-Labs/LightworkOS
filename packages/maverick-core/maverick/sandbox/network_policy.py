"""Per-tool network egress policy (allow/deny hosts).

Declarative egress control so a tool can be restricted to a set of hosts:

    [sandbox.tool.http_fetch]
    allow_egress = ["api.github.com", "*.openai.com"]

    [sandbox.tool.shell]
    deny_egress = ["*"]

``host_allowed(tool, host, policy)`` is the pure decision (fnmatch globs; deny
wins over allow; empty/absent policy = allow-all, preserving current behavior).
This module is the *policy layer*. Enforcement today is application-layer: the
built-in HTTP tools/connectors and ``tenant.egress`` consult this decision
before dialing a host. There is NO packet-level (iptables/nftables) firewall
backend yet, so a tool that bypasses the HTTP layer (e.g. raw shell) is not
constrained by this policy. The decision is unit-tested in isolation.

**Network posture** (``[security] network_policy``, Settings > All settings):
``"open"`` (the default, and what an unset key means), ``"allowlist"`` or
``"deny-all"``. It is enforced, never just displayed, and only ever narrows
what the rules above allow:

* ``deny-all`` -- the web tools (:data:`WEB_TOOLS`) are removed from every
  agent's tool list, and the work area gets no network (see
  :func:`work_area_offline`).
* ``allowlist`` -- web requests reach only hosts on an approved list (a tool's
  ``allow_egress`` or ``[egress] allow``; with no list nothing is approved),
  the web tools that cannot be held to a list (:data:`UNLISTABLE_TOOLS`) are
  removed, and the work area gets no network.
* A value this module does not know fails closed to ``deny-all``.

``[sandbox] network_policy = "deny-all"`` asserts the same no-network rule for
the work area alone (the Kubernetes backend then verifies its deny-all
NetworkPolicy before every command); a value it does not know does too.
"""
from __future__ import annotations

import logging
from fnmatch import fnmatch

log = logging.getLogger(__name__)

# Tools whose purpose is reaching arbitrary internet hosts.
WEB_TOOLS = frozenset({"http_fetch", "web_search", "browser", "websocket", "webrtc"})
# Web tools that talk to services chosen by the tool, not to a host the
# request names, so an approved-host list cannot hold them.
UNLISTABLE_TOOLS = frozenset({"web_search", "webrtc"})
_DENY_ALL = frozenset({"deny-all", "deny_all", "deny", "blocked", "none-allowed"})
_ALLOWLIST = frozenset({"allowlist", "allow-list", "allow_list"})
_OPEN = frozenset({"", "open", "allow", "allow-all", "allow_all"})


def _config(config: dict | None) -> dict:
    if config is not None:
        return config
    try:
        from ..config import config_source_errors, load_config
        cfg = load_config() or {}
        # load_config() returns defaults for a config file it cannot parse, so
        # the posture the operator wrote may be lost: block rather than open.
        if config_source_errors(include_tenant=True):
            log.warning("configuration is unreadable; blocking network access")
            return {"security": {"network_policy": "?"}}
        return cfg
    except Exception:  # an unreadable config fails closed below
        return {"security": {"network_policy": "?"}}


def _setting(section: object, key: str) -> str:
    """The raw text of ``key``; a non-string value (``false``, ``0``) reads as unknown."""
    if not isinstance(section, dict):
        return "?"
    value = section.get(key)
    if value is None:
        return ""
    return value if isinstance(value, str) else "?"


def network_posture(config: dict | None = None) -> str:
    """``"open"``, ``"allowlist"`` or ``"deny-all"`` from ``[security] network_policy``."""
    raw = _setting(_config(config).get("security") or {}, "network_policy")
    value = raw.strip().lower()
    if value in _OPEN:
        return "open"
    if value in _ALLOWLIST:
        return "allowlist"
    if value not in _DENY_ALL:
        log.warning("unknown [security] network_policy %r; blocking network access", raw)
    return "deny-all"


def denied_tools(config: dict | None = None) -> frozenset[str]:
    """The web tools the network posture removes from agents' tool lists."""
    posture = network_posture(config)
    if posture == "deny-all":
        return WEB_TOOLS
    if posture == "allowlist":
        return UNLISTABLE_TOOLS
    return frozenset()


def work_area_offline(config: dict | None = None) -> bool:
    """Whether the work area must have no network (posture or ``[sandbox] network_policy``)."""
    cfg = _config(config)
    if network_posture(cfg) != "open":
        return True
    raw = _setting(cfg.get("sandbox") or {}, "network_policy")
    value = raw.strip().lower()
    if value in _OPEN:
        return False
    if value not in _DENY_ALL:
        log.warning("unknown [sandbox] network_policy %r; keeping commands offline", raw)
    return True


def load_policy() -> dict:
    """Read ``[sandbox.tool.<name>]`` egress tables from config (or empty)."""
    try:
        from ..config import load_config
        sb = (load_config() or {}).get("sandbox", {}) or {}
        return sb.get("tool", {}) or {}
    except Exception:  # pragma: no cover -- config never blocks the sandbox
        return {}


def _canonical_dns_name(name: str) -> str:
    """Return a DNS name in policy-comparison form.

    DNS names may be written with a final root-label dot (for example,
    ``example.com.``), but that is equivalent to ``example.com`` for lookup
    purposes.  Canonicalize both request hosts and policy patterns so deny
    rules cannot be bypassed with the fully-qualified spelling.
    """
    value = (name or "").strip().lower()
    value = value.removesuffix(".")
    labels = []
    for label in value.split("."):
        if any(ch in label for ch in "*?["):
            labels.append(label)
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def _matches(host: str, patterns) -> bool:
    # A hand-edited config may give a bare string (``deny_egress = "*"``) instead
    # of a list. Iterating a string yields its characters, so a string deny rule
    # would silently never match -- a fail-OPEN on the security-critical deny
    # path. Treat a lone string as a single-pattern list.
    if isinstance(patterns, str):
        patterns = [patterns]
    h = _canonical_dns_name(host)
    return any(fnmatch(h, _canonical_dns_name(str(p))) for p in (patterns or []))


def host_allowed(tool: str, host: str, policy: dict | None = None) -> bool:
    """True iff ``tool`` may reach ``host`` under ``policy``.

    Rules (deny wins): an explicit ``deny_egress`` match blocks; otherwise, if
    ``allow_egress`` is set, the host must match it; with no policy for the tool,
    egress is allowed (unchanged default behavior).
    """
    pol = policy if policy is not None else load_policy()
    rule = (pol or {}).get(tool) or {}
    if not isinstance(rule, dict):
        # ``shell = "deny"`` instead of a table: the intent is unknown, so deny.
        log.warning("malformed [sandbox.tool.%s] egress rule; blocking egress", tool)
        return False
    if _matches(host, rule.get("deny_egress")):
        return False
    allow = rule.get("allow_egress")
    if allow:  # non-empty allow-list -> host must be on it
        return _matches(host, allow)
    return True


def describe(tool: str, policy: dict | None = None) -> str:
    """Human summary of a tool's egress rule."""
    pol = policy if policy is not None else load_policy()
    rule = (pol or {}).get(tool) or {}
    if not rule:
        return f"{tool}: egress unrestricted"
    if not isinstance(rule, dict):
        return f"{tool}: malformed rule, egress blocked"
    parts = []
    if rule.get("allow_egress"):
        parts.append(f"allow={list(rule['allow_egress'])}")
    if rule.get("deny_egress"):
        parts.append(f"deny={list(rule['deny_egress'])}")
    return f"{tool}: " + (", ".join(parts) or "unrestricted")


__all__ = ["UNLISTABLE_TOOLS", "WEB_TOOLS", "denied_tools", "describe", "host_allowed",
           "load_policy", "network_posture", "work_area_offline"]
