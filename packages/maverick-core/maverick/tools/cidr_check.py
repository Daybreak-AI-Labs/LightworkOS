"""IP access-control (CIDR) evaluator.

Decides whether an IP address is permitted under an ordered list of CIDR rules,
firewall-style: the **first matching rule wins**, falling back to a configurable
default. Handles IPv4 and IPv6 (a rule only matches an address of its own
family). Pure stdlib ``ipaddress`` — deterministic and offline. Distinct from
``geofence`` (region codes) and ``dns_lookup`` (network).

ops:
  - check(ip, rules, [default])  — ``rules`` is an ordered list of
    ``{cidr, action}`` (action ``allow``/``deny``); ``default`` (``deny``) applies
    when nothing matches. Reports ALLOW/DENY with the deciding rule.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from . import Tool


def _check(ip_obj, rules: list, default: str) -> str:
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict) or "cidr" not in rule or "action" not in rule:
            return f"ERROR: rule {i} needs 'cidr' and 'action'"
        action = str(rule["action"]).lower()
        if action not in ("allow", "deny"):
            return f"ERROR: rule {i} action must be 'allow' or 'deny'"
        try:
            net = ipaddress.ip_network(str(rule["cidr"]), strict=False)
        except ValueError:
            return f"ERROR: rule {i} cidr is not valid: {rule['cidr']!r}"
        if net.version == ip_obj.version and ip_obj in net:
            verdict = "ALLOW" if action == "allow" else "DENY"
            return f"{verdict}: {ip_obj} matched rule {i} ({net} {action})"
    return f"{default.upper()}: {ip_obj} matched no rule (default {default})"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    ip = args.get("ip")
    if not isinstance(ip, str) or not ip:
        return "ERROR: ip must be a non-empty string"
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return f"ERROR: ip is not a valid address: {ip!r}"
    rules = args.get("rules")
    if not isinstance(rules, list):
        return "ERROR: rules must be an array of {cidr, action}"
    default = str(args.get("default", "deny")).lower()
    if default not in ("allow", "deny"):
        return "ERROR: default must be 'allow' or 'deny'"
    return _check(ip_obj, rules, default)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "ip": {"type": "string", "description": "the IPv4/IPv6 address to evaluate"},
        "rules": {
            "type": "array",
            "description": "ordered CIDR rules; first match wins",
            "items": {
                "type": "object",
                "properties": {
                    "cidr": {"type": "string"},
                    "action": {"type": "string", "enum": ["allow", "deny"]},
                },
                "required": ["cidr", "action"],
            },
        },
        "default": {"type": "string", "enum": ["allow", "deny"], "description": "verdict when no rule matches (default deny)"},
    },
    "required": ["ip", "rules"],
}


def cidr_check() -> Tool:
    return Tool(
        name="cidr_check",
        description=(
            "Evaluate an IP against an ordered CIDR access-control list "
            "(firewall-style, first match wins). op=check with 'ip', 'rules' "
            "([{cidr, action: allow|deny}]), and optional 'default' (deny). "
            "IPv4/IPv6 aware. Reports ALLOW/DENY with the deciding rule. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
