"""DNS lookup tool.

Resolves A / AAAA / MX / TXT / CNAME / NS records via the
``dnspython`` library when available, falling back to the
standard ``socket`` module for A/AAAA only.

ops:
  - resolve(host, type)        — type ∈ {A, AAAA, MX, TXT, CNAME, NS}
  - reverse(ip)                — PTR lookup

Use cases the agent might hit:
  - "is this domain pointing where I expect?"
  - "what's the SPF for example.com?"
  - "does this IP have a reverse?"
"""
from __future__ import annotations

import logging
import socket
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_DNS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["resolve", "reverse"]},
        "host": {"type": "string"},
        "ip": {"type": "string"},
        "type": {
            "type": "string",
            "enum": ["A", "AAAA", "MX", "TXT", "CNAME", "NS"],
        },
    },
    "required": ["op"],
}


def _have_dnspython() -> bool:
    try:
        import dns.resolver  # noqa: F401
        return True
    except ImportError:
        return False


def _resolve_via_dnspython(host: str, rtype: str) -> str:
    import dns.resolver
    try:
        answers = dns.resolver.resolve(host, rtype, lifetime=10.0)
    except dns.resolver.NXDOMAIN:
        return f"NXDOMAIN: {host}"
    except dns.resolver.NoAnswer:
        return f"no {rtype} record for {host}"
    except dns.resolver.NoNameservers as e:
        return f"ERROR: no nameservers: {e}"
    except Exception as e:
        return f"ERROR: resolve {type(e).__name__}: {e}"
    rows: list[str] = []
    for rdata in answers:
        if rtype == "MX":
            rows.append(f"  {rdata.preference:>4}  {rdata.exchange}")
        elif rtype == "TXT":
            rows.append(f"  {b''.join(rdata.strings).decode(errors='replace')}")
        else:
            rows.append(f"  {rdata.to_text()}")
    return "\n".join(rows) if rows else f"empty answer for {host} {rtype}"


def _resolve_via_socket(host: str, rtype: str) -> str:
    if rtype not in ("A", "AAAA"):
        return (
            f"ERROR: socket fallback only supports A/AAAA "
            f"(asked {rtype}). Install dnspython: "
            "pip install dnspython"
        )
    family = socket.AF_INET if rtype == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(host, None, family=family,
                                   type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return f"ERROR: getaddrinfo: {e}"
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        out.append(f"  {addr}")
    return "\n".join(out) if out else f"no {rtype} for {host}"


def _op_resolve(host: str, rtype: str) -> str:
    if not host:
        return "ERROR: resolve requires host"
    rtype = rtype.upper()
    if _have_dnspython():
        return _resolve_via_dnspython(host, rtype)
    return _resolve_via_socket(host, rtype)


def _op_reverse(ip: str) -> str:
    if not ip:
        return "ERROR: reverse requires ip"
    if _have_dnspython():
        import dns.resolver
        import dns.reversename
        try:
            name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(name, "PTR", lifetime=10.0)
            return "\n".join(f"  {r.to_text()}" for r in answers)
        except dns.resolver.NXDOMAIN:
            return f"no reverse DNS for {ip}"
        except Exception as e:
            return f"ERROR: reverse {type(e).__name__}: {e}"
    # socket fallback
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host
    except socket.herror as e:
        return f"ERROR: gethostbyaddr: {e}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        if op == "resolve":
            return _op_resolve(
                (args.get("host") or "").strip(),
                (args.get("type") or "A").strip(),
            )
        if op == "reverse":
            return _op_reverse((args.get("ip") or "").strip())
    except Exception as e:
        return f"ERROR: dns_lookup failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def dns_lookup() -> Tool:
    return Tool(
        name="dns_lookup",
        description=(
            "DNS resolver. ops: resolve (host + type ∈ A/AAAA/MX/"
            "TXT/CNAME/NS), reverse (ip -> PTR). Uses dnspython "
            "when installed; falls back to socket (A/AAAA only)."
        ),
        input_schema=_DNS_SCHEMA,
        fn=_run,
    )
