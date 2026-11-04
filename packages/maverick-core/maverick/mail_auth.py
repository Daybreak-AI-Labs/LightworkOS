"""Admission check for mail that can start work in Lightwork.

IMAP supplies message headers, not an authenticated sender identity. Only a
receiving server that removes untrusted Authentication-Results headers and
prepends its own result can provide the trust boundary used here. A matching
DMARC result from that server is required before the From address may be used
for an allowlist or an automation event.
"""
from __future__ import annotations

import re
from email.utils import getaddresses

_SERVER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]")
_DMARC = re.compile(r"^\s*dmarc\s*=\s*([^\s;]+)", re.IGNORECASE)
_DMARC_NAME = re.compile(r"^\s*dmarc\s*=", re.IGNORECASE)
_HEADER_FROM_NAME = re.compile(r"(?:^|\s)header\.from\s*=", re.IGNORECASE)
_HEADER_FROM = re.compile(r"(?:^|\s)header\.from\s*=\s*([A-Za-z0-9.-]+)(?=\s|$)", re.IGNORECASE)


def _result_clauses(value: str) -> list[str] | None:
    """Remove comments and quoted text before interpreting result clauses."""
    if len(value) > 16_384:
        return None
    value = re.sub(r"\r?\n[ \t]+", " ", value)
    out = []
    depth = 0
    quoted = False
    escaped = False
    for char in value:
        if ord(char) < 32 and char != "\t" or ord(char) == 127:
            return None
        if escaped:
            escaped = False
            out.append("~" if quoted else " ")
        elif (depth or quoted) and char == "\\":
            escaped = True
            out.append(" ")
        elif depth:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            out.append(" ")
        elif quoted:
            if char == '"':
                quoted = False
            out.append("~")
        elif char == "(":
            depth = 1
            out.append(" ")
        elif char == '"':
            quoted = True
            out.append("~")
        elif char == ")":
            return None
        else:
            out.append(char)
    if depth or quoted or escaped:
        return None
    return "".join(out).split(";")


def valid_trusted_mail_server(value: object) -> bool:
    """The administrator must identify the server that stamps mail results."""
    text = str(value or "").strip()
    return bool(_SERVER_ID.fullmatch(text) and ".." not in text)


def authenticated_from(message, trusted_server: str) -> str:
    """Return the single authenticated From address, or an empty string.

    Trust only the topmost result and only when its exact server identity was
    configured by an administrator. SPF/DKIM on their own can pass for an
    unrelated domain; the receiving server's DMARC result binds them to From.
    """
    if not valid_trusted_mail_server(trusted_server):
        return ""
    from_headers = message.get_all("From") or []
    if len(from_headers) != 1:
        return ""
    addresses = getaddresses(from_headers)
    if len(addresses) != 1:
        return ""
    address = addresses[0][1].strip()
    if address.count("@") != 1:
        return ""
    domain = address.rsplit("@", 1)[1].lower().rstrip(".")
    if not domain:
        return ""
    results = message.get_all("Authentication-Results") or []
    if not results:
        return ""
    clauses = _result_clauses(str(results[0]))
    if not clauses or not re.fullmatch(
        re.escape(trusted_server.strip()) + r"(?:\s+\d+)?\s*", clauses[0].strip(), re.IGNORECASE,
    ):
        return ""
    dmarc_results = []
    for clause in clauses[1:]:
        result = _DMARC.match(clause)
        if not result:
            if _DMARC_NAME.match(clause):
                return ""
            continue
        names = _HEADER_FROM_NAME.findall(clause)
        reported = _HEADER_FROM.findall(clause)
        dmarc_results.append((result.group(1).lower(), names, reported))
    if len(dmarc_results) == 1:
        result, names, reported = dmarc_results[0]
        if result == "pass" and len(names) == len(reported) == 1 and reported[0].lower().rstrip(".") == domain:
            return address
    return ""
