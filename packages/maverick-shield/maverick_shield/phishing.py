"""Phishing-content detector: heuristic scan for credential-harvesting content.

A dependency-free detector for content that exhibits phishing patterns — whether
in a page the agent fetched (so it isn't tricked) or in output the agent is about
to emit (so it can't be turned into a phishing vector). Heuristics, scored and
summed:

  * credential-request language ("verify your account", "confirm your password")
  * urgency / threat ("account suspended", "within 24 hours", "act now")
  * link/display mismatch — a markdown/HTML link whose visible text names one
    domain but points at another
  * deceptive hosts — raw-IP URLs, ``@`` in the authority, punycode (``xn--``),
    and brand-lookalikes (``paypa1``, ``g00gle``, ``micros0ft``)

The score maps to a severity ("none"/"low"/"medium"/"high"). Pure and
unit-tested; ``Shield.scan_output`` wires it in fail-open so a detector bug can
never block the agent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_CRED_PHRASES = [
    r"verify your (?:account|identity|email|password)",
    r"confirm your (?:account|identity|password|payment|billing)",
    r"update your (?:billing|payment|account|password) (?:info|information|details)",
    r"enter your (?:password|pin|credentials|card number|ssn)",
    r"re-?enter your password",
    r"validate your (?:account|login)",
    r"sign in to (?:continue|avoid|restore)",
    r"unlock your account",
]
_URGENCY_PHRASES = [
    r"account (?:has been |will be )?(?:suspended|locked|disabled|terminated)",
    r"within \d+\s*(?:hours?|minutes?|days?)",
    r"act (?:now|immediately|fast)",
    r"urgent(?:ly)?\b",
    r"immediate action (?:is )?required",
    r"failure to (?:do so|comply|respond)",
    r"your account will be (?:closed|deleted|terminated)",
]
_BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "netflix",
           "facebook", "instagram", "bank", "wellsfargo", "chase", "coinbase"]

_CRED_RE = [re.compile(p, re.IGNORECASE) for p in _CRED_PHRASES]
_URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in _URGENCY_PHRASES]
# [visible text](url)  and  <a href="url">text</a>
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)", re.IGNORECASE)
_HTML_LINK_RE = re.compile(
    r"""<a[^>]+href=["'](https?://[^"']+)["'][^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL)
_URL_RE = re.compile(r"https?://[^\s)\"'<>]+", re.IGNORECASE)
_DOMAIN_IN_TEXT_RE = re.compile(r"\b([a-z0-9-]+\.(?:com|net|org|io|gov|co))\b",
                                re.IGNORECASE)

_SEVERITY = [(8, "high"), (5, "medium"), (3, "low")]


@dataclass
class PhishingVerdict:
    suspicious: bool
    score: int
    severity: str           # "none" | "low" | "medium" | "high"
    reasons: list[str] = field(default_factory=list)


def _host(url: str) -> str:
    m = re.match(r"https?://([^/?#]+)", url, re.IGNORECASE)
    if not m:
        return ""
    authority = m.group(1)
    # Strip any userinfo (the part before @) — keep it for the deceptive check.
    host = authority.split("@")[-1]
    return host.split(":")[0].lower()


def _registrable(host: str) -> str:
    """Crude eTLD+1: last two labels (good enough for lookalike comparison)."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _lookalike(host: str) -> bool:
    h = host.lower()
    if "xn--" in h:
        return True
    for brand in _BRANDS:
        if brand in h:
            continue  # genuine brand substring isn't itself a lookalike here
        # digit-for-letter substitutions of a brand (paypa1, g00gle, micros0ft)
        deleeted = (h.replace("0", "o").replace("1", "l")
                    .replace("3", "e").replace("5", "s").replace("$", "s"))
        if brand in deleeted and brand not in h:
            return True
    return False


def detect_phishing(text: str) -> PhishingVerdict:
    """Score ``text`` for phishing indicators and return a verdict."""
    if not isinstance(text, str) or not text.strip():
        return PhishingVerdict(False, 0, "none", [])
    score = 0
    reasons: list[str] = []

    cred_hits = [r.pattern for r in _CRED_RE if r.search(text)]
    if cred_hits:
        score += 3 + min(2, len(cred_hits) - 1)
        reasons.append(f"credential-request language ({len(cred_hits)} phrase(s))")

    urgency_hits = [r.pattern for r in _URGENCY_RE if r.search(text)]
    if urgency_hits:
        score += 2 + min(2, len(urgency_hits) - 1)
        reasons.append(f"urgency/threat language ({len(urgency_hits)} phrase(s))")

    # Link/display mismatch + deceptive hosts.
    links: list[tuple[str, str]] = []  # (visible_text, url)
    links += [(t, u) for t, u in _MD_LINK_RE.findall(text)]
    links += [(t, u) for u, t in _HTML_LINK_RE.findall(text)]
    mismatch = False
    for visible, url in links:
        host = _host(url)
        if not host:
            continue
        named = _DOMAIN_IN_TEXT_RE.search(visible or "")
        if named and _registrable(named.group(1).lower()) != _registrable(host):
            mismatch = True
    if mismatch:
        score += 4
        reasons.append("link text names a different domain than its target")

    deceptive: list[str] = []
    for url in _URL_RE.findall(text):
        authority = re.match(r"https?://([^/?#]+)", url, re.IGNORECASE)
        auth = authority.group(1) if authority else ""
        host = _host(url)
        if "@" in auth:
            deceptive.append("userinfo '@' in URL authority")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            deceptive.append("raw-IP URL")
        elif _lookalike(host):
            deceptive.append(f"brand-lookalike host {host!r}")
    if deceptive:
        score += 3 + min(3, len(deceptive) - 1)
        # de-dup reasons while preserving order
        uniq = list(dict.fromkeys(deceptive))
        reasons.append("deceptive URL(s): " + ", ".join(uniq[:3]))

    severity = "none"
    for threshold, label in _SEVERITY:
        if score >= threshold:
            severity = label
            break
    return PhishingVerdict(
        suspicious=score >= 3, score=score, severity=severity, reasons=reasons)


__all__ = ["PhishingVerdict", "detect_phishing"]
