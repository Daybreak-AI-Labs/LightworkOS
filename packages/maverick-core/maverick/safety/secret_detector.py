"""Secret detection for tool outputs.

Scans text for common credentials and replaces matches with redacted
placeholders before they hit logs or model context. Fast regex pass
covering AWS / GCP / Azure / GitHub / Anthropic / OpenAI / generic
JWTs / generic high-entropy secrets.

This is not a replacement for a real DLP tool. It's a guardrail
against the most common accidental leaks (config files dumped to
shell, env-var prints, secrets in log lines). False positives are
preferable to false negatives — we err on the side of redaction.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SecretMatch:
    name: str
    span: tuple[int, int]
    value_preview: str


# Each entry: (name, regex). Most patterns match common formats; the
# generic-high-entropy fallback catches modern random tokens that don't
# match a specific provider format.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("anthropic_api_key",  re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b")),
    # Body allows `_` and `-`: real sk-proj- keys contain them, and a
    # `[a-zA-Z0-9]`-only body stopped at the first separator, detecting
    # (and thus redacting) only a prefix and leaking the rest of the key.
    ("openai_api_key",     re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}")),
    ("aws_access_key_id",  re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS secret access keys are 40-char base64-ish; matching naked
    # 40-char strings produces too many false positives (hashes, UUIDs
    # without dashes), so we require an obvious AWS context word
    # within ~50 chars.
    ("aws_secret_access",  re.compile(
        # Separator window widened from {1,5} to {1,16}: aligned/indented config
        # (`aws_secret_access_key      = KEY`, YAML/INI with padding) routinely
        # exceeds 5 separator chars, which silently left the 40-char key
        # unredacted. Still bounded (ReDoS-safe) and the charset is unchanged.
        r"(?i)(?:aws_secret_access_key|aws_secret)[\s=:\"']{1,16}"
        r"([A-Za-z0-9/+=]{40})"
    )),
    ("github_pat_classic", re.compile(r"\bghp_[A-Za-z0-9]{36,40}\b")),
    ("github_pat_fine",    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("github_oauth",       re.compile(r"\bgho_[A-Za-z0-9]{36,40}\b")),
    ("google_api_key",     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("gcp_service_account",re.compile(r'"type"\s*:\s*"service_account"')),
    ("azure_storage",      re.compile(r"\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}")),
    ("slack_bot_token",    re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b")),
    ("stripe_live_key",    re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("stripe_test_key",    re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")),
    # Lightwork-issued external-agent bearer credentials and signed flow
    # decision links are capabilities even though they do not resemble a
    # third-party API key or a three-segment JWT.
    ("lightwork_agent_token", re.compile(
        r"(?<![A-Za-z0-9_-])lw-(?:rest|mcp)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"
    )),
    ("lightwork_flow_approval_token", re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{16,}\.[0-9a-fA-F]{64}(?![0-9a-fA-F])"
    )),
    # JWTs: header.payload.signature, all base64url-without-padding.
    ("jwt",                re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    # Generic private key blocks. One pattern, one span: match the WHOLE block
    # (BEGIN..END, DOTALL, non-greedy) when an END marker is present so the
    # base64 key MATERIAL is redacted -- the prior marker-only pattern left the
    # actual private key body and END line in cleartext. Kept as a single
    # pattern (not two) because scan() dedupes only EXACT spans (it stays a
    # byte-for-byte mirror of the native port); a
    # separate marker pattern would overlap, and only redact() coalesces
    # overlaps, so an extra pattern would still bloat scan()'s detection list.
    ("private_key_pem",    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"(?:"
        # Preferred: the WHOLE block when an END marker is present. Bounded
        # body so many BEGIN markers with no END can't scan to EOF per marker
        # (ReDoS guard); the bound (64KB) covers real key formats -- an RSA-8192
        # PEM, an OPENSSH key, or a concatenated key bundle whose body+whitespace
        # exceeds 8192 chars would otherwise leave the trailing key material +
        # END line un-redacted (the leak got WORSE on the largest keys).
        r".{0,65536}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"|"
        # Fallback: a header WITH a body but NO END marker (a key truncated by
        # a buffer/summary boundary -- e.g. the audit writer's own truncation).
        # Making the whole END-group optional (the prior form) matched only the
        # 26-char header and left the base64 body in cleartext -- a real leak
        # through redact()/redact_proven()/the audit log. When END is absent,
        # consume the trailing base64+whitespace run wholesale (fail-safe: a
        # PRIVATE KEY header means err toward over-redaction; the restricted
        # charset and {0,65536} bound keep it linear / ReDoS-safe).
        r"[A-Za-z0-9+/=\s]{0,65536}"
        r")",
        re.DOTALL)),
    # Coverage gaps that fed the tool-output exfil class.
    ("gitlab_pat",         re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("twilio_api_key",     re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("slack_webhook",      re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    # Connection strings carrying inline creds (postgres/mysql/mongodb/redis).
    ("db_connection_uri",  re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^:@/\s]+:[^@/\s]+@[^\s]+"
    )),
    # Authorization: Bearer <token> headers (require a token-ish length to
    # avoid flagging the literal word "Bearer").
    # Bearer token charset includes +/= so base64 tokens are fully covered.
    ("bearer_header",      re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._\-+/=]{12,}")),
    # .env-style KEY=value lines whose name contains TOKEN/KEY/SECRET/
    # PASSWORD/PASS/CREDENTIAL. The module's docstring advertised "generic
    # high-entropy" coverage but no such rule existed, so a generically
    # named secret (INTERNAL_API_TOKEN=..., DB_PASSWORD=...) was written to
    # the audit log and fed back to the model in plaintext. Mirrors the
    # `env_secret` rule in maverick.secrets so both redactors agree. Only the
    # value (named group ``val``) is redacted, keeping the var name readable.
    ("env_secret",         re.compile(
        # Leading indentation is `[^\S\n]*` (horizontal whitespace), NOT `\s*`:
        # `\s` matches `\n`, and with re.MULTILINE the `(?:^|\n)` anchor fires
        # at every line start, so on a long newline run `\s*` backtracks O(N^2)
        # -- a ReDoS, since this scans attacker-influenced tool output. The
        # newline is already consumed by the `(?:^|\n)` anchor.
        r"(?:^|\n)[^\S\n]*(?:export\s+)?"
        # The name is read in one pass: a lookahead finds a keyword after its
        # first letter, then the whole run of capitals is taken at once. As
        # `[A-Z][A-Z0-9_]*(?:TOKEN|...)[A-Z0-9_]*` it backtracked across the
        # run once for every keyword in it -- a ReDoS (~12s on one 60KB line).
        # The name is always the whole run (what follows it, spacing or `:` or
        # `=`, is never part of one), so it matches the same text. The native
        # port keeps the plain form: its regex engine does not backtrack.
        r"(?=[A-Z][A-Z0-9_]*?(?:TOKEN|KEY|SECRET|PASSWORD|PASS|CREDENTIAL))[A-Z][A-Z0-9_]*+"
        # Separator `[:=]`, not just `=`: YAML / k8s manifests / many log lines
        # use `KEY: value`. Mirrors maverick.secrets.env_secret so the two
        # redactors actually agree (they were advertised as mirrors but this one
        # silently missed every colon-delimited secret).
        r"\s*[:=]\s*"
        # Value: a quoted string (single OR double) captured WHOLE, else an
        # unquoted run up to whitespace. The prior `[^\s\n]+` stopped at the
        # first space, so `API_TOKEN="my secret value"` redacted only `"my` and
        # leaked ` secret value"` to the audit log / model context.
        r"(?P<val>\"[^\"\n]*\"|'[^'\n]*'|[^\s\n]+)",
        re.MULTILINE,
    )),
]


def scan(text: str) -> list[SecretMatch]:
    """Return all secret matches found in ``text``."""
    if not text:
        return []
    # scan() must stay a byte-for-byte mirror of the native port
    # (maverick_native.secret_scan_spans) -- see test_native_detect_parity and
    # the module footer -- so it reports every pattern's raw span and dedupes
    # only EXACT duplicates. Overlap-coalescing belongs in redact() (the splice
    # site), not here, so detection still surfaces every secret type and the
    # native engine never diverges.
    matches: list[SecretMatch] = []
    seen_spans: set[tuple[int, int]] = set()
    for name, pat in _PATTERNS:
        for m in pat.finditer(text):
            # Patterns may redact only a value sub-group (named ``val``),
            # e.g. ``env_secret`` keeps the ``NAME=`` prefix visible.
            grp = "val" if "val" in m.re.groupindex else 0
            span = m.span(grp)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            raw = m.group(grp)
            preview = raw[:6] + "..." if len(raw) > 12 else "..."
            matches.append(SecretMatch(name=name, span=span, value_preview=preview))
    return matches


def redact(text: str) -> tuple[str, list[SecretMatch]]:
    """Return ``(redacted_text, matches)``. Each match is replaced with a
    placeholder of the form ``[REDACTED:<name>]``.

    Replacement preserves text length characteristics enough for log
    readability but never leaks the original value.
    """
    if not text:
        return text, []
    matches = scan(text)
    if not matches:
        return text, []
    # Coalesce overlapping spans into one redaction range per cluster before
    # splicing (mirrors pii_detector). Different patterns can match overlapping
    # (non-identical) regions; reverse-order splicing of overlapping spans
    # corrupts offsets and can leave secret material in cleartext. Redacting the
    # union of each overlap cluster guarantees no portion leaks. scan() itself
    # stays uncoalesced so it (and the native port) report every detected
    # secret; the returned ``matches`` are likewise the raw detections.
    ordered = sorted(matches, key=lambda x: (x.span[0], -(x.span[1] - x.span[0])))
    clusters: list[tuple[int, int, str]] = []
    for m in ordered:
        a, b = m.span
        if clusters and a < clusters[-1][1]:
            pa, pb, pname = clusters[-1]
            clusters[-1] = (pa, max(pb, b), pname)
        else:
            clusters.append((a, b, m.name))
    # Replace from end to start so spans stay valid.
    out = text
    for a, b, name in sorted(clusters, key=lambda c: c[0], reverse=True):
        out = out[:a] + f"[REDACTED:{name}]" + out[b:]
    return out, matches


def redact_iter(items: Iterable[str]) -> list[tuple[str, list[SecretMatch]]]:
    """Apply :func:`redact` to each item; collect all matches."""
    return [redact(t) for t in items]


# NOTE on the native engine: rust/mvk-scan ships a byte-for-byte port of this
# scanner (maverick_native.secret_scan_spans), but it is NOT wired into this
# Python hot path. CPython's `re` is compiled C, and the 21-pattern sweep
# measured ~3x FASTER in pure Python than the native port (21 separate
# fancy-regex passes); see rust/README.md. The native build exists for the
# TypeScript / edge runtimes (Workers, Deno, browser) that have no `re`, and
# tests/test_native_detect_parity.py keeps it byte-for-byte identical to this
# module so the two never diverge.
