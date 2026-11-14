"""Secret scrubber for logs + error messages.

LLM exceptions, MCP stderr drains, and `subprocess.run` stdout can contain
API keys / bearer tokens / .env values, so they must not be logged verbatim.
This module gives a single ``scrub(text)`` that pattern-matches the common shapes and
redacts them to ``[REDACTED:<kind>]``.

The patterns aren't exhaustive (a determined exfiltrator can wrap
secrets in something unusual), but they cover what people accidentally
paste into goal descriptions, what shell tools echo by mistake, and
what LLM error payloads tend to include.
"""
from __future__ import annotations

import re

# Each entry: (kind, regex). Order matters -- longer / more specific
# patterns run first so they don't get partially matched by generic ones.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # PEM private-key block (RSA / EC / OPENSSH / generic). Redact the whole
    # block -- runs first so its base64 body isn't partially matched by the
    # key/jwt patterns below.
    ("private_key", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
        r"(?:"
        # Preferred: the whole block when an END marker is present. Bounded
        # body ({0,65536}) so many BEGIN markers with no END can't scan to EOF
        # per marker (ReDoS guard); the 64KB bound covers real key formats so a
        # key whose body exceeds 8192 chars does not leak its trailing
        # material + END line (the same bound as secret_detector).
        r".{0,65536}?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
        r"|"
        # Fallback: a BEGIN header + base64 body but NO END marker (a key
        # truncated by a buffer/summary boundary). Without this the pattern
        # required END and leaked the truncated key body to logs / support
        # bundles. Mirrors safety.secret_detector.private_key_pem.
        r"[A-Za-z0-9+/=\s]{0,65536}"
        r")",
        re.DOTALL,
    )),
    # Credentials embedded in a URL / connection string
    # (scheme://user:password@host -- postgres://, redis://, mongodb://, ...).
    # Redacts only the password segment, keeping the rest readable. The user
    # may be empty (redis://:password@host), and the password runs to the last
    # "@" before the host, so a password containing "@" is redacted whole.
    # The scheme run is bounded ({0,31}) instead of an open `*`: an
    # unbounded greedy class followed by the required `://` backtracks
    # quadratically on a long run of scheme-class chars that has no `://`
    # (a ReDoS -- scrub() runs on tool output / LLM error payloads, so a
    # crafted long string could hang the agent). No real URL scheme is
    # anywhere near 32 chars, so the bound changes no legitimate match.
    ("url_credentials", re.compile(
        r"([a-zA-Z][a-zA-Z0-9+.\-]{0,31}://[^\s:/@]*:)([^\s/]+)(@)",
    )),
    # Anthropic API key (sk-ant-...)
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    # Stripe secret/restricted key (sk_live_, sk_test_, rk_live_, rk_test_).
    # Underscore-delimited, so the openai `sk-` pattern never matches it.
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    # OpenAI / OpenRouter key (sk-...)
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    # Google / GCP API key (AIza...)
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # AWS access key id
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS SECRET access key. The env_secret pattern below only matches an
    # UPPERCASE key name, but the canonical ~/.aws/credentials file (and boto /
    # aws-cli output) uses the lowercase `aws_secret_access_key`, so the actual
    # 40-char secret -- the sensitive half -- leaked verbatim while only the
    # harmless AKIA id above got redacted. Match the lowercase key explicitly;
    # the value is exactly 40 base64 chars. Group 1 (key + separator + optional
    # quote) is preserved.
    ("aws_secret_key", re.compile(
        r"(?i)(aws_secret_access_key\s*[:=]\s*['\"]?)([A-Za-z0-9/+]{40})",
    )),
    # GitHub PAT (ghp_/gho_/ghu_/ghr_/ghs_ prefix, and fine-grained github_pat_)
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b|\bgh[ps]_[A-Za-z0-9_]{30,}\b|\bghu_[A-Za-z0-9_]{30,}\b|\bgho_[A-Za-z0-9_]{30,}\b|\bghr_[A-Za-z0-9_]{30,}\b")),
    # Lightwork personal / service-account API key (lwk_...; see
    # maverick_dashboard.api_keys). Only the configured default prefix is
    # recognised here; a custom prefix must be added to this list too.
    ("lightwork_api_key", re.compile(r"\blwk_[A-Za-z0-9_-]{20,}\b")),
    # Slack tokens (xoxb-, xoxp-, xapp-)
    ("slack_token", re.compile(r"\bxox[bpaors]-[A-Za-z0-9-]{10,}\b")),
    # Authorization header (Bearer ... or Basic <base64 user:password>)
    ("bearer", re.compile(
        r"(?i)\b(authorization\s*:\s*(?:bearer\s+(?=[A-Za-z0-9._\-+/=]{16})|basic\s+))"
        r"([A-Za-z0-9._\-+/=]+)")),
    # .env-style KEY=value lines (only the value part; only redact when key
    # contains TOKEN / KEY / SECRET / PASSWORD / PASS / CREDENTIAL). Tolerates
    # a leading `export ` so shell-style `export FOO_TOKEN=...` is covered too.
    ("env_secret", re.compile(
        # Leading indentation is `[^\S\n]*` (horizontal whitespace), NOT `\s*`:
        # `\s` includes `\n`, and with re.MULTILINE the `(?:^|\n)` anchor fires
        # at every line start, so on a long run of newlines `\s*` backtracks
        # O(N^2) -- a ReDoS, since scrub() runs on attacker-influenced output.
        # The newline itself is already handled by the `(?:^|\n)` anchor.
        # Separator is `[:=]`, not just `=`: YAML / k8s manifests / many log
        # formats use `KEY: value`, and those colon-delimited secrets slipped
        # through unredacted. The key class stays UPPERCASE so ordinary lowercase
        # prose isn't over-redacted. The name is read in one pass, as in
        # secret_detector's env_secret (the form that backtracked across a
        # run of capitals once per keyword in it was a ReDoS).
        r"((?:^|\n)[^\S\n]*(?:export\s+)?"
        r"(?=[A-Z][A-Z0-9_]*?(?:TOKEN|KEY|SECRET|PASSWORD|PASS|CREDENTIAL))[A-Z][A-Z0-9_]*+\s*[:=]\s*)"
        # Value: a single- or double-quoted string (which may contain
        # spaces) OR a bare run of non-space chars. Without the quoted
        # alternatives a value like FOO_SECRET="a b c" matched only "a,
        # leaving `b c"` -- the real secret -- unredacted.
        r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s\n]+)",
        re.MULTILINE,
    )),
    # JWT (three base64url segments separated by dots, common shape)
    # Group 1 is the run of token characters before it: only the first "eyJ"
    # in a run is tried, as in secret_detector's jwt (trying each one after a
    # "-" rescanned the rest of the run every time, a ReDoS).
    ("jwt", re.compile(
        r"((?<![A-Za-z0-9_-])(?>[A-Za-z0-9_-]*?(?=\beyJ)))"
        r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)"
    )),
    # Credential carried in a URL query string (?access_token=..., &api_key=...,
    # presigned-URL ?sig=..., webhook ?token=...). The env_secret pattern only
    # matches uppercase KEY=value at line start, so these slipped through into
    # logs / audit / replay exports verbatim. Group 1 keeps the "?key=" prefix.
    ("url_secret", re.compile(
        r"(?i)([?&](?:access_token|api_key|apikey|auth_token|token|secret|"
        r"password|passwd|sig|signature|client_secret)=)([^&#\s\"']+)",
    )),
    # Lowercase or quoted key/value pairs (password=..., api_key: ...,
    # {"api_key": "..."}) that the uppercase env_secret pattern misses. A value
    # an earlier pattern already redacted is left alone.
    ("kv_secret", re.compile(
        r"(?i)(\b(?:password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|"
        r"client[_-]?secret|secret[_-]?key)[\"']?[^\S\n]*[:=][^\S\n]*)"
        r"(?![\"']?\[REDACTED)(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&\"'}]+)",
    )),
]


def scrub(text: str) -> str:
    """Return a copy of ``text`` with detected secrets replaced.

    The replacement preserves enough structure that the redacted result
    is still useful for debugging (you can see WHAT got redacted), but
    the actual secret value is gone.
    """
    if not text:
        return text
    out = text
    for kind, pat in _PATTERNS:
        if kind in ("bearer", "env_secret", "url_secret", "aws_secret_key", "jwt", "kv_secret"):
            # Keep the prefix (header name / KEY= / ?param= / text before a
            # token), redact the value.
            out = pat.sub(lambda m, k=kind: m.group(1) + f"[REDACTED:{k}]", out)
        elif kind == "url_credentials":
            # Keep scheme://user: and the trailing @, redact the password.
            out = pat.sub(lambda m: m.group(1) + "[REDACTED:url_credentials]" + m.group(3), out)
        else:
            out = pat.sub(f"[REDACTED:{kind}]", out)
    return out
