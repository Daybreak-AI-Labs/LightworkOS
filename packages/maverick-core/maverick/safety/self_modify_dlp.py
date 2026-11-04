"""Fail-closed secret detection for privileged self-modification data paths.

Self-modification source, prompts, diffs, and lineage records can all cross a
provider or persistence boundary. Redacting them would change source semantics
and can produce a patch against bytes the model never saw, so this path refuses
detected material instead.
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)

_LOWERCASE_QUOTED_SECRET = re.compile(
    r"(?im)^[^\S\n]*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?:api_key|client_secret|password|passwd|auth_token|access_token|"
    r"secret_key|private_key)\s*(?::\s*[^=\n]+)?\s*=\s*"
    r"(?P<quote>['\"])(?P<value>[^'\"\n]{8,})(?P=quote)"
)
_LOWERCASE_MAPPING_SECRET = re.compile(
    r"(?im)^[^\S\n]*(?:api_key|client_secret|password|passwd|auth_token|"
    r"access_token|secret_key|private_key)\s*:\s*"
    r"(?P<value>[A-Za-z0-9_./+=-]{12,})\s*$"
)
_LOWERCASE_UNQUOTED_SECRET = re.compile(
    r"(?im)^[^\S\n]*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?:[a-z][a-z0-9_]*_)?(?:api_key|client_secret|password|passwd|"
    r"auth_token|access_token|secret_key|private_key)\s*"
    r"(?::\s*[^=\n]+)?\s*=\s*"
    r"(?P<value>[A-Za-z0-9_./+=!@#$%^&*-]{12,})(?:\s*(?:#.*)?)?$"
)
_KNOWN_PLACEHOLDER_FRAGMENTS = (
    "changeme", "dummy", "example", "placeholder", "replace-me",
    "replace_me", "test-only", "your-key", "your_key", "${",
)


def _has_lowercase_secret_literal(value: str) -> bool:
    """Catch credential literals missed by uppercase env-style detectors."""
    for pattern in (
        _LOWERCASE_QUOTED_SECRET,
        _LOWERCASE_MAPPING_SECRET,
        _LOWERCASE_UNQUOTED_SECRET,
    ):
        for match in pattern.finditer(value):
            literal = match.group("value").strip().casefold()
            if not any(marker in literal for marker in _KNOWN_PLACEHOLDER_FRAGMENTS):
                return True
    return False


def _diff_payload(text: str) -> str:
    """Remove unified-diff hunk markers so line-anchored detectors still fire."""
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith(("+++", "---")):
            lines.append(line)
        elif line.startswith(("+", "-")):
            lines.append(line[1:])
        else:
            lines.append(line)
    return "\n".join(lines)


def contains_secret_material(text: str, *, unified_diff: bool = False) -> bool:
    """Return true when sensitive material is detected or scanning is unavailable.

    The two established detectors have complementary coverage. A unified diff
    is inspected both verbatim and with hunk prefixes removed because an added
    ``+DB_PASSWORD=...`` otherwise defeats line-anchored assignment patterns.
    Any detector failure refuses the privileged operation rather than silently
    sending or persisting unscanned data.
    """
    try:
        # Conversion is part of the privileged scan boundary.  Keeping it in
        # the fail-closed region prevents a hostile/invalid object with a
        # raising ``__str__`` from bypassing detection through caller error
        # handling.
        value = str(text or "")
        candidates = (value, _diff_payload(value)) if unified_diff else (value,)
        from ..secrets import scrub
        from .secret_detector import scan

        for candidate in candidates:
            if (_has_lowercase_secret_literal(candidate)
                    or scan(candidate) or scrub(candidate) != candidate):
                return True
    except Exception:
        # Do not echo exception text/tracebacks: a failing detector may include
        # the material it was scanning in its exception message.
        log.warning("self-modification DLP scan failed; refusing")
        return True
    return False


__all__ = ["contains_secret_material"]
