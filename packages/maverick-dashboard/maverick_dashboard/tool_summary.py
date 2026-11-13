"""Plain-language one-line summaries for the Tools page.

Tool descriptions are written for the agent: they name environment
variables, HTTP verbs, API paths and argument syntax. People on the Tools
page get a short plain summary instead; the original text stays available
under a collapsed "Technical details" disclosure.
"""
from __future__ import annotations

import re

_READ_ONLY = re.compile(r"\bREAD-?ONLY\b|\bops? get only\b|\bops? get\b(?!/)|\(GET\)", re.IGNORECASE)
_WRITE_OPS = re.compile(r"\b(post|put|patch|delete)\b|\bmutations\b", re.IGNORECASE)
# Descriptions of connectors to outside services mention how agents call
# them ("ops get/post", "Auth: ...", "READ-ONLY").
_CONNECTOR = re.compile(r"\bAuth:|\bops?\b[ :]|\bop query\b|\bREAD-?ONLY\b|\bkeyless\b", re.IGNORECASE)
_PROTOCOL_WORDS = re.compile(
    r"(?:\s*/\s*|\s+)(?:REST|GraphQL|SOAP|JSON-RPC|OData|FHIR|API|v\d+(?:\.\d+)?)\b"
    r"(?:\s*/\s*(?:REST|GraphQL|SOAP|JSON-RPC|API)\b)*",
)
_TECHNICAL = re.compile(
    r"`|=|\{|\}|\[|\]|(?:^|\s)/\w|\b[a-z0-9]+_[a-z0-9_]+\b|\b[A-Z0-9]+_[A-Z0-9_]+\b"
    r"|\bop\b|\bops\b|\bJSON\b|\bstdlib\b|\bregex\b|\bHTTPS?\b|://|\.(?:py|js|toml|json)\b|->|'[^']*'"
)
_SENTENCE_END = re.compile(r"(?<=[a-z0-9)])\.\s+(?=[A-Z(]|op|ops\b)|(?<=[a-z0-9)])\.$")
_TRIM_AT = re.compile(
    r"\s+(?:—|--|–)\s+|\s+op=|\s+ops?[:\s]|\s+Auth:|\s+e\.g\.|\s+Args:|;\s|,\s*READ-?ONLY\b.*$",
    re.IGNORECASE,
)


# Hand-written summaries for everyday built-in tools whose descriptions are
# agent instructions rather than a sentence a person can use.
_CURATED = {
    "apply_patch": "Applies a set of prepared file changes all at once, or none at all.",
    "ask_user": "Asks you a question when the agent needs your input.",
    "http_fetch": "Opens a web page and reads its content.",
    "list_dir": "Lists the files in a workspace folder.",
    "read_attachment": "Reads a file you attached to a task.",
    "read_file": "Reads a file from the workspace.",
    "shell": "Runs a command in the protected work area.",
    "write_file": "Creates or replaces a file in the workspace.",
}


def _humanize(name: str) -> str:
    words = re.split(r"[_\-\s]+", name.strip())
    text = " ".join(w for w in words if w)
    return text[:1].upper() + text[1:] if text else "This tool"


def _first_sentence(text: str) -> str:
    first = _SENTENCE_END.split(text, maxsplit=1)[0].strip()
    # Drop parentheticals (innermost first) that hold syntax, examples or
    # aliases, then anything after the first clause break.
    previous = None
    while previous != first:
        previous, first = first, re.sub(r"\s*\([^()]*\)", "", first)
    first = re.sub(r"\s*\([^()]*$", "", first)
    first = _TRIM_AT.split(first, maxsplit=1)[0].strip()
    first = _PROTOCOL_WORDS.sub("", first)
    # "shipping/inventory" reads as "shipping and inventory".
    first = re.sub(r"(?<=[A-Za-z])\s*/\s*(?=[A-Za-z])", " and ", first)
    return re.sub(r"\s+", " ", first).strip(" ,;:.")


def plain_tool_summary(name: str, description: str | None) -> str:
    """Return one plain sentence describing what a tool does."""
    if name in _CURATED:
        return _CURATED[name]
    text = re.sub(r"\s+", " ", str(description or "")).strip()
    if not text:
        return f"{_humanize(name)}. No description given."
    first = _first_sentence(text)
    if _CONNECTOR.search(text):
        vendor = re.sub(r"\s+(?:read-?only|via|for|over)\b.*$", "", first, flags=re.IGNORECASE)
        vendor = vendor.strip(" ,;:.")
        vendor = vendor[:1].upper() + vendor[1:]
        if vendor and len(vendor) <= 120 and not _TECHNICAL.search(vendor):
            # A description that says writes need confirmation is never read-only,
            # whether or not it also names a write verb.
            if not re.search(r"\bwrites? need confirm", text) \
                    and (_READ_ONLY.search(text) or not _WRITE_OPS.search(text)):
                return f"Reads information from {vendor}."
            return (
                f"Connects to {vendor}. Changes it makes need a person's approval."
            )
    if first and len(first) <= 200 and not _TECHNICAL.search(first):
        return first[:1].upper() + first[1:] + "."
    return f"{_humanize(name)}. Open Technical details for how agents use it."
