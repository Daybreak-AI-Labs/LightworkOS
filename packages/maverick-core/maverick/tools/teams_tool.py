"""Microsoft Teams tool: post messages via an incoming webhook.

Completes the Slack/Discord/Teams trio (``slack_bot``, ``discord_bot`` already
exist). Posts a plain message or a simple title+text card to a Teams incoming
webhook URL configured in ``TEAMS_WEBHOOK_URL``. The POST goes
through ``_ssrf.safe_client``, which resolves the host once and pins the
connection to a validated public IP (DNS-rebind-safe, redirects disabled).
``_build_card`` is pure and unit-tested.
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from . import Tool

_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["send"], "default": "send"},
        "text": {"type": "string", "description": "message body (markdown)"},
        "title": {"type": "string", "description": "optional card title"},
        "webhook": {"type": "string", "description": "Unsupported; configure TEAMS_WEBHOOK_URL"},
    },
    "required": ["text"],
}


def _build_card(text: str, title: str = "") -> dict:
    """A minimal MessageCard payload Teams accepts on incoming webhooks."""
    card: dict = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "text": text,
    }
    if title:
        card["title"] = title
        card["summary"] = title
    else:
        card["summary"] = text[:60] or "Lightwork"
    return card


def _webhook(args: dict) -> str:
    return os.environ.get("TEAMS_WEBHOOK_URL", "").strip()


def _run(args: dict[str, Any]) -> str:
    if args.get("webhook"):
        return "ERROR: Teams accepts only the operator-configured webhook destination"
    op = args.get("op") or "send"
    if op != "send":
        return f"ERROR: unknown op {op!r}"
    text = str(args.get("text") or "").strip()
    if not text:
        return "ERROR: text is required"
    url = _webhook(args)
    if not url:
        return "ERROR: no webhook (set TEAMS_WEBHOOK_URL)"
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "ERROR: Teams webhook must be https://"
    card = _build_card(text, str(args.get("title") or "").strip())
    # Pin the connection to the validated public IP (resolve-once-then-pin)
    # rather than validate-then-reconnect with is_blocked_host, which is a
    # DNS-rebinding TOCTOU: a hostile resolver could pass the check and then
    # connect to an internal/metadata host. safe_client also disables redirects.
    # (ImportError is caught FIRST so BlockedHost is never referenced unbound.)
    try:
        from ._ssrf import BlockedHost, safe_client
        with safe_client(url, timeout=30.0) as client:
            r = client.post(url, json=card)
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[notifications]'"
    except BlockedHost as e:
        return f"ERROR: refusing to post to a private/disallowed host ({e})"
    except Exception as e:
        return f"ERROR: Teams request failed: {type(e).__name__}: {e}"
    if r.status_code >= 400:
        return f"ERROR: Teams webhook returned {r.status_code}: {r.text[:200]}"
    return "posted to Teams"


def teams_tool() -> Tool:
    return Tool(
        name="teams",
        description=(
            "Post a message to a Microsoft Teams channel via an incoming webhook. "
            "op: send (text [+title]). Destination is configured by the operator "
            "in TEAMS_WEBHOOK_URL. Refuses non-https / private hosts."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )


__all__ = ["teams_tool", "_build_card"]
