"""Build OAuth authorization URLs without handling credentials in agent calls.

Account connection and refresh are handled by the operator-facing connected
accounts flow. Model-supplied token endpoints and credentials must never be
used to overwrite a connected account's tokens.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from . import Tool
from ._ssrf import safe_client

_MAX_TOKEN_RESPONSE_BYTES = 100_000


def _post_form(url: str, data: dict[str, str]) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"oauth token_url must be https://, got {url!r}")

    headers = {"Accept": "application/json"}
    chunks: list[bytes] = []
    total = 0
    with safe_client(url, timeout=30.0) as client:
        with client.stream("POST", url, data=data, headers=headers) as r:
            r.raise_for_status()
            for chunk in r.iter_bytes():
                total += len(chunk)
                if total > _MAX_TOKEN_RESPONSE_BYTES:
                    raise ValueError("oauth token response too large")
                chunks.append(chunk)
    return json.loads(b"".join(chunks).decode("utf-8"))


def _authorize_url(args: dict[str, Any]) -> str:
    for req in ("authorize_url", "client_id", "redirect_uri"):
        if not args.get(req):
            return f"ERROR: {req} is required"
    from urllib.parse import urlencode

    from ..mcp_oauth import generate_pkce
    verifier, challenge = generate_pkce()
    params = {
        "response_type": "code",
        "client_id": str(args["client_id"]),
        "redirect_uri": str(args["redirect_uri"]),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if args.get("scope"):
        params["scope"] = str(args["scope"])
    if args.get("state"):
        params["state"] = str(args["state"])
    sep = "&" if urlparse(args["authorize_url"]).query else "?"
    url = f"{args['authorize_url']}{sep}{urlencode(params)}"
    return (f"open: {url}\n"
            f"pkce_verifier: {verifier}\n"
            "(keep the verifier private for an operator-controlled OAuth client)")


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "authorize_url":
        return _authorize_url(args)
    if op in {"exchange", "refresh"}:
        return "ERROR: connect or refresh accounts through the operator-facing Connected accounts flow"
    return f"ERROR: unknown op {op!r} (expected authorize_url)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["authorize_url"]},
        "authorize_url": {"type": "string"},
        "client_id": {"type": "string"},
        "redirect_uri": {"type": "string"},
        "scope": {"type": "string"},
        "state": {"type": "string"},
    },
    "required": ["op"],
}


def oauth_helper() -> Tool:
    return Tool(
        name="oauth_helper",
        description=(
            "Build an OAuth2 authorization URL with PKCE S256. Connect and "
            "refresh accounts through the operator-facing Connected accounts flow."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
