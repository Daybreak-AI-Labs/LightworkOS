"""Generic OAuth2 helper.

Build the wire artifacts for the two common OAuth2 flows without ever touching
the network: the client-credentials token request (POST body + headers) and the
authorization-code redirect URL, including a PKCE ``code_challenge`` (S256) when
a verifier is supplied. The agent gets exactly the string it would send; sending
is a separate, deliberate step (use http_fetch / browser). Deterministic and
offline; pure stdlib (hashlib + base64 + urllib). No disk, no network.

ops:
  - client_credentials_request(token_url, client_id, scope?) -> the POST it
    would make (method, URL, headers, form body). Does NOT send.
  - authorize_url(authorize_endpoint, client_id, redirect_uri, scope?, state?,
    pkce?) -> the full authorization URL; with ``pkce`` (the code_verifier)
    appends code_challenge (S256) + code_challenge_method.

Non-https endpoints are rejected (OAuth credentials must never cross plaintext).
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any
from urllib.parse import urlencode, urlsplit

from . import Tool


def _is_https(url: str) -> bool:
    return urlsplit(url).scheme.lower() == "https"


def _s256_challenge(verifier: str) -> str:
    """RFC 7636 S256: base64url(sha256(verifier)), no padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _client_credentials_request(args: dict[str, Any]) -> str:
    token_url = str(args.get("token_url") or "").strip()
    client_id = str(args.get("client_id") or "").strip()
    if not token_url:
        return "ERROR: token_url is required"
    if not client_id:
        return "ERROR: client_id is required"
    if not _is_https(token_url):
        return "ERROR: token_url must be https"

    form: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
    }
    scope = args.get("scope")
    if isinstance(scope, str) and scope.strip():
        form["scope"] = scope.strip()
    body = urlencode(form)
    lines = [
        f"POST {token_url}",
        "Content-Type: application/x-www-form-urlencoded",
        "Accept: application/json",
        "",
        body,
    ]
    return "\n".join(lines)


def _authorize_url(args: dict[str, Any]) -> str:
    endpoint = str(args.get("authorize_endpoint") or "").strip()
    client_id = str(args.get("client_id") or "").strip()
    redirect_uri = str(args.get("redirect_uri") or "").strip()
    if not endpoint:
        return "ERROR: authorize_endpoint is required"
    if not client_id:
        return "ERROR: client_id is required"
    if not redirect_uri:
        return "ERROR: redirect_uri is required"
    if not _is_https(endpoint):
        return "ERROR: authorize_endpoint must be https"

    params: list[tuple[str, str]] = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
    ]
    scope = args.get("scope")
    if isinstance(scope, str) and scope.strip():
        params.append(("scope", scope.strip()))
    state = args.get("state")
    if isinstance(state, str) and state.strip():
        params.append(("state", state.strip()))
    pkce = args.get("pkce")
    if isinstance(pkce, str) and pkce.strip():
        params.append(("code_challenge", _s256_challenge(pkce.strip())))
        params.append(("code_challenge_method", "S256"))

    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{urlencode(params)}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "client_credentials_request":
        return _client_credentials_request(args)
    if op == "authorize_url":
        return _authorize_url(args)
    return (
        f"ERROR: unknown op {op!r} "
        "(expected client_credentials_request or authorize_url)"
    )


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["client_credentials_request", "authorize_url"],
        },
        "token_url": {"type": "string", "description": "token endpoint (https) for client_credentials_request"},
        "authorize_endpoint": {"type": "string", "description": "authorization endpoint (https) for authorize_url"},
        "client_id": {"type": "string"},
        "redirect_uri": {"type": "string", "description": "redirect URI for authorize_url"},
        "scope": {"type": "string", "description": "space-delimited scopes (optional)"},
        "state": {"type": "string", "description": "opaque CSRF state for authorize_url (optional)"},
        "pkce": {"type": "string", "description": "PKCE code_verifier; adds an S256 code_challenge (optional)"},
    },
    "required": ["op"],
}


def generic_oauth() -> Tool:
    return Tool(
        name="generic_oauth",
        description=(
            "Build OAuth2 wire artifacts offline (never sends). "
            "op=client_credentials_request {token_url, client_id, scope?} -> the "
            "POST (method/URL/headers/form body). op=authorize_url "
            "{authorize_endpoint, client_id, redirect_uri, scope?, state?, pkce?} "
            "-> the authorization URL, adding an S256 code_challenge when 'pkce' "
            "(the code_verifier) is given. Non-https endpoints are rejected. "
            "Deterministic; stdlib hashlib+base64+urllib only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
