"""Share a Lightwork run as a sanitized, private GitHub gist.

``maverick share <goal-id>`` exports the run's trajectory via
``replay_export`` (which scrubs secrets) and uploads it as a PRIVATE gist,
returning the URL. Nothing is uploaded without an explicit GitHub token.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

_GIST_API = "https://api.github.com/gists"


class MissingGitHubToken(RuntimeError):
    """Sharing cannot begin until the administrator connects GitHub."""


def resolve_token(token: str | None = None) -> str:
    value = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or _saved_token()
    if not value:
        raise MissingGitHubToken("GitHub sharing is not connected on this installation.")
    return value


def upload_payload(payload: dict, token: str) -> str:
    """Send exactly a reviewed payload. Exceptions after dispatch are uncertain."""
    import httpx

    from .governed_http import guarded_sender

    response = guarded_sender(httpx.post)(_GIST_API, content=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }, timeout=30.0)
    response.raise_for_status()
    url = response.json().get("html_url", "")
    if not isinstance(url, str) or not url.startswith("https://gist.github.com/"):
        raise ValueError("GitHub did not return a verifiable gist URL")
    return url


def build_gist_payload(goal_id: int) -> dict:
    """Assemble the gist API payload from a sanitized run export."""
    from .replay import export as replay_export
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / f"maverick-run-{goal_id}.json"
        replay_export.export_json(goal_id, out)
        content = out.read_text(encoding="utf-8")
    fname = f"maverick-run-{goal_id}.json"
    return {
        "description": f"Lightwork run #{goal_id} (sanitized trajectory)",
        "public": False,  # secret gist -- shareable by URL, not listed/searchable
        "files": {fname: {"content": content}},
    }


def _saved_token() -> str:
    """``[github] share_token`` saved (sealed) on the All settings page.

    ``load_config`` opens the sealed value; it is never logged or returned."""
    try:
        from .config import load_config
        github = (load_config() or {}).get("github") or {}
        value = github.get("share_token") if isinstance(github, dict) else None
    except Exception:  # pragma: no cover -- config never blocks sharing
        return ""
    return value.strip() if isinstance(value, str) else ""


def share_run(goal_id: int, token: str | None = None) -> str:
    """Upload the sanitized run as a private gist; return its URL.

    Token resolution: explicit arg > ``GITHUB_TOKEN`` > ``GH_TOKEN`` > the
    sealed ``[github] share_token`` saved in settings. Raises if none is set
    (we never upload anonymously).
    """
    return upload_payload(build_gist_payload(goal_id), resolve_token(token))
