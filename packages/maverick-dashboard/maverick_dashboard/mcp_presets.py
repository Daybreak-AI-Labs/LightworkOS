"""Ready-made tool servers for the Tool servers page.

A person picks what they want to connect ("Files in a folder", "GitHub") and
answers only that preset's questions; the exact server command or web address
is built here. Every spec still goes through ``runtime_overrides.add_mcp_server``
and the kernel's ``MCPServerSpec`` validation, exactly like the advanced form.
Global admin only and same-origin checked.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

router = APIRouter()

# Each preset: title, one-line description, questions, and how to build the spec.
PRESETS: dict[str, dict] = {
    "files": {
        "title": "Files in a folder",
        "description": "Let agents read and write files inside one folder on this computer.",
        "where": "On this computer",
        "fields": [{"key": "folder", "label": "Folder Lightwork may use", "type": "text",
                    "placeholder": "e.g. /Users/you/Documents/Projects",
                    "help": "Agents can only reach files inside this folder."}],
    },
    "memory": {
        "title": "Notes agents keep",
        "description": "A private notebook agents use to remember facts between tasks.",
        "where": "On this computer",
        "fields": [],
    },
    "github": {
        "title": "GitHub",
        "description": "Let agents read issues, pull requests and code in your GitHub account.",
        "where": "Online service",
        "fields": [{"key": "access_key", "label": "GitHub access key", "type": "password",
                    "help": "Create one at github.com under Settings, Developer settings, Personal access tokens.",
                    "link": "https://github.com/settings/personal-access-tokens"}],
    },
    "online": {
        "title": "Another online tool server",
        "description": "Connect a tool server your provider gave you a web address for.",
        "where": "Online service",
        "fields": [{"key": "url", "label": "Web address of the server", "type": "url",
                    "placeholder": "https://…", "help": "Your provider gives you this address."},
                   {"key": "access_key", "label": "Access key (if the provider gave you one)", "type": "password",
                    "optional": True, "help": ""}],
    },
}


def _spec(preset: str, values: dict[str, str]) -> dict:
    if preset == "files":
        folder = values.get("folder", "").strip()
        if not folder:
            raise HTTPException(422, "Choose the folder Lightwork may use.")
        return {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", folder]}
    if preset == "memory":
        return {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}
    if preset == "github":
        key = values.get("access_key", "").strip()
        if not key:
            raise HTTPException(422, "Paste your GitHub access key.")
        return {"url": "https://api.githubcopilot.com/mcp/", "auth_token": key}
    if preset == "online":
        url = values.get("url", "").strip()
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.netloc:
            raise HTTPException(422, "Enter the server's full web address, starting with https://.")
        spec: dict = {"url": url}
        key = values.get("access_key", "").strip()
        if key:
            spec["auth_token"] = key
        return spec
    raise HTTPException(400, "Choose one of the listed tool servers.")


@router.post("/mcp/add-preset")
async def add_preset(request: Request) -> RedirectResponse:
    from . import app as app_module
    from .auth import require_global_permission
    app_module._require_same_origin(request)
    require_global_permission(request, "admin")
    from maverick.runtime_overrides import add_mcp_server, mcp_overlay

    from .plain_labels import unique_slug
    form = await request.form()
    preset = str(form.get("preset") or "").strip()
    if preset not in PRESETS:
        raise HTTPException(400, "Choose one of the listed tool servers.")
    spec = _spec(preset, {k: str(v) for k, v in form.items()})
    try:
        from .integration_readiness import mcp_inventory
        taken = {row["name"] for row in mcp_inventory()} | set(mcp_overlay())
    except Exception:
        taken = set(mcp_overlay())
    name = unique_slug(str(form.get("display_name") or "") or PRESETS[preset]["title"], taken,
                       fallback="server", max_len=64)
    try:
        add_mcp_server(name, spec)
    except ValueError as exc:
        raise HTTPException(422, "Those details can't be used for a tool server. Check them and try again.") from exc
    return RedirectResponse("/mcp?saved=add", status_code=303)
