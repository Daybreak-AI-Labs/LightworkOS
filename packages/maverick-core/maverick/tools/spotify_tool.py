"""Spotify tool — search + playback + playlists (read-mostly).

Auth: ``SPOTIFY_ACCESS_TOKEN`` (refreshed externally — we don't bake
OAuth flow). Scope hints depend on op:
  - read: user-library-read, playlist-read-private
  - write: user-modify-playback-state, playlist-modify-public/private

ops:
  - search(q, type, limit)              — track / album / artist / playlist / show / episode
  - track_get(track_id)
  - playlists(limit)
  - playlist_get(playlist_id)
  - playback_state()
  - play(uri, confirm)                  — start playback (write scope!)
  - pause(confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_SP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "track_get", "playlists",
                     "playlist_get", "playback_state",
                     "play", "pause"],
        },
        "q": {"type": "string"},
        "type": {"type": "string"},
        "track_id": {"type": "string"},
        "playlist_id": {"type": "string"},
        "uri": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _token() -> str:
    t = os.environ.get("SPOTIFY_ACCESS_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Spotify requires SPOTIFY_ACCESS_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    from ..governed_http import request
    r = request("GET", f"https://api.spotify.com/v1{path}",
                headers=_headers(), params=params or {}, timeout=20.0)
    try:
        return r.status_code, r.json() if r.text else {}
    except ValueError:
        return r.status_code, r.text[:300]


def _put(path: str, body: dict | None = None) -> int:
    from ..governed_http import request
    r = request("PUT", f"https://api.spotify.com/v1{path}",
                headers=_headers(), json=body or {}, timeout=20.0)
    return r.status_code


def _op_search(args: dict) -> str:
    q = (args.get("q") or "").strip()
    if not q:
        return "ERROR: search requires q"
    code, data = _get("/search", {
        "q": q,
        "type": (args.get("type") or "track"),
        "limit": max(1, min(int(args.get("limit") or 10), 50)),
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    out = []
    for kind, payload in (data or {}).items():
        rows = (payload or {}).get("items") or []
        for it in rows:
            name = it.get("name", "?")
            artists = ", ".join(a.get("name", "?")
                                 for a in (it.get("artists") or []))
            out.append(f"  [{kind:>9}] {name[:40]:<40}  {artists[:30]}  {it.get('uri', '?')}")
    return "\n".join(out) or "no matches"


def _safe_id(value: str) -> bool:
    """Spotify IDs are Base62 (letters + digits); reject anything else so a
    value can't traverse to a different API path."""
    return bool(value) and value.isalnum()


def _op_track_get(args: dict) -> str:
    tid = (args.get("track_id") or "").strip()
    if not _safe_id(tid):
        return "ERROR: track_get requires a valid track_id"
    code, data = _get(f"/tracks/{tid}")
    if code == 404:
        return f"track {tid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: track_get ({code}): {data}"
    return (
        f"{data.get('name')}\n"
        f"  artists: {', '.join(a.get('name', '?') for a in (data.get('artists') or []))}\n"
        f"  album:   {(data.get('album') or {}).get('name', '?')}\n"
        f"  ms:      {data.get('duration_ms')}\n"
        f"  uri:     {data.get('uri')}"
    )


def _op_playlists(args: dict) -> str:
    code, data = _get("/me/playlists", {
        "limit": max(1, min(int(args.get("limit") or 25), 50)),
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: playlists ({code}): {data}"
    rows = data.get("items") or []
    if not rows:
        return "no playlists"
    return "\n".join(
        f"  {p.get('id'):<22}  {p.get('name', '?')[:50]:<50}  "
        f"{(p.get('tracks') or {}).get('total', '?')} tracks"
        for p in rows
    )


def _op_playlist_get(args: dict) -> str:
    pid = (args.get("playlist_id") or "").strip()
    if not _safe_id(pid):
        return "ERROR: playlist_get requires a valid playlist_id"
    code, data = _get(f"/playlists/{pid}")
    if code == 404:
        return f"playlist {pid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: playlist_get ({code}): {data}"
    items = ((data.get("tracks") or {}).get("items")) or []
    return (
        f"{data.get('name')}  by {(data.get('owner') or {}).get('display_name', '?')}\n"
        + "\n".join(
            f"  {(it.get('track') or {}).get('name', '?')[:40]:<40}  "
            f"{(it.get('track') or {}).get('uri', '?')}"
            for it in items[:50]
        )
    )


def _op_playback_state(_args: dict) -> str:
    code, data = _get("/me/player")
    if code == 204:
        return "(no active device)"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: playback_state ({code}): {data}"
    item = data.get("item") or {}
    return (
        f"playing={data.get('is_playing')}  device={(data.get('device') or {}).get('name', '?')}\n"
        f"  track:   {item.get('name', '?')} ({item.get('uri', '?')})\n"
        f"  progress:{data.get('progress_ms')}ms"
    )


def _op_play(args: dict) -> str:
    uri = (args.get("uri") or "").strip()
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would start playback ({uri or 'current track'}). Re-run with confirm=true."
    body = {"uris": [uri]} if uri and uri.startswith("spotify:track:") else (
        {"context_uri": uri} if uri else {}
    )
    code = _put("/me/player/play", body)
    if code >= 400:
        return f"ERROR: play ({code})"
    return f"playback started ({uri or 'current track'})"


def _op_pause(args: dict) -> str:
    if not as_bool(args.get("confirm")):
        return "DRY RUN: would pause playback. Re-run with confirm=true."
    code = _put("/me/player/pause")
    if code >= 400:
        return f"ERROR: pause ({code})"
    return "playback paused"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return {
            "search":          _op_search,
            "track_get":       _op_track_get,
            "playlists":       _op_playlists,
            "playlist_get":    _op_playlist_get,
            "playback_state":  _op_playback_state,
            "play":            _op_play,
            "pause":           _op_pause,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Spotify request failed: {type(e).__name__}: {e}"


def spotify_tool() -> Tool:
    return Tool(
        name="spotify",
        description=(
            "Spotify search + library + playback. ops: search, "
            "track_get, playlists, playlist_get, playback_state, "
            "play / pause (mutations confirm=true). Auth: "
            "SPOTIFY_ACCESS_TOKEN (refreshed externally)."
        ),
        input_schema=_SP_SCHEMA,
        fn=_run,
    )
