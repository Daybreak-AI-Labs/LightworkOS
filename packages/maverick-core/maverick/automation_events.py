"""Event triggers: fire a saved workflow when something new appears in an
external source -- the "when X happens" half of workflow automation.

Push-capable services already work via the inbound webhook trigger
(``/webhook/run``). This is the POLL side, for sources that don't push: an
:class:`EventSource` is polled on a schedule; each item newer than the stored
cursor fires the bound template as a goal, with the item's fields available to
fill declared params.

An ``EventSource.poll(config, cursor)`` returns the new events plus the next
cursor. First poll establishes a baseline (records the newest id, fires
nothing) so arming a trigger never floods on historical items; later polls
return only what appeared since. Sources self-register (like automation_import),
so new connectors are additive.

Off by default (``[event_triggers] enable`` / ``MAVERICK_EVENT_TRIGGERS``):
polling reaches out to third-party endpoints, so the operator opts in
(kernel rule 1). ``fetch``/HTTP goes through the SSRF guard.
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urljoin, urlparse


class EventSourceError(RuntimeError):
    """Configuration / fetch problem for an event source (bad URL, unreachable)."""


class EventSourceTooLarge(EventSourceError):
    """A response refused for exceeding its byte limit; callers can name that limit."""


@dataclass
class PollResult:
    """The outcome of polling a source once.

    ``events`` are the new items (each a flat dict of fields usable as params),
    oldest-first so they fire in the order they occurred. ``cursor`` is the
    opaque position to pass to the next poll.
    """
    events: list[dict] = field(default_factory=list)
    cursor: str = ""
    # Source-controlled identities live outside customer-editable event fields.
    # None keeps the legacy custom-source contract; built-ins supply exact IDs.
    event_ids: list[str] | None = None
    cursor_format: int = 1


@runtime_checkable
class EventSource(Protocol):
    source: str

    def poll(self, config: dict, cursor: str) -> PollResult:
        """Return items newer than ``cursor`` + the next cursor."""
        ...


_SOURCES: dict[str, Callable[[], EventSource]] = {}


def register(source: str, factory: Callable[[], EventSource]) -> None:
    """Register an event-source factory under its name (idempotent)."""
    _SOURCES[source] = factory


def available_sources() -> list[str]:
    _register_connected_sources()
    return sorted(_SOURCES)


def get_source(source: str) -> EventSource:
    if source in {"sharepoint_files", "salesforce_records", "servicenow_tickets", "teams_messages"}:
        _register_connected_sources()
    factory = _SOURCES.get(source)
    if factory is None:
        raise EventSourceError(
            f"unknown event source {source!r}; "
            f"available: {', '.join(available_sources()) or '(none)'}"
        )
    return factory()


def enabled() -> bool:
    """Whether event-trigger polling is switched on (off by default)."""
    from .config import env_flag
    v = env_flag("MAVERICK_EVENT_TRIGGERS")
    if v is not None:
        return v
    try:
        from .config import load_config
        return bool((load_config().get("event_triggers") or {}).get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks
        return False


# ---- helpers ---------------------------------------------------------------

_MAX_EVENTS = 25  # per poll, so a backlog can't spawn an unbounded goal burst
_MAX_HTTP_JSON_BYTES = 2 * 1024 * 1024  # bound external feed bodies before JSON parse
_MAX_HTTP_TEXT_BYTES = 1024 * 1024  # RSS/Atom bodies are small; cap hostile feeds
_CURSOR_PREFIX = "lightwork:cursor:v1:"
_MAX_FILE_BOUNDARY_IDS = 4096


def _encode_cursor(kind: str, value: Any) -> str:
    return _CURSOR_PREFIX + json.dumps([kind, value], separators=(",", ":"))


def _decode_cursor(cursor: str, kind: str, cursor_format: int | None = None) -> Any:
    """Decode one envelope only; legacy non-envelope cursors retain their ID.

    Wrapping IDs, including IDs that look like envelopes, keeps initialized
    empty distinct from every newly persisted provider ID.
    """
    if cursor_format == 0 or not cursor.startswith(_CURSOR_PREFIX):
        return cursor
    try:
        result = json.loads(cursor[len(_CURSOR_PREFIX):])
        if not isinstance(result, list) or len(result) != 2 or result[0] != kind:
            raise ValueError
        return result[1]
    except (ValueError, TypeError) as exc:
        raise EventSourceError("invalid or incompatible event cursor") from exc


def _dig(obj: Any, path: str) -> Any:
    """Follow a dotted ``a.b.c`` path into nested dicts; '' returns obj as-is."""
    cur = obj
    for part in (p for p in (path or "").split(".") if p):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _flatten(item: dict, *, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict:
    """Flatten a nested event dict into ``a.b`` string keys, so declared params
    can pull ``issue.title`` etc. Values are stringified + length-bounded; depth
    and breadth are capped so a hostile payload can't explode the param map."""
    out = {} if out is None else out
    if depth > 4 or len(out) >= 100:
        return out
    for k, v in item.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, prefix=f"{key}.", out=out, depth=depth + 1)
        elif isinstance(v, (list, tuple)):
            out[key] = ", ".join(str(x) for x in v)[:2000]
        else:
            out[key] = ("" if v is None else str(v))[:2000]
        if len(out) >= 100:
            break
    return out


def diff_new_items(items: list[dict], cursor: str, id_field: str, *,
                   newest_first: bool = True, cursor_format: int | None = None) -> PollResult:
    """Given the raw items a source returned, compute the new ones vs ``cursor``.

    ``cursor`` is the id of the newest item seen at the last poll. First poll
    (empty cursor) fires nothing and just records the newest id -- so arming a
    trigger never replays history. Otherwise the items ahead of the cursor id
    are new; they're returned oldest-first and the cursor advances to the newest.
    Items are flattened to ``a.b`` param-friendly dicts and bounded.
    """
    prior = _decode_cursor(cursor, "feed", cursor_format) if cursor else None
    if prior is not None and not isinstance(prior, str):
        raise EventSourceError("invalid feed cursor")
    ordered = list(items) if newest_first else list(reversed(items))  # newest-first

    def _id(it: dict) -> str:
        value = _dig(it, id_field)
        return "" if value is None else str(value)

    ids = [_id(it) for it in ordered]
    if any(not iid for iid in ids) or len(set(ids)) != len(ids):
        raise EventSourceError("feed items require nonempty unique IDs")
    newest = ids[0] if ids else prior
    if not cursor:
        return PollResult(events=[], cursor=_encode_cursor("feed", newest))
    fresh: list[dict] = []
    if prior in ids:
        for it, iid in zip(ordered, ids, strict=False):
            if iid == prior:
                break                                   # reached last-seen
            fresh.append(it)
    elif _numeric_id(prior) is not None and all(_numeric_id(i) is not None for i in ids):
        # The last-seen item left the feed (closed, deleted, rolled off) but
        # ids are increasing numbers: only ids above it are new.
        floor = _numeric_id(prior)
        fresh = [it for it, iid in zip(ordered, ids, strict=True) if _numeric_id(iid) > floor]
    else:
        # Otherwise what is before or after it cannot be told: re-baseline
        # instead of firing every listed (possibly historical) item as new.
        return PollResult(events=[], cursor=_encode_cursor("feed", newest))
    fresh.reverse()                                     # oldest-first for firing
    # Fire the OLDEST _MAX_EVENTS of a backlog and advance the cursor only to the
    # newest item we actually fired -- so a burst larger than the cap drains over
    # subsequent polls instead of the older items being skipped and lost.
    fresh = fresh[:_MAX_EVENTS]
    if not fresh:
        return PollResult(events=[], cursor=_encode_cursor("feed", prior))
    next_cursor = _id(fresh[-1]) or newest
    events = [_flatten(it) for it in fresh]
    return PollResult(events=events, cursor=_encode_cursor("feed", next_cursor),
                      event_ids=[_id(item) for item in fresh])


def _numeric_id(value: str | None) -> int | None:
    text = (value or "").strip()
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 30 else None


# ---- built-in source: poll a JSON HTTP endpoint ----------------------------


def _base_config(config: dict, source: str) -> tuple[str, str, dict]:
    """Pull the fields every source shares: ``url`` (required), ``id_field``,
    ``headers``. Raises if ``url`` is missing/blank."""
    url = str((config or {}).get("url") or "").strip()
    if not url:
        raise EventSourceError(f"{source} event source needs a 'url'")
    id_field = str((config or {}).get("id_field") or "id")
    raw_headers = (config or {}).get("headers")
    headers = raw_headers if isinstance(raw_headers, dict) else {}
    return url, id_field, headers


def _same_origin_url(base_url: str, next_url: str) -> str:
    """Resolve a pagination URL and reject cross-origin redirects.

    Pagination links come from remote JSON bodies, so they are untrusted. Keep
    credentials scoped to the configured endpoint origin by allowing relative
    links and absolute same-origin links only.
    """
    candidate = str(next_url or "").strip()
    if not candidate:
        return ""
    resolved = urljoin(base_url, candidate)
    base = urlparse(base_url)
    page = urlparse(resolved)
    if (base.scheme, base.hostname, base.port) != (page.scheme, page.hostname, page.port):
        raise EventSourceError("pagination next URL must stay on the configured origin")
    return resolved


def _http_get(url: str, headers: dict | None = None, timeout: float = 15.0) -> Any:
    """GET ``url`` through the SSRF guard, returning the checked response (an
    event-source URL is operator config, but a loopback/metadata host would make
    the poller an SSRF proxy). Shared by the JSON and text fetchers."""
    try:
        from .tools._ssrf import BlockedHost, safe_client
    except Exception as e:  # pragma: no cover -- guard unavailable
        raise EventSourceError("SSRF guard unavailable") from e
    try:
        with safe_client(url, timeout=timeout, require_public=True) as client:
            resp = client.get(url, headers=headers or {})
    except BlockedHost as e:
        raise EventSourceError(f"blocked by SSRF guard: {e}") from e
    except Exception as e:
        raise EventSourceError(f"fetch failed: {type(e).__name__}: {e}") from e
    if getattr(resp, "status_code", 200) >= 400:
        raise EventSourceError(f"source returned HTTP {resp.status_code}")
    return resp


def _http_read_bytes(
    url: str,
    headers: dict | None = None,
    timeout: float = 15.0,
    *,
    max_bytes: int,
) -> bytes:
    """GET ``url`` through the SSRF guard and read at most ``max_bytes``.

    ``safe_get()`` materializes the whole response before returning, which is
    fine for small tools but unsafe for event sources that poll operator-provided
    feeds repeatedly. Use the same pinned safe client in streaming mode so a
    malicious feed cannot force an unbounded body download before we reject it.
    """
    try:
        from .tools._ssrf import BlockedHost, safe_client
    except Exception as e:  # pragma: no cover -- guard unavailable
        raise EventSourceError("SSRF guard unavailable") from e
    try:
        with safe_client(url, timeout=timeout, require_public=True) as client:
            with client.stream("GET", url, headers=headers or {}) as resp:
                if getattr(resp, "status_code", 200) >= 400:
                    raise EventSourceError(f"source returned HTTP {resp.status_code}")
                length = resp.headers.get("content-length")
                if length and int(length) > max_bytes:
                    raise EventSourceTooLarge(
                        f"source response exceeds {max_bytes} byte limit")
                deadline = time.monotonic() + timeout
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    if time.monotonic() > deadline:
                        raise EventSourceError("source response exceeded fetch timeout")
                    total += len(chunk)
                    if total > max_bytes:
                        raise EventSourceTooLarge(
                            f"source response exceeds {max_bytes} byte limit")
                    chunks.append(chunk)
                if time.monotonic() > deadline:
                    raise EventSourceError("source response exceeded fetch timeout")
                return b"".join(chunks)
    except EventSourceError:
        raise
    except BlockedHost as e:
        raise EventSourceError(f"blocked by SSRF guard: {e}") from e
    except Exception as e:
        raise EventSourceError(f"fetch failed: {type(e).__name__}: {e}") from e


def _http_get_json(url: str, headers: dict | None = None, timeout: float = 15.0) -> Any:
    """GET ``url`` and parse a bounded JSON body. Isolated for test injection."""
    raw = _http_read_bytes(
        url, headers=headers, timeout=timeout, max_bytes=_MAX_HTTP_JSON_BYTES)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise EventSourceError("source did not return JSON") from e


class HttpJsonSource:
    """Poll a JSON HTTP endpoint for new items.

    ``config``: ``{url, items_path?, id_field?, headers?, newest_first?}``.
    ``items_path`` digs to the array (e.g. ``data.issues``; default = the whole
    body when it's already a list). ``id_field`` is the per-item unique id used
    for dedup (dotted paths allowed; default ``id``). This one connector covers
    a large slice of "new row / new record / new lead" REST feeds.
    """
    source = "http_json"

    def _extra_headers(self, config: dict) -> dict:
        """Per-poll headers merged over the static ``headers`` config (e.g. a
        live ``Authorization``). Base source adds none; subclasses override."""
        return {}

    def poll(self, config: dict, cursor: str) -> PollResult:
        url, id_field, headers = _base_config(config, self.source)
        items_path = str((config or {}).get("items_path") or "")
        newest_first = bool((config or {}).get("newest_first", True))
        headers = {**headers, **self._extra_headers(config)}
        # Pagination: follow ``next_path`` (a dotted path to the next-page URL in
        # each response) up to ``max_pages``, so a burst larger than one page
        # doesn't lose the overflow. Off unless next_path is configured.
        next_path = str((config or {}).get("next_path") or "").strip()
        max_pages = max(1, int((config or {}).get("max_pages") or 1))
        items: list = []
        page_url: str | None = url
        pages = 0
        while page_url and pages < max_pages:
            body = _http_get_json(page_url, headers=headers)
            page_items = _dig(body, items_path) if items_path else body
            if not isinstance(page_items, list):
                raise EventSourceError(
                    "expected a JSON array of items"
                    + (f" at {items_path!r}" if items_path else ""))
            items.extend(it for it in page_items if isinstance(it, dict))
            pages += 1
            nxt = _dig(body, next_path) if next_path else None
            page_url = _same_origin_url(url, str(nxt)) if (nxt and next_path) else None
        return diff_new_items(items, cursor, id_field, newest_first=newest_first,
                              cursor_format=config.get("_lightwork_cursor_format"))


register("http_json", HttpJsonSource)


# ---- built-in source: poll an RSS / Atom feed -------------------------------


def _http_get_text(url: str, headers: dict | None = None, timeout: float = 15.0) -> str:
    """GET ``url`` as bounded text. Isolated for test injection."""
    raw = _http_read_bytes(
        url, headers=headers, timeout=timeout, max_bytes=_MAX_HTTP_TEXT_BYTES)
    return raw.decode("utf-8", "replace")


def _parse_feed(text: str) -> list[dict]:
    """Parse an RSS or Atom feed into flat item dicts (id/title/link/summary/...).

    Refuses any feed carrying a DOCTYPE/ENTITY declaration before parsing -- a
    cheap guard against XXE / billion-laughs entity-expansion in the stdlib XML
    parser, since the feed body is external."""
    head = text[:4000].lower()
    if "<!doctype" in head or "<!entity" in text.lower():
        raise EventSourceError("feed declares a DOCTYPE/ENTITY (refused for safety)")
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise EventSourceError(f"feed is not valid XML: {e}") from e
    items: list[dict] = []
    for node in root.iter():
        tag = node.tag.split("}")[-1]
        if tag not in ("item", "entry"):   # RSS <item> / Atom <entry>
            continue
        d: dict = {}
        for child in node:
            ctag = child.tag.split("}")[-1]
            val = (child.text or child.get("href") or "").strip()
            if ctag == "guid":
                d["id"] = val
            elif ctag in ("title", "link", "summary", "description", "id",
                          "published", "updated", "pubDate"):
                d.setdefault(ctag, val)
        d.setdefault("id", d.get("link") or d.get("title") or "")
        items.append(d)
    return items


class RssSource:
    """Poll an RSS or Atom feed; each new ``<item>``/``<entry>`` fires. Dedup is
    by ``id_field`` (default ``id``, sourced from ``<guid>``/``<id>``/link).
    ``config``: ``{url, id_field?, headers?}``."""
    source = "rss"

    def poll(self, config: dict, cursor: str) -> PollResult:
        url, id_field, headers = _base_config(config, "rss")
        items = _parse_feed(_http_get_text(url, headers=headers))
        return diff_new_items(items, cursor, id_field, newest_first=True,
                              cursor_format=config.get("_lightwork_cursor_format"))


register("rss", RssSource)


# ---- OAuth-authenticated sources -------------------------------------------
#
# A polled source that authenticates with a live OAuth token pulled from the
# sealed per-tenant vault (never a token in the trigger config), refreshed on
# demand. The token lives in the vault under a ``provider`` key; the trigger
# stores only that reference. Covers the large class of bearer-auth REST feeds
# (Slack, Gmail, GitHub, most SaaS APIs) with one connector, plus a couple of
# named native conveniences on top.


def _oauth_refresher(config: dict):
    """A ``refresher(record) -> token_dict`` for ``vault.access_token``, or
    ``None`` when no refresh is possible (then a stored, still-valid token is
    used as-is). The provider preset supplies both endpoint and credential
    environment names; saved triggers cannot redirect credentials elsewhere.
    """
    cfg = config or {}
    if any(cfg.get(key) for key in ("token_url", "client_id", "client_secret_env")):
        raise EventSourceError("Remove saved OAuth credential overrides and configure the provider preset environment credentials")

    def _wrap(inner):
        def _refresh(record: dict) -> dict:
            try:
                return inner(record)
            except Exception as e:
                raise EventSourceError(
                    f"OAuth token refresh failed: {type(e).__name__}") from e
        return _refresh

    # Preset fallback: a known provider supplies its own token endpoint + creds.
    provider = str(cfg.get("provider") or "").strip()
    if provider:
        from . import oauth_providers
        preset = oauth_providers.make_refresher(provider)
        if preset is not None:
            return _wrap(preset)
    return None


def _oauth_bearer(config: dict) -> str:
    """Resolve a live Bearer token for an OAuth'd source from the sealed vault
    (``provider`` key), refreshing if the trigger supplied refresh config.
    Raises when the vault is off or no usable token exists."""
    provider = str((config or {}).get("provider") or "").strip()
    if not provider:
        raise EventSourceError("oauth source needs a 'provider' (the vault key)")
    try:
        from . import oauth_vault
    except Exception as e:  # pragma: no cover -- vault module unavailable
        raise EventSourceError("OAuth vault unavailable") from e
    if not oauth_vault.enabled():
        raise EventSourceError("OAuth vault is off ([oauth] vault / MAVERICK_OAUTH_VAULT)")
    token = oauth_vault.get_vault().access_token(
        provider, refresher=_oauth_refresher(config))
    if not token:
        raise EventSourceError(
            f"no valid OAuth token for provider {provider!r}; authorize it first "
            "(configure provider credentials to auto-refresh an expired one)")
    return token


class OAuthHttpJsonSource(HttpJsonSource):
    """Poll a Bearer-authenticated JSON HTTP endpoint. Same as ``http_json`` but
    the ``Authorization`` header is a live OAuth token from the sealed vault
    (``provider``) rather than a static header -- so long-lived polling of
    Slack/Gmail/GitHub/most SaaS REST APIs works with token refresh. ``config``:
    ``{provider, url, items_path?, id_field?, newest_first?, headers?}``.
    The URL must be an approved API origin for the named provider."""
    source = "oauth_http_json"

    def _extra_headers(self, config: dict) -> dict:
        from urllib.parse import urlsplit

        allowed = {
            "google": {"www.googleapis.com", "gmail.googleapis.com"},
            "microsoft": {"graph.microsoft.com"},
            "slack": {"slack.com"}, "github": {"api.github.com"},
            "hubspot": {"api.hubapi.com"}, "zoom": {"api.zoom.us"},
            "atlassian": {"api.atlassian.com"}, "linear": {"api.linear.app"},
        }
        provider = str((config or {}).get("provider") or "").strip().lower()
        try:
            url = urlsplit(str((config or {}).get("url") or ""))
            valid = (url.scheme == "https" and not url.username and not url.password
                     and url.port in (None, 443) and url.hostname in allowed.get(provider, set()))
        except ValueError:
            valid = False
        if not valid:
            raise EventSourceError("OAuth source URL is not an approved endpoint for this provider")
        return {"Authorization": f"Bearer {_oauth_bearer(config)}"}


register("oauth_http_json", OAuthHttpJsonSource)


class GithubIssuesSource:
    """Poll a GitHub repo's issues; each newly-opened issue fires (dedup by
    number). ``config``: ``{owner, repo, state?, provider?}``. Auth: a vaulted
    OAuth token when ``provider`` is set, else ``GITHUB_TOKEN`` env, else
    anonymous (public repos, rate-limited). A named native convenience over
    ``oauth_http_json`` so a trigger needs no GitHub URL knowledge."""
    source = "github_issues"

    def poll(self, config: dict, cursor: str) -> PollResult:
        owner = str((config or {}).get("owner") or "").strip()
        repo = str((config or {}).get("repo") or "").strip()
        if not (owner and repo):
            raise EventSourceError("github_issues source needs 'owner' and 'repo'")
        state = str((config or {}).get("state") or "open")
        from .tools.github_issues import _headers, _list_url
        headers = _headers()  # GITHUB_TOKEN or anonymous
        provider = str((config or {}).get("provider") or "").strip().lower()
        if provider and provider != "github":
            raise EventSourceError("GitHub issues require the GitHub OAuth provider")
        if provider:
            headers = {**headers, "Authorization": f"Bearer {_oauth_bearer(config)}"}
        items = _http_get_json(_list_url(owner, repo, state, 50), headers=headers)
        if not isinstance(items, list):
            raise EventSourceError("GitHub did not return an issue array")
        # The issues endpoint also lists PRs; drop them. Dedup by issue number.
        items = [it for it in items if isinstance(it, dict) and "pull_request" not in it]
        return diff_new_items(items, cursor, "number", newest_first=True,
                              cursor_format=config.get("_lightwork_cursor_format"))


register("github_issues", GithubIssuesSource)


# ---- built-in source: watch a directory for new files ----------------------


def _list_dir_files(path: str, glob: str, recursive: bool) -> list:
    """The files under ``path`` matching ``glob`` (isolated for test injection)."""
    from pathlib import Path
    root = Path(path).expanduser()
    if not root.is_dir():
        raise EventSourceError(f"file_dir path is not a directory: {path}")
    it = root.rglob(glob) if recursive else root.glob(glob)
    return [p for p in it if p.is_file()]


class FileDirSource:
    """Watch a directory and fire when a new file appears. ``config``:
    ``{path, glob?, recursive?}`` (glob default ``*``). Dedup is by modification
    time and identity at its boundary. Tied batches drain across polls, including
    newly arriving files at the current boundary. Older preserved timestamps
    are historical once the boundary advances. The bounded boundary ledger
    refuses overflow instead of silently losing files. Each event carries
    ``{path, name, size, mtime}``."""
    source = "file_dir"

    def poll(self, config: dict, cursor: str) -> PollResult:
        path = str((config or {}).get("path") or "").strip()
        if not path:
            raise EventSourceError("file_dir source needs a 'path'")
        glob = str((config or {}).get("glob") or "*")
        recursive = bool((config or {}).get("recursive", False))
        files = _list_dir_files(path, glob, recursive)
        import hashlib
        import math

        prior = _decode_cursor(cursor, "files", config.get("_lightwork_cursor_format")) if cursor else None
        seen: set[str] = set()
        legacy = isinstance(prior, str)
        try:
            if legacy:
                stamp = float(prior)
                if not math.isfinite(stamp) or stamp < 0:
                    raise ValueError
                since = int(stamp * 1_000_000_000)
            elif prior is None:
                since = None
            else:
                since, identities = prior
                if (type(since) is not int or since < 0
                        or not isinstance(identities, list)
                        or len(identities) > _MAX_FILE_BOUNDARY_IDS
                        or any(not isinstance(x, str) or len(x) != 64 for x in identities)):
                    raise ValueError
                seen = set(identities)
        except (TypeError, ValueError, OverflowError) as exc:
            raise EventSourceError("invalid file cursor") from exc
        stamped = []
        for p in files:
            try:
                st = p.stat()
            except OSError:  # pragma: no cover -- file vanished mid-scan
                continue
            identity = hashlib.sha256(json.dumps(
                [str(p), st.st_mtime_ns, st.st_size], ensure_ascii=True,
                separators=(",", ":")).encode()).hexdigest()
            stamped.append((st.st_mtime_ns, str(p), p, st.st_size, identity, st.st_mtime))
        stamped.sort(key=lambda row: (row[0], row[1]))
        if since is None:
            since = stamped[-1][0] if stamped else 0
            seen = {row[4] for row in stamped if row[0] == since}
            if len(seen) > _MAX_FILE_BOUNDARY_IDS:
                raise EventSourceError("file timestamp boundary exceeds safe cursor capacity")
            return PollResult(cursor=_encode_cursor("files", [since, sorted(seen)]))
        # A legacy high-water was written from stat.st_mtime. Comparing its
        # rounded float to integer nanoseconds can replay the very same file.
        fresh = [row for row in stamped if (row[5] > stamp if legacy else (
            row[0] > since or (row[0] == since and row[4] not in seen)))]
        fresh = fresh[:_MAX_EVENTS]
        if not fresh:
            # Do not regress after deletion, or turn legacy's fully-consumed
            # timestamp into an empty seen set which would replay old ties.
            return PollResult(cursor=cursor, cursor_format=0 if legacy else 1)
        boundary = fresh[-1][0]
        next_seen = seen.copy() if boundary == since else set()
        next_seen.update(row[4] for row in fresh if row[0] == boundary)
        if len(next_seen) > _MAX_FILE_BOUNDARY_IDS:
            raise EventSourceError("file timestamp boundary exceeds safe cursor capacity")
        events = [_flatten({"id": path_text if legacy else identity, "path": path_text, "name": p.name,
                            "size": sz, "mtime": legacy_mtime if legacy else m / 1_000_000_000})
                  for (m, path_text, p, sz, identity, legacy_mtime) in fresh]
        return PollResult(events=events,
                          cursor=_encode_cursor("files", [boundary, sorted(next_seen)]),
                          event_ids=[row[4] for row in fresh])


register("file_dir", FileDirSource)


# ---- built-in source: watch an IMAP mailbox for new mail -------------------


def _email_body_text(msg) -> str:
    """The first ``text/plain`` part of an email as text, bounded. Falls back to
    the payload for a non-multipart message. Best-effort decode."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain" and \
                        "attachment" not in str(part.get("Content-Disposition") or ""):
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(part.get_content_charset() or "utf-8",
                                              "replace")[:8000]
            return ""
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(msg.get_content_charset() or "utf-8", "replace")[:8000]
    except Exception:  # pragma: no cover -- never let a weird MIME tree break polling
        return ""
    return ""


def _fetch_imap(config: dict, since_uid: int | None,
                uidvalidity: str | None = None) -> tuple[list[dict], int, str]:
    """Fetch messages with UID > ``since_uid`` from an IMAP mailbox. Returns
    ``(messages, highest_uid)`` where each message is a flat header dict. The
    password is read from the env var named by ``password_env`` (never stored in
    config). Isolated at module scope so tests can inject without a live server."""
    import email
    import imaplib
    import os
    import ssl

    from maverick.mail_auth import authenticated_from, valid_trusted_mail_server

    host = str((config or {}).get("host") or "").strip()
    user = str((config or {}).get("username") or "").strip()
    pw_env = str((config or {}).get("password_env") or "").strip()
    if not (host and user and pw_env):
        raise EventSourceError("imap_email source needs 'host', 'username', 'password_env'")
    trusted_server = str((config or {}).get("trusted_authserv_id") or "").strip()
    if not valid_trusted_mail_server(trusted_server):
        raise EventSourceError("Choose the server that checks incoming mail before this automation can start work")
    raw_senders = (config or {}).get("allowed_senders") or ""
    senders = (raw_senders.split(",") if isinstance(raw_senders, str) else raw_senders)
    if not isinstance(senders, list) or not 1 <= len(senders) <= 200 or not any(
        str(sender).strip() for sender in senders
    ):
        raise EventSourceError("Choose permitted email senders before this automation can start work")
    allowed_senders = {str(sender).strip().lower() for sender in senders}
    if any(not re.fullmatch(r"[^@\s,]+@[A-Za-z0-9.-]+", sender) or ".." in sender
           for sender in allowed_senders):
        raise EventSourceError("Permitted email senders must be full email addresses")
    password = os.environ.get(pw_env) or ""
    if not password:
        raise EventSourceError(f"imap_email: env var {pw_env} is unset")
    mailbox = str((config or {}).get("mailbox") or "INBOX")
    port = int((config or {}).get("port") or 993)
    if (config or {}).get("use_ssl", True) is not True:
        raise EventSourceError("An encrypted mail connection is required before this automation can start work")
    include_body = bool((config or {}).get("include_body", False))
    # Headers-only is cheaper; fetch the full message only when the flow needs the
    # body to act on (opt-in), then extract the text/plain part (bounded).
    fetch_spec = "(RFC822)" if include_body else "(RFC822.HEADER)"
    conn = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=30)
    try:
        typ, _ = conn.login(user, password)
        if typ != "OK":
            raise EventSourceError("IMAP login failed")
        typ, _ = conn.select(mailbox, readonly=True)
        if typ != "OK":
            raise EventSourceError("IMAP mailbox selection failed")
        _, validity_data = conn.response("UIDVALIDITY")
        validity = (validity_data[0].decode("ascii")
                    if validity_data and validity_data[0] else "")
        if not validity.isdigit() or int(validity) <= 0:
            raise EventSourceError("IMAP mailbox did not confirm UIDVALIDITY")
        baseline = since_uid is None or (uidvalidity is not None and validity != uidvalidity)
        since = 0 if baseline else since_uid
        # UID search for anything above the last-seen uid; first poll sees all
        # and just records the high-water mark (baseline, no replay).
        typ, data = conn.uid("search", None, f"UID {since + 1}:*")
        if typ != "OK":
            raise EventSourceError("IMAP UID search failed")
        uids = [int(x) for x in (data[0].split() if data and data[0] else []) if int(x) > since]
        if baseline:
            # Search covers the complete UID set, but never fetch historical
            # bodies/headers. A UIDVALIDITY reset establishes a fresh baseline.
            return [], max(uids, default=0), validity
        msgs: list[dict] = []
        highest = since
        for uid in sorted(uids)[:_MAX_EVENTS]:
            typ, mdata = conn.uid("fetch", str(uid), fetch_spec)
            if typ != "OK" or not mdata or not isinstance(mdata[0], tuple):
                raise EventSourceError("IMAP message fetch failed; cursor retained")
            msg = email.message_from_bytes(mdata[0][1])
            sender = authenticated_from(msg, trusted_server)
            highest = max(highest, uid)
            if not sender or sender.lower() not in allowed_senders:
                continue
            rec = {
                "id": f"{validity}:{uid}", "uid": uid,
                "from": sender,
                "_sender_auth": "trusted_dmarc_pass",
                "subject": str(msg.get("Subject", "")),
                "date": str(msg.get("Date", "")),
                "message_id": str(msg.get("Message-ID", "")),
            }
            if include_body:
                rec["body"] = _email_body_text(msg)
            msgs.append(rec)
        return msgs, highest, validity
    finally:
        try:
            conn.logout()
        except Exception:  # pragma: no cover -- best-effort close
            pass


class ImapEmailSource:
    """Fire when a new email arrives in an IMAP mailbox. ``config``: ``{host,
    username, password_env, mailbox?, port?, use_ssl?}``. Dedup + ordering by
    IMAP UID (monotonic within a mailbox): the cursor is the highest UID seen, so
    the first poll only records the high-water mark and never replays the inbox.
    Each event carries ``{uid, from, subject, date, message_id}``; set
    ``include_body: true`` to also fetch the ``text/plain`` body (opt-in, since it
    fetches the full message) so a flow can act on the email content."""
    source = "imap_email"

    def poll(self, config: dict, cursor: str) -> PollResult:
        validity = None
        try:
            raw = _decode_cursor(cursor, "imap", config.get("_lightwork_cursor_format")) if cursor else None
            if isinstance(raw, list) and len(raw) == 2:
                validity, since = raw
                if not isinstance(validity, str) or not validity.isdigit():
                    raise ValueError
            else:
                since = int(raw) if raw is not None else None
            if since is not None and (type(since) is not int or since < 0):
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise EventSourceError("invalid IMAP cursor") from exc
        msgs, highest, current_validity = _fetch_imap(config or {}, since, validity)
        # The first batch after a legacy cursor retains its released flow key
        # (bare UID). A failed cursor publication retries the same old key;
        # versioned cursors subsequently scope flow IDs by UIDVALIDITY.
        legacy = isinstance(raw, str)
        events = [_flatten({**m, "id": str(m["uid"]) if legacy else m["id"]}) for m in msgs]
        return PollResult(events=events,
                          cursor=_encode_cursor("imap", [current_validity, highest]),
                          event_ids=[f"{current_validity}:{m['uid']}" for m in msgs])


register("imap_email", ImapEmailSource)


# ---- built-in source: hosted-form submissions ------------------------------


class FormSource:
    """Fire when a hosted form is submitted. A public ``POST /form/<token>``
    records the submission (:mod:`maverick.form_store`); this polls that store by
    ``token`` so each new submission fires a flow with the form fields as data.
    ``config``: ``{token}``. Dedup + ordering by a per-token monotonic ``seq``,
    so the first poll only records the high-water mark (no replay of old
    submissions) and a backlog drains oldest-first."""
    source = "form"

    def poll(self, config: dict, cursor: str) -> PollResult:
        token = str((config or {}).get("token") or "").strip()
        if not token:
            raise EventSourceError("form source needs a 'token'")
        from . import form_store
        raw = _decode_cursor(cursor, "form", config.get("_lightwork_cursor_format")) if cursor else ""
        events, new_cursor = form_store.since(token, raw, limit=_MAX_EVENTS)
        return PollResult(events=[_flatten(e) for e in events], cursor=_encode_cursor("form", new_cursor),
                          event_ids=[str(e["_seq"]) for e in events])


register("form", FormSource)


def poll_source(source: str, config: dict, cursor: str) -> PollResult:
    """Poll one named source; raises :class:`EventSourceError` on trouble."""
    return get_source(source).poll(config or {}, cursor or "")


def _register_connected_sources():
    from .automation_connected_events import register_sources
    register_sources()


__all__ = [
    "EventSource", "EventSourceError", "EventSourceTooLarge", "PollResult",
    "available_sources", "get_source", "register", "enabled",
    "poll_source", "diff_new_items", "HttpJsonSource", "RssSource",
    "OAuthHttpJsonSource", "GithubIssuesSource", "FileDirSource", "ImapEmailSource",
    "FormSource",
]
