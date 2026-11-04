"""Federated content catalog for skills, plugins, MCP servers, personas.

A catalog is a JSON index hosted anywhere (GitHub Pages on an
``awesome-maverick-*`` repo is the zero-ops v1 host). Each index lists
installable entries with a content hash so the client can verify the
bytes it fetches match what the curator indexed.

Schema (one ``index.json`` per kind, served at
``<base>/<kind>/index.json``)::

    {
      "schema_version": 1,
      "kind": "skills",
      "entries": [
        {
          "name": "summarize-url",
          "version": "1.0.0",
          "summary": "Fetch a URL and summarise it.",
          "source": "gh:cdayAI/awesome-maverick-skills:summarize-url/SKILL.md",
          "sha256": "<hex digest of the fetched content>",
          "author": "cdayAI",
          "verified": true,
          "install_count": 0
        }
      ]
    }

Trust model: the index is curated (a PR against the awesome-list adds
an entry). On install the client fetches the entry's ``source`` and
verifies the SHA-256 matches the index. Because the content is both
curated AND hash-pinned, catalog installs don't require the
``MAVERICK_ALLOW_SKILL_INSTALL`` opt-in that free-text URL installs do.

The pinned SHA-256 is only integrity-in-transit: the index and the
content are served from the SAME unauthenticated host, so an attacker
controlling that host supplies both the bytes AND their hash. The
``verified`` field below is likewise SELF-ASSERTED by the index and is
NOT a trust signal. Real authenticity comes from the Ed25519
skill-signature path in ``skills`` (``trusted_pubkeys`` /
``require_signed_catalog``): a catalog install resolves to a skill whose
signature verifies against a trusted publisher, and the genuine verified
status is reported on the installed ``Skill.verified`` -- not on this
entry's ``verified`` bool.

Self-hosting: point ``[catalogs] indexes`` at your own base URL(s).
Multiple indexes merge; earlier indexes win on name collision.
"""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .constant_time import text_equals
from .paths import data_dir

log = logging.getLogger(__name__)

VALID_KINDS = ("skills", "plugins", "mcp", "personas", "templates")
SCHEMA_VERSION = 1
FETCH_TIMEOUT = 15.0
#: A page render must never wait long on the catalog host: the dashboard
#: shows an empty store and the next visit (or a background refresh) retries.
PAGE_FETCH_TIMEOUT = 3.0
_CACHE_TTL = 6 * 3600  # 6 hours
#: After a failed fetch, how long ``_fetch_index_raw`` serves the stale cache
#: (or nothing) without touching the network again. Without it an offline or
#: air-gapped install re-attempted the fetch on every Skill Store view.
NEGATIVE_CACHE_TTL = 60.0
_CACHE_DIR = data_dir("cache", "catalog")

# Default index host. Until maverick.dev is registered this points at
# the awesome-list raw content on GitHub (zero-ops Pages host). The
# client tolerates an unreachable index by returning an empty list, so
# a fresh install simply shows "no catalog entries" rather than erroring.
DEFAULT_INDEXES = (
    "https://raw.githubusercontent.com/cdayAI/awesome-maverick/main/catalog",
)


class CatalogError(Exception):
    """Raised on hash mismatch or malformed index entry."""


def _safe_rating(v) -> float:
    """Clamp a self-asserted rating to [0, 5]; malformed -> 0 (unrated),
    never an exception (one bad field must not hide the whole catalog)."""
    try:
        return max(0.0, min(5.0, float(v or 0)))
    except (TypeError, ValueError):
        return 0.0


def _safe_count(v) -> int:
    try:
        return max(0, int(v or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


@dataclass(frozen=True)
class CatalogEntry:
    name: str
    version: str
    kind: str
    summary: str
    source: str
    sha256: str
    author: str = ""
    # Kept for API compatibility. An index cannot assert publisher
    # verification; verified status is determined only after installation.
    verified: bool = False
    install_count: int = 0
    # Community rating carried by the index (display-only, like
    # install_count): average stars (0 = unrated) + how many ratings.
    rating: float = 0.0
    ratings_count: int = 0
    # Inline payload for kinds whose installable artifact IS configuration rather
    # than a separate fetched file. The MCP registry uses this to carry the
    # server spec (command/args/env or url/headers) directly in the index, since
    # an MCP server's supply-chain defense is pin_sha256 at spawn, not a hash of
    # the (config-only) spec text. Empty for content kinds (skills/personas),
    # which fetch `source` and verify `sha256`.
    spec: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, kind: str, d: dict) -> CatalogEntry:
        if not isinstance(d, dict):
            raise CatalogError("catalog entry must be an object")
        # An inline-spec entry (e.g. MCP) is installable from `spec` alone, so
        # `source` is optional there; content kinds still require it.
        spec = d.get("spec") if isinstance(d.get("spec"), dict) else {}
        if not d.get("name") or (not d.get("source") and not spec):
            raise CatalogError(f"catalog entry missing name/source: {d!r}")
        return cls(
            name=str(d["name"]),
            version=str(d.get("version", "0.0.0")),
            kind=kind,
            summary=str(d.get("summary", "")),
            source=str(d.get("source", "")),
            sha256=str(d.get("sha256", "")),
            author=str(d.get("author", "")),
            verified=False,
            install_count=_safe_count(d.get("install_count")),
            rating=_safe_rating(d.get("rating")),
            ratings_count=_safe_count(d.get("ratings_count")),
            spec=spec,
        )

    def to_dict(self) -> dict:
        d = {
            "name": self.name, "version": self.version, "kind": self.kind,
            "summary": self.summary, "source": self.source, "sha256": self.sha256,
            "author": self.author, "verified": self.verified,
            "install_count": self.install_count,
        }
        if self.ratings_count:
            d["rating"] = round(self.rating, 2)
            d["ratings_count"] = self.ratings_count
        if self.spec:
            d["spec"] = self.spec
        return d


def _configured_indexes() -> list[str]:
    """Index base URLs from ``[catalogs] indexes`` in config, else default."""
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("catalogs") or {}
        indexes = cfg.get("indexes")
        if isinstance(indexes, list) and indexes:
            return [str(i).rstrip("/") for i in indexes]
    except Exception as e:
        log.debug("catalog: config read failed: %s", e)
    return [i.rstrip("/") for i in DEFAULT_INDEXES]


def _cache_path(url: str) -> Path:
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    return _CACHE_DIR / f"{h}.json"


# Latency-sensitive callers (the per-goal self-learning preflight) opt into
# serving the on-disk index whatever its age and refreshing it off the hot
# path, so a chat turn never waits on the catalog host.
_CACHED_FIRST: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "maverick_catalog_cached_first", default=False,
)
_REFRESHING: set[str] = set()
_REFRESH_LOCK = threading.Lock()
_FETCH_TIMEOUT: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "maverick_catalog_fetch_timeout", default=None,
)
#: url -> monotonic deadline until which a failed fetch is not retried.
_NEGATIVE: dict[str, float] = {}


def _negative_cached(url: str) -> bool:
    deadline = _NEGATIVE.get(url)
    if deadline is None:
        return False
    if time.monotonic() < deadline:
        return True
    _NEGATIVE.pop(url, None)
    return False


def _read_stale(cache: Path) -> dict | None:
    if not cache.exists():
        return None
    try:
        return json.loads(cache.read_text())
    except (OSError, ValueError):
        return None


@contextlib.contextmanager
def cached_first():
    """Inside this block ``load_catalog`` never awaits the network: a cached
    index is served at any age and refreshed in the background; a missing one
    counts as empty for this call and is fetched for the next."""
    token = _CACHED_FIRST.set(True)
    try:
        yield
    finally:
        _CACHED_FIRST.reset(token)


def _refresh_in_background(url: str) -> None:
    with _REFRESH_LOCK:
        if url in _REFRESHING:
            return
        _REFRESHING.add(url)

    def _run() -> None:
        try:
            _fetch_index_raw(url)
        except Exception:  # pragma: no cover -- a refresh never raises anywhere visible
            log.debug("catalog: background refresh of %s failed", url, exc_info=True)
        finally:
            with _REFRESH_LOCK:
                _REFRESHING.discard(url)

    threading.Thread(target=_run, name="maverick-catalog-refresh", daemon=True).start()


def _fetch_index_cached_first(url: str) -> dict | None:
    """The cached index for ``url`` at any age (None when there is none),
    scheduling a background refresh when it is stale or missing."""
    cache = _cache_path(url)
    data = None
    fresh = False
    if cache.exists():
        try:
            data = json.loads(cache.read_text())
            fresh = (time.time() - cache.stat().st_mtime) < _CACHE_TTL
        except (OSError, ValueError):
            data = None
    if not fresh:
        _refresh_in_background(url)
    return data


def _fetch_index_raw(url: str) -> dict | None:
    """Fetch + parse one index JSON, with a 6h on-disk cache.

    Returns None (not raise) on any network/parse failure so an
    unreachable catalog degrades to "no entries" rather than breaking
    the dashboard. A failure is remembered for ``NEGATIVE_CACHE_TTL``
    seconds: until then the stale cache (or None) is served with no
    network attempt.
    """
    cache = _cache_path(url)
    if cache.exists():
        try:
            age = time.time() - cache.stat().st_mtime
            if age < _CACHE_TTL:
                return json.loads(cache.read_text())
        except (OSError, ValueError):
            pass
    if not url.startswith("https://"):
        log.warning("catalog: refusing non-https index url %s", url)
        return None
    if _negative_cached(url):
        return _read_stale(cache)
    # Shared SSRF guard: a configured index URL must not resolve to a
    # private/loopback/link-local/metadata address.
    from .tools.http_fetch import guarded_urlopen
    timeout = _FETCH_TIMEOUT.get() or FETCH_TIMEOUT
    try:
        with guarded_urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                _NEGATIVE[url] = time.monotonic() + NEGATIVE_CACHE_TTL
                return None
            data = json.loads(resp.read(2_000_000).decode("utf-8"))
    except Exception as e:
        log.info("catalog: fetch %s failed: %s", url, e)
        _NEGATIVE[url] = time.monotonic() + NEGATIVE_CACHE_TTL
        # Serve stale cache if we have it.
        return _read_stale(cache)
    _NEGATIVE.pop(url, None)
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data))
    except OSError:
        pass
    return data


def load_catalog(
    kind: str, *, indexes: list[str] | None = None, timeout: float | None = None,
) -> list[CatalogEntry]:
    """Return merged catalog entries for ``kind`` across all indexes.

    Earlier indexes win on name collision. Malformed entries are
    skipped with a log line, not raised — one bad entry shouldn't hide
    the whole catalog. ``timeout`` bounds each index fetch (default
    ``FETCH_TIMEOUT``); page renders pass ``PAGE_FETCH_TIMEOUT``.
    """
    if kind not in VALID_KINDS:
        raise CatalogError(f"unknown kind {kind!r}; valid: {', '.join(VALID_KINDS)}")
    bases = indexes if indexes is not None else _configured_indexes()
    seen: dict[str, CatalogEntry] = {}
    fetch = _fetch_index_cached_first if _CACHED_FIRST.get() else _fetch_index_raw
    token = _FETCH_TIMEOUT.set(timeout)
    try:
        for base in bases:
            url = f"{base.rstrip('/')}/{kind}/index.json"
            data = fetch(url)
            if not isinstance(data, dict) or not isinstance(data.get("entries", []), list):
                log.info("catalog: skipping malformed index in %s", url)
                continue
            for raw in data.get("entries", []):
                try:
                    entry = CatalogEntry.from_dict(kind, raw)
                except CatalogError as e:
                    log.info("catalog: skipping bad entry in %s: %s", url, e)
                    continue
                seen.setdefault(entry.name, entry)
    finally:
        _FETCH_TIMEOUT.reset(token)
    return sorted(seen.values(), key=lambda e: e.name)


def resolve(name: str, kind: str, *, indexes: list[str] | None = None) -> CatalogEntry | None:
    """Find a single entry by name, or None."""
    for entry in load_catalog(kind, indexes=indexes):
        if entry.name == name:
            return entry
    return None


def verify_sha256(content: str | bytes, expected: str) -> bool:
    """True iff the SHA-256 of ``content`` matches ``expected`` (hex).

    Pass the raw fetched ``bytes`` whenever they are available: the pin is
    the digest of the published file's wire bytes, and a curator hashing the
    raw file (e.g. ``sha256sum``) over content with any non-UTF-8 sequence
    would otherwise never match a hash recomputed from a lossily-decoded
    ``str`` (``errors="replace"`` substitutes U+FFFD, changing the bytes).
    A ``str`` is still accepted and hashed as UTF-8 for callers that only
    have decoded text.

    An empty expected hash returns False: a catalog entry MUST pin a
    hash to be installable without the free-text opt-in gate.
    """
    if not expected:
        return False
    raw = content if isinstance(content, bytes) else content.encode("utf-8")
    actual = hashlib.sha256(raw).hexdigest()
    return text_equals(actual, expected.lower())


__all__ = [
    "CatalogEntry", "CatalogError", "VALID_KINDS", "DEFAULT_INDEXES",
    "load_catalog", "resolve", "verify_sha256",
]
