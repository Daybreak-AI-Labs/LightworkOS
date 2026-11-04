"""LLM response cache (SQLite-backed, content-addressed).

Cache LLM completions by a stable hash of (provider, model, system,
messages, tools, max_tokens, thinking_budget). On a cache hit the
LLM call is skipped entirely — useful in two cases:

  - tests / dev: identical prompts shouldn't burn budget
  - production: idempotent re-runs (re-execute the same goal) reuse
    prior intermediate completions

Tradeoffs:
  - Cache misses cost nothing extra (just one SQLite lookup).
  - The cache is opt-in: ``MAVERICK_LLM_CACHE=1`` or programmatic
    enable. The agent kernel doesn't read from cache automatically;
    callers wire it via ``cache_key(...)`` to derive the key, then
    ``get().lookup(key)`` to read and ``get().store(key, ...)`` to write.

Storage: a tenant-resolved private SQLite WAL store. Every row is additionally
scoped to the exact active tenant/client and authenticated principal, including
when callers deliberately point multiple authorities at one explicit DB. TTL
evicts on read (no background thread).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..file_lock import (
    atomic_create_bytes,
    ensure_private_file,
    prepare_private_directory,
)
from ..paths import current_tenant_id, data_dir

log = logging.getLogger(__name__)


# ``DEFAULT_DB`` remains a Path for compatibility with older callers that
# inspect or monkeypatch it. Its original object is a sentinel, however: while
# untouched, the real path is resolved at *construction/call* time so importing
# this module in tenant A cannot freeze A's path for tenant B. A monkeypatched
# replacement still acts as the historical explicit test/operator override.
_INITIAL_DEFAULT_DB = data_dir("cache", "llm", "responses.sqlite3")
DEFAULT_DB = _INITIAL_DEFAULT_DB
DEFAULT_TTL_S = 7 * 24 * 3600  # 7 days


_CREATE_RESPONSES = """
CREATE TABLE IF NOT EXISTS responses (
  authority   TEXT NOT NULL,
  key         TEXT PRIMARY KEY,
  provider    TEXT NOT NULL,
  model       TEXT NOT NULL,
  text        TEXT NOT NULL,
  thinking    TEXT NOT NULL DEFAULT '',
  stop_reason TEXT NOT NULL DEFAULT '',
  created_at  REAL NOT NULL,
  hit_count   INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_responses_authority_created "
    "ON responses(authority, created_at)",
)


@dataclass
class CachedResponse:
    key: str
    text: str
    thinking: str
    stop_reason: str
    provider: str
    model: str
    created_at: float
    hit_count: int


def _enabled_via_env() -> bool:
    from ..env_setting import env_or_config

    return (env_or_config("MAVERICK_LLM_CACHE", "cache", "llm_responses") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _stable_dump(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)


def default_db_path() -> Path:
    """Return the cache DB for the active tenant/client at call time.

    Assigning a different Path to :data:`DEFAULT_DB` remains a supported
    compatibility override for tests and operators.
    """
    if DEFAULT_DB is not _INITIAL_DEFAULT_DB:
        return Path(DEFAULT_DB).expanduser()
    return data_dir("cache", "llm", "responses.sqlite3")


def _authority_id() -> str:
    """Opaque, durable identity for the active cache authority.

    Principal bytes are intentionally not normalised: ``user:alice`` and
    ``user:alice `` are distinct authenticated identities elsewhere in the
    runtime and must remain distinct here too. Hashing prevents tenant/user
    identifiers from becoming SQLite metadata while preserving exactness.
    """
    from ..connections import current_principal

    identity = {
        "version": 1,
        "tenant": current_tenant_id(),
        "principal": current_principal(),
    }
    encoded = _stable_dump(identity).encode("utf-8")
    return hashlib.sha256(b"maverick:llm-cache:authority:\0" + encoded).hexdigest()


def _storage_key(authority: str, key: str) -> str:
    # The physical primary key includes the scope so identical prompt hashes
    # from two principals can coexist even on one operator-supplied DB.
    return f"{authority}:{key}"


def cache_key(
    *,
    provider: str,
    model: str,
    system: str,
    messages: list[dict] | None,
    tools: list[dict] | None,
    max_tokens: int,
    thinking_budget: int | None = None,
) -> str:
    """Stable SHA-256 of the inputs that uniquely identify a completion."""
    payload = {
        "provider": provider,
        "model": model,
        "system": system,
        "messages": messages or [],
        "tools": tools or [],
        "max_tokens": int(max_tokens),
        "thinking_budget": thinking_budget,
    }
    return hashlib.sha256(_stable_dump(payload).encode("utf-8")).hexdigest()


class LLMCache:
    """Thread-safe SQLite cache. Multiple instances over the same DB are safe."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        ttl_seconds: float = DEFAULT_TTL_S,
        max_rows: int = 5000,
    ) -> None:
        self.db_path = Path(
            default_db_path() if db_path is None else db_path
        ).expanduser()
        # SQLite creates ``-wal``/``-shm`` beside the DB. The parent therefore
        # is the confidentiality boundary, not merely the main file. A missing
        # dedicated parent is created private; an existing caller-supplied one
        # must already be private and is never silently chmod/DACL-mutated.
        prepare_private_directory(self.db_path.parent)
        try:
            atomic_create_bytes(self.db_path, b"")
        except FileExistsError:
            pass
        ensure_private_file(self.db_path)
        self.ttl_seconds = float(ttl_seconds)
        # Hard cap on stored rows. TTL eviction is lazy (on read of the
        # expired key), so without a count cap a stream of unique prompts
        # would grow the DB without bound between purge_expired() sweeps.
        self.max_rows = int(max_rows) if max_rows and max_rows > 0 else 0
        self._lock = threading.Lock()
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(str(self.db_path), isolation_level=None)
        try:
            c.execute("PRAGMA secure_delete=ON")
            c.execute("PRAGMA busy_timeout=5000")
            c.execute("PRAGMA journal_mode=WAL")
            # Harden pre-existing DBs upgraded from older releases and any WAL
            # sidecars already materialised by SQLite. Their private parent is
            # what closes the creation-time exposure window.
            ensure_private_file(self.db_path)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{self.db_path}{suffix}")
                if sidecar.exists():
                    ensure_private_file(sidecar)
            c.row_factory = sqlite3.Row
            yield c
        finally:
            c.close()

    def _ensure_schema(self) -> None:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute(_CREATE_RESPONSES)
                columns = {
                    str(row[1]) for row in c.execute("PRAGMA table_info(responses)")
                }
                if "authority" not in columns:
                    # Legacy rows carry no trustworthy tenant/principal
                    # provenance. Never guess and expose them to whichever
                    # identity happens to touch the upgraded process first.
                    c.execute(
                        "ALTER TABLE responses ADD COLUMN authority TEXT "
                        "NOT NULL DEFAULT ''"
                    )
                    c.execute("DELETE FROM responses")
                    log.warning(
                        "purged legacy unscoped LLM cache rows during authority migration"
                    )
                for statement in _CREATE_INDEXES:
                    c.execute(statement)
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    def lookup(self, key: str, *, now: float | None = None) -> CachedResponse | None:
        n = now if now is not None else time.time()
        authority = _authority_id()
        stored_key = _storage_key(authority, key)
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT * FROM responses WHERE authority=? AND key=?",
                (authority, stored_key),
            ).fetchone()
            if row is None:
                return None
            age = n - float(row["created_at"])
            if self.ttl_seconds and age > self.ttl_seconds:
                c.execute(
                    "DELETE FROM responses WHERE authority=? AND key=?",
                    (authority, stored_key),
                )
                return None
            c.execute(
                "UPDATE responses SET hit_count=hit_count+1 "
                "WHERE authority=? AND key=?",
                (authority, stored_key),
            )
        return CachedResponse(
            key=key,
            text=str(row["text"]),
            thinking=str(row["thinking"] or ""),
            stop_reason=str(row["stop_reason"] or ""),
            provider=str(row["provider"]),
            model=str(row["model"]),
            created_at=float(row["created_at"]),
            hit_count=int(row["hit_count"]) + 1,
        )

    def store(
        self,
        key: str,
        *,
        provider: str,
        model: str,
        text: str,
        thinking: str = "",
        stop_reason: str = "",
    ) -> None:
        now = time.time()
        authority = _authority_id()
        stored_key = _storage_key(authority, key)
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO responses "
                "(authority, key, provider, model, text, thinking, stop_reason, "
                " created_at, hit_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    authority, stored_key, provider, model, text, thinking,
                    stop_reason, now,
                ),
            )
            if self.max_rows:
                # Same TTL+LRU-count-cap policy as cache.eviction (shared with
                # the learning cache), expressed in SQL here because this store
                # is SQLite rows rather than an in-memory dict.
                # Evict beyond the cap by recency (true LRU). The previous
                # `ORDER BY hit_count DESC` evicted the row we JUST inserted
                # (hit_count=0) whenever the cache was full of hit rows, so
                # under a stream of unique prompts the cache stopped
                # accepting new entries entirely (thrash -> ~0% hit rate).
                # Ordering by created_at keeps the newest, so the just-
                # stored row always survives.
                c.execute(
                    "DELETE FROM responses WHERE authority=? AND key NOT IN ("
                    "  SELECT key FROM responses WHERE authority=? "
                    "  ORDER BY created_at DESC, rowid DESC LIMIT ?)",
                    (authority, authority, self.max_rows),
                )

    def purge_expired(self, *, now: float | None = None) -> int:
        if not self.ttl_seconds:
            return 0
        n = now if now is not None else time.time()
        cutoff = n - self.ttl_seconds
        authority = _authority_id()
        with self._lock, self._conn() as c:
            cur = c.execute(
                "DELETE FROM responses WHERE authority=? AND created_at < ?",
                (authority, cutoff),
            )
            return cur.rowcount

    def stats(self) -> dict:
        authority = _authority_id()
        with self._conn() as c:
            row = c.execute(
                "SELECT COUNT(*) AS n, SUM(hit_count) AS hits, "
                "MIN(created_at) AS oldest FROM responses WHERE authority=?",
                (authority,),
            ).fetchone()
        return {
            "entries": int(row["n"] or 0),
            "hits":    int(row["hits"] or 0),
            "oldest":  float(row["oldest"] or 0.0),
        }

    def clear(self) -> None:
        """Clear only the exact active tenant/principal authority."""
        authority = _authority_id()
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM responses WHERE authority=?", (authority,))

    def purge_all_authorities_for_erasure(self, *, confirmed: bool = False) -> int:
        """Clear every authority in this tenant database for a legal erasure.

        Prompt keys are content hashes and cannot be mapped reliably back to a
        data subject.  The GDPR erase path therefore drops this disposable
        cache wholesale.  Ordinary callers must use :meth:`clear`, which is
        authority-scoped; this deliberately loud API requires the CLI's prior
        irreversible-operation confirmation so a routine user cannot erase
        another principal's cache accidentally.
        """
        if confirmed is not True:
            raise PermissionError(
                "all-authority cache purge requires confirmed subject erasure"
            )
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM responses")
            return int(cur.rowcount)


_singleton_lock = threading.Lock()
_singletons: weakref.WeakValueDictionary[tuple[str, str], LLMCache] = (
    weakref.WeakValueDictionary()
)


def get(db_path: Path | None = None) -> LLMCache:
    """Return the lazy cache instance for the active authority and DB.

    Long-lived processes may switch tenant/client and principal contexts. A
    single process-global object would retain the first identity's default DB;
    the registry therefore keys on both the resolved path and exact authority.
    Explicit DBs are keyed the same way and row-level scoping remains active.
    """
    path = Path(default_db_path() if db_path is None else db_path).expanduser()
    canonical_path = os.path.normcase(str(path.resolve(strict=False)))
    registry_key = (canonical_path, _authority_id())
    # Weak values prevent an unbounded stream of authenticated principals from
    # becoming a process-lifetime memory leak. A caller holding an instance
    # keeps it stable; otherwise recreating this lightweight wrapper is safe.
    with _singleton_lock:
        instance = _singletons.get(registry_key)
        if instance is None:
            instance = LLMCache(db_path=path)
            _singletons[registry_key] = instance
        return instance


def enabled() -> bool:
    return _enabled_via_env()


__all__ = [
    "LLMCache", "CachedResponse", "cache_key", "get",
    "enabled", "DEFAULT_DB", "DEFAULT_TTL_S", "default_db_path",
]
