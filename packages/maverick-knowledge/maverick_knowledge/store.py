"""Vector stores.

:class:`SqliteVectorStore` is a dependency-free brute-force cosine index -- fine
for the per-business corpora the factory produces; pgvector is an opt-in backend
for scale (``build_store`` selects it when configured).
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import operator
import sqlite3
import threading
from contextlib import closing, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .provider_accounting import metered_operation


@dataclass
class Match:
    score: float
    text: str
    meta: dict[str, Any]


@dataclass(frozen=True)
class StoredChunk:
    """One exact stored chunk returned without similarity ranking."""

    chunk_id: str
    text: str
    meta: dict[str, Any]


@dataclass(frozen=True)
class _ExactIndex:
    """A bounded, process-local index from a completely validated snapshot."""

    collection: str
    key: str
    value: str
    data_version: int
    local_changes: int
    ids: tuple[str, ...]


_MAX_EXACT_INDEX_IDS = 4096
_MAX_EXACT_INDEX_CHARS = 1_000_000
_MAX_EXACT_INDEX_KEY_CHARS = 4096


class VectorStore(Protocol):
    def add(self, collection: str, items: list[tuple[str, str, list[float], dict]]) -> None: ...

    def add_with_identity(
        self, collection: str, items: list[tuple[str, str, list[float], dict]], fingerprint: str,
        *, effect_guard=None, publication_scope=None,
    ) -> None:
        """Atomically bind immutable document provenance and embedding identity."""
        ...

    def replace_source_with_identity(
        self, collection: str, items: list[tuple[str, str, list[float], dict]], fingerprint: str,
        *, source: str, snapshot: list[StoredChunk], effect_guard=None, publication_scope=None,
    ) -> None:
        """Compare the prior source and atomically publish its complete revision."""
        ...

    def search(self, collection: str, vector: list[float], k: int = 5) -> list[Match]: ...

    def delete_collection(self, collection: str) -> None: ...

    def collections(self) -> list[str]: ...

    def delete_where(self, collection: str, key: str, value: str) -> int: ...

    def count_where(self, collection: str, key: str, value: str) -> int: ...

    def count(self, collection: str) -> int: ...

    def read_where(
        self, collection: str, key: str, value: str, *, limit: int,
    ) -> list[StoredChunk]: ...


def _cosine(a: list[float], b: list[float], *, a_norm: float | None = None) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a)) if a_norm is None else a_norm
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _score_sqlite_rows(rows, vector, collection):
    """Decode and validate every row, computing the query norm once."""
    query_norm = None
    for text, vec, meta in rows:
        stored = json.loads(vec)
        if len(stored) != len(vector):
            raise ValueError(
                f"knowledge: query vector dim {len(vector)} != stored dim "
                f"{len(stored)} for collection {collection!r}; the corpus was "
                "embedded with a different embedder/model than this query"
            )
        if query_norm is None:
            query_norm = math.sqrt(sum(x * x for x in vector))
        yield Match(_cosine(vector, stored, a_norm=query_norm), text, json.loads(meta))


def _document_publication(items: list, existing: list[StoredChunk]) -> list:
    """Validate admitted provenance under the writer's transaction/fence.

    Matching retries keep the admitted rows (including timestamps and vectors).
    A partial matching document can add missing chunks with its original time.
    The caller must hold the publication fence until these additions commit.
    """
    incoming = {cid: (text, vec, meta) for cid, text, vec, meta in items}
    if len(incoming) != len(items):
        raise ValueError("knowledge publication has duplicate chunk identifiers")
    documents = {meta["doc_sha256"] for _cid, _text, _vec, meta in items}
    timestamps = {}
    admitted = set()
    for row in existing:
        digest = row.meta.get("doc_sha256")
        if row.chunk_id not in incoming and digest not in documents:
            continue
        candidate = incoming.get(row.chunk_id)
        if (candidate is None or row.text != candidate[0]
                or {key: value for key, value in row.meta.items() if key != "ingested_at"}
                != {key: value for key, value in candidate[2].items() if key != "ingested_at"}):
            raise RuntimeError("knowledge document digest is already bound to different provenance")
        timestamp = row.meta["ingested_at"]
        if digest in timestamps and timestamps[digest] != timestamp:
            raise RuntimeError("knowledge document admitted timestamps are inconsistent")
        timestamps[digest] = timestamp
        admitted.add(row.chunk_id)
    return [
        (cid, text, vec, {**meta, "ingested_at": timestamps.get(meta["doc_sha256"], meta["ingested_at"])})
        for cid, text, vec, meta in items if cid not in admitted
    ]


def _source_replacement_removals(
    items: list, existing: list[StoredChunk], source: str, snapshot: list[StoredChunk],
) -> list[str]:
    """Validate a staged replacement under the same fence as publication."""
    if not source or not items or any(meta.get("source") != source for _, _, _, meta in items):
        raise ValueError("knowledge source replacement requires one nonempty source")
    current = sorted(
        (row for row in existing if row.meta.get("source") == source),
        key=lambda row: row.chunk_id,
    )
    if current != sorted(snapshot, key=lambda row: row.chunk_id):
        raise RuntimeError("knowledge source changed during replacement; retry")
    incoming = {cid for cid, _, _, _ in items}
    return [row.chunk_id for row in current if row.chunk_id not in incoming]


class SqliteVectorStore:
    """Brute-force cosine over vectors stored as JSON in SQLite.

    One row per chunk, scoped by ``collection`` (the domain's knowledge source),
    so retrieval is filtered per domain -- knowledge respects the compartment
    bulkheads. ``:memory:`` (the default) is used by tests.
    """

    def __init__(self, path: str | Path = ":memory:"):
        # Create the parent dir for a file-backed store (e.g. a tenant's
        # ~/.maverick/tenants/<t>/knowledge.db) -- sqlite3.connect won't, and
        # would raise on a missing directory. ":memory:" needs no dir.
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # KnowledgeBase shares one store across threads (ingestion runs under
        # asyncio.to_thread / a worker pool), so allow cross-thread use and
        # serialize access with a lock -- a single sqlite connection is not safe
        # for concurrent use.
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._exact_index: _ExactIndex | None = None
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS chunks ("
            "collection TEXT, id TEXT, text TEXT, vec TEXT, meta TEXT, "
            "PRIMARY KEY (collection, id))"
        )
        self._db.commit()

    def add(self, collection, items) -> None:
        with self._lock:
            self._exact_index = None
            self._db.executemany(
                "INSERT OR REPLACE INTO chunks VALUES (?,?,?,?,?)",
                [
                    (collection, cid, text, json.dumps(vec), json.dumps(meta))
                    for cid, text, vec, meta in items
                ],
            )
            self._db.commit()

    def add_with_identity(self, collection, items, fingerprint: str, *, effect_guard=None, publication_scope=None) -> None:
        """Bind document provenance and identity in one publication transaction."""
        self._publish_with_identity(collection, items, fingerprint, effect_guard=effect_guard, publication_scope=publication_scope)

    def replace_source_with_identity(
        self, collection, items, fingerprint: str, *, source: str, snapshot: list[StoredChunk], effect_guard=None, publication_scope=None,
    ) -> None:
        self._publish_with_identity(collection, items, fingerprint, source=source, snapshot=snapshot,
                                    effect_guard=effect_guard, publication_scope=publication_scope)

    def _publish_with_identity(
        self, collection, items, fingerprint: str, *, source: str | None = None, snapshot=None, effect_guard=None, publication_scope=None,
    ) -> None:
        with publication_scope() if publication_scope is not None else nullcontext(), self._lock, self._db:
            self._exact_index = None
            self._db.execute("BEGIN IMMEDIATE")
            if effect_guard is not None:
                effect_guard()
            rows = self._db.execute(
                "SELECT id, text, meta FROM chunks WHERE collection = ?", (collection,),
            )
            chunk_ids = {item[0] for item in items}
            documents = {item[3]["doc_sha256"] for item in items}
            existing = []
            for cid, text, raw_meta in rows:
                meta = json.loads(raw_meta)
                if meta.get("embedding_fingerprint") != fingerprint:
                    raise RuntimeError("knowledge collection changed embedding identity; reindex required")
                if (cid in chunk_ids or meta.get("doc_sha256") in documents
                        or (source is not None and meta.get("source") == source)):
                    existing.append(StoredChunk(cid, text, meta))
            removed = (
                _source_replacement_removals(items, existing, source, snapshot)
                if source is not None else []
            )
            pending = _document_publication(items, existing)
            if effect_guard is not None:
                effect_guard()
            self._db.executemany(
                "INSERT INTO chunks VALUES (?,?,?,?,?)",
                [(collection, cid, text, json.dumps(vec), json.dumps(meta))
                 for cid, text, vec, meta in pending],
            )
            self._db.executemany(
                "DELETE FROM chunks WHERE collection = ? AND id = ?",
                [(collection, cid) for cid in removed],
            )
            if effect_guard is not None:
                effect_guard()

    def search(self, collection, vector, k: int = 5) -> list[Match]:
        if k <= 0:
            return []
        k = operator.index(k)
        with self._lock:
            rows = self._db.execute(
                "SELECT text, vec, meta FROM chunks WHERE collection = ?", (collection,)
            ).fetchall()
        # Keep at most k matches while still validating every row. The ordinal
        # makes ties stable: earlier rows win, matching the original sort.
        best: list[tuple[float, int, Match]] = []
        for ordinal, match in enumerate(_score_sqlite_rows(rows, vector, collection)):
            if not math.isfinite(match.score):
                # NaN is not totally ordered. Preserve Python's original stable
                # sort for the whole snapshot, not heap ordering around NaNs.
                scored = list(_score_sqlite_rows(rows, vector, collection))
                scored.sort(key=lambda item: item.score, reverse=True)
                return scored[:k]
            item = (match.score, -ordinal, match)
            if len(best) < k:
                heapq.heappush(best, item)
            else:
                heapq.heappushpop(best, item)
        best.sort(reverse=True)
        return [match for _score, _ordinal, match in best]

    def delete_collection(self, collection: str) -> None:
        """Remove all chunks for one collection."""
        with self._lock:
            self._exact_index = None
            self._db.execute("DELETE FROM chunks WHERE collection = ?", (collection,))
            self._db.commit()

    def collections(self) -> list[str]:
        """Every collection with at least one chunk (the erasure sweep surface)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT collection FROM chunks ORDER BY collection"
            ).fetchall()
        return [r[0] for r in rows]

    def delete_where(self, collection: str, key: str, value: str) -> int:
        """Delete every chunk whose ``meta[key] == value``. Returns the count.

        The GDPR erasure primitive: a subject's or source's chunks are removed
        by provenance, not by similarity. Meta is matched in Python (no JSON1
        dependency) — collections are per-domain corpora, not billion-row sets.
        """
        with self._lock:
            self._exact_index = None
            rows = self._db.execute(
                "SELECT id, meta FROM chunks WHERE collection = ?", (collection,)
            )
            doomed = [
                cid for cid, meta in rows
                if (json.loads(meta or "{}")).get(key) == value
            ]
            if doomed:
                self._db.executemany(
                    "DELETE FROM chunks WHERE collection = ? AND id = ?",
                    [(collection, cid) for cid in doomed],
                )
                self._db.commit()
        return len(doomed)

    def count_where(self, collection: str, key: str, value: str) -> int:
        """Chunks whose ``meta[key] == value`` — the erasure-verify primitive."""
        with self._lock:
            with self._exact_snapshot(collection) as token:
                cached = self._matching_exact_index(collection, key, value, token)
                if cached is not None:
                    return len(cached.ids)
                total = 0
                ids: list[str] | None = []
                id_chars = 0
                with closing(self._db.execute(
                    "SELECT id, meta FROM chunks WHERE collection = ? ORDER BY id", (collection,)
                )) as rows:
                    for chunk_id, meta in rows:
                        if (json.loads(meta or "{}")).get(key) == value:
                            total += 1
                            if ids is not None:
                                if (type(chunk_id) not in (str,) or len(ids) >= _MAX_EXACT_INDEX_IDS
                                        or id_chars + len(chunk_id) > _MAX_EXACT_INDEX_CHARS):
                                    ids = None
                                else:
                                    ids.append(chunk_id)
                                    id_chars += len(chunk_id)
                if (token is not None and ids is not None
                        and self._exact_indexable(collection, key, value)):
                    self._exact_index = _ExactIndex(collection, key, value, *token, tuple(ids))
                else:
                    self._exact_index = None
                return total

    @contextmanager
    def _exact_snapshot(self, collection):
        """Pin a snapshot only when SQLite can prove external-write freshness.

        A cache is never consulted inside a caller-owned transaction. An
        unsupported data-version pragma or failed snapshot setup simply leaves
        the caller on the authoritative scan path. ``total_changes`` also
        invalidates the cache after writes through this connection.
        """
        if self._db.in_transaction:
            yield None
            return
        try:
            with closing(self._db.execute("PRAGMA data_version")) as version:
                before_row = version.fetchone()
            before = before_row[0] if before_row else None
        except sqlite3.Error:
            before = None
        if not isinstance(before, int):
            yield None
            return
        try:
            self._db.execute("BEGIN")
        except sqlite3.Error:
            yield None
            return
        try:
            try:
                # A SELECT starts the read snapshot before the second version
                # check; a concurrent commit cannot make the cached IDs newer
                # than the rows visible to this operation.
                with closing(self._db.execute(
                    "SELECT id FROM chunks WHERE collection = ? LIMIT 1", (collection,)
                )) as anchor:
                    anchor.fetchone()
                with closing(self._db.execute("PRAGMA data_version")) as version:
                    after_row = version.fetchone()
                after = after_row[0] if after_row else None
                token = (before, self._db.total_changes) if before == after else None
            except sqlite3.Error:
                token = None
            yield token
        finally:
            self._db.rollback()

    @staticmethod
    def _exact_indexable(collection, key, value):
        # The supported fast path is intentionally narrower than Python's
        # general equality rules. Other inputs retain the authoritative scan.
        return all(
            type(item) in (str,) and len(item) <= _MAX_EXACT_INDEX_KEY_CHARS
            for item in (collection, key, value)
        )

    def _matching_exact_index(self, collection, key, value, token):
        index = self._exact_index
        if index is None:
            return None
        if token is None or (index.data_version, index.local_changes) != token:
            self._exact_index = None
            return None
        if not self._exact_indexable(collection, key, value):
            return None
        if (index.collection, index.key, index.value) != (collection, key, value):
            return None
        return index

    def count(self, collection: str) -> int:
        with self._lock:
            (n,) = self._db.execute(
                "SELECT COUNT(*) FROM chunks WHERE collection = ?", (collection,)
            ).fetchone()
        return n

    def read_where(
        self, collection: str, key: str, value: str, *, limit: int,
    ) -> list[StoredChunk]:
        """Return exact metadata matches plus one possible overflow sentinel."""
        maximum = int(limit)
        if maximum < 1:
            raise ValueError("knowledge exact-read limit must be positive")
        with self._lock:
            if self._exact_index is not None:
                with self._exact_snapshot(collection) as token:
                    index = self._matching_exact_index(collection, key, value, token)
                    if index is not None:
                        indexed = self._read_indexed(collection, key, value, maximum, index)
                        if indexed is not None:
                            return indexed
            return self._read_where_scan(collection, key, value, maximum)

    def _read_indexed(self, collection, key, value, maximum, index):
        """Read index candidates in bounded queries, validating every result."""
        selected = index.ids[:maximum + 1]
        result = []
        for start in range(0, len(selected), 400):
            ids = selected[start:start + 400]
            placeholders = ",".join("?" for _ in ids)
            try:
                rows = self._db.execute(
                    f"SELECT id, text, meta FROM chunks WHERE collection = ? AND id IN ({placeholders}) ORDER BY id",
                    (collection, *ids),
                ).fetchall()
            except sqlite3.Error:
                # A build may impose a lower parameter limit, or a transient
                # optimized query may be unavailable. The ordinary scan stays
                # authoritative and will still surface underlying DB failures.
                return None
            if [row[0] for row in rows] != list(ids):
                return None
            for chunk_id, text, raw_meta in rows:
                meta = json.loads(raw_meta or "{}")
                if meta.get(key) != value:
                    return None
                result.append(StoredChunk(str(chunk_id), str(text), dict(meta)))
        return result

    def _read_where_scan(self, collection, key, value, maximum):
        result: list[StoredChunk] = []
        with closing(
            self._db.execute(
                "SELECT id, text, meta FROM chunks WHERE collection = ? ORDER BY id",
                (collection,),
            )
        ) as rows:
            for chunk_id, text, raw_meta in rows:
                meta = json.loads(raw_meta or "{}")
                if meta.get(key) == value:
                    result.append(StoredChunk(str(chunk_id), str(text), dict(meta)))
                    if len(result) > maximum:
                        break
        return result

    def read_collection(self, collection: str, *, limit: int) -> list[StoredChunk]:
        if not 1 <= limit <= 100_000:
            raise ValueError("knowledge collection-read limit is invalid")
        with self._lock:
            rows = self._db.execute(
                "SELECT id, text, meta FROM chunks WHERE collection = ? ORDER BY id LIMIT ?",
                (collection, limit + 1),
            ).fetchall()
        return [StoredChunk(cid, text, json.loads(meta)) for cid, text, meta in rows]

    def replace_embeddings(self, collection: str, snapshot: list[StoredChunk], items: list) -> None:
        """Compare the entire source snapshot and replace vectors in one transaction."""
        with self._lock, self._db:
            self._exact_index = None
            self._db.execute("BEGIN IMMEDIATE")
            rows = self._db.execute(
                "SELECT id, text, meta FROM chunks WHERE collection = ? ORDER BY id", (collection,),
            ).fetchall()
            current = [StoredChunk(cid, text, json.loads(meta)) for cid, text, meta in rows]
            if current != snapshot:
                raise RuntimeError("knowledge collection changed during reindex; retry")
            self._db.executemany(
                "UPDATE chunks SET vec = ?, meta = ? WHERE collection = ? AND id = ?",
                [(json.dumps(vec), json.dumps(meta), collection, cid) for cid, _text, vec, meta in items],
            )

    def close(self) -> None:
        """Close the underlying SQLite connection (idempotent)."""
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
            self._db = None
        self._exact_index = None

    def __enter__(self) -> SqliteVectorStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _to_pgvector(vec: list[float]) -> str:
    """A pgvector text literal (``[1,2,3]``) -- passed with a ``::vector`` cast so
    the backend needs only ``psycopg`` + the Postgres ``vector`` extension, not
    the optional ``pgvector`` Python package.

    Reject non-finite components: ``repr(float('nan'))`` is the bare token
    ``nan`` (likewise ``inf``/``-inf``), which pgvector's literal parser refuses,
    so an embedding carrying a NaN/Inf (a misbehaving hosted-API response or a
    downstream numeric bug) would otherwise abort the whole add()/search() with
    an opaque Postgres parse error mid-batch. Fail with a domain message first.
    """
    floats = [float(x) for x in vec]
    if not all(math.isfinite(x) for x in floats):
        raise ValueError(
            "knowledge: refusing to store/query a non-finite embedding component "
            "(nan/inf); the embedder produced an invalid vector"
        )
    return "[" + ",".join(repr(x) for x in floats) + "]"


class PgVectorStore:
    """pgvector-backed scale-out vector store -- the opt-in backend for corpora
    too large for the brute-force SQLite index.

    Same surface + collection-scoped compartments as :class:`SqliteVectorStore`,
    but cosine search runs in Postgres via the ``<=>`` operator (with an IVFFlat
    index), so retrieval doesn't scan every row in the process. Vectors are
    passed as text literals cast to ``::vector``; only ``psycopg`` and the
    Postgres ``vector`` extension are required (no numpy / pgvector-python).

    Connection-shared across threads like the SQLite store (ingestion runs on a
    threadpool); a single psycopg connection is NOT thread-safe, so every
    statement is serialized under a lock.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        dim: int = 1024,
        table: str = "knowledge_chunks",
        namespace: str = "default",
    ) -> None:
        try:
            import psycopg
        except ImportError as e:  # pragma: no cover -- exercised only without psycopg
            raise ImportError(
                "pgvector store needs psycopg. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-knowledge[pgvector]'"
            ) from e
        import os

        self._dsn = (
            dsn
            or os.environ.get("MAVERICK_KNOWLEDGE_DSN")
            or os.environ.get("MAVERICK_PG_DSN")
            or ""
        )
        if not self._dsn:
            raise RuntimeError(
                "pgvector store requires MAVERICK_KNOWLEDGE_DSN / MAVERICK_PG_DSN "
                "or [knowledge] dsn in config.toml."
            )
        if dim <= 0:
            raise ValueError(f"pgvector store needs a positive dim, got {dim}")
        self._dim = int(dim)
        # Identifier is operator/config-derived, not agent input; still constrain
        # it to a safe charset so it can be interpolated into DDL without an
        # injection surface.
        if not table.replace("_", "").isalnum():
            raise ValueError(f"invalid table name {table!r}")
        self._table = table
        self._namespace = str(namespace or "default")
        self._lock = threading.Lock()
        with metered_operation(
            "pgvector",
            category="update",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-initialize",
        ) as provider_call:
            self._db = provider_call(
                lambda: psycopg.connect(self._dsn, autocommit=True)
            )
            self._initialize_schema(provider_call)

    def _initialize_schema(self, provider_call) -> None:
        try:
            provider_call(
                lambda: self._db.execute("CREATE EXTENSION IF NOT EXISTS vector")
            )
        except Exception as e:  # pragma: no cover -- perms vary by deployment
            raise RuntimeError(
                "pgvector store: could not enable the 'vector' extension "
                f"({e}). Install pgvector and grant CREATE on the database."
            ) from e
        provider_call(
            lambda: self._db.execute(
                f"CREATE TABLE IF NOT EXISTS {self._table} ("
                "namespace TEXT, collection TEXT, id TEXT, text TEXT, "
                f"embedding vector({self._dim}), meta JSONB, "
                "PRIMARY KEY (namespace, collection, id))"
            )
        )
        # Migrate a pre-namespacing table in place. Older installs created
        # {table} with PRIMARY KEY (collection, id) and no namespace column, so a
        # shared-DSN upgrade would fail every namespace-scoped query (and the
        # CREATE TABLE IF NOT EXISTS above is a no-op on the existing table). Add
        # the column, assign existing rows to the 'default' workspace, and move
        # the primary key to include namespace so the same id can live in
        # multiple workspaces and ON CONFLICT (namespace, collection, id) upserts
        # resolve. Guarded on the column's absence so it runs once, not per init.
        with self._db.cursor() as cur:
            has_namespace = provider_call(
                lambda: (
                    cur.execute(
                        "SELECT 1 FROM information_schema.columns "
                        "WHERE table_name = %s AND column_name = 'namespace'",
                        (self._table,),
                    ),
                    cur.fetchone(),
                )[1]
            ) is not None
        if not has_namespace:
            provider_call(
                lambda: self._db.execute(
                    f"ALTER TABLE {self._table} ADD COLUMN namespace TEXT"
                )
            )
            provider_call(
                lambda: self._db.execute(
                    f"UPDATE {self._table} SET namespace = 'default' "
                    "WHERE namespace IS NULL"
                )
            )
            provider_call(
                lambda: self._db.execute(
                    f"ALTER TABLE {self._table} "
                    "ALTER COLUMN namespace SET NOT NULL"
                )
            )
            provider_call(
                lambda: self._db.execute(
                    f"ALTER TABLE {self._table} "
                    f"DROP CONSTRAINT IF EXISTS {self._table}_pkey"
                )
            )
            provider_call(
                lambda: self._db.execute(
                    f"ALTER TABLE {self._table} "
                    f"ADD CONSTRAINT {self._table}_pkey "
                    "PRIMARY KEY (namespace, collection, id)"
                )
            )
        # Cosine IVFFlat index -- approximate but the point of the scale backend.
        provider_call(
            lambda: self._db.execute(
                f"CREATE INDEX IF NOT EXISTS {self._table}_embedding_idx "
                f"ON {self._table} USING ivfflat (embedding vector_cosine_ops) "
                "WITH (lists = 100)"
            )
        )

    def add(self, collection, items) -> None:
        if not items:
            return
        params = [
            (
                self._namespace,
                collection,
                cid,
                text,
                _to_pgvector(vec),
                json.dumps(meta),
            )
            for cid, text, vec, meta in items
        ]

        def dispatch() -> None:
            with self._lock, self._db.cursor() as cur:
                cur.executemany(
                    f"INSERT INTO {self._table} "
                    "(namespace, collection, id, text, embedding, meta) "
                    "VALUES (%s, %s, %s, %s, %s::vector, %s::jsonb) "
                    "ON CONFLICT (namespace, collection, id) DO UPDATE SET "
                    "text = EXCLUDED.text, embedding = EXCLUDED.embedding, "
                    "meta = EXCLUDED.meta",
                    params,
                )

        with metered_operation(
            "pgvector",
            category="storage",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-add",
        ) as provider_call:
            provider_call(dispatch)

    def _collection_fence(self, cur, collection: str) -> None:
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (json.dumps([self._namespace, collection]),))

    def add_with_identity(self, collection, items, fingerprint: str, *, effect_guard=None, publication_scope=None) -> None:
        self._publish_with_identity(collection, items, fingerprint, effect_guard=effect_guard, publication_scope=publication_scope)

    def replace_source_with_identity(
        self, collection, items, fingerprint: str, *, source: str, snapshot: list[StoredChunk], effect_guard=None, publication_scope=None,
    ) -> None:
        self._publish_with_identity(collection, items, fingerprint, source=source, snapshot=snapshot,
                                    effect_guard=effect_guard, publication_scope=publication_scope)

    def _publish_with_identity(
        self, collection, items, fingerprint: str, *, source: str | None = None, snapshot=None, effect_guard=None, publication_scope=None,
    ) -> None:
        def dispatch():
            with publication_scope() if publication_scope is not None else nullcontext(), self._lock, self._db.transaction(), self._db.cursor() as cur:
                self._collection_fence(cur, collection)
                if effect_guard is not None:
                    effect_guard()
                found = cur.execute(
                    f"SELECT 1 FROM {self._table} WHERE namespace = %s AND collection = %s "
                    "AND (meta ->> 'embedding_fingerprint') IS DISTINCT FROM %s LIMIT 1",
                    (self._namespace, collection, fingerprint),
                ).fetchone()
                if found is not None:
                    raise RuntimeError("knowledge collection changed embedding identity; reindex required")
                rows = cur.execute(
                    f"SELECT id, text, meta FROM {self._table} "
                    "WHERE namespace = %s AND collection = %s "
                    "AND (id = ANY(%s) OR meta ->> 'doc_sha256' = ANY(%s) "
                    "OR meta ->> 'source' = %s) FOR UPDATE",
                    (self._namespace, collection, [item[0] for item in items],
                     list({item[3]["doc_sha256"] for item in items}), source),
                ).fetchall()
                existing = [StoredChunk(cid, text, dict(meta)) for cid, text, meta in rows]
                removed = (
                    _source_replacement_removals(items, existing, source, snapshot)
                    if source is not None else []
                )
                pending = _document_publication(items, existing)
                if effect_guard is not None:
                    effect_guard()
                cur.executemany(
                    f"INSERT INTO {self._table} (namespace, collection, id, text, embedding, meta) "
                    "VALUES (%s, %s, %s, %s, %s::vector, %s::jsonb)",
                    [(self._namespace, collection, cid, text, _to_pgvector(vec), json.dumps(meta))
                     for cid, text, vec, meta in pending],
                )
                if removed:
                    cur.execute(
                        f"DELETE FROM {self._table} WHERE namespace = %s AND collection = %s "
                        "AND id = ANY(%s)",
                        (self._namespace, collection, removed),
                    )
                if effect_guard is not None:
                    effect_guard()
        with metered_operation("pgvector", category="storage", service="vector-store:pgvector",
                               operation="knowledge-identity-fenced-add") as call:
            call(dispatch)

    def search(self, collection, vector, k: int = 5) -> list[Match]:
        if k <= 0:
            return []
        if len(vector) != self._dim:
            # Mirror the SQLite store: a query embedded at a different dim than
            # the corpus is a misconfiguration, not an empty result.
            raise ValueError(
                f"knowledge: query vector dim {len(vector)} != store dim "
                f"{self._dim}; the corpus was embedded with a different "
                "embedder/model than this query"
            )
        vector_literal = _to_pgvector(vector)

        def dispatch():
            with self._lock, self._db.cursor() as cur:
                return cur.execute(
                    f"SELECT text, meta, 1 - (embedding <=> %s::vector) AS score "
                    f"FROM {self._table} WHERE namespace = %s AND collection = %s "
                    "ORDER BY embedding <=> %s::vector LIMIT %s",
                    (
                        vector_literal,
                        self._namespace,
                        collection,
                        vector_literal,
                        int(k),
                    ),
                ).fetchall()

        with metered_operation(
            "pgvector",
            category="retrieval",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-search",
        ) as provider_call:
            rows = provider_call(dispatch)
        # psycopg adapts JSONB to a dict already; tolerate a str just in case.
        return [
            Match(float(score), text, meta if isinstance(meta, dict) else json.loads(meta or "{}"))
            for text, meta, score in rows
        ]

    def delete_collection(self, collection: str) -> None:
        def dispatch() -> None:
            with self._lock:
                self._db.execute(
                    f"DELETE FROM {self._table} "
                    "WHERE namespace = %s AND collection = %s",
                    (self._namespace, collection),
                )

        with metered_operation(
            "pgvector",
            category="update",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-delete-collection",
        ) as provider_call:
            provider_call(dispatch)

    def collections(self) -> list[str]:
        """Every collection with at least one chunk in this namespace."""
        def dispatch():
            with self._lock, self._db.cursor() as cur:
                return cur.execute(
                    f"SELECT DISTINCT collection FROM {self._table} "
                    "WHERE namespace = %s ORDER BY collection",
                    (self._namespace,),
                ).fetchall()

        with metered_operation(
            "pgvector",
            category="retrieval",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-collections",
        ) as provider_call:
            rows = provider_call(dispatch)
        return [r[0] for r in rows]

    def delete_where(self, collection: str, key: str, value: str) -> int:
        """Delete every chunk whose ``meta[key] == value``. Returns the count.

        JSONB containment (``@>``) keeps the erasure sweep in Postgres.
        """
        def dispatch() -> int:
            with self._lock, self._db.cursor() as cur:
                cur.execute(
                    f"DELETE FROM {self._table} "
                    "WHERE namespace = %s AND collection = %s "
                    "AND meta @> %s::jsonb",
                    (self._namespace, collection, json.dumps({key: value})),
                )
                return int(cur.rowcount or 0)

        with metered_operation(
            "pgvector",
            category="update",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-delete-where",
        ) as provider_call:
            return provider_call(dispatch)

    def count_where(self, collection: str, key: str, value: str) -> int:
        def dispatch() -> int:
            with self._lock, self._db.cursor() as cur:
                (n,) = cur.execute(
                    f"SELECT COUNT(*) FROM {self._table} "
                    "WHERE namespace = %s AND collection = %s "
                    "AND meta @> %s::jsonb",
                    (self._namespace, collection, json.dumps({key: value})),
                ).fetchone()
            return int(n)

        with metered_operation(
            "pgvector",
            category="retrieval",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-count-where",
        ) as provider_call:
            return provider_call(dispatch)

    def count(self, collection: str) -> int:
        def dispatch() -> int:
            with self._lock, self._db.cursor() as cur:
                (n,) = cur.execute(
                    f"SELECT COUNT(*) FROM {self._table} "
                    "WHERE namespace = %s AND collection = %s",
                    (self._namespace, collection),
                ).fetchone()
            return int(n)

        with metered_operation(
            "pgvector",
            category="retrieval",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-count",
        ) as provider_call:
            return provider_call(dispatch)

    def read_where(
        self, collection: str, key: str, value: str, *, limit: int,
    ) -> list[StoredChunk]:
        maximum = int(limit)
        if maximum < 1:
            raise ValueError("knowledge exact-read limit must be positive")

        def dispatch():
            with self._lock, self._db.cursor() as cur:
                return cur.execute(
                    f"SELECT id, text, meta FROM {self._table} "
                    "WHERE namespace = %s AND collection = %s "
                    "AND meta ->> %s = %s ORDER BY id LIMIT %s",
                    (
                        self._namespace,
                        collection,
                        str(key),
                        str(value),
                        maximum + 1,
                    ),
                ).fetchall()

        with metered_operation(
            "pgvector",
            category="retrieval",
            service="vector-store:pgvector",
            operation="knowledge-pgvector-exact-read",
        ) as provider_call:
            rows = provider_call(dispatch)
        return [
            StoredChunk(
                str(chunk_id),
                str(text),
                meta if isinstance(meta, dict) else json.loads(meta or "{}"),
            )
            for chunk_id, text, meta in rows
        ]

    def read_collection(self, collection: str, *, limit: int) -> list[StoredChunk]:
        if not 1 <= limit <= 100_000:
            raise ValueError("knowledge collection-read limit is invalid")
        with metered_operation("pgvector", category="retrieval", service="vector-store:pgvector",
                               operation="knowledge-reindex-read") as call:
            def dispatch():
                with self._lock, self._db.cursor() as cur:
                    return cur.execute(
                        f"SELECT id, text, meta FROM {self._table} "
                        "WHERE namespace = %s AND collection = %s ORDER BY id LIMIT %s",
                        (self._namespace, collection, limit + 1),
                    ).fetchall()
            rows = call(dispatch)
        return [StoredChunk(cid, text, meta if isinstance(meta, dict) else json.loads(meta))
                for cid, text, meta in rows]

    def replace_embeddings(self, collection: str, snapshot: list[StoredChunk], items: list) -> None:
        with metered_operation("pgvector", category="storage", service="vector-store:pgvector",
                               operation="knowledge-reindex-replace") as call:
            def dispatch():
                with self._lock, self._db.transaction(), self._db.cursor() as cur:
                    self._collection_fence(cur, collection)
                    rows = cur.execute(
                        f"SELECT id, text, meta FROM {self._table} "
                        "WHERE namespace = %s AND collection = %s ORDER BY id FOR UPDATE",
                        (self._namespace, collection),
                    ).fetchall()
                    current = [StoredChunk(cid, text, meta if isinstance(meta, dict) else json.loads(meta))
                               for cid, text, meta in rows]
                    if current != snapshot:
                        raise RuntimeError("knowledge collection changed during reindex; retry")
                    cur.executemany(
                        f"UPDATE {self._table} SET embedding = %s::vector, meta = %s::jsonb "
                        "WHERE namespace = %s AND collection = %s AND id = %s",
                        [(_to_pgvector(vec), json.dumps(meta), self._namespace, collection, cid)
                         for cid, _text, vec, meta in items],
                    )
            call(dispatch)

    def close(self) -> None:
        """Close the underlying connection (idempotent)."""
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
            self._db = None

    def __enter__(self) -> PgVectorStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class QdrantStore:
    """Qdrant retrieval/erasure adapter for existing collections.

    Its unconditional upsert is a low-level adapter operation, not atomic
    document admission. KnowledgeBase refuses ingestion through this adapter
    until it supports a shared provenance/identity publication fence.

    Same protocol + per-collection compartments as the other stores. One Qdrant
    collection per (namespace, knowledge collection) pair, named
    ``{namespace}__{collection}``, so tenant isolation survives a shared
    cluster. Payload carries ``text`` + the chunk ``meta`` (flattened under
    ``meta``), and ``delete_where``/``count_where`` filter on ``meta.{key}`` —
    the same erasure-by-provenance primitive the embedded stores expose.

    Requires the optional ``qdrant-client`` dependency
    (``pip install 'maverick-knowledge[qdrant]'``); imported lazily so the
    package stays dependency-free by default.
    """

    def __init__(self, url: str | None = None, *, api_key: str | None = None,
                 dim: int = 1024, namespace: str = "default") -> None:
        try:
            from qdrant_client import QdrantClient
        except ImportError as e:  # pragma: no cover -- exercised only without the extra
            raise ImportError(
                "qdrant store needs qdrant-client. "
                "Run: pip install 'maverick-knowledge[qdrant]'"
            ) from e
        import os

        self._url = url or os.environ.get("QDRANT_URL") or ""
        if not self._url:
            raise RuntimeError(
                "qdrant store requires QDRANT_URL or [knowledge] url in config.toml.")
        if dim <= 0:
            raise ValueError(f"qdrant store needs a positive dim, got {dim}")
        self._dim = int(dim)
        self._namespace = str(namespace or "default")
        selected_api_key = api_key or os.environ.get("QDRANT_API_KEY") or None
        # Qdrant performs a server compatibility check by default during
        # construction. Treat the constructor as the first physical hosted
        # call so a configured unknown-price cap blocks before any dispatch.
        with metered_operation(
            "qdrant",
            category="retrieval",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-initialize",
        ) as provider_call:
            self._client = provider_call(
                lambda: QdrantClient(url=self._url, api_key=selected_api_key)
            )

    def _cname(self, collection: str) -> str:
        return f"{self._namespace}__{collection}"

    def _ensure(self, collection: str, provider_call) -> str:
        from qdrant_client import models
        name = self._cname(collection)
        exists = provider_call(lambda: self._client.collection_exists(name))
        if not exists:
            vectors_config = models.VectorParams(
                size=self._dim,
                distance=models.Distance.COSINE,
            )
            provider_call(
                lambda: self._client.create_collection(
                    collection_name=name,
                    vectors_config=vectors_config,
                )
            )
        return name

    @staticmethod
    def _point_id(cid: str) -> str:
        """Qdrant point ids must be UUIDs or ints; map arbitrary chunk ids
        deterministically so re-adding the same id upserts, matching the
        other stores' INSERT OR REPLACE semantics."""
        import uuid as _uuid
        return str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"maverick-chunk:{cid}"))

    def _meta_filter(self, key: str, value: str):
        from qdrant_client import models
        return models.Filter(must=[models.FieldCondition(
            key=f"meta.{key}", match=models.MatchValue(value=value))])

    def add(self, collection, items) -> None:
        if not items:
            return
        from qdrant_client import models
        points = [
            models.PointStruct(
                id=self._point_id(cid),
                vector=[float(x) for x in vec],
                payload={"text": text, "meta": dict(meta or {}), "chunk_id": cid},
            )
            for cid, text, vec, meta in items
        ]
        with metered_operation(
            "qdrant",
            category="storage",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-add",
        ) as provider_call:
            name = self._ensure(collection, provider_call)
            provider_call(
                lambda: self._client.upsert(
                    collection_name=name,
                    points=points,
                )
            )

    def search(self, collection, vector, k: int = 5) -> list[Match]:
        if k <= 0:
            return []
        if len(vector) != self._dim:
            raise ValueError(
                f"knowledge: query vector dim {len(vector)} != store dim "
                f"{self._dim}; the corpus was embedded with a different "
                "embedder/model than this query")
        name = self._cname(collection)
        query_vector = [float(x) for x in vector]
        with metered_operation(
            "qdrant",
            category="retrieval",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-search",
        ) as provider_call:
            if not provider_call(lambda: self._client.collection_exists(name)):
                return []
            hits = provider_call(
                lambda: self._client.query_points(
                    collection_name=name,
                    query=query_vector,
                    limit=int(k),
                    with_payload=True,
                )
            ).points
        return [
            Match(
                float(h.score),
                str((h.payload or {}).get("text", "")),
                dict((h.payload or {}).get("meta") or {}),
            )
            for h in hits
        ]

    def delete_collection(self, collection: str) -> None:
        name = self._cname(collection)
        with metered_operation(
            "qdrant",
            category="update",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-delete-collection",
        ) as provider_call:
            if provider_call(lambda: self._client.collection_exists(name)):
                provider_call(lambda: self._client.delete_collection(name))

    def collections(self) -> list[str]:
        prefix = f"{self._namespace}__"
        with metered_operation(
            "qdrant",
            category="retrieval",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-collections",
        ) as provider_call:
            result = provider_call(self._client.get_collections)
        names = [c.name for c in result.collections]
        return sorted(n[len(prefix):] for n in names if n.startswith(prefix))

    def delete_where(self, collection: str, key: str, value: str) -> int:
        from qdrant_client import models
        name = self._cname(collection)
        meta_filter = self._meta_filter(key, value)
        with metered_operation(
            "qdrant",
            category="update",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-delete-where",
        ) as provider_call:
            if not provider_call(lambda: self._client.collection_exists(name)):
                return 0
            doomed = int(
                provider_call(
                    lambda: self._client.count(
                        collection_name=name,
                        count_filter=meta_filter,
                        exact=True,
                    )
                ).count
            )
            if doomed:
                selector = models.FilterSelector(filter=meta_filter)
                provider_call(
                    lambda: self._client.delete(
                        collection_name=name,
                        points_selector=selector,
                    )
                )
            return doomed

    def count_where(self, collection: str, key: str, value: str) -> int:
        name = self._cname(collection)
        meta_filter = self._meta_filter(key, value)
        with metered_operation(
            "qdrant",
            category="retrieval",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-count-where",
        ) as provider_call:
            if not provider_call(lambda: self._client.collection_exists(name)):
                return 0
            return int(
                provider_call(
                    lambda: self._client.count(
                        collection_name=name,
                        count_filter=meta_filter,
                        exact=True,
                    )
                ).count
            )

    def count(self, collection: str) -> int:
        name = self._cname(collection)
        with metered_operation(
            "qdrant",
            category="retrieval",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-count",
        ) as provider_call:
            if not provider_call(lambda: self._client.collection_exists(name)):
                return 0
            return int(
                provider_call(
                    lambda: self._client.count(
                        collection_name=name,
                        exact=True,
                    )
                ).count
            )

    def read_where(
        self, collection: str, key: str, value: str, *, limit: int,
    ) -> list[StoredChunk]:
        maximum = int(limit)
        if maximum < 1:
            raise ValueError("knowledge exact-read limit must be positive")
        name = self._cname(collection)
        meta_filter = self._meta_filter(str(key), str(value))
        with metered_operation(
            "qdrant",
            category="retrieval",
            service="vector-store:qdrant",
            operation="knowledge-qdrant-exact-read",
        ) as provider_call:
            if not provider_call(lambda: self._client.collection_exists(name)):
                return []
            points, _offset = provider_call(
                lambda: self._client.scroll(
                    collection_name=name,
                    scroll_filter=meta_filter,
                    limit=maximum + 1,
                    with_payload=True,
                    with_vectors=False,
                )
            )
        return [
            StoredChunk(
                str((point.payload or {}).get("chunk_id", point.id)),
                str((point.payload or {}).get("text", "")),
                dict((point.payload or {}).get("meta") or {}),
            )
            for point in points
        ]

    def close(self) -> None:
        client = getattr(self, "_client", None)
        if client is not None:
            try:
                client.close()
            except Exception:  # pragma: no cover -- close is best-effort
                pass
            self._client = None


def _namespace_from_cfg(cfg: dict) -> str:
    """Stable pgvector namespace preserving per-workspace knowledge isolation."""
    raw = cfg.get("namespace") or cfg.get("tenant") or cfg.get("path") or "default"
    namespace = str(raw)
    digest = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:16]
    return f"workspace:{digest}"


def build_store(cfg: dict | None = None):
    """Select a vector store from config. Defaults to embedded SQLite; pgvector
    (``[knowledge] store = "pgvector"``) is the opt-in scale backend.

    pgvector reads its DSN from ``[knowledge] dsn`` /
    ``MAVERICK_KNOWLEDGE_DSN`` / ``MAVERICK_PG_DSN`` and its vector width from
    ``[knowledge] dim`` (default 1024 -- matches ``voyage-3``)."""
    cfg = cfg or {}
    backend = str(cfg.get("store", "sqlite")).lower()
    if backend == "pgvector":
        return PgVectorStore(
            dsn=cfg.get("dsn") or None,
            dim=int(cfg.get("dim", 1024)),
            namespace=_namespace_from_cfg(cfg),
        )
    if backend == "qdrant":
        return QdrantStore(
            url=cfg.get("url") or None,
            api_key=cfg.get("store_api_key") or None,
            dim=int(cfg.get("dim", 1024)),
            namespace=_namespace_from_cfg(cfg),
        )
    return SqliteVectorStore(cfg.get("path") or ":memory:")
