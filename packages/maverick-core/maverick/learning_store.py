"""World-DB backend for the self-harness learning stores (fleet-shared state).

The three LEARNING stores -- the addenda map, the provenance/outcome line-meta sidecar, and the
transfer tried-memory -- can live as world-database tables instead of per-host
JSON files, so a fleet spanning hosts shares one learning state (transfer
sweeps see every host's guidance, outcome evidence aggregates, and two hosts
can't promote conflicting lines). The eval corpus and its harvest sidecars
stay on files this phase (operator data keyed by a configurable path).

Selection is the ``[self_harness] store`` knob (``"files"`` default,
``"world"`` opt-in) and the seam lives in :mod:`maverick.self_harness`: an
EXPLICIT ``path`` argument always means the file store at that path (tests
and tenant redirection are unchanged), while the default location resolves to
whichever store is configured. Semantics here mirror the file store exactly:
whole-map reads and whole-map replaces, serialized by the caller's existing
in-process + flock critical section -- plus :func:`rmw_lock`, which adds the
DB-side serialization ``flock`` cannot provide across hosts (a Postgres
advisory lock; SQLite is same-host and needs nothing extra).

Backends ride the world model's own rails: SQLite uses the same
tenant-floored ``world.db`` file, Postgres the same DSN resolution as
``PostgresWorldModel``. Tables are in each backend's migration ladder (v25)
and are also created lazily here, so the store works even if nothing opened
the world first. Reads are tolerant (``{}`` on any error, like the file
loaders); writes propagate so a failed promotion is never silently dropped.
"""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import logging
import math
import os
import sqlite3
import threading
import time
from pathlib import Path

from .learning_store_pg_schema import LearningSchemaError

log = logging.getLogger(__name__)

# One row per logical file the store replaces.
_TABLES = ("harness_addenda", "harness_line_meta", "harness_transfer_tried")

_SQLITE_DDL = (
    "CREATE TABLE IF NOT EXISTS harness_addenda ("
    " key TEXT PRIMARY KEY, block TEXT NOT NULL, updated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS harness_line_meta ("
    " line_id TEXT PRIMARY KEY, record TEXT NOT NULL, updated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS harness_transfer_tried ("
    " line_id TEXT PRIMARY KEY, ts REAL NOT NULL)",
    # The eval-corpus family. ``kind`` is live|pending|rejected plus
    # ``extra`` for a live file's non-list top-level entries (operator
    # annotations like "_meta"), so an export/import round-trip loses nothing.
    # ``seq`` preserves row order -- review indexes are positional.
    "CREATE TABLE IF NOT EXISTS harness_corpus ("
    " kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL,"
    " row TEXT NOT NULL, PRIMARY KEY (kind, key, seq))",
)

# Session-scoped Postgres advisory lock serializing the store's whole
# load-modify-save across HOSTS (flock only serializes one host). Fixed
# arbitrary key, distinct from the migration lock.
_PG_RMW_LOCK = 0x6D766B6C726E  # 'mvklrn'


def enabled() -> bool:
    """True when ``[self_harness] store = "world"`` selects this backend."""
    try:
        from .self_harness import settings
        return str(settings().get("store") or "files").strip().lower() == "world"
    except Exception:  # pragma: no cover -- config trouble means file store
        return False


def _postgres() -> bool:
    try:
        from .world_model_backends import is_postgres_configured
        return is_postgres_configured()
    except Exception:  # pragma: no cover -- backends extra absent
        return False


def _sqlite_path() -> Path:
    """The same tenant-aware world DB location ``open_world()`` resolves
    (``data_dir`` scopes to the active tenant) -- computed at CALL time, so
    env/tenant changes and per-test isolation apply, unlike the import-frozen
    ``world_model.DEFAULT_DB`` constant."""
    from . import practice
    from .paths import data_dir
    # Practice runs learn nothing into the real world model.
    return practice.world_path() if practice.active() else data_dir("world.db")


def _pg_dsn() -> str:
    dsn = os.environ.get("MAVERICK_PG_DSN") or ""
    if not dsn:
        try:
            from .config import load_config
            dsn = str(((load_config() or {}).get("world_model") or {})
                      .get("dsn") or "")
        except Exception:  # pragma: no cover
            dsn = ""
    if not dsn:
        raise RuntimeError("world learning store: postgres selected but no "
                           "MAVERICK_PG_DSN / [world_model] dsn configured")
    return dsn


@contextlib.contextmanager
def _sqlite_conn():
    p = _sqlite_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        for ddl in _SQLITE_DDL:
            conn.execute(ddl)
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextlib.contextmanager
def _pg_conn():
    import psycopg  # the [postgres] extra; same dependency rule as the world
    conn = psycopg.connect(_pg_dsn(), autocommit=False)
    try:
        from .learning_store_pg_schema import ensure_schema

        with conn.cursor() as cur:
            ensure_schema(cur)
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _conn():
    return _pg_conn() if _postgres() else _sqlite_conn()


_rmw_session = threading.local()


@contextlib.contextmanager
def rmw_lock():
    """DB-side serialization for a whole load-modify-save. A no-op on SQLite
    (the callers' flock already serializes the single host that can reach a
    SQLite file); on Postgres, a session advisory lock held for the critical
    section so two HOSTS can't interleave a read-modify-write."""
    if not _postgres():
        yield
        return
    dsn = _pg_dsn()
    bindings = getattr(_rmw_session, "bindings", None)
    if bindings is None:
        bindings = _rmw_session.bindings = {}
    binding = os.getpid(), dsn
    if binding in bindings:
        if bindings[binding].closed:
            raise RuntimeError("The current learning writer session is unavailable")
        yield
        return
    import psycopg
    conn = psycopg.connect(dsn, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_PG_RMW_LOCK,))
        bindings[binding] = conn
        yield
    finally:
        bindings.pop(binding, None)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (_PG_RMW_LOCK,))
        finally:
            conn.close()


def _rows(conn, sql: str, params: tuple = ()) -> list[tuple]:
    if hasattr(conn, "cursor") and not isinstance(conn, sqlite3.Connection):
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    return conn.execute(sql, params).fetchall()


def _exec(conn, sql: str, params: tuple = ()) -> None:
    if hasattr(conn, "cursor") and not isinstance(conn, sqlite3.Connection):
        with conn.cursor() as cur:
            cur.execute(sql, params)
        return
    conn.execute(sql, params)


def _ph(n: int) -> str:
    """Placeholder list for the active backend's paramstyle."""
    mark = "%s" if _postgres() else "?"
    return ", ".join([mark] * n)


# Tables the shared world store keeps. On Postgres each carries a ``tenant_id``
# so a single shared DSN can never pool one tenant's learning into another's
# recall (the same boundary the world model enforces on its own tables). The
# SQLite store needs no column: ``data_dir`` already scopes ``world.db`` per
# tenant, so two tenants never share a file.
_TENANT_SCOPED_TABLES = (
    "harness_addenda",
    "harness_line_meta",
    "harness_transfer_tried",
    "harness_corpus",
)


def _active_tenant() -> str | None:
    """The tenant scoping this call, or ``None`` for the unbound single-tenant
    store. Lazy import keeps this module free of a hard ``paths`` dependency."""
    try:
        from .paths import current_tenant_id
        return current_tenant_id()
    except Exception:  # pragma: no cover -- no tenant context resolves to unbound
        return None


def _tenant_predicate() -> tuple[str, tuple]:
    """Exact tenant scope for the SHARED Postgres store, else no predicate.

    On Postgres a single DSN backs every tenant, so reads, whole-map DELETEs and
    the tenant column stamped on writes all pin the active tenant EXACTLY
    (``tenant_id IS NULL`` for an unbound single-tenant deployment). On SQLite the
    file is already tenant-scoped, so the predicate is empty and the emitted SQL
    is byte-for-byte unchanged."""
    if not _postgres():
        return "", ()
    tenant = _active_tenant()
    if tenant is None:
        return "tenant_id IS NULL", ()
    return "tenant_id = %s", (tenant,)


def _tenant_column() -> tuple[str, str, tuple]:
    """``(", tenant_id", ", %s", (value,))`` to splice onto an INSERT on Postgres;
    all empty on SQLite. The stamped value is the active tenant (``NULL`` when
    unbound), so it matches the exact read predicate above."""
    if not _postgres():
        return "", "", ()
    return ", tenant_id", ", %s", (_active_tenant(),)


def _where(predicate: str) -> str:
    return f" WHERE {predicate}" if predicate else ""


def _and(predicate: str) -> str:
    return f" AND {predicate}" if predicate else ""


def guidance_source() -> dict:
    """Private exact backend binding; never includes a connection string."""
    from .paths import current_tenant_id_strict
    from .self_harness import _store_path, settings

    cfg = settings()
    if not cfg.get("_config_valid", True):
        raise RuntimeError("Current learning storage settings are unavailable")
    mode = str(cfg.get("store") or "files").strip().lower()
    if mode not in {"files", "world"}:
        raise RuntimeError("Current learning storage is unsupported")
    tenant = current_tenant_id_strict()
    backend = "files" if mode == "files" else "postgres" if _postgres() else "sqlite"
    location = (_pg_dsn() if backend == "postgres" else str(
        (_sqlite_path() if mode == "world" else _store_path()).resolve()))
    binding = hashlib.sha256(json.dumps(
        [backend, tenant, location], separators=(",", ":"),
    ).encode()).hexdigest()
    return {"mode": mode, "backend": backend, "tenant": tenant, "binding": binding}


_guidance_scope: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "learning_guidance_snapshot_scope", default=None,
)


@contextlib.contextmanager
def derived_guidance_fence():
    """Common cross-process fence for file-derived guidance and safety copies."""
    from .file_lock import cross_process_lock
    from .paths import data_dir

    with cross_process_lock(data_dir("learning-state-writes"), strict=True):
        yield


@contextlib.contextmanager
def guidance_fence():
    """Use the production addenda/provenance writer fence, once per capture.

    This is held only while copying/restoring state, never while a model runs.
    The shared Postgres advisory lock fences the whole two-table transaction.
    """
    from .file_lock import cross_process_lock
    from .self_harness import _lock, _store_path, _store_rmw_lock

    expected = guidance_source()
    with (derived_guidance_fence(), _lock,
          cross_process_lock(_store_path(), strict=True), _store_rmw_lock(_store_path())):
        if guidance_source() != expected:
            raise RuntimeError("Learning storage changed; prepare a new safety copy")
        token = _guidance_scope.set(expected)
        try:
            yield expected
        finally:
            _guidance_scope.reset(token)


def _require_guidance_fence(source: dict) -> None:
    if _guidance_scope.get() != source or guidance_source() != source:
        raise RuntimeError("Learning guidance must use its current mutation fence")


def validate_guidance_snapshot(state: dict, source: dict) -> None:
    """Refuse malformed or differently scoped derived guidance before writes."""
    if (not isinstance(state, dict) or set(state) != {"version", "source", "addenda", "line_meta"}
            or type(state["version"]) is not int or state["version"] != 1
            or state["source"] != source or source["mode"] != "world"):
        raise RuntimeError("The safety copy belongs to different learning storage")
    for family in ("addenda", "line_meta"):
        rows = state[family]
        if not isinstance(rows, list) or len(rows) > 10000:
            raise RuntimeError("The saved learning guidance exceeds its supported bounds")
        seen = set()
        for row in rows:
            if (not isinstance(row, list) or len(row) != 3
                    or not isinstance(row[0], str) or not row[0] or len(row[0]) > 10000
                    or row[0] in seen or not isinstance(row[1], str)
                    or len(row[1].encode()) > 2 * 1024 * 1024
                    or type(row[2]) not in (int, float) or not math.isfinite(row[2])):
                raise RuntimeError("The saved learning guidance is invalid")
            seen.add(row[0])
            if family == "line_meta":
                parsed = json.loads(row[1])
                if not isinstance(parsed, dict):
                    raise RuntimeError("The saved learning provenance is invalid")
                json.dumps(parsed, allow_nan=False)
    if len(json.dumps(state, allow_nan=False).encode()) > 32 * 1024 * 1024:
        raise RuntimeError("The saved learning guidance exceeds its supported bounds")


def export_guidance_snapshot() -> dict:
    """Strict selective read under guidance_fence; customer/history rows stay live."""
    source = _guidance_scope.get()
    if source is None or source["mode"] != "world":
        raise RuntimeError("The current learning guidance fence is required")
    _require_guidance_fence(source)
    pred, params = _tenant_predicate()
    with _conn() as c:
        # SQLite's ordinary SELECT does not begin a read transaction itself.
        if isinstance(c, sqlite3.Connection):
            c.execute("BEGIN")
        state = {"version": 1, "source": source}
        total = 0
        for key, table, columns in (
            ("addenda", "harness_addenda", "key, block, updated_at"),
            ("line_meta", "harness_line_meta", "line_id, record, updated_at"),
        ):
            identity, content, _ = columns.split(", ")
            size = (lambda col: f"octet_length({col})") if _postgres() else (
                lambda col: f"length(CAST({col} AS BLOB))")
            count, amount, maximum = _rows(c,
                f"SELECT COUNT(*), COALESCE(SUM({size(identity)} + {size(content)}), 0), "
                f"COALESCE(MAX({size(content)}), 0) FROM {table}{_where(pred)}", params)[0]
            total += amount
            if count > 10000 or maximum > 2 * 1024 * 1024 or total > 32 * 1024 * 1024:
                raise RuntimeError("Current learned guidance exceeds the safety-copy bounds")
            state[key] = [list(row) for row in _rows(
                c, f"SELECT {columns} FROM {table}{_where(pred)} LIMIT 10001", params,
            )]
        _require_guidance_fence(source)
    validate_guidance_snapshot(state, source)
    return state


def restore_guidance_snapshot(state: dict) -> None:
    """Atomically replace only this tenant's accepted guidance and provenance."""
    source = _guidance_scope.get()
    if source is None:
        raise RuntimeError("The current learning guidance fence is required")
    _require_guidance_fence(source)
    validate_guidance_snapshot(state, source)
    pred, params = _tenant_predicate()
    tcol, tph, tparam = _tenant_column()
    with _conn() as c:
        for key, table, columns in (
            ("addenda", "harness_addenda", "key, block, updated_at"),
            ("line_meta", "harness_line_meta", "line_id, record, updated_at"),
        ):
            _exec(c, f"DELETE FROM {table}{_where(pred)}", params)
            for row in state[key]:
                _exec(c, f"INSERT INTO {table} ({columns}{tcol}) "
                      f"VALUES ({_ph(3)}{tph})", (*row, *tparam))
        _require_guidance_fence(source)


def load_addenda_db() -> dict[str, str]:
    """``{key: block}`` -- the world-store addenda map ({} on any error)."""
    pred, params = _tenant_predicate()
    try:
        with _conn() as c:
            return {str(k): str(b) for k, b in
                    _rows(c, f"SELECT key, block FROM harness_addenda{_where(pred)}",
                          params)}
    except LearningSchemaError:
        raise
    except Exception:
        log.debug("learning_store: addenda read failed", exc_info=True)
        return {}


def write_addenda_db(data: dict[str, str], *, effect_guard=None) -> None:
    """Whole-map replace, mirroring the file store's atomic rewrite.

    The DELETE is scoped to the active tenant so replacing one tenant's map never
    touches another's rows on the shared Postgres store."""
    now = time.time()
    pred, params = _tenant_predicate()
    tcol, tph, tparam = _tenant_column()
    with _conn() as c:
        if effect_guard is not None:
            effect_guard()
        _exec(c, f"DELETE FROM harness_addenda{_where(pred)}", params)
        for k, block in (data or {}).items():
            _exec(c, f"INSERT INTO harness_addenda (key, block, updated_at{tcol}) "
                     f"VALUES ({_ph(3)}{tph})", (str(k), str(block), now, *tparam))

        if effect_guard is not None:
            effect_guard()

def load_line_meta_db() -> dict[str, dict]:
    """``{line_id: record}`` provenance sidecar ({} on any error)."""
    out: dict[str, dict] = {}
    pred, params = _tenant_predicate()
    try:
        with _conn() as c:
            for lid, rec in _rows(
                    c, f"SELECT line_id, record FROM harness_line_meta{_where(pred)}",
                    params):
                try:
                    parsed = json.loads(rec)
                    if isinstance(parsed, dict):
                        out[str(lid)] = parsed
                except ValueError:
                    continue
    except LearningSchemaError:
        raise
    except Exception:
        log.debug("learning_store: line-meta read failed", exc_info=True)
    return out


def write_line_meta_db(meta: dict[str, dict], *, effect_guard=None) -> None:
    now = time.time()
    pred, params = _tenant_predicate()
    tcol, tph, tparam = _tenant_column()
    with _conn() as c:
        if effect_guard is not None:
            effect_guard()
        _exec(c, f"DELETE FROM harness_line_meta{_where(pred)}", params)
        for lid, rec in (meta or {}).items():
            _exec(c, f"INSERT INTO harness_line_meta (line_id, record, "
                     f"updated_at{tcol}) VALUES ({_ph(3)}{tph})",
                  (str(lid), json.dumps(rec, sort_keys=True), now, *tparam))

        if effect_guard is not None:
            effect_guard()

def load_transfer_tried_db(*, strict: bool = False) -> dict[str, float]:
    """Transfer attempt memory; strict callers retain read failures."""
    pred, params = _tenant_predicate()
    try:
        with _conn() as c:
            return {str(k): float(ts) for k, ts in
                    _rows(c,
                          f"SELECT line_id, ts FROM harness_transfer_tried{_where(pred)}",
                          params)}
    except LearningSchemaError:
        raise
    except Exception:
        if strict:
            raise
        log.debug("learning_store: tried read failed", exc_info=True)
        return {}


def write_transfer_tried_db(tried: dict[str, float], *, effect_guard=None) -> None:
    pred, params = _tenant_predicate()
    tcol, tph, tparam = _tenant_column()
    with _conn() as c:
        if effect_guard is not None:
            effect_guard()
        _exec(c, f"DELETE FROM harness_transfer_tried{_where(pred)}", params)
        for lid, ts in (tried or {}).items():
            _exec(c, f"INSERT INTO harness_transfer_tried (line_id, ts{tcol}) "
                     f"VALUES ({_ph(2)}{tph})", (str(lid), float(ts), *tparam))
        if effect_guard is not None:
            effect_guard()


def _corpus_row_sensitive(kind: str) -> bool:
    """True for machine-owned corpus rows that mirror sealed file sidecars."""
    return str(kind) in {"pending", "rejected"}


def _encode_corpus_row(kind: str, row: object) -> str:
    text = json.dumps(row, sort_keys=True)
    if _corpus_row_sensitive(kind):
        from .crypto_at_rest import at_rest_enabled
        if at_rest_enabled():
            from .crypto_at_rest import seal_to_str
            return seal_to_str(text)
    return text


def _decode_corpus_row(kind: str, row: str) -> object:
    if _corpus_row_sensitive(kind):
        from .crypto_at_rest import at_rest_enabled, is_sealed_str, strict_at_rest, unseal_from_str
        if at_rest_enabled():
            if is_sealed_str(row):
                row = unseal_from_str(row)
            elif strict_at_rest():
                log.error(
                    "at-rest strict: withholding an unsealed harness_corpus.%s row",
                    kind,
                )
                raise ValueError("unsealed sensitive corpus row withheld")
            else:
                log.warning(
                    "at-rest: unsealed harness_corpus.%s row "
                    "(pre-migration legacy or tampering); run 'maverick encryption migrate'",
                    kind,
                )
    return json.loads(row)


def load_corpus_db(kind: str, *, strict: bool = False) -> dict:
    """The corpus family from the world store, in the FILE shape:
    ``kind="live"`` returns ``{key: [row-dicts]}`` merged with any preserved
    non-list top-level entries (stored under kind ``extra``); ``"pending"``
    returns ``{key: [row-dicts]}``; ``"rejected"`` returns ``{key: [goals]}``.
    ``{}`` on any error, like the tolerant file loaders. Writers use ``strict``
    so an unreadable row or database cannot become a partial whole-family save.
    The checker keeps its historical tolerant read by default."""
    out: dict = {}
    pred, tp = _tenant_predicate()
    try:
        with _conn() as c:
            for key, seq, row in _rows(
                    c, f"SELECT key, seq, row FROM harness_corpus WHERE kind = {_ph(1)}"
                       f"{_and(pred)} ORDER BY key, seq", (str(kind), *tp)):
                try:
                    if strict and (not isinstance(key, str) or type(seq) is not int
                                   or seq != len(out.get(key, []))):
                        raise ValueError("The retained learning collection needs review.")
                    out.setdefault(str(key), []).append(_decode_corpus_row(str(kind), row))
                except ValueError:
                    if strict:
                        raise
                    continue
            if kind == "live":
                for key, seq, row in _rows(
                        c, f"SELECT key, seq, row FROM harness_corpus "
                           f"WHERE kind = {_ph(1)}{_and(pred)} ORDER BY key, seq",
                        ("extra", *tp)):
                    try:
                        if strict and (not isinstance(key, str) or type(seq) is not int
                                       or seq != 0 or key in out):
                            raise ValueError("The retained learning collection needs review.")
                        out[str(key)] = _decode_corpus_row("extra", row)
                    except ValueError:
                        if strict:
                            raise
                        continue
            if strict:
                json.dumps(out, allow_nan=False)
    except LearningSchemaError:
        raise
    except Exception as exc:
        if strict:
            raise ValueError("The current learning collection could not be read safely.") from exc
        log.debug("learning_store: corpus read failed (%s)", kind, exc_info=True)
        return {}
    return out


def write_corpus_db(kind: str, data: dict, *, effect_guard=None) -> None:
    """Whole-family replace for ``kind``, mirroring the file store's atomic
    rewrite. For ``"live"``, non-list top-level values are preserved under the
    ``extra`` kind so operator annotations survive the round-trip."""
    with _conn() as c:
        if effect_guard is not None:
            if isinstance(c, sqlite3.Connection):
                c.execute("BEGIN IMMEDIATE")
            else:
                _exec(c, "LOCK TABLE harness_corpus IN ROW EXCLUSIVE MODE")
            effect_guard()
        _write_corpus_family(c, kind, data)
        if effect_guard is not None:
            effect_guard()


def _write_corpus_family(c, kind: str, data: dict) -> None:
    pred, tp = _tenant_predicate()
    tcol, tph, tparam = _tenant_column()
    _exec(c, f"DELETE FROM harness_corpus WHERE kind = {_ph(1)}{_and(pred)}", (str(kind), *tp))
    if kind == "live":
        _exec(c, f"DELETE FROM harness_corpus WHERE kind = {_ph(1)}{_and(pred)}", ("extra", *tp))
    for key, val in (data or {}).items():
        if kind == "live" and not isinstance(val, list):
            _exec(c, f"INSERT INTO harness_corpus (kind, key, seq, row{tcol}) VALUES ({_ph(4)}{tph})",
                  ("extra", str(key), 0, _encode_corpus_row("extra", val), *tparam))
            continue
        for i, row in enumerate(val if isinstance(val, list) else []):
            _exec(c, f"INSERT INTO harness_corpus (kind, key, seq, row{tcol}) VALUES ({_ph(4)}{tph})",
                  (str(kind), str(key), i, _encode_corpus_row(str(kind), row), *tparam))


def write_corpus_families_db(families: dict[str, dict]) -> None:
    """One native transaction for a reviewed pending/live/rejected decision.

    Callers retain the existing corpus authority and RMW locks. Validation is
    complete before DELETE; unsupported non-list secondary-family data is never
    silently discarded. Native encoding and tenant predicates are unchanged.
    """
    if set(families) != {"live", "pending", "rejected"} or any(not isinstance(value, dict) for value in families.values()):
        raise ValueError("The current learning collections could not be changed safely.")
    for kind, value in families.items():
        if (len(json.dumps(value, allow_nan=False).encode()) > 5 * 1024 * 1024
                or kind != "live" and any(not isinstance(rows, list) for rows in value.values())):
            raise ValueError("The current learning collections could not be changed safely.")
    with _conn() as c:
        for kind in ("live", "rejected", "pending"):
            _write_corpus_family(c, kind, families[kind])


__all__ = [
    "enabled", "rmw_lock",
    "load_addenda_db", "write_addenda_db",
    "load_line_meta_db", "write_line_meta_db",
    "load_transfer_tried_db", "write_transfer_tried_db",
    "load_corpus_db", "write_corpus_db",
]
