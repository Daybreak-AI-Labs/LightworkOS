"""MongoDB tool.

Connect to a MongoDB cluster and run common CRUD operations from
inside an agent task. Auth + connection string from ``MONGODB_URI``;
optionally ``MONGODB_DB`` for the default database.

ops:
  - find(collection, filter, limit, sort)
  - find_one(collection, filter)
  - insert(collection, doc)
  - update(collection, filter, set_, upsert, confirm)   — needs confirm=true
  - delete(collection, filter, confirm)                 — needs confirm=true
  - count(collection, filter)
  - collections()                                       — list names

Mutations are gated by ``confirm=true`` so the agent can't blow away
a collection accidentally.

Requires::

    python -m pip install -e './packages/maverick-core[mongodb]'
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

from ..fastjson import dumps_compact
from . import Tool, as_bool

# Bounds every server round trip, so a slow scan or a stalled server cannot
# hold a tool worker thread indefinitely.
_SOCKET_TIMEOUT_MS = 30_000

log = logging.getLogger(__name__)


_MONGO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["find", "find_one", "insert", "update",
                     "delete", "count", "collections"],
        },
        "db": {"type": "string", "description": "Database name (default: MONGODB_DB)."},
        "collection": {"type": "string"},
        "filter": {"type": "object", "description": "Mongo query filter."},
        "set_": {"type": "object", "description": "$set fields (update)."},
        "doc": {"type": "object", "description": "Doc to insert."},
        "limit": {"type": "integer"},
        "sort": {
            "type": "array",
            "items": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "integer"}]},
            "description": "List of (field, direction) pairs. direction = 1 or -1.",
        },
        "upsert": {"type": "boolean"},
        "confirm": {"type": "boolean", "description": "Required true to mutate."},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str]:
    uri = os.environ.get("MONGODB_URI", "").strip()
    db = os.environ.get("MONGODB_DB", "").strip()
    if not uri:
        raise RuntimeError("MongoDB requires MONGODB_URI.")
    _check_egress(uri)
    return uri, db


def _check_egress(uri: str) -> None:
    """pymongo uses raw sockets, outside the process egress guard, so check
    every seed host in the URI against the egress policy.

    A ``mongodb+srv://`` URI names a DNS record whose hosts pymongo looks up
    itself, so under any egress policy it is refused: list the hosts in a
    ``mongodb://`` URI instead."""
    from ._sdk_egress import egress_restricted, require_sdk_egress

    if uri.lower().startswith("mongodb+srv://") and egress_restricted("mongodb"):
        raise RuntimeError(
            "mongodb: an egress policy is active and a mongodb+srv:// URI hides the "
            "real database hosts behind DNS, so they cannot be checked; set "
            "MONGODB_URI to a mongodb:// URI that lists the hosts")
    rest = uri.split("://", 1)[-1]
    hosts = rest.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
    for host in hosts.split(","):
        require_sdk_egress("mongodb", f"http://{host.strip()}/")


# One MongoClient is built per _run() and closed in its finally (see below).
# Building a fresh MongoClient -- a connection pool plus background
# topology-monitor threads -- on every _op_* would leak sockets + threads per
# tool call. The active client is stashed
# thread-locally so the _op_* helpers reuse it without signature changes.
_TL = threading.local()


def _client():
    cur = getattr(_TL, "client", None)
    if cur is not None:
        return cur
    # Fallback (e.g. a helper called directly outside _run): build a one-off.
    from pymongo import MongoClient
    uri, _db = _config()
    return MongoClient(uri, serverSelectionTimeoutMS=5000,
                       socketTimeoutMS=_SOCKET_TIMEOUT_MS)


def _db_for(args: dict[str, Any]):
    _uri, default_db = _config()
    name = (args.get("db") or "").strip() or default_db
    if not name:
        return None, "ERROR: db not provided and MONGODB_DB unset"
    return _client()[name], None


def _serialize(obj: Any, _depth: int = 0) -> Any:
    """ObjectId / datetime / bytes -> JSON-safe."""
    # Depth cap: a document is external data; a deeply-nested one would blow the
    # stack here. Real BSON nesting is shallow (server cap 100).
    if _depth > 64:
        return str(obj)
    try:
        from bson import ObjectId
    except ImportError:
        ObjectId = None  # type: ignore
    import datetime as _dt
    if ObjectId is not None and isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _serialize(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v, _depth + 1) for v in obj]
    return obj


def _dump(obj: Any, max_chars: int = 3000) -> str:
    s = dumps_compact(_serialize(obj))
    if len(s) > max_chars:
        s = s[:max_chars] + "\n... (truncated)"
    return s


def _op_collections(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    names = list(db.list_collection_names())
    return "\n".join(f"  {n}" for n in names) if names else "(no collections)"


def _op_find(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    col = (args.get("collection") or "").strip()
    if not col:
        return "ERROR: find requires collection"
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else {}
    limit = max(1, min(int(args.get("limit") or 25), 1000))
    sort_pairs = args.get("sort") or []
    cursor = db[col].find(flt)
    if sort_pairs:
        try:
            cursor = cursor.sort([(s[0], int(s[1])) for s in sort_pairs])
        except (TypeError, ValueError, IndexError):
            # A bad sort must fail loudly: sort decides WHICH documents
            # survive the limit below, so silently dropping it would return
            # the wrong documents labeled as a successful sorted query.
            return (
                "ERROR: sort must be a list of [field, direction] pairs "
                f"with direction 1 or -1 (got {sort_pairs!r})"
            )
    docs = list(cursor.limit(limit))
    if not docs:
        return "no docs"
    return _dump(docs)


def _op_find_one(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    col = (args.get("collection") or "").strip()
    if not col:
        return "ERROR: find_one requires collection"
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else {}
    doc = db[col].find_one(flt)
    if doc is None:
        return "no doc matched"
    return _dump(doc)


def _op_count(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    col = (args.get("collection") or "").strip()
    if not col:
        return "ERROR: count requires collection"
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else {}
    n = db[col].count_documents(flt)
    return f"{n} document(s) match"


def _op_insert(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    if not as_bool(args.get("confirm")):
        return "DRY RUN: insert blocked. Re-run with confirm=true."
    col = (args.get("collection") or "").strip()
    doc = args.get("doc") if isinstance(args.get("doc"), dict) else None
    if not col or doc is None:
        return "ERROR: insert requires collection and doc"
    result = db[col].insert_one(doc)
    return f"inserted _id={result.inserted_id}"


def _op_update(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    if not as_bool(args.get("confirm")):
        return "DRY RUN: update blocked. Re-run with confirm=true."
    col = (args.get("collection") or "").strip()
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else None
    set_ = args.get("set_") if isinstance(args.get("set_"), dict) else None
    if not col or flt is None or set_ is None:
        return "ERROR: update requires collection, filter, set_"
    result = db[col].update_many(flt, {"$set": set_},
                                  upsert=as_bool(args.get("upsert")))
    return (
        f"matched={result.matched_count} modified={result.modified_count} "
        f"upserted_id={result.upserted_id}"
    )


def _op_delete(args: dict[str, Any]) -> str:
    db, err = _db_for(args)
    if err:
        return err
    if not as_bool(args.get("confirm")):
        return "DRY RUN: delete blocked. Re-run with confirm=true."
    col = (args.get("collection") or "").strip()
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else None
    if not col or flt is None:
        return "ERROR: delete requires collection and filter"
    result = db[col].delete_many(flt)
    return f"deleted_count={result.deleted_count}"


# Query operators that execute arbitrary JavaScript on the Mongo server.
_SERVER_JS_OPERATORS = frozenset({"$where", "$function", "$accumulator"})


def _reject_server_side_js(node: Any) -> str | None:
    """Return an error if the query filter contains a server-side-JS operator.

    ``$where`` / ``$function`` / ``$accumulator`` run attacker-controlled
    JavaScript on the database server, so a model-supplied filter carrying one
    is a code-injection / DoS vector. Walk the filter recursively (keys at any
    depth, inside ``$and`` / ``$or`` arrays) and refuse the whole request.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in _SERVER_JS_OPERATORS:
                return (
                    f"ERROR: filter operator {k!r} runs server-side JavaScript "
                    "and is not allowed"
                )
            err = _reject_server_side_js(v)
            if err:
                return err
    elif isinstance(node, list):
        for item in node:
            err = _reject_server_side_js(item)
            if err:
                return err
    return None


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    # Refuse server-side-JS query operators before building the client, so a
    # hostile filter never reaches the database.
    bad = _reject_server_side_js(args.get("filter"))
    if bad:
        return bad
    try:
        import pymongo  # noqa: F401
    except ImportError:
        return (
            "ERROR: pymongo not installed. "
            "Run: python -m pip install -e './packages/maverick-core[mongodb]'"
        )
    # Build ONE client for this call and close it in finally so we don't leak a
    # pool + monitor threads per op.
    try:
        from pymongo import MongoClient
        uri, _db = _config()
        _TL.client = MongoClient(uri, serverSelectionTimeoutMS=5000,
                                 socketTimeoutMS=_SOCKET_TIMEOUT_MS)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: MongoDB request failed: {type(e).__name__}: {e}"
    try:
        if op == "collections":
            return _op_collections(args)
        if op == "find":
            return _op_find(args)
        if op == "find_one":
            return _op_find_one(args)
        if op == "count":
            return _op_count(args)
        if op == "insert":
            return _op_insert(args)
        if op == "update":
            return _op_update(args)
        if op == "delete":
            return _op_delete(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: MongoDB request failed: {type(e).__name__}: {e}"
    finally:
        try:
            _TL.client.close()
        except Exception:
            pass
        _TL.client = None
    return f"ERROR: unknown op {op!r}"


def mongodb_tool() -> Tool:
    return Tool(
        name="mongodb",
        description=(
            "MongoDB CRUD. ops: collections, find (filter + sort + "
            "limit), find_one, count, insert, update (with $set + "
            "upsert), delete. Mutations gated by confirm=true. "
            "Auth: MONGODB_URI (+ MONGODB_DB)."
        ),
        input_schema=_MONGO_SCHEMA,
        fn=_run,
    )
