"""Elasticsearch / OpenSearch tool.

Works against both Elasticsearch and OpenSearch (the API surfaces
are still close enough for the basic CRUD + search ops we expose).

Auth:
  - ``ES_URL`` (e.g. ``https://es.example.com:9200``)
  - ``ES_API_KEY`` (preferred) OR ``ES_USERNAME`` + ``ES_PASSWORD``

ops:
  - search(index, query, limit)
  - get(index, doc_id)
  - index(index, doc_id, body, confirm)        — create-or-update doc
  - delete(index, doc_id, confirm)
  - indices(prefix)                            — list indices + sizes
  - count(index, query)
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Any

from ..fastjson import dumps_compact
from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)


_ES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "get", "index", "delete", "indices", "count"],
        },
        "index": {"type": "string"},
        "doc_id": {"type": "string"},
        "query": {"type": "object", "description": "ES query DSL body."},
        "body": {"type": "object"},
        "limit": {"type": "integer"},
        "prefix": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _base() -> str:
    u = os.environ.get("ES_URL", "").strip().rstrip("/")
    if not u:
        raise RuntimeError("Elasticsearch requires ES_URL.")
    return u


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    key = os.environ.get("ES_API_KEY", "").strip()
    if key:
        h["Authorization"] = f"ApiKey {key}"
        return h
    user = os.environ.get("ES_USERNAME", "").strip()
    pwd = os.environ.get("ES_PASSWORD", "").strip()
    if user and pwd:
        raw = f"{user}:{pwd}".encode("ascii")
        h["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return h


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_base()}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_base()}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _put(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.put)(f"{_base()}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _delete(path: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.delete)(f"{_base()}{path}", headers=_headers(), timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _seg(value: str) -> str:
    """URL-quote a path segment so a hostile index/doc_id cannot traverse to
    another ES endpoint (e.g. doc_id='../../_cluster/settings' or
    index='_all'). quote(safe='') encodes '/', making traversal impossible;
    legitimate ES index/doc names contain none of these reserved chars."""
    from urllib.parse import quote
    return quote(value, safe="")


def _op_search(args: dict) -> str:
    index = (args.get("index") or "").strip()
    if not index:
        return "ERROR: search requires index"
    query = args.get("query") if isinstance(args.get("query"), dict) else {
        "query": {"match_all": {}},
    }
    limit = max(1, min(int(args.get("limit") or 10), 100))
    body = {**query, "size": limit}
    code, data = _post(f"/{_seg(index)}/_search", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    hits = (data.get("hits") or {}).get("hits") or []
    total = (data.get("hits") or {}).get("total") or {}
    total_val = total.get("value") if isinstance(total, dict) else total
    if not hits:
        return f"no hits (total={total_val})"
    out = [f"total={total_val} took={data.get('took')}ms"]
    for h in hits:
        # _score is null on any query with a `sort` clause (the norm for
        # time-series/log search), so format it conditionally.
        sc = h.get("_score")
        score_s = f"{sc:>6.2f}" if isinstance(sc, (int, float)) else f"{'—':>6}"
        out.append(
            f"  [{score_s}]  {h.get('_id')}  "
            f"{dumps_compact(h.get('_source') or {})[:200]}"
        )
    return "\n".join(out)


def _op_get(args: dict) -> str:
    index = (args.get("index") or "").strip()
    did = (args.get("doc_id") or "").strip()
    if not index or not did:
        return "ERROR: get requires index and doc_id"
    code, data = _get(f"/{_seg(index)}/_doc/{_seg(did)}")
    if code == 404:
        return f"doc {index}/{did} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: get ({code}): {data}"
    return dumps_compact(data.get("_source") or {})[:3000]


def _op_index(args: dict) -> str:
    index = (args.get("index") or "").strip()
    did = (args.get("doc_id") or "").strip()
    body = args.get("body") if isinstance(args.get("body"), dict) else None
    if not index or not did or body is None:
        return "ERROR: index requires index, doc_id, body"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would index {index}/{did}. Re-run with confirm=true."
    code, data = _put(f"/{_seg(index)}/_doc/{_seg(did)}", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: index ({code}): {data}"
    return f"indexed {index}/{did} result={data.get('result')}"


def _op_delete(args: dict) -> str:
    index = (args.get("index") or "").strip()
    did = (args.get("doc_id") or "").strip()
    if not index or not did:
        return "ERROR: delete requires index and doc_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete {index}/{did}. Re-run with confirm=true."
    code, data = _delete(f"/{_seg(index)}/_doc/{_seg(did)}")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: delete ({code}): {data}"
    return f"deleted {index}/{did} result={data.get('result')}"


def _op_indices(args: dict) -> str:
    prefix = (args.get("prefix") or "").strip()
    path = "/_cat/indices"
    if prefix:
        path += f"/{_seg(prefix)}*"
    code, data = _get(path, {"format": "json", "h": "index,docs.count,store.size"})
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: indices ({code}): {data}"
    if not data:
        return "no indices"
    return "\n".join(
        f"  {it.get('index', '?'):<40}  docs={it.get('docs.count', '?')}  "
        f"size={it.get('store.size', '?')}"
        for it in data
    )


def _op_count(args: dict) -> str:
    index = (args.get("index") or "").strip()
    if not index:
        return "ERROR: count requires index"
    query = args.get("query") if isinstance(args.get("query"), dict) else {
        "query": {"match_all": {}},
    }
    code, data = _post(f"/{_seg(index)}/_count", query)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: count ({code}): {data}"
    return f"count={data.get('count')}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "search":  _op_search,
            "get":     _op_get,
            "index":   _op_index,
            "delete":  _op_delete,
            "indices": _op_indices,
            "count":   _op_count,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Elasticsearch request failed: {type(e).__name__}: {e}"


def elasticsearch_tool() -> Tool:
    return Tool(
        name="elasticsearch",
        description=(
            "Elasticsearch / OpenSearch CRUD + search. ops: search "
            "(query DSL + size), get / index / delete (mutations "
            "need confirm=true), indices (list), count. Auth: "
            "ES_URL + ES_API_KEY (or ES_USERNAME + ES_PASSWORD)."
        ),
        input_schema=_ES_SCHEMA,
        fn=_run,
    )
