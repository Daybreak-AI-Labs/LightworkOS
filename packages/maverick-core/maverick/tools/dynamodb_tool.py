"""AWS DynamoDB tool — get / put / query / scan.

Standard boto3 auth chain. Optional ``AWS_ENDPOINT_URL`` for
DynamoDB Local. All writes gated by ``confirm=true``.

ops:
  - tables()
  - get(table, key)
  - put(table, item, confirm)
  - delete(table, key, confirm)
  - query(table, key_cond_expression, expression_values, limit)
  - scan(table, filter_expression, expression_values, limit)
"""
from __future__ import annotations

import logging
import os
from decimal import Decimal
from typing import Any

from ..fastjson import dumps_compact
from . import Tool, as_bool

log = logging.getLogger(__name__)


_DDB_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["tables", "get", "put", "delete", "query", "scan"],
        },
        "table": {"type": "string"},
        "key": {"type": "object", "description": "Primary key (PK + optional SK)."},
        "item": {"type": "object"},
        "key_cond_expression": {"type": "string", "description": "DynamoDB KeyConditionExpression."},
        "filter_expression": {"type": "string"},
        "expression_values": {"type": "object", "description": "Map of :name -> value."},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _client():
    import boto3
    return boto3.resource(
        "dynamodb",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None,
        region_name=os.environ.get("AWS_REGION") or None,
    )


def _serialize(obj: Any, _depth: int = 0) -> Any:
    # Depth cap: a DynamoDB item is external data; a deeply-nested one would
    # blow the stack. Real nesting is shallow (service cap ~32).
    if _depth > 64:
        return str(obj)
    if isinstance(obj, Decimal):
        return float(obj) if obj % 1 else int(obj)
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _serialize(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v, _depth + 1) for v in obj]
    return obj


def _dump(obj: Any, n: int = 3000) -> str:
    s = dumps_compact(_serialize(obj))
    if len(s) > n:
        s = s[:n] + "\n... (truncated)"
    return s


def _op_tables(_args: dict) -> str:
    c = _client().meta.client
    names = c.list_tables().get("TableNames") or []
    return "\n".join(f"  {n}" for n in names) if names else "(no tables)"


def _op_get(args: dict) -> str:
    table = (args.get("table") or "").strip()
    key = args.get("key") if isinstance(args.get("key"), dict) else None
    if not table or not key:
        return "ERROR: get requires table and key"
    t = _client().Table(table)
    r = t.get_item(Key=key)
    item = r.get("Item")
    if item is None:
        return "(not found)"
    return _dump(item)


def _op_put(args: dict) -> str:
    table = (args.get("table") or "").strip()
    item = args.get("item") if isinstance(args.get("item"), dict) else None
    if not table or not item:
        return "ERROR: put requires table and item"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would put item in {table}. Re-run with confirm=true."
    _client().Table(table).put_item(Item=item)
    return f"put item in {table}"


def _op_delete(args: dict) -> str:
    table = (args.get("table") or "").strip()
    key = args.get("key") if isinstance(args.get("key"), dict) else None
    if not table or not key:
        return "ERROR: delete requires table and key"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete item from {table}. Re-run with confirm=true."
    _client().Table(table).delete_item(Key=key)
    return f"deleted item from {table}"


def _paginate(method, base_kwargs: dict, limit: int) -> list[dict]:
    """Run a DynamoDB query/scan without exceeding the requested read budget.

    DynamoDB ``Limit`` is a per-request evaluated/scanned cap, not a total
    matched-item cap. Keep separate read and page budgets so filtered requests
    cannot multiply the requested work across continuation pages.
    """
    items: list[dict] = []
    start_key = None
    remaining_read_budget = limit
    max_pages = 10
    for _ in range(max_pages):
        if remaining_read_budget <= 0 or len(items) >= limit:
            break
        page_limit = min(1000, remaining_read_budget, limit - len(items))
        kwargs = dict(base_kwargs)
        kwargs["Limit"] = page_limit
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        r = method(**kwargs)
        items.extend(r.get("Items") or [])
        scanned = r.get("ScannedCount")
        if isinstance(scanned, int) and scanned > 0:
            remaining_read_budget -= min(scanned, page_limit)
        else:
            remaining_read_budget -= page_limit
        start_key = r.get("LastEvaluatedKey")
        if not start_key:
            break
    return items[:limit]


def _op_query(args: dict) -> str:
    table = (args.get("table") or "").strip()
    expr = (args.get("key_cond_expression") or "").strip()
    if not table or not expr:
        return "ERROR: query requires table and key_cond_expression"
    vals = args.get("expression_values") if isinstance(
        args.get("expression_values"), dict) else {}
    limit = max(1, min(int(args.get("limit") or 25), 1000))
    items = _paginate(_client().Table(table).query, {
        "KeyConditionExpression": expr,
        "ExpressionAttributeValues": vals,
    }, limit)
    if not items:
        return "no items"
    return f"count={len(items)}\n" + _dump(items)


def _op_scan(args: dict) -> str:
    table = (args.get("table") or "").strip()
    if not table:
        return "ERROR: scan requires table"
    limit = max(1, min(int(args.get("limit") or 25), 1000))
    kwargs: dict = {}
    f = (args.get("filter_expression") or "").strip()
    if f:
        kwargs["FilterExpression"] = f
        vals = args.get("expression_values") if isinstance(
            args.get("expression_values"), dict) else {}
        kwargs["ExpressionAttributeValues"] = vals
    items = _paginate(_client().Table(table).scan, kwargs, limit)
    if not items:
        return "no items"
    return f"count={len(items)}\n" + _dump(items)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import boto3  # noqa: F401
    except ImportError:
        return "ERROR: boto3 not installed. Run: python -m pip install -e './packages/maverick-core[s3]'"
    try:
        return {
            "tables": _op_tables,
            "get":    _op_get,
            "put":    _op_put,
            "delete": _op_delete,
            "query":  _op_query,
            "scan":   _op_scan,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: DynamoDB request failed: {type(e).__name__}: {e}"


def dynamodb_tool() -> Tool:
    return Tool(
        name="dynamodb",
        description=(
            "DynamoDB CRUD + query/scan. ops: tables, get, put, "
            "delete (mutations confirm=true), query "
            "(KeyConditionExpression + expression_values), scan "
            "(optional filter). Standard boto3 auth + "
            "AWS_ENDPOINT_URL override."
        ),
        input_schema=_DDB_SCHEMA,
        fn=_run,
    )
