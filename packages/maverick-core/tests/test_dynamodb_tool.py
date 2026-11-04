"""Tests for the DynamoDB tool (maverick.tools.dynamodb_tool)."""
from __future__ import annotations

import sys
import types

# ---------- DynamoDB ----------

def _install_fake_boto3_ddb(monkeypatch, *, tables=None, item=None,
                            query_items=None, scan_items=None):
    boto3 = types.ModuleType("boto3")

    class _Meta:
        def __init__(self, c):
            self.client = c

    class _LL:
        def list_tables(self):
            return {"TableNames": tables or []}

    class _Table:
        def __init__(self, name):
            self.name = name

        def get_item(self, **k):
            return {"Item": item} if item is not None else {}

        def put_item(self, **k):
            return {}

        def delete_item(self, **k):
            return {}

        def query(self, **k):
            return {"Items": query_items or [], "Count": len(query_items or [])}

        def scan(self, **k):
            return {"Items": scan_items or [], "Count": len(scan_items or [])}

    class _Resource:
        @property
        def meta(self):
            return _Meta(_LL())

        def Table(self, name):
            return _Table(name)

    boto3.resource = lambda service, *a, **k: _Resource()
    boto3.client = lambda *a, **k: _LL()
    monkeypatch.setitem(sys.modules, "boto3", boto3)


def test_dynamodb_requires_op():
    from maverick.tools.dynamodb_tool import dynamodb_tool
    assert "op is required" in dynamodb_tool().fn({})


def test_dynamodb_tables(monkeypatch):
    _install_fake_boto3_ddb(monkeypatch, tables=["Users", "Orders"])
    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({"op": "tables"})
    assert "Users" in out and "Orders" in out


def test_dynamodb_get(monkeypatch):
    _install_fake_boto3_ddb(monkeypatch, item={"id": "1", "name": "alice"})
    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({
        "op": "get", "table": "Users", "key": {"id": "1"},
    })
    assert "alice" in out


def test_dynamodb_put_dry_run(monkeypatch):
    _install_fake_boto3_ddb(monkeypatch)
    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({
        "op": "put", "table": "Users", "item": {"id": "1"},
    })
    assert "DRY RUN" in out


def test_dynamodb_query(monkeypatch):
    _install_fake_boto3_ddb(monkeypatch, query_items=[
        {"id": "1", "name": "alice"},
    ])
    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({
        "op": "query", "table": "Users",
        "key_cond_expression": "id = :id",
        "expression_values": {":id": "1"},
    })
    assert "count=1" in out and "alice" in out


def test_dynamodb_query_follows_last_evaluated_key(monkeypatch):
    import types as _t

    boto3 = _t.ModuleType("boto3")
    calls = {"query": []}

    class _Table:
        def query(self, **k):
            calls["query"].append(k)
            if "ExclusiveStartKey" not in k:
                return {"Items": [{"id": "1", "name": "alice"}],
                        "ScannedCount": 1,
                        "LastEvaluatedKey": {"id": "1"}}
            return {"Items": [{"id": "2", "name": "bob"}], "ScannedCount": 1}

    class _Resource:
        def Table(self, name):
            return _Table()

    boto3.resource = lambda *a, **k: _Resource()
    boto3.client = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "boto3", boto3)

    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({
        "op": "query", "table": "Users",
        "key_cond_expression": "id = :id",
        "expression_values": {":id": "1"}, "limit": 50,
    })
    assert "alice" in out and "bob" in out and "count=2" in out
    assert len(calls["query"]) == 2
    assert calls["query"][1]["ExclusiveStartKey"] == {"id": "1"}


def test_dynamodb_scan_pagination_obeys_total_read_budget(monkeypatch):
    import types as _t

    boto3 = _t.ModuleType("boto3")
    calls = {"scan": []}

    class _Table:
        def scan(self, **k):
            calls["scan"].append(k)
            return {
                "Items": [],
                "ScannedCount": k["Limit"],
                "LastEvaluatedKey": {"id": str(len(calls["scan"]))},
            }

    class _Resource:
        def Table(self, name):
            return _Table()

    boto3.resource = lambda *a, **k: _Resource()
    boto3.client = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "boto3", boto3)

    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({
        "op": "scan", "table": "Users",
        "filter_expression": "kind = :kind",
        "expression_values": {":kind": "missing"}, "limit": 1000,
    })
    assert out == "no items"
    assert len(calls["scan"]) == 1
    assert sum(call["Limit"] for call in calls["scan"]) == 1000


def test_dynamodb_scan_pagination_missing_scanned_count_fails_closed(monkeypatch):
    import types as _t

    boto3 = _t.ModuleType("boto3")
    calls = {"scan": []}

    class _Table:
        def scan(self, **k):
            calls["scan"].append(k)
            return {"Items": [], "LastEvaluatedKey": {"id": str(len(calls["scan"]))}}

    class _Resource:
        def Table(self, name):
            return _Table()

    boto3.resource = lambda *a, **k: _Resource()
    boto3.client = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "boto3", boto3)

    from maverick.tools.dynamodb_tool import dynamodb_tool
    out = dynamodb_tool().fn({"op": "scan", "table": "Users", "limit": 1000})
    assert out == "no items"
    assert len(calls["scan"]) == 1
    assert sum(call["Limit"] for call in calls["scan"]) == 1000
