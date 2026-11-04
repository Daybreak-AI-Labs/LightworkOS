"""MongoDB tool: reject server-side-JavaScript query operators ($where /
$function / $accumulator). A model-supplied filter carrying one would run
arbitrary JS on the database server (code injection / DoS)."""
from __future__ import annotations

import pytest
from maverick.tools.mongodb_tool import _reject_server_side_js, mongodb_tool


@pytest.mark.parametrize("flt", [
    {"$where": "function(){ return true; }"},
    {"$function": {"body": "x", "args": [], "lang": "js"}},
    {"$accumulator": {"init": "x"}},
    {"$or": [{"a": 1}, {"$where": "evil"}]},            # nested in an array
    {"age": {"$gt": 21}, "meta": {"$where": "evil"}},   # nested in a subdoc
    {"$AND": [{"$WHERE": "x"}]},                         # case-insensitive
])
def test_rejects_server_side_js(flt):
    out = _reject_server_side_js(flt)
    assert out is not None and "JavaScript" in out


@pytest.mark.parametrize("flt", [
    None,
    {},
    {"age": {"$gt": 21}},
    {"$or": [{"a": 1}, {"b": {"$in": [1, 2]}}]},
    {"name": "$where is fine as a value"},              # value, not a key
])
def test_allows_safe_filters(flt):
    assert _reject_server_side_js(flt) is None


def test_run_blocks_where_before_client():
    # The guard runs before pymongo is imported/connected, so a hostile filter
    # is refused even with no DB configured/installed locally.
    out = mongodb_tool().fn({"op": "find", "collection": "c",
                             "filter": {"$where": "while(1){}"}})
    assert out.startswith("ERROR") and ("JavaScript" in out or "$where" in out)
