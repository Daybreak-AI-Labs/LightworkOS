"""The JSON seam preserves stdlib semantics with optional extras installed."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

import pytest
from maverick import fastjson


def test_roundtrip_basic():
    obj = {"b": 1, "a": [1, 2, {"x": "y"}], "n": None, "f": 1.5, "t": True}
    assert fastjson.loads(fastjson.dumps(obj)) == obj


def test_loads_accepts_bytes_and_str():
    assert fastjson.loads('{"a": 1}') == {"a": 1}
    assert fastjson.loads(b'{"a": 1}') == {"a": 1}


def test_dumps_returns_str():
    assert isinstance(fastjson.dumps({"a": 1}), str)


def test_sort_keys():
    out = fastjson.dumps({"b": 1, "a": 2}, sort_keys=True)
    # key order is a..b regardless of backend (whitespace may differ)
    assert out.index('"a"') < out.index('"b"')
    assert fastjson.loads(out) == {"a": 2, "b": 1}


def test_falls_back_for_nonstandard_types():
    # default=str stringifies unsupported values rather than raising.
    out = fastjson.dumps({"s": {1, 2}})
    assert isinstance(out, str)
    assert "s" in fastjson.loads(out)


def test_output_is_valid_json_for_stdlib_consumers():
    # whatever backend produced it, stdlib json can parse it back
    assert json.loads(fastjson.dumps({"a": [1, 2], "b": "x"})) == {"a": [1, 2], "b": "x"}


def test_backend_name():
    assert fastjson.backend() == "stdlib"


@pytest.mark.parametrize("serializer", [fastjson.dumps, fastjson.dumps_compact])
def test_serialization_matches_stdlib_for_nonstandard_values(serializer):
    @dataclass
    class Record:
        value: int

    value = {"nan": float("nan"), "date": datetime(2026, 1, 2, 3, 4, 5), "record": Record(3)}
    expected = json.dumps(value, default=str)
    assert json.loads(serializer(value), parse_constant=str) == json.loads(
        expected, parse_constant=str
    )


@pytest.mark.parametrize("payload", ["115292150460684697612345", b'{"n":115292150460684697612345}'])
def test_loads_preserves_arbitrary_precision_integers(payload):
    assert fastjson.loads(payload) == json.loads(payload)


def test_dumps_compact_has_no_separator_whitespace():
    # Model-facing payloads: every space is a wasted token, and callers that
    # truncate to a char budget lose real data to it. Both backends must emit
    # the dense form.
    out = fastjson.dumps_compact({"a": 1, "b": [1, 2], "c": {"d": "e"}})
    assert out == '{"a":1,"b":[1,2],"c":{"d":"e"}}'


def test_dumps_compact_roundtrips_and_sorts():
    obj = {"b": 1, "a": {"y": [3, 2], "x": None}}
    assert fastjson.loads(fastjson.dumps_compact(obj)) == obj
    out = fastjson.dumps_compact(obj, sort_keys=True)
    assert out.index('"a"') < out.index('"b"')


def test_dumps_compact_falls_back_for_nonstandard_types():
    # default=str stringifies unsupported values, as in dumps().
    out = fastjson.dumps_compact({"s": {1, 2}})
    assert "s" in fastjson.loads(out)


def test_tool_cache_snapshot_roundtrips_via_fastjson(tmp_path, monkeypatch):
    # The wired site: save_snapshot writes rows with fastjson; warm_on_start
    # parses them back. A full round-trip through the fastjson seam.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT", "1")
    from maverick.cache import tool as tool_cache

    class _Tool:
        name = "toolX"
        parallel_safe = True

    tool_cache.reset()
    tool_cache.store_cached(_Tool(), {"q": 1}, "result-value")
    assert tool_cache.save_snapshot() == 1

    tool_cache.reset()
    loaded = tool_cache.warm_on_start()
    assert loaded == 1
    hit, val = tool_cache.get_cached(_Tool(), {"q": 1})
    assert hit and val == "result-value"
