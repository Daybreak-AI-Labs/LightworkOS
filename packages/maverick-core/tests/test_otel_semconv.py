"""otel_semconv: OpenTelemetry semantic-conventions mapper."""
from __future__ import annotations

import json

from maverick.tools.otel_semconv import otel_semconv


def _map(span):
    return otel_semconv().fn({"op": "map", "span": span})


def _attrs(out):
    line = [ln for ln in out.splitlines() if ln.strip().startswith("attrs=")][0]
    return json.loads(line.split("attrs=", 1)[1])


def test_http_keys_renamed():
    out = _map({"kind": "client", "attrs": {"http_method": "GET", "http_status": 200}})
    assert out.startswith("OK kind=client renamed=2 unknown=0")
    attrs = _attrs(out)
    assert attrs == {"http.request.method": "GET", "http.response.status_code": 200}


def test_llm_keys_renamed():
    out = _map({"kind": "internal",
                "attrs": {"llm_model": "claude", "llm_prompt_tokens": 42}})
    attrs = _attrs(out)
    assert attrs["gen_ai.request.model"] == "claude"
    assert attrs["gen_ai.usage.input_tokens"] == 42


def test_unknown_keys_flagged_and_passed_through():
    out = _map({"kind": "server", "attrs": {"custom_thing": 1, "http_method": "POST"}})
    assert "renamed=1 unknown=1" in out
    assert "unknown_keys=[custom_thing]" in out
    attrs = _attrs(out)
    assert attrs["custom_thing"] == 1
    assert attrs["http.request.method"] == "POST"


def test_empty_attrs():
    out = _map({"kind": "", "attrs": {}})
    assert "kind=(none) renamed=0 unknown=0" in out
    assert _attrs(out) == {}
    assert "unknown_keys=[]" in out


def test_status_aliases_map_same():
    out = _map({"attrs": {"http_status_code": 404}})
    attrs = _attrs(out)
    assert attrs == {"http.response.status_code": 404}


def test_errors():
    t = otel_semconv()
    assert t.fn({"op": "map"}).startswith("ERROR")                 # no span
    assert t.fn({"op": "map", "span": {"kind": "x"}}).startswith("ERROR")  # no attrs
    assert t.fn({"op": "nope", "span": {"attrs": {}}}).startswith("ERROR")
