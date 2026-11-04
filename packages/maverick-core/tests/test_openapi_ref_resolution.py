"""openapi_runner resolves $ref and path-level parameters.

Before this, describe() rendered a $ref'd parameter as `param (?): ? : ?`,
dumped a $ref'd body schema as the raw `{"$ref": ...}`, and ignored path-item-
level parameters; call() couldn't substitute a $ref'd/path-level path param.
"""
from __future__ import annotations

from maverick.tools import openapi_runner as oar

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/widgets/{widgetId}": {
            # path-item-level parameter: applies to every operation on this path
            "parameters": [{"$ref": "#/components/parameters/WidgetId"}],
            "get": {
                "operationId": "getWidget",
                "summary": "Get a widget",
                "parameters": [{"$ref": "#/components/parameters/Verbose"}],
            },
            "post": {
                "operationId": "createWidget",
                "requestBody": {"$ref": "#/components/requestBodies/WidgetBody"},
            },
        },
    },
    "components": {
        "parameters": {
            "WidgetId": {"name": "widgetId", "in": "path", "required": True,
                         "schema": {"type": "string"}},
            "Verbose": {"name": "verbose", "in": "query",
                        "schema": {"type": "boolean"}},
        },
        "requestBodies": {
            "WidgetBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Widget"}}}},
        },
        "schemas": {
            "Widget": {"type": "object", "properties": {"name": {"type": "string"}}},
        },
    },
}


def _patch_spec(monkeypatch):
    monkeypatch.setattr(oar, "_load_spec", lambda src, workdir=None: SPEC)


# ---------- _resolve_ref ----------

def test_resolve_ref_internal():
    assert oar._resolve_ref(SPEC, {"$ref": "#/components/schemas/Widget"})["type"] == "object"


def test_resolve_ref_passthrough_on_external_missing_or_plain():
    ext = {"$ref": "common.yaml#/Foo"}          # external ref: left as-is
    assert oar._resolve_ref(SPEC, ext) is ext
    miss = {"$ref": "#/components/schemas/Nope"}  # unresolvable: left as-is
    assert oar._resolve_ref(SPEC, miss) is miss
    assert oar._resolve_ref(SPEC, {"type": "string"}) == {"type": "string"}  # not a ref


def test_resolve_ref_is_cycle_safe():
    spec = {"components": {"schemas": {
        "A": {"$ref": "#/components/schemas/B"},
        "B": {"$ref": "#/components/schemas/A"},
    }}}
    out = oar._resolve_ref(spec, {"$ref": "#/components/schemas/A"})
    assert isinstance(out, dict)  # terminates without recursion error


# ---------- _merged_parameters ----------

def test_merged_parameters_combines_path_and_op_levels():
    path_item = SPEC["paths"]["/widgets/{widgetId}"]
    params = oar._merged_parameters(SPEC, path_item, path_item["get"])
    by = {(p["name"], p["in"]): p for p in params}
    assert ("widgetId", "path") in by   # from the path-item-level $ref
    assert ("verbose", "query") in by   # from the operation-level $ref
    assert by[("widgetId", "path")]["required"] is True


def test_merged_parameters_op_level_overrides_path_level():
    path_item = {"parameters": [{"name": "x", "in": "query", "required": False}]}
    op = {"parameters": [{"name": "x", "in": "query", "required": True}]}
    params = oar._merged_parameters({}, path_item, op)
    assert len(params) == 1
    assert params[0]["required"] is True


# ---------- describe ----------

def test_describe_resolves_refd_param_and_body(monkeypatch):
    _patch_spec(monkeypatch)
    out = oar._op_describe("spec", "createWidget")
    # $ref'd, path-item-level path param now resolves (name + type, not "?")
    assert "param (path): widgetId* : string" in out
    # $ref'd requestBody + schema resolve to the real Widget schema
    assert "$ref" not in out
    assert '"type": "object"' in out


def test_describe_shows_both_parameter_levels(monkeypatch):
    _patch_spec(monkeypatch)
    out = oar._op_describe("spec", "getWidget")
    assert "widgetId" in out   # path-item level
    assert "verbose" in out    # operation level


# ---------- call ----------

def test_call_recognizes_refd_path_param(monkeypatch):
    _patch_spec(monkeypatch)
    # widgetId is a $ref'd, path-item-level, required path param. Omitting it
    # must be caught -- proving call() now sees it -- before any network call.
    out = oar._op_call(
        "spec", "getWidget", params={}, body=None, headers=None,
        base_url="https://api.example.com",
    )
    assert "required path param 'widgetId' not provided" in out
