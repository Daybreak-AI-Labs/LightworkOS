"""Workflow catalog projections expose metadata without private schemas."""
from __future__ import annotations

from types import SimpleNamespace

from maverick.flow import ir
from maverick_dashboard.tool_catalog_projection import project_tools


def test_catalog_filters_policy_denied_tools_and_keeps_schema_separate(monkeypatch):
    monkeypatch.setattr(ir, "action_tool_policy_error", lambda name: "denied" if name == "blocked" else "")
    schema = {"type": "object", "properties": {f"field_{n}": {} for n in range(15)}}
    live = [
        SimpleNamespace(name="allowed", description="x" * 300, input_schema=schema),
        SimpleNamespace(name="blocked", description="hidden", input_schema={}),
        SimpleNamespace(name="no_schema", description=None, input_schema=None),
    ]

    index, schemas = project_tools(live)

    assert [row["name"] for row in index] == ["allowed", "no_schema"]
    assert len(index[0]["params"]) == 12
    assert len(index[0]["description"]) == 200
    assert "schema" not in index[0]
    assert schemas == {"allowed": schema}
    assert schemas["allowed"] is not schema
