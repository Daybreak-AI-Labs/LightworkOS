"""Resource projection applies caller authorization before touching storage."""
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from maverick_mcp.protocol import ProtocolError
from maverick_mcp.resources import ResourceDependencies, ResourceService


def _dependencies(*, world_factory, permits, denial, principal=lambda *args: "alice"):
    return ResourceDependencies(
        world_factory=world_factory,
        read_tools={"maverick://goals": "maverick_status", "maverick://skills": "maverick_skills_list"},
        access_permits=permits,
        record_denial=denial,
        connector_principal=principal,
        shield_required=lambda: True,
        shield_scan_reason=lambda *args, **kwargs: None,
    )


def test_denied_resource_is_hidden_before_world_is_opened():
    denied = []

    def must_not_open():
        raise AssertionError("denied request opened storage")

    service = ResourceService(_dependencies(
        world_factory=must_not_open,
        permits=lambda *args: False,
        denial=lambda *args: denied.append(args),
    ))
    with pytest.raises(ProtocolError, match="unknown resource path") as error:
        service.read({"uri": "maverick://goals"}, caller_identity="alice", capability="restricted")
    assert error.value.code == -32602
    assert denied == [("restricted", "alice", "maverick_status")]
    assert service.list({}, capability="restricted") == {"resources": []}


def test_resource_read_scopes_world_query_and_runs_output_policy(monkeypatch):
    calls = []

    @contextmanager
    def world():
        calls.append("open")
        try:
            yield SimpleNamespace(list_goals=lambda **kwargs: (
                calls.append(("list", kwargs)) or [SimpleNamespace(id=1, status="done", title="Task")]
            ))
        finally:
            calls.append("close")

    monkeypatch.setattr("maverick.secrets.scrub", lambda text: text)
    dependencies = _dependencies(world_factory=world, permits=lambda *args: True, denial=lambda *args: None)
    service = ResourceService(dependencies)
    result = service.read({"uri": "maverick://goals"}, caller_identity="alice")
    assert json.loads(result["contents"][0]["text"]) == [{"id": 1, "status": "done", "title": "Task"}]
    assert calls == ["open", ("list", {"owner": "alice"}), "close"]
