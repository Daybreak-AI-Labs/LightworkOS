"""Copilot reads the "Sensitive data at the exit" record through the summary
behind the Safety monitoring page: the page's audit permission, the task titles
the person may see, and no change."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import product_operations as registry
    from maverick_dashboard import product_operations_sensitive_data_exit as ops

    dash_app._world_cache.clear()
    yield registry, ops
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()


def _request():
    return Request({"type": "http", "method": "POST", "path": "/immune",
                    "headers": [(b"host", b"127.0.0.1")]})


def test_copilot_shows_sensitive_data_at_the_exit_like_the_page(setup):
    from maverick import ifc
    from maverick.immune import _ledger
    from maverick_dashboard._shared import _world

    registry, ops = setup
    [adapter] = ops.entries()
    assert adapter.id in registry.adapters()
    assert adapter.execute is None and adapter.pages == ("/immune",)

    quiet = adapter.snapshot(_request(), {})
    assert not quiet.blocked
    assert "No sensitive data has reached a tool that sends it outside." in quiet.summary

    goal = _world().create_goal("Send the quarterly report")
    _ledger.append(ifc.ledger_path(), {
        "tool": "send_email", "labels": ["data:customer", ifc.UNREADABLE_LABELS], "explicit": [],
        "mode": "block", "outcome": "blocked", "to": "abc", "goal_id": goal, "at": 1_000.0})

    state = adapter.snapshot(_request(), {})
    assert state.revision != quiet.revision
    assert "1 time" in state.summary
    # The same recovery steps the page gives for labels that cannot be read.
    assert "Earlier information-flow labels for this task could not be read." in state.summary
    assert "repair the task's label file" in state.summary
    [row] = state.details["recent"]
    assert row == {"task": "Send the quarterly report", "tool": "Send email",
                   "labels": ["Customer", "Earlier labels unavailable"], "outcome": "Blocked"}
    assert state.details["earlier_labels_unreadable"] == 1
    review = adapter.prepare(_request(), {}, {})
    assert review.summary == state.summary and review.native == state.details


def test_copilot_sensitive_data_record_needs_the_page_permission(setup, monkeypatch):
    _registry, ops = setup
    from maverick_dashboard import immune_console

    seen = []

    def deny(request, permission):
        seen.append(permission)
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(immune_console, "require_permission", deny)
    [adapter] = ops.entries()
    with pytest.raises(HTTPException) as error:
        adapter.snapshot(_request(), {})
    assert error.value.status_code == 403 and seen == ["audit"]
