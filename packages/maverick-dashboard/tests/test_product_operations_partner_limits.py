"""Copilot reaches partner request limits through the same checked services
as the Agent trust page: installation administrators only, audit row first."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from maverick import audit, config, federation, world_model
    from maverick import federation_admission as admission

    cfg = tmp_path / "config.toml"
    cfg.write_text('[federation]\npeers = [{name = "edge", target = "edge:1", token = "t"}]\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(federation, "_CORRELATION_PER_PEER_MAX", 1)
    rows = []
    monkeypatch.setattr(audit, "record", lambda kind, **kw: rows.append((kind, kw)) or True)
    config.reset_config_cache()
    with world_model.WorldModel(world_model.DEFAULT_DB) as world:
        admission.reserve(world, peer="edge", correlation="c1", digest="a" * 64, title="t",
                          description="", capability=None, max_dollars=1, max_wall_seconds=1)
    from maverick_dashboard import product_operations as registry
    from maverick_dashboard import product_operations_partner_limits as ops
    yield registry, ops, rows, admission
    config.reset_config_cache()


def _request():
    return Request({"type": "http", "method": "POST", "path": "/trust",
                    "headers": [(b"host", b"127.0.0.1")]})


def _run(ops, operation, arguments):
    adapter = {a.id: a for a in ops.entries()}[operation]
    request = _request()
    state = adapter.snapshot(request, {})
    assert not state.blocked, state.blocked
    review = adapter.prepare(request, {}, arguments)
    return state, review, adapter.execute(request, {}, arguments, review.native, "a" * 32)


def test_copilot_shows_and_changes_partner_limits_like_the_page(setup):
    registry, ops, rows, admission = setup
    ids = {"trust.partner_limits.show", "trust.partner_limits.raise", "trust.partner_limits.reset",
           "trust.partner_limits.storage", "trust.partner_limits.start_over"}
    assert ids <= set(registry.adapters())
    show = {a.id: a for a in ops.entries()}["trust.partner_limits.show"]
    state = show.snapshot(_request(), {})
    assert state.details["partners"][0]["reached"] is True and state.details["storage_full"] is False
    assert "edge" in state.summary

    _, review, done = _run(ops, "trust.partner_limits.raise", {"partner": "edge", "limit": 5})
    assert review.changes == [{"field": "Requests edge may send", "before": "1", "after": "5"}]
    assert done.status == "confirmed" and done.details["limit"] == 5
    _run(ops, "trust.partner_limits.reset", {"partner": "edge"})
    _run(ops, "trust.partner_limits.storage", {"limit": 300_000})
    changed = [kw for kind, kw in rows if kind == "federation_admission_limit_changed"]
    assert [(c["new_limit"], c["reset"]) for c in changed] == [(5, False), (5, True), (300_000, False)]
    assert all(c["actor"] != "model" and c["actor"] for c in changed)

    blocked = {a.id: a for a in ops.entries()}["trust.partner_limits.start_over"].snapshot(_request(), {})
    assert blocked.blocked
    admission._limits_path().write_text("{broken", encoding="utf-8")
    assert "can't be read" in show.snapshot(_request(), {}).summary
    _, _, started = _run(ops, "trust.partner_limits.start_over", {})
    assert started.status == "confirmed"
    assert rows[-1][1]["start_over"] is True


def test_copilot_partner_limits_refuse_anyone_but_an_installation_administrator(setup, monkeypatch):
    _registry, ops, rows, _admission = setup
    from maverick_dashboard import trust_page_api

    def deny(request, permission):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(trust_page_api, "require_global_permission", deny)
    for adapter in ops.entries():
        with pytest.raises(HTTPException) as error:
            adapter.snapshot(_request(), {})
        assert error.value.status_code == 403
    adapter = {a.id: a for a in ops.entries()}["trust.partner_limits.raise"]
    with pytest.raises(HTTPException):
        adapter.execute(_request(), {}, {"partner": "edge", "limit": 9}, {}, "b" * 32)
    assert not [r for r in rows if r[0] == "federation_admission_limit_changed"]
