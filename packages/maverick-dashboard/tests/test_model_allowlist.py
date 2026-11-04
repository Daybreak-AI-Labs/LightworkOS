"""Admin model allow-list: the admin restricts the catalogue to an approved
set, everyone is limited to it, and it is a hard cap at model resolution (not
just a UI hint)."""
from __future__ import annotations

from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}
_SONNET = "claude-sonnet-4-6"
_OPUS = "claude-opus-4-8"


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _iso(monkeypatch, tmp_path):
    """Isolate the overlay file and clear the env overrides that outrank it."""
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    for r in ("ORCHESTRATOR", "CODER", "WRITER", "SUMMARIZER", "RESEARCHER",
              "ANALYST", "VERIFIER"):
        monkeypatch.delenv(f"MAVERICK_MODEL_OVERRIDE_{r}", raising=False)


def _prep(monkeypatch, tmp_path):
    """Full dashboard isolation (world DB + overlay + caches)."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    _iso(monkeypatch, tmp_path)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_allowlist_caps_role_resolution(monkeypatch, tmp_path):
    _iso(monkeypatch, tmp_path)
    from maverick.llm import model_for_role
    from maverick.runtime_overrides import allowed_models, set_allowed_models
    # Baseline: no allow-list, the orchestrator keeps its Opus default.
    assert allowed_models() == set()
    assert model_for_role("orchestrator") == _OPUS
    # Cap to Sonnet only: every role collapses onto the one allowed model,
    # including roles whose default (Opus/Haiku) is now disallowed.
    set_allowed_models([_SONNET])
    for role in ("orchestrator", "coder", "writer", "summarizer"):
        assert model_for_role(role) == _SONNET


def test_allowlist_lets_an_allowed_default_through(monkeypatch, tmp_path):
    _iso(monkeypatch, tmp_path)
    from maverick.llm import model_for_role
    from maverick.runtime_overrides import set_allowed_models
    # Opus is allowed, so the orchestrator's Opus default is untouched, while a
    # role defaulting to a disallowed model is capped to the lone allowed one.
    set_allowed_models([_OPUS])
    assert model_for_role("orchestrator") == _OPUS
    assert model_for_role("summarizer") == _OPUS  # Haiku default not allowed


def test_settings_page_renders_allowlist_section(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/settings")
    assert r.status_code == 200
    assert 'action="/settings/models/allowed"' in r.text
    # a checkbox per catalogue model, posting under the "models" field
    assert 'name="models" value="claude-opus-4-8"' in r.text
    assert 'name="models" value="openai:gpt-5.4"' in r.text


def test_post_allowlist_restricts_pickers(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/settings/models/allowed",
               data={"models": [_SONNET, _OPUS]},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    from maverick.runtime_overrides import allowed_models
    assert allowed_models() == {_SONNET, _OPUS}
    page = c.get("/settings").text
    # the default picker now offers only the two approved models, not the rest
    assert 'Only approved models are offered' in page
    picker = page.split('name="model"', 1)[1].split("</select>", 1)[0]
    assert "openai:gpt-5.4" not in picker and _SONNET in picker and _OPUS in picker
    # and the approved boxes render checked
    assert f'name="models" value="{_SONNET}" checked' in page


def test_pin_disallowed_default_is_rejected(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import set_allowed_models
    set_allowed_models([_SONNET])
    r = _client().post("/settings/models", data={"model": _OPUS},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 400


def test_pin_allowed_default_succeeds(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import set_allowed_models
    set_allowed_models([_SONNET])
    r = _client().post("/settings/models", data={"model": _SONNET},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    from maverick.runtime_overrides import default_model_override
    assert default_model_override() == _SONNET


def test_role_pin_disallowed_is_rejected(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import set_allowed_models
    set_allowed_models([_SONNET])
    r = _client().post("/settings/models/roles", data={"coder": _OPUS},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 400


def test_clearing_allowlist_removes_the_restriction(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import allowed_models, set_allowed_models
    set_allowed_models([_SONNET])
    assert allowed_models() == {_SONNET}
    # posting with no boxes checked clears it -> every model allowed again
    r = _client().post("/settings/models/allowed", data={},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert allowed_models() == set()
    # a previously disallowed pin now goes through
    r = _client().post("/settings/models", data={"model": _OPUS},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303


def test_allowlist_coexists_with_other_overlays(monkeypatch, tmp_path):
    """Setting the allow-list must not clobber a denied tool, a budget, or a
    pinned model already in the overlay (one file, full-state writes)."""
    _iso(monkeypatch, tmp_path)
    from maverick.runtime_overrides import (
        allowed_models,
        budget_override,
        denied_tools,
        disable_tool,
        set_allowed_models,
        set_budget,
        set_default_model,
    )
    disable_tool("browser")
    set_budget(7.5)
    set_default_model(_SONNET)
    set_allowed_models([_SONNET, _OPUS])
    assert denied_tools() == {"browser"}
    assert budget_override() == 7.5
    assert allowed_models() == {_SONNET, _OPUS}
