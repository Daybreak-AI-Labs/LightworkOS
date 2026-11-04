"""An LLM built without a model resolves the "default" role (kernel rule 2).

Background runs (the dashboard runner, MCP, the GitHub app, A2A tasks) build
``LLM()`` with no model. That fallback goes through
``model_for_role("default")``, so the dashboard's default-model choice,
``[models] default``, the ``--model`` flag and the admin allow-list reach calls
that do not name a role; with nothing configured the answer is
``DEFAULT_MODEL``.
"""
from __future__ import annotations

import pytest

CONFIGURED = "anthropic:claude-configured-default"
PINNED = "anthropic:claude-dashboard-default"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    for name in ("MAVERICK_MODEL_OVERRIDE", "MAVERICK_MODEL_OVERRIDE_DEFAULT"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / "config.toml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))
    return config


def test_nothing_configured_keeps_the_built_in_default(home):
    from maverick.llm import DEFAULT_MODEL, LLM

    assert LLM().model == DEFAULT_MODEL


def test_config_default_model_applies(home):
    from maverick.llm import LLM

    home.write_text(f'[models]\ndefault = "{CONFIGURED}"\n', encoding="utf-8")
    assert LLM().model == CONFIGURED


def test_dashboard_default_pin_applies(home, monkeypatch):
    import maverick.runtime_overrides as ro
    from maverick.llm import LLM

    monkeypatch.setattr(ro, "default_model_override", lambda: PINNED)
    assert LLM().model == PINNED


def test_run_wide_model_flag_applies(home, monkeypatch):
    from maverick.llm import LLM

    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", CONFIGURED)
    assert LLM().model == CONFIGURED


def test_admin_allow_list_applies(home, monkeypatch):
    import maverick.runtime_overrides as ro
    from maverick.llm import LLM

    monkeypatch.setattr(ro, "allowed_models", lambda: [PINNED])
    assert LLM().model == PINNED


def test_a_named_model_still_wins(home, monkeypatch):
    from maverick.llm import LLM

    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", CONFIGURED)
    assert LLM("anthropic:claude-named").model == "anthropic:claude-named"


class TestModelOverride:
    def test_env_override_wins_over_defaults(self, monkeypatch):
        from maverick.llm import model_for_role
        monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_CODER", "claude-opus-4-7")
        assert model_for_role("coder") == "claude-opus-4-7"

    def test_env_override_is_role_specific(self, monkeypatch):
        from maverick.llm import model_for_role
        # Setting coder override does NOT affect orchestrator.
        monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_CODER", "deepseek-v4-pro")
        monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE_ORCHESTRATOR", raising=False)
        assert model_for_role("orchestrator") != "deepseek-v4-pro"

    def test_no_override_falls_back_to_defaults(self, monkeypatch):
        from maverick.llm import ROLE_MODELS, model_for_role
        monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE_CODER", raising=False)
        assert model_for_role("coder") == ROLE_MODELS["coder"]
