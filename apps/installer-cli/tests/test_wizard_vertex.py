"""Claude on Google Cloud Vertex AI in the setup wizard.

The wizard asks for the project, region and the model ID exactly as shown in
the Vertex AI Model Garden, writes them to [providers.vertex] with no key, and
offers the typed model ID for the agent roles.
"""
from __future__ import annotations

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

import pytest
from maverick_installer import models, wizard

_HAIKU = "claude-haiku-4-5@20251001"


@pytest.fixture
def config_home(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", tmp_path)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", tmp_path / "config.toml")
    for name in ("ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "CLOUD_ML_REGION"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _write(tmp_path, **overrides):
    values = dict(
        providers=["vertex"], role_models={}, channels={},
        safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={}, capabilities={}, advanced={},
        provider_options={"vertex": {"project_id": "acme-ai", "region": "us-east5",
                                     "model_id": _HAIKU}},
    )
    values.update(overrides)
    wizard.write_config(**values)
    return tomllib.loads((tmp_path / "config.toml").read_text(encoding="utf-8"))


def test_vertex_table_is_written_with_no_key(config_home):
    parsed = _write(config_home)
    assert parsed["providers"]["vertex"] == {
        "project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU,
    }
    assert "api_key" not in parsed["providers"]["vertex"]


def test_vertex_role_is_written_with_the_typed_model(config_home):
    parsed = _write(config_home, role_models={"coder": f"vertex:{_HAIKU}"})
    assert parsed["models"]["coder"] == f"vertex:{_HAIKU}"


def test_vertex_step_asks_for_project_region_and_model_and_re_asks_bad_values(monkeypatch):
    answers = iter(["bad/../project", "acme-ai",
                    "US-EAST5", "us-east5",
                    "", _HAIKU])
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": next(answers))
    assert wizard.pick_vertex() == {
        "project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU,
    }


def test_vertex_step_re_asks_a_model_id_without_the_version(monkeypatch):
    """A bare id such as claude-haiku-4-5 is not the name@version form the client accepts."""
    answers = iter(["acme-ai", "us-east5", "claude-haiku-4-5", _HAIKU])
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": next(answers))
    assert wizard.pick_vertex()["model_id"] == _HAIKU


def test_typed_vertex_model_replaces_the_placeholder_in_role_choices(monkeypatch):
    offered: list[list[str]] = []

    def pick_first_vertex(message, choices, default=None):
        offered.append(list(choices))
        return next(choice for choice in choices if choice.startswith("vertex:"))

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: False)
    monkeypatch.setattr(wizard, "_q_select", pick_first_vertex)
    roles = wizard.pick_models_per_role(
        ["vertex"], {"vertex": {"project_id": "acme-ai", "region": "us-east5", "model_id": _HAIKU}})
    assert set(roles.values()) == {f"vertex:{_HAIKU}"}
    assert offered and all("vertex:vertex" not in choice for choice in offered[0])


def test_vertex_is_a_ready_provider_with_no_api_key_variable():
    info = models.PROVIDERS["vertex"]
    assert info["status"] == "ready"
    assert not info.get("env")
