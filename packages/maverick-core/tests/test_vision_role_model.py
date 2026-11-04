"""Vision tools + the skill distiller must resolve their model through
model_for_role (CLAUDE.md rule 2: users own model choice), not a hard-coded
string that ignores [models] config and the --model flag."""
from __future__ import annotations

import pathlib

from maverick import llm

_CORE = pathlib.Path(__file__).resolve().parents[1] / "maverick"


def test_vision_role_default_is_sonnet(monkeypatch):
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE_VISION", raising=False)
    monkeypatch.setattr("maverick.config.get_role_model", lambda role: None)
    # No config override -> the ROLE_MODELS default, a vision-capable model.
    assert "vision" in llm.ROLE_MODELS
    assert llm.model_for_role("vision") == llm.ROLE_MODELS["vision"] == llm.MODEL_SONNET


def test_vision_role_honors_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE_VISION", raising=False)
    # A [models].vision config spec wins -- the old hard-coded default ignored it.
    monkeypatch.setattr(
        "maverick.config.get_role_model",
        lambda role: "myprov:vmodel" if role == "vision" else None,
    )
    assert llm.model_for_role("vision") == "myprov:vmodel"


def test_vision_role_honors_env_override(monkeypatch):
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_VISION", "envprov:vmodel")
    assert llm.model_for_role("vision") == "envprov:vmodel"


def test_skill_distiller_resolves_through_role(monkeypatch):
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE_SKILL_DISTILLER", raising=False)
    monkeypatch.setattr("maverick.config.get_role_model", lambda role: None)
    assert llm.model_for_role("skill_distiller") == llm.ROLE_MODELS["skill_distiller"]


def test_no_hardcoded_vision_model_in_resolution_path():
    # Guard: the tools resolve via model_for_role, and the old hard-coded
    # `or "anthropic:..."` fallback (which bypassed config) is gone.
    for rel in ("tools/view_image.py", "tools/view_video.py", "skills.py"):
        src = (_CORE / rel).read_text(encoding="utf-8")
        assert "model_for_role(" in src, f"{rel} should resolve via model_for_role"
    for rel in ("tools/view_image.py", "tools/view_video.py"):
        src = (_CORE / rel).read_text(encoding="utf-8")
        assert 'or "anthropic:claude-sonnet-4-6"' not in src
