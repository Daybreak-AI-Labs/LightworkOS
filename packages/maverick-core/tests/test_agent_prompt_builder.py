"""Characterization tests for the PromptBuilder seam.

``agent.select_base_template`` is the side-effect-free collaborator that
``Agent._build_system`` uses to pick its base template. These pin its branch
behavior (the orchestrator/worker/coding-mode selection).
"""
from __future__ import annotations

from maverick.agent import (
    ORCHESTRATOR_SYSTEM_TEMPLATE,
    WORKER_SYSTEM_TEMPLATE,
    apply_global_overlays,
    apply_memory_brief,
    apply_role_overlays,
    apply_skill_overlays,
    select_base_template,
)


class _FakeSkill:
    def __init__(self, name: str) -> None:
        self.name = name


def test_orchestrator_template_when_not_coding():
    out = select_base_template(
        role="orchestrator", depth=0, max_depth=5, coding_enabled=False)
    assert out == ORCHESTRATOR_SYSTEM_TEMPLATE.format(max_depth=5)


def test_worker_template_for_other_roles():
    out = select_base_template(
        role="researcher", depth=2, max_depth=5, coding_enabled=False)
    assert out == WORKER_SYSTEM_TEMPLATE.format(
        role="researcher", depth=2, max_depth=5)


def test_coding_mode_overrides_role():
    from maverick.coding_mode import CODER_CODING_MODE_TEMPLATE
    out = select_base_template(
        role="orchestrator", depth=0, max_depth=5, coding_enabled=True)
    assert out == CODER_CODING_MODE_TEMPLATE.format(
        role="orchestrator", depth=0, max_depth=5)
    # Coding mode overrides the role -> NOT the prose orchestrator template.
    assert out != ORCHESTRATOR_SYSTEM_TEMPLATE.format(max_depth=5)


def test_coding_mode_worker_is_also_coder():
    from maverick.coding_mode import CODER_CODING_MODE_TEMPLATE
    out = select_base_template(
        role="coder", depth=1, max_depth=3, coding_enabled=True)
    assert out == CODER_CODING_MODE_TEMPLATE.format(
        role="coder", depth=1, max_depth=3)


# ---- apply_global_overlays (second PromptBuilder collaborator) ----

def test_overlays_append_persona_style_habits_in_order(monkeypatch):
    monkeypatch.setattr("maverick.persona.render_persona_prompt", lambda: "P")
    monkeypatch.setattr("maverick.styles.render_active_style_prompt", lambda: "S")
    monkeypatch.setattr("maverick.data_engine.enabled", lambda: True)
    monkeypatch.setattr("maverick.procedural_memory.recall_prompt", lambda: "H")
    # base + persona + style + habits, in that exact order.
    assert apply_global_overlays("BASE") == "BASEPSH"


def test_overlays_skip_empty_and_disabled(monkeypatch):
    monkeypatch.setattr("maverick.persona.render_persona_prompt", lambda: "")
    monkeypatch.setattr("maverick.styles.render_active_style_prompt", lambda: "")
    monkeypatch.setattr("maverick.data_engine.enabled", lambda: False)
    assert apply_global_overlays("BASE") == "BASE"


def test_overlays_fail_open_on_error(monkeypatch):
    def boom():
        raise RuntimeError("overlay source down")
    monkeypatch.setattr("maverick.persona.render_persona_prompt", boom)
    monkeypatch.setattr("maverick.styles.render_active_style_prompt", lambda: "S")
    monkeypatch.setattr("maverick.data_engine.enabled", lambda: False)
    # Persona raises -> that overlay is skipped; style still applies; no raise.
    assert apply_global_overlays("BASE") == "BASES"


def test_overlays_habits_skipped_when_data_engine_off(monkeypatch):
    monkeypatch.setattr("maverick.persona.render_persona_prompt", lambda: "")
    monkeypatch.setattr("maverick.styles.render_active_style_prompt", lambda: "")
    monkeypatch.setattr("maverick.data_engine.enabled", lambda: False)
    # recall_prompt must NOT be consulted when the data engine is off.
    monkeypatch.setattr(
        "maverick.procedural_memory.recall_prompt",
        lambda: (_ for _ in ()).throw(AssertionError("should not be called")),
    )
    assert apply_global_overlays("BASE") == "BASE"


# ---- apply_role_overlays (third PromptBuilder collaborator) ----

def test_role_overlays_append_addendum_then_domain(monkeypatch):
    monkeypatch.setattr("maverick.role_edit.role_addendum", lambda role: "ADD")
    out = apply_role_overlays("BASE", role="coder", domain_persona="DOM")
    # role addendum first, then domain persona, each blank-line separated.
    assert out == "BASE\n\nADD\n\nDOM"


def test_role_overlays_no_addendum_no_domain(monkeypatch):
    monkeypatch.setattr("maverick.role_edit.role_addendum", lambda role: "")
    assert apply_role_overlays("BASE", role="coder", domain_persona=None) == "BASE"


def test_role_overlays_addendum_fails_open(monkeypatch):
    def boom(role):
        raise RuntimeError("role editor down")
    monkeypatch.setattr("maverick.role_edit.role_addendum", boom)
    # Addendum raises -> skipped; domain persona still applies; no raise.
    out = apply_role_overlays("BASE", role="coder", domain_persona="DOM")
    assert out == "BASE\n\nDOM"


def test_role_overlays_addendum_keyed_on_role(monkeypatch):
    seen = {}
    def _addendum(role):
        seen["role"] = role
        return ""
    monkeypatch.setattr("maverick.role_edit.role_addendum", _addendum)
    apply_role_overlays("BASE", role="analyst", domain_persona=None)
    assert seen["role"] == "analyst"


# ---- apply_skill_overlays (fourth PromptBuilder collaborator) ----

def test_skill_overlays_appends_and_returns_skills(monkeypatch):
    sk = [_FakeSkill("a"), _FakeSkill("b")]
    monkeypatch.setattr("maverick.skills.available_skills", lambda: ["all"])
    monkeypatch.setattr("maverick.skills.relevant_skills", lambda brief, avail, max_n=3: sk)
    def render(skills, *, rendered_skills):
        rendered_skills.extend(skills)
        return "RENDERED"
    monkeypatch.setattr("maverick.skills.render_for_prompt", render)
    base, skills = apply_skill_overlays("BASE", brief="do x", use_skills=True)
    assert base == "BASE\n\nRENDERED"
    assert skills == sk  # caller uses these to record stats + skills_used


def test_skill_overlays_disabled_is_noop(monkeypatch):
    # Skills off -> the store is never consulted, returns (base, []).
    monkeypatch.setattr(
        "maverick.skills.relevant_skills",
        lambda *a: (_ for _ in ()).throw(AssertionError("must not be called")),
    )
    assert apply_skill_overlays("BASE", brief="x", use_skills=False) == ("BASE", [])


def test_skill_overlays_no_relevant_skills(monkeypatch):
    monkeypatch.setattr("maverick.skills.available_skills", list)
    monkeypatch.setattr("maverick.skills.relevant_skills", lambda brief, avail, max_n=3: [])
    assert apply_skill_overlays("BASE", brief="x", use_skills=True) == ("BASE", [])


def test_skill_overlays_fail_open_on_missing_store(monkeypatch):
    def boom():
        raise FileNotFoundError("no skills dir")
    monkeypatch.setattr("maverick.skills.available_skills", boom)
    # FileNotFoundError/ImportError/ValueError are swallowed -> no-op.
    assert apply_skill_overlays("BASE", brief="x", use_skills=True) == ("BASE", [])


# ---- apply_memory_brief (fifth PromptBuilder collaborator) ----

def test_memory_brief_appended_for_root_agent(monkeypatch):
    monkeypatch.setattr("maverick.tools.memory.memory_brief", lambda: "MEM")
    assert apply_memory_brief("BASE", depth=0) == "BASE\n\nMEM"


def test_memory_brief_skipped_for_deep_workers(monkeypatch):
    # depth > 0 -> the memory tool is not even consulted.
    monkeypatch.setattr(
        "maverick.tools.memory.memory_brief",
        lambda: (_ for _ in ()).throw(AssertionError("must not be called")),
    )
    assert apply_memory_brief("BASE", depth=2) == "BASE"


def test_memory_brief_empty_is_noop(monkeypatch):
    monkeypatch.setattr("maverick.tools.memory.memory_brief", lambda: "")
    assert apply_memory_brief("BASE", depth=0) == "BASE"


def test_memory_brief_fails_open(monkeypatch):
    def boom():
        raise RuntimeError("memory store down")
    monkeypatch.setattr("maverick.tools.memory.memory_brief", boom)
    # Never blocks a run: a memory error leaves base unchanged.
    assert apply_memory_brief("BASE", depth=0) == "BASE"
