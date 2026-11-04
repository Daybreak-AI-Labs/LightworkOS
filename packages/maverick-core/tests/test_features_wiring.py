"""The [features] config section actually gates behavior.

These keys were documented in configuration.md but nothing read them:
  - skills      -> inject skills into agent prompts (env var still overrides)
  - world_model -> inject persisted facts (cross-run memory) into runs
  - streaming   -> live progress poller (covered by the config getter test;
                   the poller branch also depends on TTY/MAVERICK_NO_PROGRESS)
  - pack_editing-> allow editing/overriding agents (domain packs) from the
                   dashboard editor (mutating /api/v1/agents endpoints)
"""
from __future__ import annotations

from pathlib import Path

import pytest

# ---------- config.get_features ----------

def test_get_features_defaults_preserve_opt_in_customer_workflows(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("")  # no [features] section at all
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick.config import get_features
    assert get_features() == {
        "personal_preferences": True, "configuration_profiles": True,
        "employee_task_diagnostics": True, "employee_activation": True,
        "deliverable_bundles": False, "project_workspaces": False, "task_handoffs": False,
        "employee_companions": False, "employee_content_access_requests": False,
        "permission_access_requests": False, "employee_departures": False, "personal_data_controls": False,
        "skills": True, "world_model": True, "streaming": True,
        "pack_editing": True, "role_editing": True, "scheduling": True,
        "triggers": True, "action_center": True, "draft_recovery": True,
        "support_center": True,
        "guided_onboarding": True, "record_search": True, "workspace_recovery": False,
        "workflow_readiness": True, "project_reviews": False, "outcome_measurement": False,
        "signing_identity_transition": False, "copilot_operations": False,
        "commitment_viability": False, "shared_decision_evidence": False,
        "commitment_capability_learning": False,
        "semantic_rule_reuse": False,
        "procedure_interactions": False,
        "operational_competence_acquisition": False,
        "request_program": False,
        "commitment_economic_alternatives": False,
        "workflow_step_checks": False,
        "applicability_regions": False,
        "governed_rule_evolution": False,
        "recovery_visibility": False,
        "private_task_computation": False,
        "portable_competence": False,
        "work_restructuring": False,
        "human_conversation_handoffs": False,
    }


def test_get_features_reads_overrides(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[features]\nskills = false\nworld_model = false\nstreaming = false\n"
        "pack_editing = false\nrole_editing = false\nscheduling = false\n"
        "triggers = false\naction_center = false\ndraft_recovery = false\n"
        "support_center = false\n"
        "guided_onboarding = false\nrecord_search = false\nworkspace_recovery = false\n"
        "workflow_readiness = false\nproject_reviews = true\noutcome_measurement = true\n"
        "copilot_operations = true\n"
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick.config import get_features
    assert get_features() == {
        "personal_preferences": True, "configuration_profiles": True,
        "employee_task_diagnostics": True, "employee_activation": True,
        "deliverable_bundles": False, "project_workspaces": False, "task_handoffs": False,
        "employee_companions": False, "employee_content_access_requests": False,
        "permission_access_requests": False, "employee_departures": False, "personal_data_controls": False,
        "skills": False, "world_model": False, "streaming": False,
        "pack_editing": False, "role_editing": False, "scheduling": False,
        "triggers": False, "action_center": False, "draft_recovery": False,
        "support_center": False,
        "guided_onboarding": False, "record_search": False, "workspace_recovery": False,
        "workflow_readiness": False, "project_reviews": True, "outcome_measurement": True,
        "signing_identity_transition": False, "copilot_operations": True,
        "commitment_viability": False, "shared_decision_evidence": False,
        "commitment_capability_learning": False,
        "semantic_rule_reuse": False,
        "procedure_interactions": False,
        "operational_competence_acquisition": False,
        "request_program": False,
        "commitment_economic_alternatives": False,
        "workflow_step_checks": False,
        "applicability_regions": False,
        "governed_rule_evolution": False,
        "recovery_visibility": False,
        "private_task_computation": False,
        "portable_competence": False,
        "work_restructuring": False,
        "human_conversation_handoffs": False,
    }


# ---------- swarm._default_use_skills precedence ----------

def test_use_skills_env_wins_over_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[features]\nskills = false\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick.swarm import _default_use_skills
    # env explicitly on -> on, despite config saying off
    monkeypatch.setenv("MAVERICK_USE_SKILLS", "1")
    assert _default_use_skills() is True
    # env explicitly off -> off
    monkeypatch.setenv("MAVERICK_USE_SKILLS", "0")
    assert _default_use_skills() is False


def test_use_skills_falls_back_to_config_when_env_unset(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[features]\nskills = false\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_USE_SKILLS", raising=False)
    from maverick.swarm import _default_use_skills
    assert _default_use_skills() is False


def test_use_skills_default_on_when_nothing_set(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_USE_SKILLS", raising=False)
    from maverick.swarm import _default_use_skills
    assert _default_use_skills() is True


# ---------- world_model gates persisted-fact injection ----------

async def _run_capturing_brief(tmp_path, fake_llm, monkeypatch, *, world_model: bool):
    from maverick.budget import Budget
    from maverick.orchestrator import run_goal
    from maverick.sandbox import LocalBackend
    from maverick.world_model import WorldModel

    # Isolate from the shield (the fact loop would otherwise scan each fact).
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)
    monkeypatch.setattr(
        "maverick.config.get_features",
        lambda: {"skills": True, "world_model": world_model, "streaming": True},
    )
    world = WorldModel(path=tmp_path / "world.db")
    world.upsert_fact("favorite_color", "chartreuse")
    gid = world.create_goal("say hi", "trivial")
    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    # The orchestrator brief (which carries the facts block) is passed as the
    # task message, not the system prompt -- capture the whole call.
    return "\n".join(str(c) for c in fake_llm.calls)


@pytest.mark.asyncio
async def test_world_model_on_injects_facts(tmp_path: Path, fake_llm, monkeypatch):
    briefs = await _run_capturing_brief(tmp_path, fake_llm, monkeypatch, world_model=True)
    assert "chartreuse" in briefs


@pytest.mark.asyncio
async def test_world_model_off_drops_facts(tmp_path: Path, fake_llm, monkeypatch):
    briefs = await _run_capturing_brief(tmp_path, fake_llm, monkeypatch, world_model=False)
    assert "chartreuse" not in briefs
