"""Product-default contract for governed learning and the separate DGM gate."""
from __future__ import annotations

from maverick import (
    consequence,
    credit,
    data_engine,
    dreaming,
    evaluator_evolution,
    experience,
    factory_learning,
    failure_telemetry,
    jit_rl,
    operations_scientist,
    prm_guidance,
    promotion_effect,
    reasoning_reward,
    reflexion,
    rehearsal,
    self_harness,
    self_improvement,
    self_learning,
    self_modify,
    self_tuning_budget,
    trajectory_store,
)
from maverick.skill import distillation_local, synthesis

_ENV_FLAGS = (
    "MAVERICK_SELF_LEARNING",
    "MAVERICK_REFLEXION",
    "MAVERICK_DREAMING",
    "MAVERICK_SELF_HARNESS",
    "MAVERICK_SELF_IMPROVEMENT",
    "MAVERICK_TRAJECTORY_CAPTURE",
    "MAVERICK_DISTILL_LOCAL",
    "MAVERICK_CONSEQUENCE",
    "MAVERICK_CREDIT",
    "MAVERICK_DATA_ENGINE",
    "MAVERICK_EXPERIENCE_GUIDANCE",
    "MAVERICK_SKILL_SYNTHESIS",
    "MAVERICK_REHEARSAL",
    "MAVERICK_OPERATIONS_SCIENTIST",
    "MAVERICK_FACTORY_LEARNING",
    "MAVERICK_EVALUATOR_EVOLUTION",
    "MAVERICK_FAILURE_TELEMETRY",
    "MAVERICK_BUDGET_SELF_TUNING",
    "MAVERICK_PRM_GUIDANCE",
    "MAVERICK_REASONING_REWARD",
    "MAVERICK_REASONING_REWARD_AUDIT",
    "MAVERICK_JIT_RL",
    "MAVERICK_CAUSAL_PROMOTION",
    "MAVERICK_SELF_MODIFY",
)


def _isolate(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for name in _ENV_FLAGS:
        monkeypatch.delenv(name, raising=False)
    from maverick.config import reset_config_cache
    reset_config_cache()


def _governed_states() -> dict[str, bool]:
    return {
        "self_learning": self_learning.enabled(),
        "reflexion": reflexion.enabled(),
        "dreaming": dreaming.enabled(),
        "self_harness": self_harness.enabled(),
        "self_improvement": self_improvement.enabled(),
        "capture": trajectory_store.enabled(),
        "distill_local": distillation_local.enabled(),
        "consequence": consequence.enabled(),
        "credit": credit.enabled(),
        "data_engine": data_engine.enabled(),
        "experience": experience.enabled(),
        "skill_synthesis": synthesis.enabled(),
        "rehearsal": rehearsal.enabled(),
        "operations_scientist": operations_scientist.enabled(),
        "factory_learning": factory_learning.enabled(),
        "evaluator_evolution": evaluator_evolution.enabled(),
        "failure_telemetry": failure_telemetry.enabled(),
        "budget_tuning": self_tuning_budget.enabled(),
        "prm_guidance": prm_guidance.enabled(),
        "reasoning_reward": reasoning_reward.enabled(),
        "reward_audit": reasoning_reward.audit_rewards_enabled(),
        "jit_rl": jit_rl.enabled(),
        "causal_promotion": promotion_effect.enabled(),
    }


def test_governed_learning_defaults_on_but_dgm_defaults_off(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    states = _governed_states()
    assert states.pop("budget_tuning") is False
    assert all(states.values())
    from maverick.config import get_self_harness, get_self_improvement, get_self_learning

    assert get_self_learning()["create_tools"] is False
    assert get_self_learning()["allow_mcp_acquisition"] is False
    assert get_self_learning()["allow_provider_egress"] is False
    assert get_self_harness()["risk_limited"] is True
    assert get_self_harness()["auto_run"] is True
    assert get_self_improvement()["capture"] is True
    assert self_modify.enabled() is False
    status = self_modify.production_status()
    assert status["state"] == "off"
    assert status["live_adoption"] is False


def test_malformed_learning_booleans_fail_closed(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text(
        """
[self_learning]
enable = "false"
create_tools = "false"
allow_mcp_acquisition = "false"
allow_provider_egress = "false"

[self_harness]
enable = "false"
risk_limited = "false"
auto_run = "false"

[self_improvement]
enable = "false"
causal_promotion = "false"
require_signed_approval = "false"
""".strip() + "\n",
        encoding="utf-8",
    )
    from maverick.config import (
        get_self_harness,
        get_self_improvement,
        get_self_learning,
        reset_config_cache,
    )
    reset_config_cache()

    settings = get_self_learning()
    assert settings["enable"] is False
    assert settings["create_tools"] is False
    assert settings["allow_mcp_acquisition"] is False
    assert settings["allow_provider_egress"] is False
    assert self_learning.mcp_acquisition_enabled() is False
    assert self_learning.provider_egress_enabled() is False
    harness = get_self_harness()
    assert harness["enable"] is False
    assert harness["risk_limited"] is True
    assert harness["auto_run"] is False
    improvement = get_self_improvement()
    assert improvement["enable"] is False
    assert improvement["causal_promotion"] is True
    assert improvement["require_signed_approval"] is True


def test_malformed_present_learning_environment_fails_closed(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "not-a-boolean")
    assert self_harness.enabled() is False
    monkeypatch.delenv("MAVERICK_SELF_HARNESS")
    monkeypatch.setenv("MAVERICK_CAUSAL_PROMOTION", "not-a-boolean")
    assert promotion_effect.enabled() is False


def test_invalid_global_min_improvement_freezes_shared_promotion(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text(
        '[self_improvement]\nmin_improvement = "0.25"\n',
        encoding="utf-8",
    )
    from maverick.config import get_self_improvement, reset_config_cache

    reset_config_cache()
    settings = get_self_improvement()
    assert settings["promotion_policy_valid"] is False
    assert settings["min_improvement"] == -1.0

    self_improvement.reset_shared()
    try:
        controller = self_improvement.shared()
        verdict = controller.evaluate(self_improvement.Candidate(
            rung="config",
            summary="must not promote under a malformed global margin",
            baseline_score=0.1,
            candidate_score=0.9,
            samples=20,
            rollback="snapshot-1",
        ))
        assert verdict.promote is False
        assert any(
            gate.gate == "evidence" and gate.ok is False
            for gate in verdict.gates
        )
    finally:
        self_improvement.reset_shared()


def test_zero_environment_overrides_disable_default_learning(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    for name in _ENV_FLAGS:
        if name != "MAVERICK_SELF_MODIFY":
            monkeypatch.setenv(name, "0")
    assert not any(_governed_states().values())
    assert self_modify.enabled() is False


def test_corrupt_active_config_fails_default_learning_closed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text("[self_learning\nenable = true\n")
    from maverick.config import reset_config_cache
    reset_config_cache()
    assert not any(_governed_states().values())
    assert self_modify.production_status()["state"] == "blocked"


def test_corrupt_config_cannot_be_bypassed_by_dgm_environment_opt_in(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text("[self_modify\nenable = true\n")
    monkeypatch.setenv("MAVERICK_SELF_MODIFY", "1")
    from maverick.config import reset_config_cache
    reset_config_cache()
    assert self_modify.enabled() is False
    status = self_modify.production_status()
    assert status["requested"] is False and status["state"] == "blocked"
    assert "config_source_error" in {item["code"] for item in status["blockers"]}


def test_dgm_enable_requires_a_real_boolean(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text('[self_modify]\nenable = "false"\n')
    from maverick.config import reset_config_cache
    reset_config_cache()
    assert self_modify.enabled() is False
    status = self_modify.production_status()
    assert "invalid_self_modify_enable" in {
        item["code"] for item in status["blockers"]
    }


def test_tenant_overlay_cannot_change_global_dgm_policy(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text(
        """
[self_modify]
enable = true
editable_paths = ["src/narrow/**"]
eval_tests = ["tests/global_a.py", "tests/global_b.py"]

[sandbox]
backend = "ep:global-attested"
""".strip() + "\n"
    )
    tenant_cfg = tmp_path / "tenants" / "acme" / "config.toml"
    tenant_cfg.parent.mkdir(parents=True)
    tenant_cfg.write_text(
        """
[self_modify]
enable = false
editable_paths = ["**"]
eval_tests = ["tests/tenant_only.py"]

[sandbox]
backend = "local"
""".strip() + "\n"
    )
    from maverick import self_modify_runner
    from maverick.config import get_self_modify, reset_config_cache
    from maverick.paths import reset_tenant, set_tenant
    reset_config_cache()
    token = set_tenant("acme")
    try:
        assert self_modify.enabled() is True
        assert get_self_modify()["editable_paths"] == ["src/narrow/**"]
        assert self_modify_runner._self_modify_config()["eval_tests"] == [
            "tests/global_a.py", "tests/global_b.py",
        ]
        assert self_modify.production_status()["ready"] is True
        called = []
        result = self_modify_runner.run(proposer=lambda *_: called.append(True))
        assert result.ran is False and "explicit tenant" in result.reason
        assert called == []
    finally:
        reset_tenant(token)


def test_dgm_client_request_reports_static_readiness_without_running(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text(
        """
[self_modify]
enable = true
editable_paths = ["src/product/**"]
eval_tests = ["tests/test_a.py::test_a", "tests/test_b.py::test_b"]

[sandbox]
backend = "ep:attested-evaluator"
""".strip()
        + "\n"
    )
    from maverick.config import reset_config_cache
    reset_config_cache()
    status = self_modify.production_status()
    assert status["requested"] is True
    assert status["effective"] is True
    assert status["ready"] is True
    assert status["state"] == "ready"
    assert status["runtime_preflight_required"] is True
    assert status["research_only"] is True
    assert status["live_adoption"] is False


def test_dgm_environment_policy_owns_effective_state(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "config.toml").write_text("[self_modify]\nenable = true\n")
    monkeypatch.setenv("MAVERICK_SELF_MODIFY", "0")
    from maverick.config import reset_config_cache
    reset_config_cache()
    status = self_modify.production_status()
    assert status["configured"] is True
    assert status["requested"] is False
    assert status["managed_by_environment"] is True
    assert status["environment_override"] is False
