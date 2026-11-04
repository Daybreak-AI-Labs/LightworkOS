"""`maverick start` preflight UX: refuse early, leave no residue, exit honestly.

Fixed behaviour:
  - A halted `maverick start` printed the refusal but exited 0, so scripts
    could not tell "ran" from "refused"; it also created a goal row first.
    Now: killswitch is checked before goal creation -> exit 3, no row.
  - A missing provider SDK (e.g. the openai package for vllm:/ollama:
    routed roles) surfaced AFTER the goal row existed, orphaning a failed
    goal per attempt. Now: SDK availability is preflighted before goal
    creation -> exit 2, no row, same actionable message.
  - Unknown model ids on self-hosted providers (ollama:/vllm:/tgi:)
    billed at the Sonnet fallback rate, accruing phantom spend for free
    local models. Now priced at $0. The generic openai_compatible provider
    is not blanket-zeroed because it can target paid public gateways; an
    unknown hosted rate now fails closed instead of becoming a bill.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.budget import Budget, UnpricedModelError


def _goal_count(home) -> int:
    import sqlite3
    db = home / ".maverick" / "world.db"
    if not db.exists():
        return 0
    return sqlite3.connect(db).execute("select count(*) from goals").fetchone()[0]


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-dummy")
    # Bust the killswitch's 1s stat-throttle so each test sees ITS home's
    # HALT state, not the previous test's cached answer (established
    # pattern, see test_killswitch.py).
    from maverick import killswitch as ks
    ks._last_file_check_ts = 0.0
    ks.clear()


def test_halted_start_exits_3_and_creates_no_goal(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    halt = tmp_path / ".maverick" / "HALT"
    halt.parent.mkdir(parents=True, exist_ok=True)
    halt.write_text("operator\n", encoding="utf-8")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["start", "blocked goal"])

    assert res.exit_code == 3, res.output
    assert "unhalt" in res.output
    assert _goal_count(tmp_path) == 0


def test_missing_sdk_exits_2_and_creates_no_goal(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import maverick.providers as providers
    monkeypatch.setattr(
        providers, "missing_sdks",
        lambda specs: ["openai SDK not installed. Run: pip install 'maverick-agent[openai]'"],
    )

    from maverick.cli import main
    res = CliRunner().invoke(main, ["start", "sdk-less goal"])

    assert res.exit_code == 2, res.output
    assert "openai SDK not installed" in res.output
    assert _goal_count(tmp_path) == 0


def test_start_warns_about_file_work_before_creating_a_task(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import maverick.cli as cli_mod
    import maverick.providers as providers
    from maverick import config, runtime_overrides

    path = tmp_path / "config.toml"
    path.write_text(
        '[sandbox]\nbackend = "local"\n'
        '[security]\ndenied_tools = ["shell", "write_file", "apply_patch", '
        '"str_replace_editor", "ast_edit"]\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setattr(runtime_overrides, "denied_tools", lambda: set())
    monkeypatch.setattr(cli_mod, "_require_llm_key", lambda: "configured")
    monkeypatch.setattr(providers, "missing_sdks", lambda specs: [])
    monkeypatch.setattr(cli_mod, "_kernel", lambda: (_ for _ in ()).throw(
        RuntimeError("stop after the notice")))
    config.reset_config_cache()

    result = CliRunner().invoke(cli_mod.main, ["start", "Build a CLI and run it"])

    assert "Before starting: File changes or program execution are off" in result.output
    assert "Permissions > Where work runs" in result.output
    assert _goal_count(tmp_path) == 0


def test_sdk_gate_uses_effective_local_routes_not_anthropic_default(
    tmp_path, monkeypatch,
):
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    from maverick.llm import ROLE_MODELS

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        "[models]\n"
        + "\n".join(f'{role} = "ollama:qwen3"' for role in ROLE_MODELS)
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_path))
    monkeypatch.setenv("MAVERICK_ROLES_FILE", str(tmp_path / "roles.toml"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    for role in ROLE_MODELS:
        monkeypatch.delenv(
            f"MAVERICK_MODEL_OVERRIDE_{role.upper()}",
            raising=False,
        )
    import maverick.runtime_overrides as runtime_overrides

    monkeypatch.setattr(
        runtime_overrides,
        "OVERRIDES_PATH",
        tmp_path / "runtime-overrides.toml",
    )
    config.reset_config_cache()
    import maverick.cli as cli_mod
    import maverick.providers as providers

    monkeypatch.setattr(cli_mod, "_require_llm_key", lambda *args: "config")
    seen: list[str] = []

    def capture(specs):
        seen.extend(specs)
        return ["stop after route capture"]

    monkeypatch.setattr(providers, "missing_sdks", capture)
    result = CliRunner().invoke(cli_mod.main, ["start", "local-only goal"])

    assert result.exit_code == 2, result.output
    assert seen == ["ollama:qwen3"]
    assert "stop after route capture" in result.output
    assert _goal_count(tmp_path) == 0


def test_missing_sdks_helper_detects_absent_module(monkeypatch):
    import importlib.util

    from maverick import providers

    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name, *a, **k):
        if name == "openai":
            return None
        return real_find_spec(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    msgs = providers.missing_sdks(["vllm:stub-1", "claude-opus-4-8"])
    assert any("openai" in m for m in msgs)
    # anthropic SDK is installed -> no complaint about it
    assert not any("anthropic" in m.lower() for m in msgs)


def test_missing_sdks_helper_quiet_when_all_present():
    from maverick import providers
    assert providers.missing_sdks(["claude-opus-4-8"]) == []


def test_unknown_local_models_priced_zero():
    for spec in ("ollama:my-local-llm", "vllm:stub-1", "tgi:custom"):
        b = Budget(max_dollars=1.0)
        b.record_tokens(1000, 1000, model=spec)
        assert b.dollars == 0.0, (spec, b.dollars)


def test_unknown_openai_compatible_model_fails_closed():
    b = Budget(max_dollars=10.0)
    with pytest.raises(UnpricedModelError):
        b.record_tokens(1_000_000, 0, model="openai_compatible:proxy-model")
    assert b.dollars == 0
    assert b.input_tokens == 0


def test_unknown_hosted_model_fails_closed():
    b = Budget(max_dollars=10.0)
    with pytest.raises(UnpricedModelError):
        b.record_tokens(1_000_000, 0, model="mystery-model")
    assert b.dollars == 0
    assert b.input_tokens == 0


def test_known_model_via_local_prefix_uses_local_zero_metering():
    # A self-hosted route does not incur the direct provider's API charge,
    # even when both routes serve a model with the same name.
    local = Budget(max_dollars=10.0)
    local.record_tokens(1_000_000, 0, model="ollama:deepseek-v4-flash")
    assert local.dollars == 0

    direct = Budget(max_dollars=10.0)
    direct.record_tokens(1_000_000, 0, model="deepseek:deepseek-v4-flash")
    assert direct.dollars > 0


def test_debate_and_plan_reflect_refuse_cleanly_when_unconfigured(tmp_path, monkeypatch):
    """Neither command may skip the provider preflight, or an unconfigured
    install gets a raw anthropic-SDK TypeError traceback. They must refuse
    like `start` does: friendly message, exit 2, no traceback."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "none.toml"))

    from maverick.cli import main
    for argv in (["debate", "tabs or spaces?"], ["plan-reflect", "make tea"]):
        res = CliRunner().invoke(main, argv)
        assert res.exit_code == 2, (argv, res.output)
        assert "can't reach an LLM" in res.output
        assert "TypeError" not in res.output
