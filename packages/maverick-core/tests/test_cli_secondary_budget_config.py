"""Secondary CLI runs honor the same configured task limits as `start`."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from click.testing import CliRunner


class _FakeLLM:
    def __init__(self, model=None):
        self.model = model

    def complete(self, **_kwargs):
        raise AssertionError("the command runner is stubbed")


@pytest.mark.parametrize("command", ["debate", "plan-reflect", "watch"])
@pytest.mark.parametrize(
    ("configured", "env_dollars", "flag", "expected"),
    [
        ({"max_dollars": 1.25, "max_wall_seconds": 90, "max_tool_calls": 7},
         None, [], (1.25, 90, 7)),
        ({"max_dollars": 1.25, "max_wall_seconds": 90, "max_tool_calls": 7},
         "2.5", [], (2.5, 90, 7)),
        ({"max_dollars": 1.25, "max_wall_seconds": 90, "max_tool_calls": 7},
         "2.5", ["--max-dollars", "3.5"], (3.5, 90, 7)),
        ({}, None, [], ("fallback", None, None)),
        ({"task_limits_enabled": False, "max_dollars": 1.25,
          "max_wall_seconds": 90, "max_tool_calls": 7},
         None, [], (None, None, None)),
    ],
    ids=["configured-caps", "environment-dollar-override",
         "explicit-dollar-override", "no-configured-cap-uses-fallback",
         "limits-explicitly-disabled"],
)
def test_secondary_cli_budget_precedence(
    monkeypatch, tmp_path, command, configured, env_dollars, flag, expected,
):
    import maverick.cli as cli
    import maverick.debate as debate_mod
    import maverick.plan_execute_reflect as plan_mod

    home = tmp_path / ".maverick"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")  # pragma: allowlist secret
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_BUDGET_DOLLARS", raising=False)
    if env_dollars is not None:
        monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", env_dollars)
    config = tmp_path / "config.toml"
    lines = [
        '[models]',
        'orchestrator = "anthropic:claude-configured-orchestrator"',
        'analyst = "anthropic:claude-configured-analyst"',
    ]
    if configured:
        lines.extend(["", "[budget]"])
        lines.extend(
            f"{key} = {str(value).lower() if isinstance(value, bool) else value}"
            for key, value in configured.items()
        )
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))

    captured = []

    def run_goal(_llm, world, budget, goal_id, **_kwargs):
        captured.append(budget)
        world.set_goal_status(goal_id, "done", result="done")
        return "done"

    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        LLM=_FakeLLM, build_sandbox=lambda **_kwargs: object(),
        run_goal_sync=run_goal,
    ))
    def fake_debate(*_args, budget, **_kwargs):
        captured.append(budget)
        return SimpleNamespace(
            transcript=[], winner="done", judge_reason="", key_argument="",
            rounds_completed=0, total_dollars=0.0,
        )

    def fake_plan(*_args, budget, **_kwargs):
        captured.append(budget)
        return SimpleNamespace(
            plan=[], results=[], reflections=[], status="done", iterations=0, total_dollars=0.0,
        )

    monkeypatch.setattr(debate_mod, "run_debate", fake_debate)
    monkeypatch.setattr(plan_mod, "run_plan_execute_reflect", fake_plan)

    if command == "watch":
        marked = tmp_path / "marked.py"
        marked.write_text("x = 1  # AI: add a docstring\n", encoding="utf-8")
        monkeypatch.setattr(cli, "_watch_goal_allowed", lambda _goal: (True, None))
        args = ["watch", str(marked), "--run", *flag]
    else:
        args = [command, "test the budget", *flag]
    response = CliRunner().invoke(cli.main, args)

    assert response.exit_code == 0, response.output
    assert len(captured) == 1
    budget = captured[0]
    if expected[0] == "fallback":
        expected = (1.0 if command == "debate" else 2.0, None, None)
    assert (budget.max_dollars, budget.max_wall_seconds, budget.max_tool_calls) == expected
