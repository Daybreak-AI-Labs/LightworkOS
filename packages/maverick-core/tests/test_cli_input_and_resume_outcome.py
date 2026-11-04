"""No provider calls: canceled input and actual kernel HALT at CLI boundaries."""
from types import SimpleNamespace
from unittest.mock import Mock

import click
import pytest
from click.testing import CliRunner
from maverick import cli
from maverick.world_model import WorldModel


@pytest.mark.parametrize("first", ['"""unfinished', 'unfinished\\'])
@pytest.mark.parametrize("stop", [click.Abort, EOFError])
def test_multiline_cancel_creates_no_goal_or_turn(monkeypatch, tmp_path, first, stop):
    world = WorldModel(tmp_path / "world.db")
    create, append, run = Mock(), Mock(), Mock()
    monkeypatch.setattr(world, "create_goal", create)
    monkeypatch.setattr(world, "append_turn", append)
    monkeypatch.setattr(cli, "open_world", lambda path: world)
    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        DEFAULT_MODEL="fixture:offline", LLM=lambda **kw: None,
        build_sandbox=lambda **kw: None, run_goal_sync=run))
    monkeypatch.setattr(click, "prompt", Mock(side_effect=[first, stop()]))
    result = CliRunner().invoke(cli.main, ["chat"])
    assert result.exit_code == 0, result.output
    create.assert_not_called()
    append.assert_not_called()
    run.assert_not_called()
    world.close()


def test_resume_reports_native_halt_as_nonzero(monkeypatch, tmp_path):
    from maverick.file_lock import atomic_write_text
    from maverick.orchestrator import run_goal_sync
    from maverick.sandbox.local import LocalBackend

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("halted resume", "")
    world.set_goal_status(goal_id, "blocked", "awaiting resume")
    halt = tmp_path / "HALT"
    atomic_write_text(halt, "test halt")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(halt))
    monkeypatch.setattr(cli, "open_world", lambda path: world)
    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    class NoProvider:
        def __init__(self, **kwargs):
            self.model = "fixture:offline"
        async def complete_async(self, **kwargs):
            pytest.fail("HALT must precede provider dispatch")
    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        DEFAULT_MODEL="fixture:offline", LLM=NoProvider,
        build_sandbox=lambda **kw: LocalBackend(tmp_path), run_goal_sync=run_goal_sync))
    result = CliRunner().invoke(cli.main, ["resume", str(goal_id)])
    assert result.exit_code == 2, (result.output, result.exception)
    assert "halted" in result.output.lower()
    assert world.get_goal(goal_id).status == "blocked"
    world.close()


@pytest.mark.parametrize("status,expected", [("done", 0), ("blocked", 2)])
def test_resume_uses_persisted_run_outcome(monkeypatch, tmp_path, status, expected):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("resume", "")
    def run(llm, actual_world, budget, gid, **kwargs):
        actual_world.set_goal_status(gid, status, "test result")
        return "test result"
    monkeypatch.setattr(cli, "open_world", lambda path: world)
    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        DEFAULT_MODEL="fixture:offline", LLM=lambda **kw: None,
        build_sandbox=lambda **kw: None, run_goal_sync=run))
    result = CliRunner().invoke(cli.main, ["resume", str(goal_id)])
    assert result.exit_code == expected, result.output
    world.close()


@pytest.mark.parametrize("questions", [[], [SimpleNamespace(id=1, question="Choose a target")]])
def test_resume_empty_and_open_question_paths_never_dispatch_provider(monkeypatch, tmp_path, questions):
    world = WorldModel(tmp_path / "world.db")
    args = ["resume"]
    if questions:
        args.append(str(world.create_goal("resume", "")))
        monkeypatch.setattr(world, "open_questions", lambda _: questions)
    provider = Mock(side_effect=AssertionError("provider must not be initialized"))
    monkeypatch.setattr(cli, "open_world", lambda _: world)
    monkeypatch.setattr(cli, "_require_llm_key", provider)
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == (2 if questions else 0), result.output
    provider.assert_not_called()
    world.close()


@pytest.mark.parametrize("lines", [['"""first', 'second', '"""', 'exit'], ['first\\', 'second', 'exit']])
def test_completed_multiline_dispatches_exactly_one_complete_goal(monkeypatch, tmp_path, lines):
    world = WorldModel(tmp_path / "world.db")
    seen = []

    def run(_llm, actual_world, _budget, gid, **_kwargs):
        seen.append(actual_world.get_goal(gid).description)
        return "fixture result"

    monkeypatch.setattr(cli, "open_world", lambda _: world)
    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        DEFAULT_MODEL="fixture:offline", LLM=lambda **kw: None,
        build_sandbox=lambda **kw: None, run_goal_sync=run))
    monkeypatch.setattr(click, "prompt", Mock(side_effect=lines))
    result = CliRunner().invoke(cli.main, ["chat"])
    assert result.exit_code == 0, result.output
    assert seen == ["first\nsecond"]
    world.close()


def test_cli_chat_goal_uses_finite_defaults_before_install(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    world = WorldModel(tmp_path / "world.db")
    seen = []

    def run(_llm, _world, budget, _gid, **_kwargs):
        seen.append((budget.max_dollars, budget.max_wall_seconds))
        return "fixture result"

    monkeypatch.setattr(cli, "open_world", lambda _: world)
    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        DEFAULT_MODEL="fixture:offline", LLM=lambda **kw: None,
        build_sandbox=lambda **kw: None, run_goal_sync=run))
    monkeypatch.setattr(click, "prompt", Mock(side_effect=["hello", "exit"]))
    result = CliRunner().invoke(cli.main, ["chat"])
    assert result.exit_code == 0, result.output
    assert seen == [(2.0, 1800.0)]
    world.close()


def test_cli_start_uses_goal_defaults_and_honors_explicit_limits(monkeypatch, tmp_path):
    from maverick import operator_preflight, providers

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    seen = []

    def run(_llm, _world, budget, _gid, **_kwargs):
        seen.append((budget.max_dollars, budget.max_wall_seconds))
        return "fixture result"

    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    monkeypatch.setattr(cli, "_cli_model", lambda *_args: "fixture:offline")
    monkeypatch.setattr(cli, "open_world", lambda _: WorldModel(tmp_path / "world.db"))
    monkeypatch.setattr(cli, "_kernel", lambda: SimpleNamespace(
        LLM=lambda **kw: None, build_sandbox=lambda **kw: None, run_goal_sync=run))
    monkeypatch.setattr(operator_preflight, "_model_specs", lambda _: {})
    monkeypatch.setattr(providers, "missing_sdks", lambda _: [])

    default = CliRunner().invoke(cli.main, ["start", "first"])
    explicit = CliRunner().invoke(cli.main, [
        "start", "second", "--max-dollars", "5", "--max-wall-seconds", "3600",
    ])
    assert default.exit_code == explicit.exit_code == 0, (default.output, explicit.output)
    assert seen == [(2.0, 1800.0), (5.0, 3600.0)]
