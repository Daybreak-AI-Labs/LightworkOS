"""CLI commands use the configured role models, never a hard-coded model.

Kernel rule 2: without ``--model`` the CLI resolves its LLM through
``model_for_role`` with the same role the dashboard and channel server use for
the same action -- ``orchestrator`` for running a goal (start, chat, resume,
watch --run) and ``writer`` for drafting a specialist (onboard, learn-demo,
the role the dashboard's agent drafting uses). An explicit ``--model`` still
wins. The LLM is stubbed to capture the model it was built with; no provider
call is made.
"""
from __future__ import annotations

import types

import pytest
from click.testing import CliRunner

ORCHESTRATOR = "anthropic:claude-configured-orchestrator"
WRITER = "anthropic:claude-configured-writer"
EXPLICIT = "anthropic:claude-explicit-choice"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-dummy")  # pragma: allowlist secret
    # `--model` writes MAVERICK_MODEL_OVERRIDE straight into os.environ; set
    # then delete so monkeypatch removes whatever the CLI leaves behind.
    for name in ("MAVERICK_MODEL_OVERRIDE", "MAVERICK_MODEL_OVERRIDE_ORCHESTRATOR",
                 "MAVERICK_MODEL_OVERRIDE_WRITER"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    config = tmp_path / "config.toml"
    config.write_text(
        f'[models]\norchestrator = "{ORCHESTRATOR}"\nwriter = "{WRITER}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))
    from maverick import killswitch

    killswitch._last_file_check_ts = 0.0
    killswitch.clear()
    return tmp_path


def _kernel_capturing(captured: list):
    """A kernel stand-in whose LLM records the model it was built with."""
    from maverick.budget import Budget

    def llm(model=None):
        captured.append(model)
        return object()

    def run_goal_sync(_llm, world, _budget, goal_id, **_kw):
        world.set_goal_status(goal_id, "done", result="FINAL: ok")
        return "FINAL: ok"

    return types.SimpleNamespace(
        Budget=Budget, LLM=llm, build_sandbox=lambda **_kw: object(),
        run_goal_sync=run_goal_sync, scrub=lambda text: text,
    )


def _invoke(args, **kw):
    import maverick.cli as cli_mod

    return CliRunner().invoke(cli_mod.main, args, **kw)


def _patch_kernel(monkeypatch, captured):
    import maverick.cli as cli_mod

    monkeypatch.setattr(cli_mod, "_kernel", lambda: _kernel_capturing(captured))


def _blocked_goal() -> int:
    from maverick.workspace import Workspace
    from maverick.world_model import WorldModel

    world = WorldModel(Workspace.current().db_path)
    goal_id = world.create_goal("resumable", "")
    world.set_goal_status(goal_id, "blocked")
    world.close()
    return goal_id


def test_start_uses_the_configured_orchestrator_model(home, monkeypatch):
    captured: list = []
    _patch_kernel(monkeypatch, captured)
    res = _invoke(["start", "summarise the weekly numbers", "--sandbox", "local"])
    assert res.exit_code == 0, res.output
    assert captured == [ORCHESTRATOR]


def test_start_explicit_model_still_wins(home, monkeypatch):
    captured: list = []
    _patch_kernel(monkeypatch, captured)
    res = _invoke(["--model", EXPLICIT, "start", "summarise the weekly numbers",
                   "--sandbox", "local"])
    assert res.exit_code == 0, res.output
    assert captured == [EXPLICIT]


def test_chat_uses_the_configured_orchestrator_model(home, monkeypatch):
    captured: list = []
    _patch_kernel(monkeypatch, captured)
    res = _invoke(["chat"], input="exit\n")
    assert res.exit_code == 0, res.output
    assert captured == [ORCHESTRATOR]


def test_resume_uses_the_configured_orchestrator_model(home, monkeypatch):
    goal_id = _blocked_goal()
    captured: list = []
    _patch_kernel(monkeypatch, captured)
    res = _invoke(["resume", "--goal-id", str(goal_id)])
    assert res.exit_code == 0, res.output
    assert captured == [ORCHESTRATOR]


def test_watch_run_uses_the_configured_orchestrator_model(home, monkeypatch):
    marked = home / "notes.py"
    marked.write_text("x = 1  # AI: add a docstring to this module\n", encoding="utf-8")
    captured: list = []
    _patch_kernel(monkeypatch, captured)
    res = _invoke(["watch", str(marked), "--run"])
    assert res.exit_code == 0, res.output
    assert captured == [ORCHESTRATOR]


class _CapturingLLM:
    """Stands in for ``maverick.llm.LLM``: records the model, then refuses so
    the command takes its deterministic path (no provider call)."""

    built: list = []

    def __init__(self, model=None, **_kw):
        type(self).built.append(model)
        raise RuntimeError("stub provider")


@pytest.fixture
def capturing_llm(monkeypatch):
    import maverick.llm as llm_mod

    _CapturingLLM.built = []
    monkeypatch.setattr(llm_mod, "LLM", _CapturingLLM)
    return _CapturingLLM.built


def _demo_file(home):
    demo = home / "weekly_report.txt"
    demo.write_text(
        "ACTION[read_file]: open the weekly sales sheet -> sales.xlsx\n"
        "NOTE: I check the totals against last week\n"
        "ACTION: write a two-line summary for the team\n",
        encoding="utf-8",
    )
    return demo


def test_onboard_uses_the_configured_writer_model(home, capturing_llm):
    res = _invoke(["onboard", "--name", "Acme Co"], input="n\n")
    assert res.exit_code == 0, res.output
    assert "Discarded" in res.output
    assert capturing_llm == [WRITER]


def test_learn_demo_uses_the_configured_writer_model(home, capturing_llm):
    res = _invoke(["learn-demo", str(_demo_file(home))], input="n\n")
    assert res.exit_code == 0, res.output
    assert "Discarded" in res.output
    assert capturing_llm == [WRITER]


def test_learn_demo_explicit_model_still_wins(home, capturing_llm):
    res = _invoke(["--model", EXPLICIT, "learn-demo", str(_demo_file(home))], input="n\n")
    assert res.exit_code == 0, res.output
    assert capturing_llm == [EXPLICIT]


def test_route_check_defaults_to_the_orchestrator_role(home):
    import maverick.cli as cli_mod

    assert cli_mod._default_model() == ORCHESTRATOR
    assert cli_mod._default_model("writer") == WRITER
