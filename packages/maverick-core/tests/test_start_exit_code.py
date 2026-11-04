"""`maverick start` must exit nonzero when the run did not complete.

A run paused awaiting a user answer, stopped by a budget/time cap, or refused
by an input guard must not look like a clean success by exit code, or scripts
and CI cannot tell them apart. start exits 2 when the kernel marks the goal
``blocked``; a genuinely completed (``done``) goal exits 0.
"""
from __future__ import annotations

import types

from click.testing import CliRunner


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # A present (not necessarily valid) key passes start's provider preflight;
    # the fake kernel never makes a real call.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-dummy")
    from maverick import killswitch as ks
    ks._last_file_check_ts = 0.0
    ks.clear()


def _fake_kernel(final_status: str, message: str):
    """A kernel stand-in whose run marks the goal ``final_status`` and returns
    ``message`` -- no real LLM/provider needed to exercise start's exit code."""
    ns = types.SimpleNamespace()
    ns.DEFAULT_MODEL = "claude-opus-4-8"  # anthropic SDK is installed -> preflight passes
    ns.LLM = lambda model=None: object()
    ns.build_sandbox = lambda **kw: object()

    def run_goal_sync(llm, world, bud, goal_id, **kw):
        world.set_goal_status(goal_id, final_status, result=message)
        return message

    ns.run_goal_sync = run_goal_sync
    return ns


def test_start_exits_2_when_goal_is_blocked(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import maverick.cli as cli_mod
    monkeypatch.setattr(
        cli_mod, "_kernel",
        lambda: _fake_kernel("blocked", "Paused: waiting for you to answer 1 question."),
    )
    res = CliRunner().invoke(cli_mod.main, ["start", "QQASK plan a trip", "--sandbox", "local"])
    assert res.exit_code == 2, res.output
    assert "Paused" in res.output


def test_start_exits_0_when_goal_is_done(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import maverick.cli as cli_mod
    monkeypatch.setattr(
        cli_mod, "_kernel",
        lambda: _fake_kernel("done", "FINAL: task complete."),
    )
    res = CliRunner().invoke(cli_mod.main, ["start", "say hi", "--sandbox", "local"])
    assert res.exit_code == 0, res.output
    assert "FINAL" in res.output


def test_start_repeat_runs_goal_n_times(tmp_path, monkeypatch):
    """--repeat N runs the SAME task N times (DPO needs repeated attempts at one
    task to form preference pairs). Each run creates its own goal row."""
    _isolate(monkeypatch, tmp_path)
    import maverick.cli as cli_mod
    monkeypatch.setattr(
        cli_mod, "_kernel",
        lambda: _fake_kernel("done", "FINAL: ok"),
    )
    res = CliRunner().invoke(
        cli_mod.main, ["start", "solve it", "--sandbox", "local", "--repeat", "3"],
    )
    assert res.exit_code == 0, res.output
    # Three goals created, each labelled with its index.
    assert res.output.count("goal #") == 3, res.output
    assert "[1/3]" in res.output and "[3/3]" in res.output


def test_start_repeat_does_not_exit_2_on_blocked(tmp_path, monkeypatch):
    """In repeat mode a non-clean run is EXPECTED (it's the worse half of a
    preference pair), so a blocked outcome must NOT abort the batch with exit 2."""
    _isolate(monkeypatch, tmp_path)
    import maverick.cli as cli_mod
    monkeypatch.setattr(
        cli_mod, "_kernel",
        lambda: _fake_kernel("blocked", "Paused: needs input."),
    )
    res = CliRunner().invoke(
        cli_mod.main, ["start", "solve it", "--sandbox", "local", "--repeat", "2"],
    )
    assert res.exit_code == 0, res.output
    assert res.output.count("goal #") == 2, res.output


def test_start_single_run_keeps_exit_2_contract(tmp_path, monkeypatch):
    """--repeat 1 (the default) preserves the exit-2-on-blocked contract."""
    _isolate(monkeypatch, tmp_path)
    import maverick.cli as cli_mod
    monkeypatch.setattr(
        cli_mod, "_kernel",
        lambda: _fake_kernel("blocked", "Paused: needs input."),
    )
    res = CliRunner().invoke(
        cli_mod.main, ["start", "solve it", "--sandbox", "local", "--repeat", "1"],
    )
    assert res.exit_code == 2, res.output
    # No index label when running once.
    assert "[1/1]" not in res.output
