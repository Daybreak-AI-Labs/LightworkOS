"""terminal-bench-style stateful shell-agent harness.

Drives eval_terminal_bench with deterministic solvers (no LLM / no Docker): an
oracle that performs the right shell actions, a no-op, and partial/wrong solvers
-- exercising BOTH grading legs (final filesystem AND required commands) on the
shipped virtual-FS fixture.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load(name: str):
    p = Path(__file__).parent / name
    spec = importlib.util.spec_from_file_location(f"benchmarks_{p.stem}", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def tb():
    return _load("eval_terminal_bench.py")


def _oracle(task, tools):
    if task.task_id == "tb-create":
        tools["write_file"]("/app/config.yaml", "debug: true")
    elif task.task_id == "tb-cleanup":
        tools["delete_file"]("/var/log/old.log")
    elif task.task_id == "tb-inspect":
        tools["read_file"]("/etc/hosts")


# ---- end-to-end over the fixture --------------------------------------------

def test_oracle_solver_passes_all(tb):
    s = tb.run_terminal_bench(_oracle)
    assert s["n"] == 3 and s["pass_at_1"] == 1.0


def test_noop_solver_fails_all(tb):
    s = tb.run_terminal_bench(lambda t, tools: None)
    assert s["pass_at_1"] == 0.0


def test_load_tasks(tb):
    assert {t.task_id for t in tb.load_tasks()} == {
        "tb-create", "tb-cleanup", "tb-inspect"}


# ---- the two grading legs ---------------------------------------------------

def test_command_check_decides_the_pure_inspect(tb):
    # tb-inspect has no expected/absent files, so ONLY the required command
    # (cat /etc/hosts) decides it -- isolating the process check.
    miss = next(r for r in tb.run_terminal_bench(lambda t, tools: None)["results"]
                if r.task_id == "tb-inspect")
    assert not miss.passed and "cat /etc/hosts" in miss.got

    def only_inspect(t, tools):
        if t.task_id == "tb-inspect":
            tools["read_file"]("/etc/hosts")

    hit = next(r for r in tb.run_terminal_bench(only_inspect)["results"]
               if r.task_id == "tb-inspect")
    assert hit.passed


def test_outcome_check_catches_unwritten_file(tb):
    # Reading the target dir but never writing the file: state stays empty AND
    # the write command is missing -> fail, with `got` naming both legs.
    def peek(t, tools):
        tools["list_dir"]("/app")

    r = tb.run_terminal_bench(peek, limit=1)["results"][0]  # limit=1 -> tb-create
    assert r.task_id == "tb-create" and not r.passed
    # `got` reports the missing-command *regex pattern* verbatim (with its
    # escaped dot), so assert on the dot-free prefix.
    assert "files" in r.got and "write /app/config" in r.got


def test_absent_file_leg(tb):
    # tb-cleanup grades on a file being GONE. A solver that reads but never
    # deletes leaves it present -> fails both the absent-file and the rm-command.
    def peek(t, tools):
        if t.task_id == "tb-cleanup":
            tools["read_file"]("/var/log/old.log")

    r = next(r for r in tb.run_terminal_bench(peek)["results"] if r.task_id == "tb-cleanup")
    assert not r.passed and "should be absent" in r.got and "rm /var/log/old" in r.got


def test_wrong_content_fails_outcome_leg(tb):
    # Right command (write logged), wrong bytes: the process leg passes but the
    # outcome leg fails on exact-content mismatch.
    def wrong(t, tools):
        if t.task_id == "tb-create":
            tools["write_file"]("/app/config.yaml", "debug: false")

    r = next(r for r in tb.run_terminal_bench(wrong)["results"] if r.task_id == "tb-create")
    assert not r.passed and "files" in r.got and "missing commands" not in r.got


# ---- verify() unit + robustness ---------------------------------------------

def test_verify_requires_files_and_commands(tb):
    task = tb.TerminalTask(
        task_id="t", prompt="p",
        expected_files={"/a.txt": "hi"},
        required_commands=[r"write /a\.txt"],
    )
    env = tb.TerminalEnv({})
    env.files["/a.txt"] = "hi"
    env.commands.append("write /a.txt")
    assert tb.verify(task, env) == (1.0, "ok")
    # File right, command absent -> fail.
    bare = tb.TerminalEnv({"/a.txt": "hi"})
    score, detail = tb.verify(task, bare)
    assert score == 0.0 and "write /a" in detail


def test_run_command_escape_hatch_matches_required(tb):
    # An arbitrary command issued via run_command satisfies a required regex
    # (e.g. chmod), the terminal-bench affordance the typed tools don't cover.
    task = tb.TerminalTask(task_id="t", prompt="p",
                           required_commands=[r"chmod \+x .*deploy\.sh"])
    env = tb.TerminalEnv({})
    tools = tb.build_shell_tools(env)
    tools["run_command"]("chmod +x /opt/deploy.sh")
    assert tb.verify(task, env) == (1.0, "ok")


def test_malformed_required_command_pattern_degrades(tb):
    # A bad regex in a fixture row falls back to substring match, not a crash.
    task = tb.TerminalTask(task_id="t", prompt="p", required_commands=["rm (oops"])
    env = tb.TerminalEnv({})
    env.commands.append("rm (oops")
    assert tb.verify(task, env) == (1.0, "ok")


def test_task_without_criteria_is_never_a_pass(tb):
    # e.g. a row whose only criterion was misspelled ("absent_file").
    task = tb.TerminalTask(task_id="t", prompt="p")
    score, detail = tb.verify(task, tb.TerminalEnv({}))
    assert score == 0.0 and "not evaluated" in detail


def test_solver_exception_scores_zero_not_crash(tb):
    def boom(t, tools):
        raise RuntimeError("solver blew up")

    s = tb.run_terminal_bench(boom, limit=1)
    assert s["passed"] == 0 and "solver blew up" in s["results"][0].got
