"""Notebook execution tool."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.sandbox import LocalBackend
from maverick.tools.notebook_exec import _extract_code, notebook_exec


class _FakeSandbox:
    def __init__(self, stdout="hello\n", code=0, stderr="", workdir="."):
        self.stdout, self.code, self.stderr = stdout, code, stderr
        self.workdir = workdir
        self.last_cmd = None

    def exec(self, cmd, timeout=None):
        self.last_cmd = cmd

        class R:
            pass
        r = R()
        r.exit_code, r.stdout, r.stderr = self.code, self.stdout, self.stderr
        return r


def _nb(*sources, markdown=True):
    cells = []
    if markdown:
        cells.append({"cell_type": "markdown", "source": ["# title\n"]})
    for s in sources:
        cells.append({"cell_type": "code", "source": s})
    return {"cells": cells, "nbformat": 4}


@pytest.fixture
def human_approval(tmp_path, monkeypatch):
    import maverick.safety.consent as consent

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        ),
    )


def test_extract_skips_markdown_and_magics():
    nb = _nb(["%matplotlib inline\n", "print('a')\n"], ["!pip install x\n", "print('b')\n"])
    code = _extract_code(nb)
    assert "print('a')" in code and "print('b')" in code
    assert "%matplotlib" not in code and "!pip" not in code
    assert "# title" not in code


def test_extract_empty_when_no_code():
    assert _extract_code({"cells": [{"cell_type": "markdown", "source": ["x"]}]}) == ""


def test_run_executes_via_sandbox(tmp_path, human_approval):
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb(["print('hi')\n"])), encoding="utf-8")
    sb = _FakeSandbox(stdout="hi\n", code=0, workdir=str(tmp_path))
    tool = notebook_exec(sb)
    out = tool.fn({"path": str(nb_path)})
    assert "exit_code: 0" in out
    assert "hi" in out
    assert "python" in sb.last_cmd  # ran through the sandbox


@pytest.mark.parametrize("backend", ["sandbox", "host"])
@pytest.mark.parametrize("mode", ["auto-deny", "auto-approve"])
def test_run_requires_human_approval_even_without_sandbox(
    tmp_path, monkeypatch, backend, mode,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", mode)
    marker = tmp_path / "must-not-exist.txt"
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb([f"open({str(marker)!r}, 'w').write('ran')\n"])), encoding="utf-8")
    sb = _FakeSandbox(workdir=str(tmp_path)) if backend == "sandbox" else None

    out = notebook_exec(sb).fn({"path": str(nb_path)})

    assert "notebook execution was not approved" in out
    assert not marker.exists()
    if sb is not None:
        assert sb.last_cmd is None


def test_run_without_sandbox_after_human_approval(tmp_path, human_approval):
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb(["print('host-approved')\n"])), encoding="utf-8")

    out = notebook_exec(None).fn({"path": str(nb_path)})

    assert "exit_code: 0" in out
    assert "host-approved" in out


def test_notebook_change_during_approval_refuses_dispatch(
    tmp_path, monkeypatch,
):
    import maverick.safety.consent as consent

    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb(["print('before')\n"])), encoding="utf-8")
    sb = _FakeSandbox(workdir=str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))

    def approve(*_args, **_kwargs):
        nb_path.write_text(json.dumps(_nb(["print('after')\n"])), encoding="utf-8")
        return SimpleNamespace(granted=True, source="dashboard", actor="user:reviewer")

    monkeypatch.setattr(consent, "require_consent", approve)
    out = notebook_exec(sb).fn({"path": str(nb_path)})

    assert "changed; review it again" in out
    assert sb.last_cmd is None


def test_windows_local_backend_executes_approved_notebook(
    tmp_path: Path, human_approval,
):
    if __import__("os").name != "nt":
        pytest.skip("Windows LocalBackend command syntax")
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb(["print('windows-approved')\n"])), encoding="utf-8")

    out = notebook_exec(LocalBackend(workdir=tmp_path)).fn({"path": str(nb_path)})

    assert "exit_code: 0" in out
    assert "windows-approved" in out


def test_windows_local_backend_accepts_notebook_larger_than_command_limit(
    tmp_path: Path, human_approval,
):
    if __import__("os").name != "nt":
        pytest.skip("Windows cmd.exe length limit")
    nb_path = tmp_path / "large.ipynb"
    nb_path.write_text(
        json.dumps(_nb(["# " + "x" * 7000 + "\nprint('large-approved')\n"])),
        encoding="utf-8",
    )

    out = notebook_exec(LocalBackend(workdir=tmp_path)).fn({"path": str(nb_path)})

    assert "exit_code: 0" in out
    assert "large-approved" in out


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["sandbox", "host"])
async def test_agent_cannot_run_notebook_without_approval(
    tmp_path, monkeypatch, fake_llm, backend,
):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TEST_SECURE_DEFAULT", "1")
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    marker = tmp_path / "agent-must-not-run.txt"
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb([f"open({str(marker)!r}, 'w').write('ran')\n"])), encoding="utf-8")
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path) if backend == "sandbox" else None,
        goal_id=world.create_goal("test notebook consent", ""),
        use_skills=False, user_id="ordinary:member",
    )

    out = await Agent(ctx=ctx, role="researcher", brief="run notebook")._run_tool(
        "notebook_exec", {"path": str(nb_path)},
    )

    assert "notebook execution was not approved" in out
    assert not marker.exists()


@pytest.mark.asyncio
async def test_agent_approved_notebook_requires_fresh_one_use_decision(
    tmp_path, monkeypatch, fake_llm,
):
    import maverick.safety.consent as consent
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TEST_SECURE_DEFAULT", "1")
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb(["print('agent-approved')\n"])), encoding="utf-8")
    decisions = []

    def decide(*_args, **kwargs):
        decisions.append(kwargs.get("approval_card"))
        if len(decisions) == 1:
            return SimpleNamespace(granted=True, source="dashboard", actor="user:reviewer")
        raise consent.ConsentDenied("one-use approval already spent")

    monkeypatch.setattr(consent, "require_consent", decide)
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=world.create_goal("test notebook consent", ""),
        use_skills=False, user_id="ordinary:member",
    )
    agent = Agent(ctx=ctx, role="researcher", brief="run notebook")

    first = await agent._run_tool("notebook_exec", {"path": str(nb_path)})
    second = await agent._run_tool("notebook_exec", {"path": str(nb_path)})

    assert "exit_code: 0" in first and "agent-approved" in first
    assert "notebook execution was not approved" in second
    assert len(decisions) == 2
    assert decisions[0]["action"] == "notebook_exec"
    assert decisions[0]["parameters"]["sha256"]
    assert "First lines" in decisions[0]["parameters"]["summary"][0]
    assert "agent-approved" in decisions[0]["parameters"]["summary"][0]


def test_run_missing_file(tmp_path):
    out = notebook_exec(_FakeSandbox(workdir=str(tmp_path))).fn(
        {"path": str(tmp_path / "no_such.ipynb")})
    assert out.startswith("ERROR")


def test_run_no_code_cells(tmp_path):
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps({"cells": []}), encoding="utf-8")
    out = notebook_exec(_FakeSandbox(workdir=str(tmp_path))).fn({"path": str(nb_path)})
    assert "no executable code" in out


def test_oversized_notebook_and_code_refuse_before_approval(tmp_path):
    nb_path = tmp_path / "nb.ipynb"
    sb = _FakeSandbox(workdir=str(tmp_path))
    nb_path.write_bytes(b" " * (16 * 1024 * 1024 + 1))

    out = notebook_exec(sb).fn({"path": str(nb_path)})

    assert "larger than 16 MiB" in out
    assert sb.last_cmd is None

    nb_path.write_text(json.dumps(_nb(["# " + "x" * (64 * 1024) + "\n"])), encoding="utf-8")
    out = notebook_exec(sb).fn({"path": str(nb_path)})

    assert "code exceeds 64 KiB" in out
    assert sb.last_cmd is None


def test_excessive_timeout_refuses_before_approval(tmp_path):
    nb_path = tmp_path / "nb.ipynb"
    nb_path.write_text(json.dumps(_nb(["print('never')\n"])), encoding="utf-8")
    sb = _FakeSandbox(workdir=str(tmp_path))

    out = notebook_exec(sb).fn({"path": str(nb_path), "timeout": 601})

    assert "between 1 and 600 seconds" in out
    assert sb.last_cmd is None


def test_run_confines_path_to_sandbox_workspace(tmp_path):
    """A notebook path outside the sandbox workdir is refused before any
    cell executes -- a model-supplied ~/anything.ipynb must not run."""
    workdir = tmp_path / "ws"
    workdir.mkdir()
    outside = tmp_path / "secret.ipynb"
    outside.write_text(json.dumps(_nb(["print('hi')\n"])), encoding="utf-8")
    sb = _FakeSandbox(workdir=str(workdir))
    out = notebook_exec(sb).fn({"path": str(outside)})
    assert out.startswith("ERROR: path escapes the workspace")
    assert sb.last_cmd is None  # never executed
