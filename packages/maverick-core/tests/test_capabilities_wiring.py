"""[capabilities] config must actually gate the optional tools.

The wizard writes [capabilities] (computer_use / browser / web_search), and
base_registry gates those tools on enable_* flags -- but the agent's
_build_tools never read config to set them, so enabling a capability in config
was a silent no-op. The agent now passes the config-derived flags.
"""
from __future__ import annotations

from pathlib import Path

from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.config import get_capabilities
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


def _write_caps(tmp_path: Path, body: str) -> None:
    d = tmp_path / ".maverick"
    d.mkdir(exist_ok=True)
    (d / "config.toml").write_text(body)


def _agent_tool_names(tmp_path: Path, fake_llm) -> set[str]:
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("x", "")
    ctx = SwarmContext(
        llm=fake_llm, world=world, budget=Budget(), blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=str(tmp_path)), goal_id=gid,
        max_depth=1, use_skills=False,
    )
    return {t.name for t in Agent(ctx=ctx, role="researcher", brief="x").tools.all()}


def test_get_capabilities_reads_config(tmp_path: Path):
    # conftest's autouse fixture points HOME at tmp_path.
    _write_caps(tmp_path, "[capabilities]\nweb_search = true\nbrowser = false\nros = true\n")
    caps = get_capabilities()
    assert caps["web_search"] is True
    assert caps["browser"] is False
    assert caps["computer_use"] is False
    assert caps["ros"] is True


def test_agent_enables_web_search_when_capability_set(tmp_path: Path, fake_llm):
    _write_caps(tmp_path, "[capabilities]\nweb_search = true\n")
    assert "web_search" in _agent_tool_names(tmp_path, fake_llm)


def test_agent_omits_web_search_by_default(tmp_path: Path, fake_llm):
    _write_caps(tmp_path, "")  # no [capabilities]
    assert "web_search" not in _agent_tool_names(tmp_path, fake_llm)


def test_agent_enables_ros_when_capability_set(tmp_path: Path, fake_llm):
    _write_caps(tmp_path, "[capabilities]\nros = true\n")
    assert "ros" in _agent_tool_names(tmp_path, fake_llm)


def test_agent_omits_ros_by_default(tmp_path: Path, fake_llm):
    _write_caps(tmp_path, "")  # no [capabilities]
    assert "ros" not in _agent_tool_names(tmp_path, fake_llm)
