"""A2A-initiated goals run under a tool ceiling.

A2A is a remote, machine-to-machine surface, so its goals must not inherit
full local tool access. ``_default_runner`` now builds a ``Capability`` from
``_a2a_capability()`` and passes it into the orchestrator. The default ceiling
is ``max_risk="medium"`` (high-risk tools -- shell / code_exec / write / send /
infra, and the unclassified MCP tools that default to high -- are off), and an
operator can tighten or lift it via ``[a2a]`` config / ``MAVERICK_A2A_*`` env.
"""
from __future__ import annotations

import importlib

import pytest


def _write_a2a_config(tmp_path, body: str = "") -> None:
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.toml").write_text(body)
    import maverick.config as cfg_mod
    importlib.reload(cfg_mod)


def _clear_env(monkeypatch) -> None:
    for k in ("MAVERICK_A2A_MAX_RISK", "MAVERICK_A2A_TOOLS", "MAVERICK_A2A_DENY_TOOLS"):
        monkeypatch.delenv(k, raising=False)


# --- the ceiling itself -----------------------------------------------------

def test_default_ceiling_is_medium(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path)  # no [a2a] config
    from maverick.a2a_tasks import _a2a_capability
    cap = _a2a_capability()
    assert cap.max_risk == "medium"
    assert cap.permits("read_file")            # low
    assert cap.permits("kv_memory")            # reviewed medium
    assert not cap.permits("some_unknown_tool")  # unrated -> high floor -> blocked
    assert not cap.permits("shell")            # high -> blocked
    assert not cap.permits("mcp_x__y")         # MCP defaults high -> blocked


def test_env_overrides_config_and_lifts_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path, '[a2a]\nmax_risk = "low"\n')
    monkeypatch.setenv("MAVERICK_A2A_MAX_RISK", "none")  # env wins -> no cap
    from maverick.a2a_tasks import _a2a_capability
    cap = _a2a_capability()
    assert cap.max_risk is None
    assert cap.permits("shell")  # uncapped


def test_config_max_risk_low(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path, '[a2a]\nmax_risk = "low"\n')
    from maverick.a2a_tasks import _a2a_capability
    cap = _a2a_capability()
    assert cap.max_risk == "low"
    assert cap.permits("read_file")
    assert not cap.permits("some_unknown_tool")  # medium > low -> blocked


def test_unrecognized_risk_falls_back_to_medium(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path)
    monkeypatch.setenv("MAVERICK_A2A_MAX_RISK", "bogus")
    from maverick.a2a_tasks import _a2a_capability
    assert _a2a_capability().max_risk == "medium"


def test_blank_max_risk_keeps_the_ceiling(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path, '[a2a]\nmax_risk = ""\n')
    from maverick.a2a_tasks import _a2a_capability
    assert _a2a_capability().max_risk == "medium"
    monkeypatch.setenv("MAVERICK_A2A_MAX_RISK", "  ")
    assert _a2a_capability().max_risk == "medium"


def test_allowlist_from_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(
        tmp_path, '[a2a]\nmax_risk = "high"\ntools = ["read_file", "web_search"]\n'
    )
    from maverick.a2a_tasks import _a2a_capability
    cap = _a2a_capability()
    assert cap.permits("read_file") and cap.permits("web_search")
    assert not cap.permits("shell")  # high risk allowed, but not on the allowlist


def test_allowlist_and_deny_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path)
    monkeypatch.setenv("MAVERICK_A2A_MAX_RISK", "none")
    monkeypatch.setenv("MAVERICK_A2A_TOOLS", "read_file, web_search")
    monkeypatch.setenv("MAVERICK_A2A_DENY_TOOLS", "web_search")
    from maverick.a2a_tasks import _a2a_capability
    cap = _a2a_capability()
    assert cap.permits("read_file")
    assert not cap.permits("web_search")   # deny wins over allow
    assert not cap.permits("shell")        # not on the allowlist


@pytest.mark.parametrize("key", ["tools", "deny_tools"])
def test_malformed_tool_policy_fails_closed(tmp_path, monkeypatch, key):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path, f"[a2a]\n{key} = true\n")
    from maverick.a2a_tasks import _a2a_capability

    with pytest.raises(RuntimeError, match="policy must be a list"):
        _a2a_capability()


# --- the runner wires it through --------------------------------------------

def test_default_runner_passes_capability(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _clear_env(monkeypatch)
    _write_a2a_config(tmp_path)
    import maverick.a2a_tasks as a2at

    captured: dict = {}

    def _fake_run_goal_sync(*args, **kwargs):
        captured.update(kwargs)
        return "ok"

    class _FakeWorld:
        def create_goal(self, *a, **k):
            return 1

    monkeypatch.setattr("maverick.orchestrator.run_goal_sync", _fake_run_goal_sync)
    monkeypatch.setattr("maverick.llm.LLM", lambda *a, **k: object())
    monkeypatch.setattr("maverick.world_model.WorldModel", lambda *a, **k: _FakeWorld())
    monkeypatch.setattr("maverick.sandbox.build_sandbox", lambda *a, **k: object())

    out = a2at._default_runner("hi", max_dollars=1.0, max_wall=10.0, max_depth=1)
    assert out == "ok"
    cap = captured.get("capability")
    assert cap is not None
    assert cap.max_risk == "medium"
    assert cap.permits("read_file") and not cap.permits("shell")
