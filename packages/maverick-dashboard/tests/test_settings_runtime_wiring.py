"""Settings > All settings: runtime settings that used to change nothing.

Each test saves a value through the catalog API (the path the page uses) and
then checks the code that owns the behaviour acts on it; where the setting has
an environment variable, the variable still wins. Unset keys keep today's
behaviour.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_runtime as runtime
from maverick_dashboard.app import app

from test_support.settings_pages import save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
ROWS = runtime.entries(catalog.S, catalog.C, catalog.Column)
_ENV = sorted({name for s in ROWS for name in s.env} | {
    "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
    "MAVERICK_TOOL_CACHE", "MAVERICK_ENTERPRISE", "MAVERICK_REQUIRE_CONTAINER_BACKEND",
    "MAVERICK_CONTAINMENT", "MAVERICK_REVIEW_CHECKPOINT_DOLLARS",
    "MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS", "MAVERICK_CONSENT_MODE",
})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _save(changes, confirm=True):
    from maverick import config

    r = save_catalog(client, API, json={"changes": changes, "confirm": confirm})
    config.reset_config_cache()
    return r


def _set(setting_id, value):
    r = _save([{"id": setting_id, "value": value}])
    assert r.status_code == 200, r.text


# ----------------------------------------------------------- memory and tools
def test_learning_cache_setting_reuses_a_checked_answer(monkeypatch):
    from maverick import orchestrator
    from maverick.cache import learning
    from maverick_dashboard.app import _world

    learning.reset_shared()
    world = _world()
    goal = world.get_goal(world.create_goal("Build the app", "", owner="ada"))
    orchestrator._maybe_store_learning_cache(goal, "run make -j test", 0.9)
    assert orchestrator._maybe_learning_cache_block(goal, None) is None  # off: today

    _set("memory.learning_cache", True)
    assert learning.enabled() is True
    orchestrator._maybe_store_learning_cache(goal, "run make -j test", None)  # not checked
    assert orchestrator._maybe_learning_cache_block(goal, None) is None
    orchestrator._maybe_store_learning_cache(goal, "run make -j test", 0.9)
    block = orchestrator._maybe_learning_cache_block(goal, None)
    assert block and "run make -j test" in block and "untrusted" in block
    other = types.SimpleNamespace(id=8, owner="bob", title="Build the app", description="")
    assert orchestrator._maybe_learning_cache_block(other, None) is None  # per person

    monkeypatch.setenv("MAVERICK_LEARNING_CACHE", "0")
    assert learning.enabled() is False  # the environment still wins
    learning.reset_shared()


def _counting_registry():
    from maverick.tools import Tool, ToolRegistry

    calls = []

    def read(args):
        calls.append(dict(args))
        return f"contents of {args['path']}"

    reg = ToolRegistry(principal="ada")
    reg.register(Tool(name="peek", description="read", input_schema={"type": "object"},
                      fn=read, parallel_safe=True))
    return reg, calls


def test_speculative_setting_warms_the_cache_the_real_call_reads(monkeypatch):
    from maverick import speculative_tools
    from maverick.agent import Agent
    from maverick.cache import tool as tool_cache

    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool_cache.reset()
    assert speculative_tools.enabled() is False  # unset: off, as today
    _set("tools.speculative", True)
    assert speculative_tools.enabled() is True

    reg, calls = _counting_registry()
    budget = types.SimpleNamespace(check=lambda: None)
    stub = types.SimpleNamespace(tools=reg, ctx=types.SimpleNamespace(budget=budget),
                                 _recent_tool_calls=[("peek", {"path": "a.txt"})] * 2)

    async def _turn():
        Agent._maybe_speculate_reads(stub)
        await asyncio.gather(*list(stub._speculation_futures))

    asyncio.run(_turn())
    assert calls == [{"path": "a.txt"}]  # read ahead once
    out = asyncio.run(reg.run("peek", {"path": "a.txt"}))
    assert out == "contents of a.txt" and len(calls) == 1  # served from the cache

    monkeypatch.setenv("MAVERICK_SPECULATIVE_TOOLS", "0")
    assert speculative_tools.enabled() is False  # the environment still wins
    tool_cache.reset()


def test_speculation_stops_when_the_budget_is_spent(monkeypatch):
    from maverick.cache import tool as tool_cache

    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool_cache.reset()
    reg, calls = _counting_registry()
    report = reg.speculate_reads([("peek", {"path": "b.txt"})], budget_guard=lambda: False)
    assert calls == [] and report.executed == []
    tool_cache.reset()


def test_energy_settings_change_the_estimate(monkeypatch):
    from maverick.tools.energy_accounting import _estimate

    assert "energy=0.3000 Wh" in _estimate({"tokens": 1000})  # built-in figure
    _set("energy.wh_per_1k_tokens", 2.0)
    _set("energy.grid_co2_g_per_kwh", 100.0)
    out = _estimate({"tokens": 1000})
    assert "energy=2.0000 Wh" in out and "grid: 100 gCO2e/kWh" in out
    monkeypatch.setenv("MAVERICK_ENERGY_WH_PER_1K_TOKENS", "1")
    assert "energy=1.0000 Wh" in _estimate({"tokens": 1000})


def test_crash_log_setting_adds_a_crash_safe_sink(monkeypatch):
    import logging

    from maverick import logging_config
    from maverick.crash_only_log import replay

    assert logging_config._crash_only_handler() is None  # off by default
    _set("logging.crash_log", True)
    _set("logging.crash_only_fsync", "never")
    handler = logging_config._crash_only_handler()
    assert handler is not None and handler._sink._fsync is False
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "disk full", (), None)
    for flt in handler.filters:
        flt.filter(record)
    handler.emit(record)
    rows = replay(logging_config.crash_log_path()).records
    assert rows and rows[-1]["msg"] == "disk full"
    monkeypatch.setenv("MAVERICK_CRASH_LOG", "0")
    assert logging_config._crash_only_handler() is None  # the environment still wins


# --------------------------------------------------------------- background
def test_background_program_settings_decide_what_starts(monkeypatch):
    from maverick import profiling_daemon
    from maverick_dashboard import background_programs as bp

    assert [k for k in bp.KINDS if bp.wanted(k)] == []  # nothing starts by default
    started = []
    monkeypatch.setattr(bp, "start", lambda kind: started.append(kind))
    _set("perf.profiling.enabled", True)
    _set("perf.profiling.interval_seconds", 60)
    _set("ebpf_monitor.enable", True)
    _set("model_proxy.enable", True)
    assert bp.start_enabled() == ["profiling", "ebpf_monitor", "model_proxy"]
    assert started == ["profiling", "ebpf_monitor", "model_proxy"]
    cfg = profiling_daemon.config_from_env()
    assert cfg.enabled and cfg.interval_seconds == 60
    monkeypatch.setenv("MAVERICK_PROFILING", "0")
    assert bp.wanted("profiling") is False  # the environment still wins
    assert bp.command("ebpf_monitor")[1:4] == ["-m", "maverick.ebpf_monitor", "run"]
    assert str(os.getpid()) in bp.command("profiling")


def test_background_program_is_supervised_and_stopped(monkeypatch):
    from maverick_dashboard import background_programs as bp
    from maverick_dashboard import service_supervisor

    # The dashboard's single child-program registry runs it.
    monkeypatch.setattr(service_supervisor, "command", lambda kind: [
        sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(60)"])
    state = bp.start("model_proxy")
    try:
        assert state["running"] is True
        assert bp.start("model_proxy")["running"] is True  # one instance per kind
        deadline = time.monotonic() + 10
        while "ready" not in bp.status()[2]["log"] and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "ready" in bp.status()[2]["log"]
        assert bp.alive() is True
    finally:
        bp.stop_all(timeout=2.0)
    assert bp.alive() is False
    assert bp.status()[2]["running"] is False


def test_model_proxy_reads_its_saved_settings(monkeypatch):
    from maverick import model_proxy

    _set("model_proxy.upstream", "https://api.anthropic.com")
    _set("model_proxy.listen", "127.0.0.1:9876")
    _set("model_proxy.auth_style", "x-api-key")
    _set("model_proxy.client_token", "proxy-pass-123")
    cfg = model_proxy.config_from_env()
    assert (cfg.upstream, cfg.listen_port, cfg.auth_style, cfg.client_token) == (
        "https://api.anthropic.com", 9876, "x-api-key", "proxy-pass-123")
    monkeypatch.setenv("MAVERICK_PROXY_UPSTREAM", "https://gateway.example.com")
    assert model_proxy.config_from_env().upstream == "https://gateway.example.com"


# -------------------------------------------------------------- terminal view
def test_saved_keys_drive_the_terminal_view(monkeypatch):
    from maverick import keymap
    from maverick.monitor import MonitorKeys, decode_key

    _set("tui.keys", [{"name": "quit", "key": "x"}, {"name": "toggle_follow", "key": "p"}])
    view = MonitorKeys(keymap.resolve())
    assert view.press("x", 3) == "quit"
    assert view.press("q", 3) is None
    assert view.press("p", 3) == "toggle_follow" and view.follow is False
    assert view.press(decode_key("\x1b[B"), 3) == "focus_next" and view.focus == 0
    assert view.press(decode_key("\r"), 3) == "expand" and view.expanded == {0}
    monkeypatch.setenv("MAVERICK_TUI_KEYS", "quit=z")
    assert keymap.resolve()["quit"] == "z"  # the environment still wins


def test_clashing_keys_are_refused():
    r = _save([{"id": "tui.keys", "value": [{"name": "refresh", "key": "q"}]}])
    assert r.status_code == 400 and "share one key" in r.json()["message"]


# ----------------------------------------------------------- network policy
def _web_registry():
    """A registry as base_registry leaves it: an existing denial, then the posture."""
    from maverick.tools import ToolRegistry, _apply_network_posture

    reg = ToolRegistry()
    reg.set_acl(denied={"already_denied"})
    _apply_network_posture(reg)
    return reg


def test_blocked_network_policy_is_enforced():
    from maverick.sandbox import SandboxPolicyError, _offline_policy
    from maverick.sandbox.network_policy import work_area_offline
    from maverick.tenant.egress import egress_allowed

    assert egress_allowed("http_fetch", "example.com") is True  # unset: open, as today
    assert work_area_offline() is False
    r = _save([{"id": "security.network_policy", "value": "deny-all"}], confirm=False)
    assert r.status_code == 200  # tightening needs no confirmation
    from maverick import config

    config.reset_config_cache()
    assert egress_allowed("http_fetch", "example.com") is False
    reg = _web_registry()
    assert not reg._acl_allows("http_fetch") and not reg._acl_allows("web_search")
    assert reg._acl_allows("peek") and not reg._acl_allows("already_denied")
    assert work_area_offline() is True
    assert _offline_policy({}, "docker")["allow_network"] is False
    assert _offline_policy({}, "local")["require_container"] is True
    with pytest.raises(SandboxPolicyError):
        _offline_policy({}, "ssh")
    r = _save([{"id": "security.network_policy", "value": ""}], confirm=False)
    assert r.status_code == 409  # opening it again needs a confirmation


def test_approved_websites_policy_only_reaches_listed_hosts():
    from maverick.tenant.egress import egress_allowed

    _set("security.network_policy", "allowlist")
    assert egress_allowed("http_fetch", "api.example.com") is False  # nothing approved
    _set("egress.allow", ["api.example.com"])
    assert egress_allowed("http_fetch", "api.example.com") is True
    assert egress_allowed("http_fetch", "other.example.com") is False
    reg = _web_registry()
    assert reg._acl_allows("http_fetch") and not reg._acl_allows("web_search")


def test_work_area_network_policy_keeps_commands_offline():
    from maverick.sandbox.network_policy import work_area_offline
    from maverick.tenant.egress import egress_allowed

    _set("sandbox.network_policy", "deny-all")
    assert work_area_offline() is True
    assert egress_allowed("http_fetch", "example.com") is True  # web tools unaffected


def test_permissions_page_shows_the_enforced_policy():
    from maverick.sandbox.network_policy import network_posture

    assert network_posture({}) == "open"
    assert network_posture({"security": {"network_policy": "deny_all"}}) == "deny-all"
    assert network_posture({"security": {"network_policy": "restricted?"}}) == "deny-all"


# ------------------------------------------------------------- ekko, hunting
def test_ekko_provider_egress_is_refused_with_a_reason():
    r = _save([{"id": "ekko.provider_egress", "value": True}])
    assert r.status_code == 400
    assert "can't be turned on yet" in r.json()["message"]
    from maverick.config import get_ekko

    assert get_ekko()["provider_egress"] is False


def test_enrichment_sources_setting_turns_a_registered_source_on():
    from maverick_dashboard import security_api

    _set("env_hunt.enrichment_sources", [{"name": "intel_feed", "enable": True},
                                         {"name": "old_feed", "enable": False}])
    _providers, allowed = security_api._configured_environment_enrichment_providers()
    assert allowed == ("intel_feed",)


# ----------------------------------------------------- models and back ends
def _fake_weaviate(monkeypatch):
    from unittest.mock import MagicMock

    fake_client = MagicMock(name="client")
    fake_client.collections.exists.return_value = True
    module = MagicMock(name="weaviate")
    module.connect_to_custom.return_value = fake_client
    monkeypatch.setitem(sys.modules, "weaviate", module)
    return module


def test_weaviate_settings_reach_the_connection(monkeypatch):
    from maverick.vector_store.weaviate_store import WeaviateStore

    module = _fake_weaviate(monkeypatch)
    _set("memory.weaviate_grpc_host", "grpc.example.com")
    _set("memory.weaviate_grpc_port", 60051)
    _set("memory.weaviate_vectorizer", "text2vec-ollama")
    store = WeaviateStore(url="https://weaviate.example.com")
    kwargs = module.connect_to_custom.call_args.kwargs
    assert (kwargs["grpc_host"], kwargs["grpc_port"]) == ("grpc.example.com", 60051)
    assert store._vectorizer == "text2vec-ollama"
    monkeypatch.setenv("MAVERICK_WEAVIATE_GRPC_PORT", "50052")
    WeaviateStore(url="https://weaviate.example.com")
    assert module.connect_to_custom.call_args.kwargs["grpc_port"] == 50052


def test_embedding_and_sound_model_settings(monkeypatch):
    from maverick.tools.audio_understanding import clap_model_name
    from maverick.tools.embeddings import _default_model

    assert _default_model() == "BAAI/bge-small-en-v1.5"
    assert clap_model_name() == "laion/clap-htsat-unfused"
    _set("models.embed", "BAAI/bge-base-en-v1.5")
    _set("models.clap", "laion/larger_clap_general")
    assert _default_model() == "BAAI/bge-base-en-v1.5"
    assert clap_model_name() == "laion/larger_clap_general"
    monkeypatch.setenv("MAVERICK_EMBED_MODEL", "custom/model")
    assert _default_model() == "custom/model"


def test_recording_settings_turn_run_traces_on(monkeypatch, tmp_path):
    from maverick.paths import data_dir
    from maverick.replay.trace import goal_trace_path, trace_dir

    assert trace_dir() is None and goal_trace_path(3) is None  # off by default
    _set("replay.record", True)
    assert trace_dir() == Path(data_dir("traces"))
    folder = tmp_path / "recordings"
    folder.mkdir()
    _set("replay.trace_dir", str(folder))
    assert goal_trace_path(3) == folder / "goal-3.jsonl"
    monkeypatch.setenv("MAVERICK_TRACE_DIR", str(tmp_path / "env"))
    assert trace_dir() == tmp_path / "env"  # the environment still wins


def test_task_questions_switch_and_plain_missing_message(monkeypatch):
    from maverick_dashboard import insight_ops_api

    data = client.get("/api/v1/analytics/choices").json()
    assert data["turned_on"] is True
    monkeypatch.setattr(insight_ops_api, "_available", lambda: False)
    data = client.get("/api/v1/analytics/choices").json()
    assert data["available"] is False and "DuckDB add-on" in data["reason"]
    _set("analytics.task_questions", False)
    data = client.get("/api/v1/analytics/choices").json()
    assert data["available"] is False and data["turned_on"] is False
    assert "turned off" in data["reason"]
    r = client.post("/api/v1/analytics/ask", json={"metric": "spend"})
    assert r.status_code == 403


def test_skill_install_switch_reaches_the_tools_page():
    from maverick_dashboard import tools_ops_api

    assert tools_ops_api._install_allowed() is False
    _set("skills.allow_url_install", True)
    assert tools_ops_api._install_allowed() is True


def test_director_profiles_setting_shapes_a_director_run(monkeypatch):
    from maverick import director_mode
    from maverick.cli import _apply_director

    _set("director.profiles", [{"name": "supervised", "consent_mode": "dashboard",
                                "budget_multiplier": 3.0, "dollars": 5, "tool_calls": 50}])
    run = director_mode.direct("Close the books", profile="supervised", base_max_dollars=10.0)
    assert run.consent_mode == "dashboard"
    assert run.checkpoint == {"dollars": 5.0, "tool_calls": 50}
    assert run.max_dollars == 30.0
    for name in ("MAVERICK_CONSENT_MODE", "MAVERICK_REVIEW_CHECKPOINT_DOLLARS",
                 "MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS"):
        monkeypatch.setenv(name, "placeholder")  # restored after the test
    monkeypatch.setattr("maverick.runner.configured_max_dollars", lambda: 12.0)
    monkeypatch.setattr("maverick.runner.configured_goal_ceiling_dollars", lambda: 12.0)
    title, description, cap = _apply_director("supervised", "Close the books", "", 10.0)
    assert cap == 12.0  # never above the configured spending cap
    assert os.environ["MAVERICK_CONSENT_MODE"] == "dashboard"
    assert title == "Close the books" and description.startswith("Outcome:")


def test_declared_plugin_requirements_are_checked_against_the_grant():
    from maverick import plugins
    from maverick.plugin_manifest import parse_dict

    manifest = parse_dict({"plugin": {"name": "acme", "version": "1.0", "api": 2},
                           "capabilities": {"requires": ["net:egress", "tool:http_fetch"]}})
    assert manifest.permissions.network is True
    assert manifest.permissions.requires == ["tool:http_fetch"]
    _set("plugins.grant", ["network"])
    granted, enforce = plugins._permission_policy()
    assert enforce is True
    assert plugins._permission_violations(manifest, granted) == ["tool:http_fetch"]


# ------------------------------------------------------------ startup limits
def test_startup_limits_are_read_from_settings(monkeypatch):
    from maverick import agent, attachments, compaction, retry, runner, verifier
    from maverick.providers import openai_provider
    from maverick.tools import openapi_runner, spawn

    assert agent._loop_guard_settings() == (True, 3, 6)  # built-in values
    changes = {
        "agent.loop_guard": False, "agent.loop_guard_threshold": 4,
        "agent.loop_guard_block": 9, "agent.step_budget_warning": 5,
        "agent.max_concurrent_goals": 20, "agent.max_concurrent_goals_per_principal": 2,
        "latency.retry_attempts": 2, "latency.retry_base_delay": 0.5,
        "latency.retry_max_delay": 10, "swarm.max_fanout": 4, "swarm.default_max_depth": 2,
        "verification.confidence_accept": 0.9, "verification.disagreement_high": 0.4,
        "compaction.keep_recent": 6, "attachments.max_file_bytes": 10,
        "tools.openapi_spec_max_bytes": 5, "models.openai_max_tools": 64,
    }
    r = _save([{"id": k, "value": v} for k, v in changes.items()])
    assert r.status_code == 200, r.text
    assert agent._loop_guard_settings() == (False, 4, 9)
    assert agent._step_budget_warning_setting() == 5
    assert runner._concurrency_settings() == (20, 2)
    assert retry._retry_settings() == (2, 0.5, 10.0)
    assert spawn._max_fanout_setting() == 4 and runner._default_max_depth_setting() == 2
    assert verifier._threshold_settings() == (0.4, 0.9)
    assert compaction._env_int("MAVERICK_COMPACT_KEEP_RECENT", 4, "keep_recent") == 6
    assert attachments._env_int("MAVERICK_ATTACH_MAX_FILE_BYTES", 1, "max_file_bytes") \
        == 10 * 1048576
    assert openapi_runner._limit_setting("MAVERICK_OPENAPI_SPEC_MAX_BYTES",
                                         "openapi_spec_max_bytes", 1) == 5_000_000
    assert openai_provider._max_tools_setting() == 64
    monkeypatch.setenv("MAVERICK_LOOP_GUARD", "1")
    monkeypatch.setenv("MAVERICK_LLM_RETRY_ATTEMPTS", "5")
    assert agent._loop_guard_settings()[0] is True  # the environment still wins
    assert retry._retry_settings()[0] == 5


# ---------------------------------------------------------------- tool server
def test_tool_server_reads_the_mcp_section(monkeypatch):
    from maverick_mcp import http_transport, server
    from maverick_mcp.settings import mcp_setting
    from maverick_mcp.tasks import TaskStore

    assert http_transport._max_body_bytes() == 2 * 1024 * 1024  # built-in value
    r = _save([{"id": "mcp.max_body_bytes", "value": 4096},
               {"id": "mcp.rate_limit", "value": 30},
               {"id": "mcp.allowed_origins", "value": ["https://gateway.example.com"]},
               {"id": "mcp.http_tasks", "value": True},
               {"id": "mcp.token", "value": "shared-pass-456"},
               {"id": "mcp.elicitation_timeout", "value": 60},
               {"id": "mcp.max_tasks", "value": 10},
               {"id": "mcp.task_workers", "value": 2}])
    assert r.status_code == 200, r.text
    assert http_transport._max_body_bytes() == 4096 * 1024
    assert http_transport._rate_limit_per_min() == 30
    assert http_transport._allowed_origins() == {"https://gateway.example.com"}
    assert http_transport._http_tasks_enabled() is True
    assert mcp_setting("token") == "shared-pass-456"
    assert server._elicit_timeout() == 60.0
    store = TaskStore(lambda *a, **k: {})
    try:
        assert store._max_tasks == 10 and store._executor._max_workers == 2
    finally:
        store.shutdown()
    monkeypatch.setenv("MAVERICK_MCP_RATE_LIMIT", "5")
    assert http_transport._rate_limit_per_min() == 5  # the environment still wins


# --------------------------------------------------- director runs (dashboard)
@pytest.fixture
def start_env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    world = world_model.WorldModel(world_model.DEFAULT_DB)
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr("maverick_dashboard.api._world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr("maverick_dashboard.api.require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request, **_: None)
    monkeypatch.setattr("maverick.runner.configured_max_dollars", lambda: 10.0)
    monkeypatch.setattr("maverick.runner.configured_goal_ceiling_dollars", lambda: 10.0)
    calls = []

    async def run(goal_id, *args, **kwargs):
        calls.append((goal_id, args, kwargs))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    _set("director.profiles", [{"name": "semi", "consent_mode": "dashboard",
                                "budget_multiplier": 0.5, "dollars": 3, "tool_calls": 30}])
    yield world, calls
    world.close()


def test_start_form_offers_the_configured_autonomy_levels(start_env):
    page = client.get("/chat").text
    assert 'name="director_profile"' in page
    assert "Partly on its own: waits on the Approvals page" in page


def test_dashboard_start_honours_the_director_profile(start_env):
    from maverick import director_mode, review_checkpoint
    from maverick.review_checkpoint import CheckpointPolicy
    from maverick.safety import consent

    world, calls = start_env
    r = client.post("/chat/send", data={"title": "Close the books", "description": "Q3 only",
                                        "director_profile": "semi"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    goal = world.list_goals()[0]
    assert goal.description.startswith("Outcome: Close the books") and "Q3 only" in goal.description
    (goal_id, _args, kwargs), = calls
    assert goal_id == goal.id and kwargs["max_dollars"] == 5.0  # 0.5 x the 10.0 cap
    env = director_mode.recorded_envelope(world, goal.id)
    assert env["consent_mode"] == "dashboard" and env["max_dollars"] == 5.0
    assert consent._resolve_mode("low") == "auto-approve"  # outside the run: as configured
    with director_mode.run_scope(env):
        assert consent._resolve_mode("low") == "dashboard"
        assert review_checkpoint.policy_from_config() == CheckpointPolicy(dollars=3.0,
                                                                          tool_calls=30)
    assert director_mode.spending_cap(env, 8.0) == 5.0
    assert director_mode.spending_cap(env, 2.0) == 2.0


def test_the_runner_applies_the_director_envelope(start_env, monkeypatch):
    from maverick import runner
    from maverick.safety import consent

    world, _calls = start_env
    r = client.post("/chat/send", data={"title": "Close the books", "director_profile": "semi"},
                    follow_redirects=False)
    assert r.status_code == 303, r.text
    goal = world.list_goals()[0]
    seen = {}

    def fake_run(llm, world_, budget, goal_id, **kwargs):
        from maverick.review_checkpoint import policy_from_config

        seen.update(max_dollars=budget.max_dollars, consent=consent._resolve_mode("low"),
                    checkpoint=policy_from_config().dollars)

    monkeypatch.setattr("maverick.orchestrator.run_goal_sync", fake_run)
    monkeypatch.setattr("maverick.llm.LLM", lambda *a, **k: object())
    monkeypatch.setattr("maverick.sandbox.build_sandbox", lambda *a, **k: None)
    monkeypatch.setattr(runner, "_runner_principal_binding", lambda *a: True)
    runner.run_goal_in_thread(goal.id, max_dollars=9.0)
    assert seen == {"max_dollars": 5.0, "consent": "dashboard", "checkpoint": 3.0}


def test_a_profile_never_loosens_the_installation_consent(start_env, monkeypatch):
    from maverick import director_mode
    from maverick.safety import consent

    _set("safety.consent_mode", "ask")
    with director_mode.run_scope({"profile": "autonomous", "consent_mode": "auto-approve"}):
        assert consent._resolve_mode("low") == "ask"
    with consent.task_consent_mode("dashboard"):
        assert consent._resolve_mode("critical") == "ask"  # "ask" is stricter here
    with consent.task_consent_mode("auto-deny"):
        assert consent._resolve_mode("low") == "auto-deny"  # tightening is allowed
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    with consent.task_consent_mode("dashboard"):
        assert consent._resolve_mode("low") == "auto-deny"  # the environment is the ceiling
    with consent.task_consent_mode("no-such-mode"):
        assert consent._TASK_MODE.get() == "ask"  # an unknown level asks a person


def test_api_start_applies_the_profile_budget_and_refuses_unknown_levels(start_env):
    from maverick import director_mode

    world, calls = start_env
    r = client.post("/api/v1/goals", json={"title": "Close the books", "max_dollars": 4.0,
                                           "director_profile": "semi"})
    assert r.status_code == 201, r.text
    goal_id = r.json()["id"]
    (called_id, args, _kwargs), = calls
    assert called_id == goal_id and args[0] == 2.0  # 0.5 x the requested 4.0
    assert director_mode.recorded_envelope(world, goal_id)["profile"] == "semi"
    r = client.post("/api/v1/goals", json={"title": "x", "director_profile": "reckless"})
    assert r.status_code == 400 and "autonomy levels" in r.json()["detail"]
    r = client.post("/chat/send", data={"title": "x", "director_profile": "reckless"},
                    follow_redirects=False)
    assert r.status_code == 400


# ------------------------------------------------- AI cost collection limits
def test_cost_collection_limits_reach_the_collector():
    from maverick.ai_cost_collectors import configured_collector_limits
    from maverick.config import load_config

    before = configured_collector_limits({})
    assert (before.page_cap, before.record_cap, before.page_size, before.timeout_seconds) \
        == (20, 1000, 200, 20.0)
    r = _save([{"id": "ai_cost_roi.collector_limits.page_cap", "value": 5},
               {"id": "ai_cost_roi.collector_limits.record_cap", "value": 300},
               {"id": "ai_cost_roi.collector_limits.page_size", "value": 50},
               {"id": "ai_cost_roi.collector_limits.timeout_seconds", "value": 10}],
              confirm=False)
    assert r.status_code == 200, r.text  # lowering needs no confirmation
    limits = configured_collector_limits(load_config().get("ai_cost_roi") or {})
    assert (limits.page_cap, limits.record_cap, limits.page_size, limits.timeout_seconds) \
        == (5, 300, 50, 10.0)
    r = _save([{"id": "ai_cost_roi.collector_limits.page_cap", "value": 40}], confirm=False)
    assert r.status_code == 409  # raising a limit needs a confirmation
    r = _save([{"id": "ai_cost_roi.collector_limits.page_cap", "value": 51}])
    assert r.status_code == 400  # beyond what the collector accepts


def test_supervised_log_normalizes_split_crlf_without_removing_meaningful_spaces():
    from maverick_dashboard import service_supervisor as supervisor

    service = supervisor.Service("model_proxy")
    pending = supervisor._take_lines(service, b"", b"  ready  \r")
    assert list(service.log) == []
    pending = supervisor._take_lines(service, pending, b"\nnext\n")
    assert pending == b""
    assert list(service.log) == ["  ready  ", "next"]
