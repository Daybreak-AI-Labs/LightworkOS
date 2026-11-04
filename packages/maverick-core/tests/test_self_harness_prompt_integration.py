"""Self-harness CONSUMER side: the learned addendum must actually reach the
agent's system prompt.

Everything else tests the producer/store (mine -> propose -> validate -> gate).
This tests the delivery point -- Agent._build_system recalling the addendum --
which is what makes the feature do anything. It caught a real init-ordering bug:
self.system was built BEFORE self.model was assigned, so the addendum's
recall_addendum(self.model) raised AttributeError, was swallowed, and the
learned guidance was silently dropped from every prompt.
"""
from __future__ import annotations

import pytest
from maverick import self_harness as sh
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


def _write_shared_fixture(blocks, path):
    """Publish synthetic local guidance with explicit source metadata."""
    sh._write_addenda(blocks, path)
    meta = sh.load_line_meta(path)
    for model, block in blocks.items():
        for line in sh._bullets(block):
            sh._upsert_line_meta(meta, model, line, {"source_goal_ids": [0]}, now=1)
    sh._write_line_meta(meta, path)

_BLOCK = "Operating guidance learned for this model:\n- ALWAYS verify the export window first"
_NEEDLE = "verify the export window first"


@pytest.fixture
def ctx(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("g", "")
    return SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=1, use_skills=False)


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: p)
    return p


def _agent(ctx, model):
    return Agent(ctx=ctx, role="orchestrator", brief="do a thing", model_override=model)


def test_addendum_reaches_system_prompt(ctx, store, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_fixture({"model-x": _BLOCK}, store)
    agent = _agent(ctx, "model-x")
    assert agent.model == "model-x"
    assert _NEEDLE in agent.system          # the learned guidance is in the prompt


def test_model_resolved_before_build_system(ctx, store, monkeypatch):
    # Regression for the init-ordering bug: if self.model weren't set before
    # _build_system ran, the addendum would be silently dropped here.
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_fixture({"model-x": _BLOCK}, store)
    agent = _agent(ctx, "model-x")
    assert hasattr(agent, "model") and agent.model == "model-x"
    assert _NEEDLE in agent.system


def test_cross_model_isolation_in_prompt(ctx, store, monkeypatch):
    # An addendum for model-x must NOT leak into model-y's prompt.
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_fixture({"model-x": _BLOCK}, store)
    assert _NEEDLE in _agent(ctx, "model-x").system
    assert _NEEDLE not in _agent(ctx, "model-y").system


def test_disabled_keeps_prompt_unchanged(ctx, store, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "0")
    monkeypatch.setattr("maverick.config.load_config", dict)
    _write_shared_fixture({"model-x": _BLOCK}, store)
    assert _NEEDLE not in _agent(ctx, "model-x").system     # off -> not injected


def test_no_addendum_for_model_is_noop(ctx, store, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_fixture({"some-other-model": _BLOCK}, store)
    # The agent's model has no entry -> prompt is unchanged, no error.
    assert _NEEDLE not in _agent(ctx, "model-x").system


def test_recall_failure_is_fail_safe(ctx, store, monkeypatch):
    # A broken recall must never block agent construction; the prompt degrades
    # to the base (no addendum), not a crash.
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_fixture({"model-x": _BLOCK}, store)

    def _boom(*a, **k):
        raise RuntimeError("recall blew up")

    # The agent recalls through recall_addendum_with_sources (the guidance and
    # its permitted sources together); break both public entry points.
    monkeypatch.setattr(sh, "recall_addendum", _boom)
    monkeypatch.setattr(sh, "recall_addendum_with_sources", _boom)
    agent = _agent(ctx, "model-x")          # must not raise
    assert _NEEDLE not in agent.system


def test_addendum_appended_not_replacing_base(ctx, store, monkeypatch):
    # The addendum AUGMENTS the system prompt -- the base instructions remain.
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    base_only = _agent(ctx, "model-y").system      # no entry for model-y
    _write_shared_fixture({"model-x": _BLOCK}, store)
    with_addendum = _agent(ctx, "model-x").system
    assert with_addendum.startswith(base_only[:200])   # base preserved as prefix
    assert _NEEDLE in with_addendum and len(with_addendum) > len(base_only)
