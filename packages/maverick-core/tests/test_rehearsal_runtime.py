"""Live rehearsal wiring: build a world-model from the captured Operating Record
and gate a tool on it -- proceeding on good history, holding on bad, and staying
fail-open when disabled or data-less.
"""
from __future__ import annotations

import threading

from maverick import rehearsal as rh
from maverick import rehearsal_runtime as rt
from maverick.trajectory_store import TrajectoryStep, TrajectoryStore


def _store(tmp_path, outcome):
    """A store where role=coder runs `shell` in domain=ops, then finishes with
    the given terminal outcome -- 6 episodes so support clears the floor."""
    store = TrajectoryStore(path=tmp_path / "t.ndjson")
    for e in range(6):
        store.record(TrajectoryStep(ts=1.0, goal_id=1, episode_id=e, step=0,
                                    role="coder", tool="shell", domain="ops"))
        store.record(TrajectoryStep(ts=1.0, goal_id=1, episode_id=e, step=1,
                                    role="coder", tool="", domain="ops", is_final=True,
                                    outcome=outcome))
    return store


def test_encode_state_is_general_to_specific():
    assert rt.encode_state("ops", "coder", "shell") == ("ops", "coder", "shell")
    assert rt.encode_state(None, None, None) == ("", "", "")


def test_gate_tool_fail_open_when_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_REHEARSAL", raising=False)
    monkeypatch.setattr("maverick.rehearsal._settings", lambda: dict(rh._DEFAULTS))
    rt.reset_cache()
    v = rt.gate_tool(domain="ops", role="coder", last_tool="", tool_name="shell")
    assert v.decision == rh.PROCEED and "disabled" in v.reason


def test_gate_tool_fail_open_when_no_data(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    monkeypatch.setattr("maverick.trajectory_store.shared",
                        lambda: TrajectoryStore(path=tmp_path / "empty.ndjson"))
    rt.reset_cache()
    v = rt.gate_tool(domain="ops", role="coder", last_tool="", tool_name="shell")
    assert v.decision == rh.PROCEED and "no world-model" in v.reason


def test_gate_tool_proceeds_on_good_history(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: _store(tmp_path, 0.9))
    rt.reset_cache()
    v = rt.gate_tool(domain="ops", role="coder", last_tool="", tool_name="shell")
    assert v.decision == rh.PROCEED and v.known
    assert v.predicted_outcome > 0.7


def test_gate_tool_holds_on_bad_history(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: _store(tmp_path, 0.05))
    rt.reset_cache()
    v = rt.gate_tool(domain="ops", role="coder", last_tool="", tool_name="shell")
    assert v.decision == rh.BLOCK and v.predicted_outcome < 0.3


def test_old_refused_calls_do_not_train_rehearsal_as_executed(tmp_path, monkeypatch):
    store = TrajectoryStore(path=tmp_path / "history.ndjson")
    for episode in range(6):
        store.record(TrajectoryStep(
            ts=1.0, goal_id=1, episode_id=episode, step=0,
            role="coder", tool="shell", domain="ops",
            tool_succeeded=False,  # old refusal: execution was not recorded
        ))
        store.record(TrajectoryStep(
            ts=1.0, goal_id=1, episode_id=episode, step=1,
            role="coder", domain="ops", is_final=True, outcome=0.0,
        ))
    for episode in range(6, 12):
        store.record(TrajectoryStep(
            ts=1.0, goal_id=1, episode_id=episode, step=0,
            role="coder", tool="shell", domain="ops",
            tool_succeeded=False, tool_executed=True,
        ))
        store.record(TrajectoryStep(
            ts=1.0, goal_id=1, episode_id=episode, step=1,
            role="coder", domain="ops", is_final=True, outcome=0.9,
        ))
    store.record(TrajectoryStep(
        ts=1.0, goal_id=1, episode_id=12, step=0,
        role="coder", tool="shell", domain="ops",
        tool_succeeded=True, tool_executed=False,
    ))
    store.record(TrajectoryStep(
        ts=1.0, goal_id=1, episode_id=12, step=1,
        role="coder", domain="ops", is_final=True, outcome=0.0,
    ))
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: store)
    rt.reset_cache()

    model = rt.world_model()

    assert model is not None
    assert model.support(("ops", "coder", ""), "shell") == 6


def test_model_cache_rebuilds_when_trajectory_source_changes(tmp_path, monkeypatch):
    """A tenant/store switch must not reuse another source's fitted verdict."""
    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    bad_store = _store(tmp_path / "tenant-a", 0.05)
    good_store = _store(tmp_path / "tenant-b", 0.9)
    assert bad_store.count() == good_store.count() < rt._REFRESH_EVERY

    active = {"store": bad_store}
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: active["store"])
    rt.reset_cache()

    first = rt.gate_tool(domain="ops", role="coder", last_tool="", tool_name="shell")
    assert first.decision == rh.BLOCK and first.predicted_outcome < 0.3

    active["store"] = good_store
    second = rt.gate_tool(domain="ops", role="coder", last_tool="", tool_name="shell")
    assert second.decision == rh.PROCEED and second.predicted_outcome > 0.7


def test_model_cache_reuses_source_after_tenant_round_trip(tmp_path, monkeypatch):
    """A -> B -> A remains isolated without refitting A on its return."""
    bad_store = _store(tmp_path / "tenant-a", 0.05)
    good_store = _store(tmp_path / "tenant-b", 0.9)
    active = {"store": bad_store}
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: active["store"])

    original_build = rt._build_model
    builds = []

    def counted_build(store=None):
        builds.append(store.path)
        return original_build(store)

    monkeypatch.setattr(rt, "_build_model", counted_build)
    rt.reset_cache()

    first_a = rt.world_model()
    active["store"] = good_store
    model_b = rt.world_model()
    active["store"] = bad_store
    second_a = rt.world_model()

    assert first_a is second_a
    assert model_b is not first_a
    assert builds.count(bad_store.path) == 1
    assert builds.count(good_store.path) == 1


def test_model_cache_invalidates_immediately_when_source_shrinks(tmp_path, monkeypatch):
    """Erased trajectory evidence must stop influencing rehearsal immediately."""
    store = _store(tmp_path / "tenant-a", 0.05)
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: store)
    rt.reset_cache()

    assert rt.world_model() is not None
    original_count = store.count()
    assert 0 < original_count < rt._REFRESH_EVERY

    store.path.write_text("", encoding="utf-8")
    assert store.count() == 0
    assert rt.world_model() is None


def test_different_sources_build_concurrently(tmp_path, monkeypatch):
    """A slow tenant fit must not hold the global cache map lock."""
    stores = {
        "a": TrajectoryStore(path=tmp_path / "tenant-a" / "t.ndjson"),
        "b": TrajectoryStore(path=tmp_path / "tenant-b" / "t.ndjson"),
    }
    active = threading.local()
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: active.store)

    rendezvous = threading.Barrier(2)

    def concurrent_build(store=None):
        rendezvous.wait(timeout=5)
        return store.path

    monkeypatch.setattr(rt, "_build_model", concurrent_build)
    rt.reset_cache()
    results = {}

    def worker(name):
        active.store = stores[name]
        results[name] = rt.world_model()

    threads = [threading.Thread(target=worker, args=(name,)) for name in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not any(thread.is_alive() for thread in threads)
    assert results == {name: store.path for name, store in stores.items()}


def test_model_cache_is_bounded(tmp_path, monkeypatch):
    stores = [
        TrajectoryStore(path=tmp_path / f"tenant-{i}" / "t.ndjson")
        for i in range(rt._MAX_CACHE_SOURCES + 3)
    ]
    active = {"store": stores[0]}
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: active["store"])
    monkeypatch.setattr(rt, "_build_model", lambda store=None: store.path)
    rt.reset_cache()

    for store in stores:
        active["store"] = store
        assert rt.world_model() == store.path

    assert len(rt._cache) == rt._MAX_CACHE_SOURCES


def test_build_model_generalises_across_role(tmp_path, monkeypatch):
    # The backoff model lets a NEW role in a known domain still be vouched for
    # (generalises over the trailing feature) rather than escalating blindly.
    monkeypatch.setattr("maverick.trajectory_store.shared", lambda: _store(tmp_path, 0.9))
    rt.reset_cache()
    model = rt._model()
    assert model is not None
    # exact context known; novel last_tool within the same (domain, role) backs off
    assert model.support(("ops", "coder", "novel_prev"), "shell") >= 3
