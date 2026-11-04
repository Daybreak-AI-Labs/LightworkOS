"""Cluster-wide killswitch: a halt armed in the shared world store
propagates to every replica's killswitch, not just the one that served the
arm request. On the default SQLite (single-host) backend the shared consult is
skipped -- the local HALT file already covers it and a per-call DB read would be
hot-path cost for no benefit.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

import pytest
from maverick import killswitch, world_model


@pytest.fixture
def world(monkeypatch, tmp_path):
    db = Path(tempfile.mkdtemp()) / "w.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    w = world_model.WorldModel(db)
    # Isolate the local HALT file to a clean path so a sibling test's file (or its
    # cached presence) can't make check() raise with the file source instead of
    # the cluster source we're asserting.
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    # Reset killswitch module state between tests (file cache + shared throttle
    # cache + handle + in-process flag).
    killswitch._last_file_check_ts = 0.0
    killswitch._last_file_present = False
    killswitch._last_shared_check_ts = 0.0
    killswitch._last_shared_halt = None
    killswitch._shared_world = None
    killswitch.clear()
    yield w
    # ...and after: a cached cluster halt is served for up to 2 s without
    # re-reading the backend, so leaving one behind halted whichever test the
    # same worker ran next (the intermittent "DID NOT RAISE" lifecycle failures).
    killswitch._last_shared_check_ts = 0.0
    killswitch._last_shared_halt = None
    killswitch._shared_world = None
    killswitch.clear()


def test_world_halt_roundtrip(world):
    assert world.active_halt() is None
    world.arm_halt("budget blown", source="dashboard", armed_by="user:alice")
    st = world.active_halt()
    assert st["reason"] == "budget blown"
    assert st["source"] == "dashboard"
    assert st["armed_by"] == "user:alice"
    assert isinstance(st["armed_at"], (int, float))
    assert isinstance(st["generation"], str) and st["generation"]
    # Re-arm replaces the single global row (no duplicate).
    world.arm_halt("second reason", source="cli")
    latest = world.active_halt()
    assert latest["reason"] == "second reason"
    assert latest["generation"] != st["generation"]
    assert world.disarm_halt(expected_generation=latest["generation"]) is True
    assert world.active_halt() is None


def test_world_halt_compare_and_delete_preserves_concurrent_rearm(world):
    world.arm_halt("first", source="dashboard")
    first = world.active_halt()
    world.arm_halt("new incident", source="dashboard")
    second = world.active_halt()

    assert first["generation"] != second["generation"]
    assert world.disarm_halt(expected_generation=first["generation"]) is False
    assert world.active_halt() == second


def test_world_halt_callback_failure_rolls_back_shared_clear(world):
    world.arm_halt("incident", source="dashboard")
    observed = world.active_halt()
    callbacks = []

    def _local_clear_failure():
        callbacks.append("attempted")
        raise OSError("local authority unavailable")

    with pytest.raises(OSError, match="local authority unavailable"):
        world.disarm_halt(
            expected_generation=observed["generation"],
            durable_clear=_local_clear_failure,
        )

    assert callbacks == ["attempted"]
    assert world.active_halt() == observed


def test_world_halt_mismatch_does_not_run_durable_clear(world):
    world.arm_halt("first", source="dashboard")
    first = world.active_halt()
    world.arm_halt("new incident", source="dashboard")
    second = world.active_halt()
    callbacks = []

    assert world.disarm_halt(
        expected_generation=first["generation"],
        durable_clear=lambda: callbacks.append("unsafe"),
    ) is False
    assert callbacks == []
    assert world.active_halt() == second


def test_clear_transition_holds_are_exact_owner_and_preserve_concurrent_halt(
    world,
):
    first = killswitch._begin_clear_transition_hold()
    second = killswitch._begin_clear_transition_hold()
    try:
        with pytest.raises(killswitch.Halted) as held:
            killswitch.check(force_refresh=True)
        assert held.value.source == "control-plane-clear"

        killswitch.clear()
        with pytest.raises(killswitch.Halted):
            killswitch.check(force_refresh=True)

        killswitch._end_clear_transition_hold(first)
        with pytest.raises(killswitch.Halted):
            killswitch.check(force_refresh=True)

        killswitch.halt("new incident", source="concurrent-arm")
        killswitch._end_clear_transition_hold(second)
        with pytest.raises(killswitch.Halted) as concurrent:
            killswitch.check(force_refresh=True)
        assert concurrent.value.reason == "new incident"
        assert concurrent.value.source == "concurrent-arm"
    finally:
        for token in (first, second):
            try:
                killswitch._end_clear_transition_hold(token)
            except killswitch.HaltGenerationChanged:
                pass
        killswitch.clear()


def test_shared_consult_skipped_on_sqlite(world):
    world.arm_halt("stop", source="dashboard")
    with mock.patch(
        "maverick.world_model_backends.is_postgres_configured", return_value=False
    ):
        killswitch._last_shared_check_ts = 0.0
        assert killswitch._shared_halt_active() is None  # not consulted on SQLite


def test_check_raises_on_shared_halt_when_postgres(world):
    world.arm_halt("cluster stop", source="dashboard")
    with mock.patch(
        "maverick.world_model_backends.is_postgres_configured", return_value=True
    ), mock.patch("maverick.world_model.open_world", return_value=world):
        killswitch._last_shared_check_ts = 0.0
        with pytest.raises(killswitch.Halted) as ei:
            killswitch.check()
        assert ei.value.reason == "cluster stop"


def test_shared_halt_throttled(world):
    # Within the throttle window the cached value is returned without re-querying.
    world.arm_halt("x", source="dashboard")
    calls = {"n": 0}

    class _Probe:
        def active_halt(self):
            calls["n"] += 1
            return {"reason": "x", "source": "dashboard", "armed_by": "", "armed_at": 1.0}

    with mock.patch(
        "maverick.world_model_backends.is_postgres_configured", return_value=True
    ), mock.patch("maverick.world_model.open_world", return_value=_Probe()):
        killswitch._last_shared_check_ts = 0.0
        killswitch._shared_world = None
        killswitch._shared_halt_active(min_interval=1000.0)
        killswitch._shared_halt_active(min_interval=1000.0)  # cached, no 2nd query
        assert calls["n"] == 1


def test_shared_consult_fails_open(world):
    # A shared-store error must not wedge the run: _shared_halt_active swallows it.
    with mock.patch(
        "maverick.world_model_backends.is_postgres_configured", return_value=True
    ), mock.patch("maverick.world_model.open_world", side_effect=RuntimeError("db down")):
        killswitch._last_shared_check_ts = 0.0
        killswitch._shared_world = None
        assert killswitch._shared_halt_active() is None  # fail-open, no raise


def test_shared_consult_fails_closed_for_privileged_callers(world):
    with mock.patch(
        "maverick.world_model_backends.is_postgres_configured", return_value=True
    ), mock.patch(
        "maverick.world_model.open_world", side_effect=RuntimeError("db down")
    ):
        killswitch._last_shared_check_ts = 0.0
        killswitch._shared_world = None
        with pytest.raises(killswitch.Halted) as exc:
            killswitch._shared_halt_active(fail_closed=True)
        assert exc.value.source == "shared-error"


# ----- cluster-wide provider spend ledger -----

def test_provider_spend_atomic_increment(world):
    assert world.get_provider_spend("2026-06-22", "anthropic") == 0.0
    assert world.add_provider_spend("2026-06-22", "anthropic", 1.50) == 1.50
    assert world.add_provider_spend("2026-06-22", "anthropic", 2.25) == 3.75
    assert world.get_provider_spend("2026-06-22", "anthropic") == 3.75
    # Distinct (period, provider) keys are independent.
    assert world.add_provider_spend("2026-06-22", "openai", 0.50) == 0.50
    assert world.add_provider_spend("2026-06-23", "anthropic", 1.0) == 1.0
    assert world.get_provider_spend("2026-06-22", "anthropic") == 3.75


def test_provider_cost_cap_uses_shared_store_when_postgres(world, monkeypatch):
    # record/check route through the shared world (not the per-host JSON file)
    # when a shared backend is configured, so the cap total is fleet-wide.
    from maverick import provider_cost_cap as pcc
    monkeypatch.setattr(pcc, "_shared_world_cache", None)
    monkeypatch.setattr(
        "maverick.world_model_backends.is_postgres_configured", lambda: True
    )
    monkeypatch.setattr("maverick.world_model.open_world", lambda: world)
    monkeypatch.setenv("MAVERICK_PROVIDER_CAPS_PERIOD", "day")
    pcc.record("anthropic", 2.0, now=1_750_000_000.0)
    pcc.record("anthropic", 1.0, now=1_750_000_000.0)
    st = pcc.check("anthropic", now=1_750_000_000.0)
    assert st.spent == 3.0  # read back from the shared ledger, not a local file
    # The shared ledger stamps the period from its own clock inside the
    # mutation transaction, so read back the period it actually used.
    period, _total, _receipts = world.read_current_provider_cap(
        pcc.period_from_config(), "anthropic",
    )
    assert world.get_provider_spend(period, "anthropic") == 3.0
