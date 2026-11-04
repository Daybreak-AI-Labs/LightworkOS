"""The daily summary scheduler: config-gated, leased, backs off, stops cleanly."""
from __future__ import annotations

import threading

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DAILY_DIGEST", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda kind, **p: True)
    config.reset_config_cache()
    yield
    from maverick_dashboard import daily_digest_scheduler as sched

    sched.stop_daily_digest_scheduler()
    config.reset_config_cache()


def test_lease_is_exclusive_renewable_and_expires():
    from maverick_dashboard.daily_digest_scheduler import acquire_lease, release_lease

    assert acquire_lease("a", now=100.0, ttl_seconds=60) is True
    assert acquire_lease("b", now=120.0, ttl_seconds=60) is False
    assert acquire_lease("a", now=150.0, ttl_seconds=60) is True  # renew
    assert acquire_lease("b", now=211.0, ttl_seconds=60) is True  # a's lease lapsed
    release_lease("a")  # not the holder: nothing happens
    assert acquire_lease("c", now=212.0, ttl_seconds=60) is False
    release_lease("b")
    assert acquire_lease("c", now=213.0, ttl_seconds=60) is True


def test_cycle_is_off_by_default_and_leased(tmp_path, monkeypatch):
    from maverick import config
    from maverick_dashboard import daily_digest_scheduler as sched

    assert sched.scheduler_cycle("h1") is None
    assert sched.start_daily_digest_scheduler() is False
    (tmp_path / "config.toml").write_text("[my_work]\ndigest_enable = true\n")
    config.reset_config_cache()
    called = []
    monkeypatch.setattr("maverick.daily_digest.run_digest_cycle",
                        lambda world, **kw: called.extend(kw["principals"]) or {"sent": 0})
    monkeypatch.setattr(sched, "_recipients", lambda: ["user:b", "user:a"])
    assert sched.scheduler_cycle("h1", now=1000.0) == {"sent": 0}
    assert sorted(called) == ["user:a", "user:b"]  # each recipient, one at a time
    assert sched.scheduler_cycle("h2", now=1001.0) is None  # h1 holds the lease


def _digest_enabled(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text("[my_work]\ndigest_enable = true\n")
    config.reset_config_cache()


def _slow_sender(monkeypatch, sched, clock, *, seconds, other_worker_tries):
    """A fake ``run_digest_cycle`` whose every recipient takes ``seconds``; after
    each one the other worker's loop wakes and tries its own cycle."""
    state = {"busy": False, "sent": [], "other_tried": [], "other_sent": []}

    def run(world, *, principals, **kwargs):
        if state["busy"]:  # the other worker got a lease and reached the sender
            state["other_sent"].extend(principals)
            return {"sent": len(principals)}
        state["busy"] = True
        try:
            for principal in principals:
                state["sent"].append(principal)
                clock["t"] += seconds
                state["other_tried"].append(other_worker_tries())
        finally:
            state["busy"] = False
        return {"sent": len(principals)}

    monkeypatch.setattr("maverick.daily_digest.run_digest_cycle", run)
    return state


def test_a_slow_cycle_renews_its_lease_so_a_second_worker_never_resends(tmp_path, monkeypatch):
    from maverick_dashboard import daily_digest_scheduler as sched

    _digest_enabled(tmp_path)
    monkeypatch.setattr(sched, "_recipients", lambda: ["user:a", "user:b", "user:c"])
    clock = {"t": 1000.0}

    def fake_clock():
        return clock["t"]

    # Three recipients at 70 s each: 210 s in all, well past the 120 s lease.
    state = _slow_sender(monkeypatch, sched, clock, seconds=70.0,
                         other_worker_tries=lambda: sched.scheduler_cycle("B", clock=fake_clock))
    assert sched.scheduler_cycle("A", clock=fake_clock) == {"sent": 3}
    assert state["sent"] == ["user:a", "user:b", "user:c"]
    assert state["other_tried"] == [None, None, None]  # B never got the lease mid-cycle
    assert state["other_sent"] == []


def test_a_cycle_that_loses_its_lease_stops_before_the_next_recipient(tmp_path, monkeypatch):
    from maverick_dashboard import daily_digest_scheduler as sched

    _digest_enabled(tmp_path)
    monkeypatch.setattr(sched, "_recipients", lambda: ["user:a", "user:b", "user:c"])
    clock = {"t": 1000.0}

    def fake_clock():
        return clock["t"]

    # The first send hangs for 300 s: A's lease lapses and B takes it over.
    state = _slow_sender(monkeypatch, sched, clock, seconds=300.0,
                         other_worker_tries=lambda: sched.scheduler_cycle("B", clock=fake_clock))
    assert sched.scheduler_cycle("A", clock=fake_clock) == {"sent": 1}
    assert state["sent"] == ["user:a"]  # A gave up instead of sending the rest again
    assert state["other_sent"] == ["user:a", "user:b", "user:c"]


def test_recipients_union_roster_links_and_preferences(monkeypatch):
    from maverick import channel_identities, user_preferences
    from maverick_dashboard import daily_digest_scheduler as sched
    from maverick_dashboard import rbac

    monkeypatch.setattr(rbac, "list_users", lambda: {"user:role": "viewer"})
    channel_identities.link("slack", "U1", "user:linked", actor="admin")
    user_preferences.set_preferences("user:prefs", digest_hour=9)
    assert sched._recipients() == ["user:linked", "user:prefs", "user:role"]


def test_start_and_stop_thread(tmp_path, monkeypatch):
    from maverick import config
    from maverick_dashboard import daily_digest_scheduler as sched

    (tmp_path / "config.toml").write_text("[my_work]\ndigest_enable = true\ndigest_poll_seconds = 30\n")
    config.reset_config_cache()
    ran = threading.Event()
    monkeypatch.setattr(sched, "scheduler_cycle", lambda holder, now=None: ran.set() or {"sent": 0})
    assert sched.start_daily_digest_scheduler() is True
    assert sched.start_daily_digest_scheduler() is False  # already running
    assert ran.wait(5)
    assert sched.stop_daily_digest_scheduler(timeout=5) is True
    assert sched.stop_daily_digest_scheduler() is False


def test_failed_cycle_backs_off(monkeypatch):
    from maverick_dashboard import daily_digest_scheduler as sched

    waits = []
    stop = threading.Event()

    class Stop:
        def is_set(self):
            return len(waits) >= 3

        def wait(self, seconds):
            waits.append(seconds)

    def boom(holder, now=None):
        raise RuntimeError("down")

    monkeypatch.setattr(sched, "scheduler_cycle", boom)
    monkeypatch.setattr(sched, "release_lease", lambda holder: None)
    sched._scheduler_loop(Stop(), "h", 30.0)
    assert waits == [60.0, 120.0, 240.0]
    assert not stop.is_set()


def test_an_administrators_scheduled_summary_lists_only_their_own_work(tmp_path, monkeypatch):
    # The summary leaves Lightwork by chat or email. A configured administrator
    # lists only their own work in the app (/me); lifting the owner filter here
    # sent everyone's results, questions and keys to that inbox.
    from maverick_dashboard import auth
    from maverick_dashboard import daily_digest_scheduler as sched

    _digest_enabled(tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    assert auth.is_dashboard_admin("user:root") is True
    lifted = []

    def cycle(world, **kw):
        everything = kw.get("sees_everything")
        lifted.append(bool(everything and everything("user:root")))
        return {"sent": 0}

    monkeypatch.setattr("maverick.daily_digest.run_digest_cycle", cycle)
    monkeypatch.setattr(sched, "_recipients", lambda: ["user:root"])
    sched.scheduler_cycle("h1", now=1000.0)
    assert lifted == [False]
