"""Explicit observer and live control tests for the Ekko daemon."""
from __future__ import annotations

from collections import deque

import pytest
from maverick.ekko_daemon import EkkoDaemon, GuidedJsonlObserver, WindowsForegroundObserver
from maverick.work_discovery import CapturePolicy, ObservedActivity, SessionState
from maverick.work_discovery_store import CollectorLeaseError, WorkDiscoveryStore

NOW = 1_800_000_000.0


def _policy() -> CapturePolicy:
    return CapturePolicy(
        enabled=True,
        allowed_apps=frozenset({"chrome", "excel", "powerpoint"}),
        allowed_actions=frozenset({"switch"}),
        allowed_object_types=frozenset({"none"}),
        retention_days=14,
        min_occurrences=2,
        min_distinct_days=2,
        poll_interval_seconds=1,
    )


class _Observer:
    def __init__(self, *values):
        self.values = deque(values)

    def observe(self):
        return self.values.popleft() if self.values else None


def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "cd" * 32)
    return WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme",
        path=tmp_path / "ekko.sqlite3", clock=lambda: NOW,
        authority_check=lambda _policy: None,
    )


def _daemon(store, observer, policy):
    return EkkoDaemon(
        store=store,
        observer=observer,
        policy=policy,
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        policy_check=lambda _policy: None,
        halt_check=lambda: None,
        event_id_factory=lambda: "event-1",
    )


def test_windows_observer_maps_only_fixed_executables_and_drops_unknowns():
    processes = deque([
        r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        r"C:\\Sensitive\\SecretClient.exe",
        r"C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
    ])
    ticks = iter((1.0, 2.0, 6.0))
    observer = WindowsForegroundObserver(
        resolver=processes.popleft, clock=lambda: next(ticks),
    )

    first = observer.observe()
    assert first == ObservedActivity("chrome", "switch", "none", 0)
    assert observer.observe() is None
    assert observer.observe() is None
    last = observer.observe()
    assert last.app == "powerpoint"
    assert last.action == "switch"
    assert "SecretClient" not in repr(observer.__dict__)


def test_daemon_attaches_to_dashboard_approved_session_and_persists_event(
    tmp_path, monkeypatch,
):
    store = _store(tmp_path, monkeypatch)
    policy = _policy()
    store.enroll(policy)
    approved = store.create_session(policy=policy, session_id="dashboard-approved")
    daemon = _daemon(store, _Observer(ObservedActivity("chrome", "switch")), policy)

    attached = daemon.start()
    inserted = daemon.run_once()

    assert attached.session_id == approved.session_id
    assert inserted is True
    assert store.list_events()[0].session_id == approved.session_id


def test_guided_rejected_lines_and_eof_do_not_sleep(tmp_path, monkeypatch):
    from dataclasses import replace

    store = _store(tmp_path, monkeypatch)
    policy = replace(_policy(), allowed_apps=frozenset({"excel"}))
    store.enroll(policy)
    observer = GuidedJsonlObserver.from_text(
        '{"app":"chrome","action":"switch"}\n' * 4
        + '{"app":"excel","action":"switch"}\n'
    )
    daemon = _daemon(store, observer, policy)
    sleeps = []
    daemon._sleep = sleeps.append
    assert daemon.run() == 1
    assert daemon.blocked_events == 4
    assert observer.exhausted
    assert sleeps == []
    daemon.stop()


def test_guided_follow_idle_poll_still_sleeps(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    policy = _policy()
    store.enroll(policy)
    path = tmp_path / "events.jsonl"
    path.write_text("")
    observer = GuidedJsonlObserver(path, follow=True)
    daemon = _daemon(store, observer, policy)
    sleeps = []
    daemon._sleep = sleeps.append
    daemon.run(stop_when=lambda: len(sleeps) == 1, max_idle_sleep=0.25)
    assert sleeps == [0.25]
    daemon.stop()
    observer.close()


def test_guided_line_limit_includes_blank_lines():
    observer = GuidedJsonlObserver.from_text('\n\n{"app":"excel","action":"switch"}\n')
    observer.max_lines = 2
    assert observer.observe() is None
    assert observer.line_number == 2
    assert not observer.exhausted
    observer.close()


def test_paused_guided_import_waits_without_consuming_input(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    policy = _policy()
    store.enroll(policy)
    observer = GuidedJsonlObserver.from_text('{"app":"excel","action":"switch"}\n')
    daemon = _daemon(store, observer, policy)
    session = daemon.start()
    store.transition_session(session.session_id, SessionState.PAUSED)
    sleeps = []
    daemon._sleep = sleeps.append
    daemon.run(stop_when=lambda: bool(sleeps), max_idle_sleep=0.25)
    assert sleeps == [0.25]
    assert observer.line_number == 0
    daemon.stop()
    observer.close()


def test_concurrent_dashboard_pause_and_stop_prevent_capture(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    policy = _policy()
    store.enroll(policy)
    daemon = _daemon(
        store,
        _Observer(
            ObservedActivity("chrome", "switch"),
            ObservedActivity("excel", "switch"),
        ),
        policy,
    )
    session = daemon.start()

    store.transition_session(session.session_id, SessionState.PAUSED)
    assert daemon.run_once() is False
    assert store.list_events() == []
    store.transition_session(session.session_id, SessionState.RUNNING)
    assert daemon.run_once() is True
    store.transition_session(session.session_id, SessionState.STOPPED)
    assert daemon.run_once() is False
    assert len(store.list_events()) == 1


def test_revocation_and_global_halt_end_capture_fail_closed(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    policy = _policy()
    store.enroll(policy)
    daemon = _daemon(store, _Observer(ObservedActivity("chrome", "switch")), policy)
    session = daemon.start()
    store.revoke_enrollment()

    assert daemon.run_once() is False
    assert store.get_session(session.session_id).state == SessionState.STOPPED
    assert store.list_events() == []

    # A halt authority error also terminates capture without observing.
    store.enroll(policy)
    observer = _Observer(ObservedActivity("chrome", "switch"))
    halted = EkkoDaemon(
        store=store,
        observer=observer,
        policy=policy,
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        policy_check=lambda _policy: None,
        halt_check=lambda: (_ for _ in ()).throw(RuntimeError("halted")),
    )
    new_session = halted.start()
    assert halted.run_once() is False
    assert store.get_session(new_session.session_id).state == SessionState.HALTED
    assert len(observer.values) == 1


def test_only_one_live_collector_can_own_a_device_session(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)
    policy = _policy()
    store.enroll(policy)
    first = _daemon(store, _Observer(), policy)
    session = first.start()

    assert store.collector_status(session.session_id)["state"] == "live"
    second = _daemon(store, _Observer(), policy)
    with pytest.raises(CollectorLeaseError, match="live collector"):
        second.start()
    assert second.stop() is None
    assert store.get_session(session.session_id).state == SessionState.RUNNING


def test_expired_heartbeat_halts_capture_without_observing(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "34" * 32)
    now = {"value": NOW}
    store = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme",
        path=tmp_path / "ekko.sqlite3",
        clock=lambda: now["value"],
        authority_check=lambda _policy: None,
    )
    policy = _policy()
    store.enroll(policy)
    observer = _Observer(ObservedActivity("chrome", "switch"))
    daemon = EkkoDaemon(
        store=store,
        observer=observer,
        policy=policy,
        clock=lambda: now["value"],
        sleep=lambda _seconds: None,
        policy_check=lambda _policy: None,
        halt_check=lambda: None,
        collector_id_factory=lambda: "collector-expiry-capability",
        lease_seconds=5,
    )
    session = daemon.start()
    now["value"] = NOW + 6

    assert store.collector_status(session.session_id)["state"] == "stale"
    assert daemon.run_once() is False
    assert store.get_session(session.session_id).state == SessionState.HALTED
    assert len(observer.values) == 1
