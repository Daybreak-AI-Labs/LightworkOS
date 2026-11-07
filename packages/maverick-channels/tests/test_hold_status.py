"""The status a chat worker publishes about held replies: counts and times only."""
from __future__ import annotations

import json
import os
import sys
import threading
import time

import pytest
from maverick_channels import hold_status


def _counts(**overrides):
    counts = {"held": 0, "behind_unreadable": 0, "unreadable": 0, "retrying": 0, "release_at": None,
              "went_ahead": 0, "went_ahead_at": None}
    counts.update(overrides)
    return counts


def _publish(directory, channel, counts, *, clock=None):
    publisher = hold_status.Publisher(channel, directory=directory, clock=clock or time.time)
    publisher.update(counts)
    assert publisher.write_now()
    return publisher


def test_a_published_status_is_sealed_counts_only_and_reads_back_fresh(tmp_path):
    publisher = _publish(tmp_path, "signal", _counts(held=3, behind_unreadable=2, unreadable=1, retrying=1,
                                                     release_at=5000.0))
    files = list(tmp_path.glob("*.enc"))
    assert len(files) == 1
    raw = files[0].read_bytes()
    found, unreadable = hold_status.records(directory=tmp_path)
    assert not unreadable and len(found) == 1
    record = found[0]
    assert record["fresh"] is True and record["channel"] == "signal"
    assert (record["held"], record["behind_unreadable"], record["unreadable"], record["retrying"],
            record["release_at"]) == (3, 2, 1, 1, 5000.0)
    # Only these fields are kept: no message text, person, chat or saved-reply name.
    assert set(record) == {"schema", "channel", "instance", "seen_at", "fresh", "ahead", "held",
                           "behind_unreadable", "unreadable", "retrying", "release_at", "went_ahead",
                           "went_ahead_at"}
    publisher.close()
    assert not list(tmp_path.glob("*.enc"))
    assert b"held" not in raw and b"signal" not in raw  # sealed with the deployment key


def test_a_status_that_is_not_renewed_is_not_fresh_and_a_damaged_one_names_its_app(tmp_path):
    _publish(tmp_path, "irc", _counts(), clock=lambda: 1000.0)
    found, unreadable = hold_status.records(directory=tmp_path, now=1000.0 + hold_status.FRESH_SECONDS + 1)
    assert not unreadable and found[0]["fresh"] is False
    (tmp_path / "irc-1-damaged.enc").write_bytes(b"not a sealed status")
    (tmp_path / "Bad Name.enc").write_bytes(b"not a sealed status")
    found, unreadable = hold_status.records(directory=tmp_path, now=1000.0)
    assert unreadable == {"irc", "unknown"} and len(found) == 1


def test_an_unsealed_status_is_never_read_as_nothing_held(tmp_path):
    _publish(tmp_path, "signal", _counts(held=4))
    forged = {"schema": 1, "channel": "signal", "instance": "signal-1-forged", "seen_at": time.time() + 1,
              **_counts()}
    (tmp_path / "signal-1-forged.enc").write_text(json.dumps(forged), encoding="utf-8")
    state = hold_status.summary({"signal"}, directory=tmp_path)
    assert state["state"] == "holding" and state["held"] == 4 and state["unavailable"] == ["signal"]


@pytest.mark.parametrize("bad", [
    {"held": -1}, {"held": True}, {"held": 1, "behind_unreadable": 2}, {"release_at": float("inf")},
    {"went_ahead": "3"}, {"unreadable": 2, "behind_unreadable": 1, "held": 1}, {"retrying": -2},
])
def test_a_status_with_impossible_counts_is_refused(tmp_path, bad):
    publisher = hold_status.Publisher("signal", directory=tmp_path)
    with pytest.raises(ValueError):
        publisher.update(_counts(**bad))


def test_summary_adds_up_the_fresh_channels_and_takes_the_latest_release(tmp_path):
    _publish(tmp_path, "signal", _counts(held=2, behind_unreadable=2, unreadable=1, release_at=9000.0))
    _publish(tmp_path, "irc", _counts(held=3, behind_unreadable=1, unreadable=1, retrying=2, release_at=7000.0,
                                      went_ahead=1, went_ahead_at=6000.0))
    state = hold_status.summary({"signal", "irc"}, directory=tmp_path, now=time.time())
    assert state["state"] == "holding"
    assert (state["held"], state["behind_unreadable"], state["unreadable"], state["retrying"]) == (5, 3, 2, 2)
    # Every held reply goes out by the latest of the times, not the earliest.
    assert state["release_at"] == 9000.0 and state["went_ahead"] == 1 and state["went_ahead_at"] == 6000.0
    assert state["not_reporting"] == [] and state["reporting"] == ["irc", "signal"]
    assert state["release_passed"] is True  # 9000 seconds after 1970 is long past


def test_a_release_time_still_ahead_has_not_passed(tmp_path):
    _publish(tmp_path, "signal", _counts(held=1, behind_unreadable=1, unreadable=1, release_at=time.time() + 3600))
    assert hold_status.summary({"signal"}, directory=tmp_path)["release_passed"] is False


def test_replies_waiting_for_another_attempt_alone_are_holding(tmp_path):
    _publish(tmp_path, "irc", _counts(retrying=1))
    state = hold_status.summary({"irc"}, directory=tmp_path)
    assert state["state"] == "holding" and state["held"] == 0 and state["retrying"] == 1


def test_summary_states_when_nothing_can_be_said_to_be_held(tmp_path):
    assert hold_status.summary(set(), directory=tmp_path)["state"] == "off"
    quiet = hold_status.summary({"signal"}, directory=tmp_path)
    assert quiet["state"] == "not_reporting" and quiet["not_reporting"] == ["signal"]
    _publish(tmp_path, "signal", _counts(), clock=lambda: 1000.0)
    stale = hold_status.summary({"signal"}, directory=tmp_path, now=1000.0 + hold_status.FRESH_SECONDS + 1)
    assert stale["state"] == "stale" and stale["last_seen"] == 1000.0
    assert hold_status.summary({"signal"}, directory=tmp_path, now=1001.0)["state"] == "clear"
    (tmp_path / "signal-2-damaged.enc").write_bytes(b"garbage")
    fresh_and_damaged = hold_status.summary({"signal"}, directory=tmp_path, now=1001.0)
    assert fresh_and_damaged["state"] == "clear" and fresh_and_damaged["unavailable"] == ["signal"]
    for path in tmp_path.glob("*.enc"):
        path.unlink()
    (tmp_path / "signal-3-damaged.enc").write_bytes(b"garbage")
    unreadable = hold_status.summary({"signal"}, directory=tmp_path)
    assert unreadable["state"] == "unavailable" and unreadable["unavailable"] == ["signal"]


def test_a_turned_off_apps_unreadable_leftover_does_not_hide_a_quiet_app(tmp_path):
    (tmp_path / "irc-1-damaged.enc").write_bytes(b"garbage")
    state = hold_status.summary({"signal"}, directory=tmp_path)
    assert state["state"] == "not_reporting" and state["unavailable"] == []


def test_summary_names_an_enabled_channel_that_is_not_reporting(tmp_path):
    _publish(tmp_path, "signal", _counts(held=1))
    state = hold_status.summary({"signal", "irc"}, directory=tmp_path)
    assert state["state"] == "holding" and state["not_reporting"] == ["irc"] and state["reporting"] == ["signal"]


def test_an_app_turned_off_but_still_running_is_still_counted(tmp_path):
    _publish(tmp_path, "signal", _counts(held=3))
    for enabled in (set(), {"irc"}):
        state = hold_status.summary(enabled, directory=tmp_path)
        assert state["held"] == 3 and state["running_off"] == ["signal"] and state["state"] == "holding"


def test_a_leftover_from_the_future_never_hides_the_current_status(tmp_path):
    now = time.time()
    _publish(tmp_path, "signal", _counts(held=3), clock=lambda: now)
    _publish(tmp_path, "signal", _counts(held=0), clock=lambda: now + 3600)
    state = hold_status.summary({"signal"}, directory=tmp_path, now=now)
    assert state["state"] == "holding" and state["held"] == 3
    for path in tmp_path.glob("*.enc"):
        path.unlink()
    _publish(tmp_path, "signal", _counts(), clock=lambda: now + 3600)
    alone = hold_status.summary({"signal"}, directory=tmp_path, now=now)
    # Alone it says nothing about now: no time that has not happened, and the
    # same answer on every read (Copilot compares two reads).
    assert alone["state"] == "not_reporting" and alone["last_seen"] is None
    assert hold_status.summary({"signal"}, directory=tmp_path, now=now + 1) == alone


def test_a_renewal_just_after_the_reader_took_the_time_is_current(tmp_path):
    # The worker renews between summary() taking the time and reading the
    # file, so the status is stamped slightly after that time.
    now = time.time()
    _publish(tmp_path, "signal", _counts(held=2), clock=lambda: now + 0.5)
    state = hold_status.summary({"signal"}, directory=tmp_path, now=now)
    assert state["state"] == "holding" and state["held"] == 2


def test_a_stale_status_reports_when_it_was_last_renewed(tmp_path):
    _publish(tmp_path, "signal", _counts(held=1), clock=lambda: 1000.0)
    later = 1000.0 + hold_status.FRESH_SECONDS + 50
    state = hold_status.summary({"signal"}, directory=tmp_path, now=later)
    assert state["state"] == "stale" and state["last_seen"] == 1000.0
    assert hold_status.summary({"signal"}, directory=tmp_path, now=later + 1) == state


def test_an_old_status_beside_an_unreadable_one_is_stale_and_still_names_the_unreadable_app(tmp_path):
    _publish(tmp_path, "irc", _counts(), clock=lambda: 1000.0)
    (tmp_path / "signal-2-damaged.enc").write_bytes(b"not a sealed status")
    state = hold_status.summary({"signal", "irc"}, directory=tmp_path, now=1000.0 + hold_status.FRESH_SECONDS + 50)
    assert state["state"] == "stale" and state["last_seen"] == 1000.0
    assert state["unavailable"] == ["signal"]


def test_the_freshest_status_of_a_channel_wins_over_an_older_process(tmp_path):
    _publish(tmp_path, "signal", _counts(held=9), clock=lambda: 1000.0)
    _publish(tmp_path, "signal", _counts(held=0), clock=lambda: 1050.0)
    assert hold_status.summary({"signal"}, directory=tmp_path, now=1060.0)["state"] == "clear"


def test_a_failed_write_is_logged_once_and_never_raises(tmp_path, caplog):
    blocked = tmp_path / "file-not-directory"
    blocked.write_text("x")
    publisher = hold_status.Publisher("signal", directory=blocked)
    publisher.update(_counts(held=1))
    assert publisher.write_now() is False
    assert publisher.write_now() is False
    warnings = [record for record in caplog.records if "held chat replies" in record.getMessage()]
    assert len(warnings) == 1


def test_the_renewal_thread_writes_at_once_renews_and_stops_on_close(tmp_path):
    clock = [1000.0]
    publisher = hold_status.Publisher("irc", directory=tmp_path, clock=lambda: clock[0], renew_seconds=0.02)
    publisher.update(_counts(held=1))
    publisher.start()
    deadline = time.monotonic() + 5
    while not list(tmp_path.glob("*.enc")) and time.monotonic() < deadline:
        time.sleep(0.01)
    first, _ = hold_status.records(directory=tmp_path, now=1000.0)
    clock[0] = 1010.0
    while time.monotonic() < deadline:
        renewed, _ = hold_status.records(directory=tmp_path, now=1010.0)
        if renewed and renewed[0]["seen_at"] == 1010.0:
            break
        time.sleep(0.01)
    assert first[0]["held"] == 1 and renewed[0]["seen_at"] == 1010.0
    publisher.update(_counts(held=2))
    while time.monotonic() < deadline:
        changed, _ = hold_status.records(directory=tmp_path, now=1010.0)
        if changed and changed[0]["held"] == 2:
            break
        time.sleep(0.01)
    assert changed[0]["held"] == 2
    publisher.close()
    assert not list(tmp_path.glob("*.enc"))
    assert not publisher.write_now()  # a closed publisher never writes again


def test_a_write_still_running_when_close_gives_up_does_not_bring_the_status_back(tmp_path, monkeypatch):
    from maverick import file_lock

    real, entered, release = file_lock.atomic_write_bytes, threading.Event(), threading.Event()

    def slow(*args, **kwargs):
        entered.set()
        release.wait(10)
        return real(*args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_bytes", slow)
    monkeypatch.setattr(hold_status, "_CLOSE_WAIT", 0.05)
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=60)
    publisher.update(_counts(held=2))
    publisher.start()
    assert entered.wait(5)
    publisher.close()  # gives up waiting for the write
    release.set()
    publisher._thread.join(5)
    assert not list(tmp_path.glob("*.enc"))
    assert hold_status.summary({"signal"}, directory=tmp_path)["state"] == "not_reporting"


def test_old_statuses_and_this_apps_unrenewed_ones_are_cleared_on_start(tmp_path):
    old = tmp_path / "irc-1-old.enc"
    old.write_bytes(b"x")
    week = time.time() - 8 * 86400
    os.utime(old, (week, week))
    orphan = tmp_path / "signal-2-orphan.enc"
    orphan.write_bytes(b"x")
    gone = time.time() - hold_status.FRESH_SECONDS - 5
    os.utime(orphan, (gone, gone))
    live = tmp_path / "signal-3-live.enc"
    live.write_bytes(b"x")
    other_app = tmp_path / "irc-4-recent.enc"
    other_app.write_bytes(b"x")
    os.utime(other_app, (gone, gone))
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=60).start()
    try:  # checked before close(), which clears leftovers too
        assert not old.exists() and not orphan.exists()
        assert live.exists() and other_app.exists()  # a renewed status, and another app's, are left alone
    finally:
        publisher.close()


def test_a_running_worker_clears_its_apps_unrenewed_status_left_just_before_it_started(tmp_path, monkeypatch):
    # A process killed seconds before this one started left a status that was
    # still recent at start. Once nobody has renewed it for FRESH_SECONDS the
    # running worker removes it, so it never stands in for this worker later.
    monkeypatch.setattr(hold_status, "FRESH_SECONDS", 0.3)
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=0.02)
    publisher.update(_counts(held=1))
    publisher.start()
    orphan = tmp_path / "signal-2-orphan.enc"
    orphan.write_bytes(b"x")
    other_app = tmp_path / "irc-3-other.enc"
    other_app.write_bytes(b"x")
    gone = time.time() - 10
    os.utime(orphan, (gone, gone))
    os.utime(other_app, (gone, gone))
    deadline = time.monotonic() + 5
    while orphan.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    try:
        assert not orphan.exists()
        assert publisher.path.exists() and other_app.exists()
    finally:
        publisher.close()


def test_a_worker_that_stops_clears_its_apps_unrenewed_statuses_too(tmp_path):
    orphan = tmp_path / "signal-2-orphan.enc"
    orphan.write_bytes(b"x")
    recent = time.time() - 20
    os.utime(orphan, (recent, recent))
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=60).start()
    assert orphan.exists()  # still recent at start: it may be renewed
    gone = time.time() - hold_status.FRESH_SECONDS - 5
    os.utime(orphan, (gone, gone))
    publisher.close()
    assert not list(tmp_path.glob("*.enc"))
    assert hold_status.summary({"signal"}, directory=tmp_path)["state"] == "not_reporting"


def test_a_status_left_before_the_clock_was_set_back_is_cleared(tmp_path):
    ahead = tmp_path / "signal-2-ahead.enc"
    ahead.write_bytes(b"x")
    later = time.time() + 3600
    os.utime(ahead, (later, later))
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=60).start()
    try:  # checked before close(), which clears leftovers too
        assert not ahead.exists()
    finally:
        publisher.close()
    assert hold_status.summary({"signal"}, directory=tmp_path, now=later)["state"] == "not_reporting"


@pytest.mark.parametrize("jump", [3600, -60])
def test_a_running_worker_is_current_again_soon_after_the_clock_jumps(tmp_path, monkeypatch, jump):
    # A laptop wakes (the clock jumps ahead without the renewal wait counting
    # the time asleep) or the clock is set back: the worker renews within a
    # few seconds instead of reading as stopped until its wait runs out.
    monkeypatch.setattr(hold_status, "_SKEW", 0.2)
    offset = [0.0]

    def wall():
        return time.time() + offset[0]
    publisher = hold_status.Publisher("signal", directory=tmp_path, clock=wall, renew_seconds=30)
    publisher.update(_counts(held=2))
    publisher.start()
    try:
        deadline = time.monotonic() + 5
        while publisher._stamped is None and time.monotonic() < deadline:
            time.sleep(0.02)
        stamped = publisher._stamped
        offset[0] += jump
        state = hold_status.summary({"signal"}, directory=tmp_path, now=wall())
        while (state["state"] != "holding" or publisher._stamped == stamped) and time.monotonic() < deadline:
            time.sleep(0.05)
            state = hold_status.summary({"signal"}, directory=tmp_path, now=wall())
        assert state["state"] == "holding" and state["held"] == 2
        assert publisher._stamped - stamped == pytest.approx(jump, abs=5)  # renewed on the new clock
    finally:
        publisher.close()


def test_a_change_whose_write_failed_is_tried_again_within_seconds(tmp_path, monkeypatch):
    # The counts change and that write fails once (a full disk for a moment):
    # the last status, renewed under RENEW_SECONDS ago, still reads as current,
    # so the write is tried again every few seconds, not once it is due.
    from maverick import file_lock

    monkeypatch.setattr(hold_status, "_SKEW", 0.2)
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=30)
    publisher.update(_counts(held=1))
    publisher.start()
    try:
        deadline = time.monotonic() + 5
        while publisher._stamped is None and time.monotonic() < deadline:
            time.sleep(0.02)
        real, failures = file_lock.atomic_write_bytes, [1]

        def fails_once(*args, **kwargs):
            if failures[0]:
                failures[0] -= 1
                raise OSError("no space left on device")
            return real(*args, **kwargs)
        monkeypatch.setattr(file_lock, "atomic_write_bytes", fails_once)
        publisher.update(_counts(held=2))
        state = hold_status.summary({"signal"}, directory=tmp_path)
        while state["held"] != 2 and time.monotonic() < deadline:
            time.sleep(0.05)
            state = hold_status.summary({"signal"}, directory=tmp_path)
        assert not failures[0] and state["state"] == "holding" and state["held"] == 2
    finally:
        publisher.close()


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links and FIFOs need POSIX here")
def test_cleanup_never_follows_a_linked_folder(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    victim = elsewhere / "x.enc"
    victim.write_bytes(b"x")
    week = time.time() - 8 * 86400
    os.utime(victim, (week, week))
    (tmp_path / "holds").symlink_to(elsewhere, target_is_directory=True)
    hold_status.Publisher("signal", directory=tmp_path / "holds", renew_seconds=60).start().close()
    assert victim.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links and FIFOs need POSIX here")
def test_a_fifo_or_device_in_the_folder_is_unreadable_not_a_hang(tmp_path):
    publisher = _publish(tmp_path, "signal", _counts(held=1))
    os.mkfifo(tmp_path / "signal-9-fifo.enc")
    (tmp_path / "signal-8-zero.enc").symlink_to("/dev/zero")
    started = time.monotonic()
    found, unreadable = hold_status.records(directory=tmp_path)
    assert time.monotonic() - started < 5
    assert [record["held"] for record in found] == [1] and unreadable == {"signal"}
    publisher.close()


def test_a_record_names_only_a_known_channel(tmp_path):
    with pytest.raises(ValueError):
        hold_status.Publisher("../signal", directory=tmp_path)
    assert json.dumps(_counts())  # the counts are plain JSON
