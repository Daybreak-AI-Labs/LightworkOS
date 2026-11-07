"""The status a chat worker publishes about held replies: counts and times only."""
from __future__ import annotations

import json
import time

import pytest
from maverick_channels import hold_status


def _counts(**overrides):
    counts = {"held": 0, "behind_unreadable": 0, "unreadable": 0, "release_at": None,
              "went_ahead": 0, "went_ahead_at": None}
    counts.update(overrides)
    return counts


def _publish(directory, channel, counts, *, clock=None):
    publisher = hold_status.Publisher(channel, directory=directory, clock=clock or time.time)
    publisher.update(counts)
    assert publisher.write_now()
    return publisher


def test_a_published_status_is_sealed_counts_only_and_reads_back_fresh(tmp_path):
    publisher = _publish(tmp_path, "signal", _counts(held=3, behind_unreadable=2, unreadable=1, release_at=5000.0))
    files = list(tmp_path.glob("*.enc"))
    assert len(files) == 1
    raw = files[0].read_bytes()
    found, unavailable = hold_status.records(directory=tmp_path)
    assert not unavailable and len(found) == 1
    record = found[0]
    assert record["fresh"] is True and record["channel"] == "signal"
    assert (record["held"], record["behind_unreadable"], record["unreadable"], record["release_at"]) == (3, 2, 1, 5000.0)
    # Only these fields are kept: no message text, person, chat or saved-reply name.
    assert set(record) == {"schema", "channel", "instance", "seen_at", "fresh", "held", "behind_unreadable",
                           "unreadable", "release_at", "went_ahead", "went_ahead_at"}
    publisher.close()
    assert not list(tmp_path.glob("*.enc"))
    assert b"held" not in raw and b"signal" not in raw  # sealed with the deployment key


def test_a_status_that_is_not_renewed_is_not_fresh_and_a_damaged_one_is_unavailable(tmp_path):
    _publish(tmp_path, "irc", _counts(), clock=lambda: 1000.0)
    found, unavailable = hold_status.records(directory=tmp_path, now=1000.0 + hold_status.FRESH_SECONDS + 1)
    assert not unavailable and found[0]["fresh"] is False
    (tmp_path / "irc-1-damaged.enc").write_bytes(b"not a sealed status")
    found, unavailable = hold_status.records(directory=tmp_path, now=1000.0)
    assert unavailable and len(found) == 1


@pytest.mark.parametrize("bad", [
    {"held": -1}, {"held": True}, {"held": 1, "behind_unreadable": 2}, {"release_at": float("inf")},
    {"went_ahead": "3"}, {"unreadable": 2, "behind_unreadable": 1, "held": 1},
])
def test_a_status_with_impossible_counts_is_refused(tmp_path, bad):
    publisher = hold_status.Publisher("signal", directory=tmp_path)
    with pytest.raises(ValueError):
        publisher.update(_counts(**bad))


def test_summary_adds_up_the_fresh_channels_and_takes_the_earliest_release(tmp_path):
    _publish(tmp_path, "signal", _counts(held=2, behind_unreadable=2, unreadable=1, release_at=9000.0))
    _publish(tmp_path, "irc", _counts(held=3, behind_unreadable=1, unreadable=1, release_at=7000.0,
                                      went_ahead=1, went_ahead_at=6000.0))
    state = hold_status.summary({"signal", "irc"}, directory=tmp_path)
    assert state["state"] == "holding"
    assert (state["held"], state["behind_unreadable"], state["unreadable"]) == (5, 3, 2)
    assert state["release_at"] == 7000.0 and state["went_ahead"] == 1 and state["went_ahead_at"] == 6000.0
    assert state["not_reporting"] == []


def test_summary_states_when_nothing_can_be_said_to_be_held(tmp_path):
    assert hold_status.summary(set(), directory=tmp_path)["state"] == "off"
    assert hold_status.summary({"signal"}, directory=tmp_path)["state"] == "not_reporting"
    _publish(tmp_path, "signal", _counts(), clock=lambda: 1000.0)
    stale = hold_status.summary({"signal"}, directory=tmp_path, now=1000.0 + hold_status.FRESH_SECONDS + 1)
    assert stale["state"] == "stale" and stale["last_seen"] == 1000.0
    assert hold_status.summary({"signal"}, directory=tmp_path, now=1001.0)["state"] == "clear"
    (tmp_path / "signal-2-damaged.enc").write_bytes(b"garbage")
    fresh_and_damaged = hold_status.summary({"signal"}, directory=tmp_path, now=1001.0)
    assert fresh_and_damaged["state"] == "clear" and fresh_and_damaged["unavailable"] is True
    for path in tmp_path.glob("*.enc"):
        path.unlink()
    (tmp_path / "signal-3-damaged.enc").write_bytes(b"garbage")
    assert hold_status.summary({"signal"}, directory=tmp_path)["state"] == "unavailable"


def test_summary_names_an_enabled_channel_that_is_not_reporting_and_ignores_disabled_ones(tmp_path):
    _publish(tmp_path, "signal", _counts(held=1))
    _publish(tmp_path, "irc", _counts(held=4))
    state = hold_status.summary({"signal"}, directory=tmp_path)
    assert state["held"] == 1 and state["not_reporting"] == []
    (tmp_path / "unused").mkdir()
    _publish(tmp_path / "unused", "signal", _counts(held=1))
    state = hold_status.summary({"signal", "irc"}, directory=tmp_path / "unused")
    assert state["state"] == "holding" and state["not_reporting"] == ["irc"]


def test_the_freshest_status_of_a_channel_wins_over_an_older_process(tmp_path):
    _publish(tmp_path, "signal", _counts(held=9), clock=lambda: 1000.0)
    _publish(tmp_path, "signal", _counts(held=0), clock=lambda: 1050.0)
    assert hold_status.summary({"signal"}, directory=tmp_path, now=1060.0)["state"] == "clear"


def test_a_failed_write_is_logged_once_and_never_raises(tmp_path, monkeypatch, caplog):
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


def test_old_statuses_left_by_stopped_processes_are_cleared_on_start(tmp_path):
    old = tmp_path / "signal-1-old.enc"
    old.write_bytes(b"x")
    stamp = time.time() - 8 * 86400
    import os
    os.utime(old, (stamp, stamp))
    publisher = hold_status.Publisher("signal", directory=tmp_path, renew_seconds=60).start()
    publisher.close()
    assert not old.exists()


def test_a_record_names_only_a_known_channel(tmp_path):
    with pytest.raises(ValueError):
        hold_status.Publisher("../signal", directory=tmp_path)
    assert json.dumps(_counts())  # the counts are plain JSON
