"""Held chat replies on Channels > Message delivery and in Copilot, one answer for both."""
from __future__ import annotations

import html as _html
import re
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick_channels import hold_status
from maverick_dashboard import channel_holds
from maverick_dashboard.plain_labels import datetime_text
from starlette.requests import Request

PRIVATE = ("held_behind", "went_ahead_of", "chd-", "receipt", "sha256", "digest", "instance")
JARGON = re.compile(r"\b(?:tenant|principal|digest|endpoint|schema|revision|runtime|adapter|"
                    r"preflight|authority|credential|worker|process id|unreadable_since)\b", re.IGNORECASE)
RESTART = ("If this lasts, open Manage the chat service to check that the chat service is running and see what it "
           "last reported, then restart it.")


def _request():
    return Request({"type": "http", "method": "GET", "path": "/channels", "headers": []})


def _state(**overrides):
    state = {"state": "clear", "held": 0, "behind_unreadable": 0, "unreadable": 0, "retrying": 0,
             "release_at": None, "release_passed": False, "went_ahead": 0, "went_ahead_at": None,
             "reporting": ["irc", "signal"], "not_reporting": [], "running_off": [], "last_seen": None,
             "unavailable": []}
    state.update(overrides)
    return state


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import integration_readiness
    integration_readiness._clear_for_testing()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    integration_readiness._clear_for_testing()
    config.reset_config_cache()


def _publish(counts, *, clock=time.time, channel="signal"):
    publisher = hold_status.Publisher(channel, clock=clock)
    publisher.update({"held": 0, "behind_unreadable": 0, "unreadable": 0, "retrying": 0, "release_at": None,
                      "went_ahead": 0, "went_ahead_at": None, **counts})
    assert publisher.write_now()
    return publisher


@pytest.mark.parametrize(("state", "expected"), [
    # Nothing reads a turned-off app's saved replies, so it never says none are held.
    (_state(state="off", reporting=[]), "Signal and IRC are turned off, so held chat replies are not being "
                                        "checked. A reply that was waiting when its app was turned off stays "
                                        "saved until that app is turned on again."),
    # It names the apps it covers: other chat apps' replies are not counted.
    (_state(), "No IRC or Signal replies are waiting."),
    (_state(state="holding", held=1), "1 chat reply is waiting for an earlier reply in the same chat to be sent "
                                      "first. It goes out after that one does."),
    (_state(state="holding", retrying=2), "2 chat replies could not be sent or handled and are tried again every "
                                          "30 seconds."),
    (_state(state="not_reporting", reporting=[], not_reporting=["signal"]),
     "Signal is turned on but not reporting from the chat service on this computer, so held chat replies cannot "
     "be checked."),
    (_state(state="not_reporting", reporting=[], not_reporting=["irc", "signal"]),
     "IRC and Signal are turned on but not reporting from the chat service on this computer"),
    (_state(state="unavailable", reporting=[], unavailable=["signal"]),
     "The saved status for Signal could not be read, so held chat replies cannot be checked."),
])
def test_each_state_reads_as_one_plain_answer(state, expected):
    text = channel_holds.describe(state)
    assert text.startswith(expected)
    assert not JARGON.search(text) and not any(word in text for word in PRIVATE)


def test_the_next_step_is_one_signal_and_irc_actually_have():
    for state in (_state(state="holding", held=1), _state(state="holding", retrying=1)):
        text = channel_holds.describe(state)
        assert RESTART in text
        assert "test message" not in text and "Test connection" not in text


def test_an_app_that_is_not_reporting_is_named_with_steps_for_a_running_or_stopped_service():
    text = channel_holds.describe(_state(state="not_reporting", reporting=[], not_reporting=["irc"]))
    assert text.startswith("IRC is turned on") and "Signal" not in text
    assert "If the chat service is stopped, start it" in text and "If it is running, restart it" in text


def test_replies_behind_an_unreadable_one_say_when_they_go_out_at_the_latest():
    release = 1_800_000_000.0
    text = channel_holds.describe(_state(state="holding", held=5, behind_unreadable=3, unreadable=1,
                                         release_at=release))
    assert ("3 chat replies are waiting because an earlier reply in the same chat cannot be read right now. "
            f"They go out once it can be read, or by {datetime_text(release)} at the latest.") in text
    assert "2 more are waiting for an earlier reply in the same chat to be sent first." in text
    assert "If this lasts, ask whoever manages this computer's encryption key to check that it is available." in text


def test_a_release_time_that_has_passed_is_not_promised_as_a_limit():
    release = 1_800_000_000.0
    text = channel_holds.describe(_state(state="holding", held=2, behind_unreadable=2, unreadable=1,
                                         release_at=release, release_passed=True))
    assert (f"They were due to go out at {datetime_text(release)} and go out as soon as the chat service "
            "finishes what it is working on.") in text
    assert "at the latest" not in text


def test_replies_that_went_ahead_of_an_expired_hold_are_reported():
    when = 1_800_000_000.0
    text = channel_holds.describe(_state(went_ahead=2, went_ahead_at=when))
    assert text.startswith("No IRC or Signal replies are waiting.")
    assert ("Since the chat service started, 2 replies went out without waiting, after an earlier reply "
            f"stayed unreadable for 24 hours (most recently {datetime_text(when)}).") in text


def test_replies_that_went_ahead_are_counted_only_for_the_apps_that_report(monkeypatch):
    # Each app's worker keeps its own count; one that stopped reporting took its count with it.
    from maverick_dashboard import product_operations_channel_holds as adapter

    state = _state(went_ahead=2, reporting=["signal"], not_reporting=["irc"])
    assert "Since the chat service started, 2 Signal replies went out without waiting" in channel_holds.describe(state)
    assert "1 Signal reply went out" in channel_holds.describe({**state, "went_ahead": 1})
    monkeypatch.setattr(channel_holds, "held_reply_status", lambda _request: {**state, "summary": "x"})
    details = adapter.snapshot(_request(), {}).details
    assert details["Went out without waiting since the chat service started (Signal only)"] == 2


def test_a_stale_status_and_a_quiet_app_are_named_not_counted_as_nothing_held():
    seen = 1_800_000_000.0
    stale = channel_holds.describe(_state(state="stale", reporting=[], last_seen=seen))
    # The chat service may be running without the app that last reported (a
    # status left by an earlier run), so the steps cover both.
    assert stale == (f"Held chat replies were last reported at {datetime_text(seen)} and have not been reported "
                     "since, so they cannot be checked. If the chat service is stopped, start it with Manage the "
                     "chat service. If it is running, restart it, then refresh this page. If your IT team runs it "
                     "on another computer, ask them.")
    partial = channel_holds.describe(_state(reporting=["signal"], not_reporting=["irc"]))
    assert partial.startswith("No Signal replies are waiting.")
    # An app stops reporting when its connection ends (nothing starts it
    # again) or when it was turned on after the chat service started; a
    # restart is the step for both.
    assert ("IRC is not reporting, so its replies cannot be checked. This happens when IRC loses its connection "
            "or was turned on after the chat service started. Restart the chat service with Manage the chat "
            "service, then refresh this page. If your IT team runs it on another computer, ask them.") in partial


def test_a_stale_status_beside_an_unreadable_one_keeps_the_encryption_key_step():
    seen = 1_800_000_000.0
    text = channel_holds.describe(_state(state="stale", reporting=[], last_seen=seen, unavailable=["signal"]))
    assert text.startswith(f"Held chat replies were last reported at {datetime_text(seen)}")
    assert ("A saved status for Signal could not be read. If this keeps happening, check that this computer's "
            "encryption key is available.") in text


def test_with_one_app_turned_off_the_answer_names_the_app_it_covers(monkeypatch):
    from maverick_dashboard import product_operations_channel_holds as adapter

    clear = _state(reporting=["irc"])
    assert channel_holds.describe(clear) == "No IRC replies are waiting."
    monkeypatch.setattr(channel_holds, "held_reply_status",
                        lambda _request: {**_state(state="holding", held=1, reporting=["irc"]), "summary": "x"})
    details = adapter.snapshot(_request(), {}).details
    assert details["Waiting behind an earlier reply (IRC only)"] == 1


def test_an_app_turned_off_but_still_running_is_explained():
    text = channel_holds.describe(_state(state="holding", held=3, running_off=["signal"]))
    assert "Signal is turned off, but the chat service keeps running it until the chat service is restarted." in text


def test_an_unreadable_status_names_its_app():
    text = channel_holds.describe(_state(unavailable=["irc"]))
    assert ("A saved status for IRC could not be read. If this keeps happening, check that this computer's "
            "encryption key is available.") in text


def test_status_is_admin_only_and_checked_before_anything_is_read(monkeypatch):
    def deny(*_args):
        raise HTTPException(status_code=403, detail="admin required")
    monkeypatch.setattr(channel_holds, "require_global_permission", deny)
    monkeypatch.setattr(hold_status, "summary", lambda *a, **k: pytest.fail("status read before authorization"))
    with pytest.raises(HTTPException) as error:
        channel_holds.held_reply_status(_request())
    assert error.value.status_code == 403


def test_status_reads_only_the_chat_apps_that_are_turned_on(monkeypatch):
    calls = []
    monkeypatch.setattr(channel_holds, "require_global_permission", lambda *a: None)
    monkeypatch.setattr(channel_holds, "_enabled_channels", lambda: {"signal"})
    monkeypatch.setattr(hold_status, "summary", lambda enabled, **k: calls.append(enabled) or _state())
    result = channel_holds.held_reply_status(_request())
    assert calls == [{"signal"}] and result["summary"] == "No IRC or Signal replies are waiting."


def test_the_message_delivery_panel_shows_the_answer(client, monkeypatch):
    release = time.time() + 3600
    publisher = _publish({"held": 2, "behind_unreadable": 2, "unreadable": 1, "release_at": release})
    monkeypatch.setattr(channel_holds, "_enabled_channels", lambda: {"signal"})
    page = client.get("/channels")
    assert page.status_code == 200
    text = visible_text(page.text)
    assert "2 chat replies are waiting because an earlier reply in the same chat cannot be read right now." in text
    assert "data-ch-held-replies" in page.text
    assert not any(word in text for word in PRIVATE)
    publisher.close()
    assert "Signal is turned on but not reporting" in visible_text(client.get("/channels").text)


def test_the_panel_still_renders_when_the_answer_fails(client, monkeypatch):
    def broken(_request):
        raise OSError("status directory unavailable")
    monkeypatch.setattr(channel_holds, "held_reply_status", broken)
    page = client.get("/channels")
    assert page.status_code == 200
    assert "Held chat replies could not be checked. Refresh this page." in visible_text(page.text)


def test_copilot_gives_the_same_answer_read_only_under_the_same_check(client, monkeypatch):
    from maverick_dashboard import product_operations as operations

    assert "channels.held_replies" in operations.adapters()
    publisher = _publish({"held": 1})
    monkeypatch.setattr(channel_holds, "_enabled_channels", lambda: {"signal"})
    monkeypatch.setattr(operations, "_gate", lambda _request: None)
    monkeypatch.setattr(operations, "enabled_families", lambda: {"connections"})
    page_answer = channel_holds.held_reply_status(_request())["summary"]
    catalog = client.post("/api/v1/copilot/product-operations/catalog", json={"page": "/channels", "selection": {}}).json()
    action = next(row for row in catalog["operations"] if row["id"] == "channels.held_replies")
    assert action["label"] == "Check held chat replies"
    read = client.post("/api/v1/copilot/product-operations/prepare", json={
        "page": "/channels", "selection": {}, "operation": action["id"], "context": catalog["context"],
        "revision": action["revision"], "arguments": {}})
    assert read.status_code == 200 and read.json()["read_only"] is True
    assert page_answer in read.text and "Nothing was sent, resent or changed." in read.text
    assert not any(word in read.text for word in ("held_behind", "went_ahead_of", "chd-", "sha256"))
    proposed = client.post("/api/v1/copilot/product-operations/propose", json={
        "page": "/channels", "selection": {}, "context": catalog["context"],
        "message": "Are any chat replies waiting?"})
    assert proposed.status_code == 200 and "channels.held_replies" in proposed.text
    publisher.close()


def test_the_channels_page_suggests_the_held_replies_question():
    from maverick_dashboard import copilot_context

    context = copilot_context.context_for_page("/channels")
    suggestions = copilot_context.suggestions_for(context, frozenset({"view", "operate", "audit", "admin"}))
    assert "Are any chat replies waiting?" in suggestions


def test_copilot_counts_name_only_the_apps_that_are_reporting(monkeypatch):
    from maverick_dashboard import product_operations_channel_holds as adapter

    monkeypatch.setattr(channel_holds, "held_reply_status",
                        lambda _request: {**_state(reporting=["signal"], not_reporting=["irc"]), "summary": "x"})
    details = adapter.snapshot(_request(), {}).details
    assert "Waiting behind an earlier reply" not in details and "Waiting behind an earlier reply (Signal only)" in details


def test_copilot_is_refused_before_reading_for_someone_who_is_not_an_administrator(monkeypatch):
    from maverick_dashboard import product_operations_channel_holds as adapter

    def deny(*_args):
        raise HTTPException(status_code=403, detail="admin required")
    monkeypatch.setattr(channel_holds, "require_global_permission", deny)
    monkeypatch.setattr(hold_status, "summary", lambda *a, **k: pytest.fail("status read before authorization"))
    with pytest.raises(HTTPException) as error:
        adapter.snapshot(_request(), {})
    assert error.value.status_code == 403


def test_a_renewed_status_keeps_the_copilot_answer_current(monkeypatch):
    from maverick_dashboard import product_operations_channel_holds as adapter

    monkeypatch.setattr(channel_holds, "require_global_permission", lambda *a: None)
    monkeypatch.setattr(channel_holds, "_enabled_channels", lambda: {"signal"})
    clock = [time.time() - 60]  # both writes stay within the freshness window of the real clock
    publisher = _publish({"held": 1}, clock=lambda: clock[0])
    first = adapter.snapshot(_request(), {}).revision
    clock[0] += 30
    assert publisher.write_now()
    assert adapter.snapshot(_request(), {}).revision == first  # a renewal alone changes nothing a person sees
    publisher.update({"held": 2, "behind_unreadable": 0, "unreadable": 0, "retrying": 0, "release_at": None,
                      "went_ahead": 0, "went_ahead_at": None})
    assert publisher.write_now()
    assert adapter.snapshot(_request(), {}).revision != first
    publisher.close()


@pytest.mark.parametrize("value", ['"signal"', "true", '["signal"]'])
def test_a_wrongly_typed_chat_setting_leaves_copilot_working_on_the_settings_pages(client, monkeypatch, tmp_path,
                                                                                   value):
    from maverick import config

    path = tmp_path / "mvhome" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'channels = {value}\n[copilot]\noperation_families = ["connections"]\n')
    config.reset_config_cache()
    monkeypatch.setattr(channel_holds, "require_global_permission", lambda *a: None)
    for page in ("/settings", "/settings/all"):
        catalog = client.post("/api/v1/copilot/product-operations/catalog", json={"page": page, "selection": {}})
        assert catalog.status_code == 200
        action = next(row for row in catalog.json()["operations"] if row["id"] == "channels.held_replies")
        assert action["available"] is False
    assert channel_holds.page_summary(_request()) == channel_holds.UNAVAILABLE


def test_a_reply_tried_again_points_to_the_permitted_people_too():
    text = channel_holds.describe(_state(state="holding", retrying=1))
    assert RESTART in text
    assert ("A reply to someone who is no longer among the app's permitted people waits until they are permitted "
            "again; check the app's permitted people in All settings.") in text


def test_copilot_labels_say_what_each_count_is(monkeypatch):
    from maverick_dashboard import product_operations_channel_holds as adapter

    monkeypatch.setattr(channel_holds, "held_reply_status",
                        lambda _request: {**_state(state="holding", retrying=1), "summary": "x"})
    details = adapter.snapshot(_request(), {}).details
    # A reply tried again is waiting too, so no count reads as "replies waiting: 0" beside it.
    assert not any(label.startswith("Replies waiting") for label in details)
    assert details["Waiting behind an earlier reply"] == 0
    assert details["Could not be sent or handled, tried again"] == 1


def test_the_held_replies_question_is_answered_with_default_copilot_settings(client, monkeypatch):
    # With the Connections Copilot actions off (the default), the suggested
    # question still leads somewhere: to Message delivery, which has the answer.
    from maverick_dashboard import product_operations as operations

    assert "connections" not in operations.enabled_families()
    payload = client.post("/api/v1/copilot", json={"message": "Are any chat replies waiting?", "page": "/channels",
                                                   "history": []}).json()
    link = payload["action_link"]
    assert (link["href"], link.get("focus"), link["label"]) == ("/channels", "channel-delivery", "Open Message delivery")


def test_only_administrators_are_offered_the_held_replies_question():
    from maverick_dashboard import copilot_context

    context = copilot_context.context_for_page("/channels")
    assert "Are any chat replies waiting?" not in copilot_context.suggestions_for(context, frozenset({"view",
                                                                                                    "operate"}))
