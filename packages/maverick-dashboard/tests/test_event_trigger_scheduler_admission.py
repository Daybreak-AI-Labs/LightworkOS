"""Automatic event polling re-admits durable host-resource configurations."""
from __future__ import annotations

import json
import os
import subprocess

import pytest


@pytest.fixture(autouse=True)
def _isolated_scheduler(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    from maverick import config, templates, world_model
    from maverick_dashboard import automation_queue

    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    template_dir = home / "templates"
    template_dir.mkdir(parents=True)
    monkeypatch.setattr(templates, "USER_TEMPLATES", template_dir)
    (template_dir / "triage.md").write_text(
        "---\ntitle: Triage {{title}}\nparams:\n  - title\n---\nHandle {{title}}.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(automation_queue, "_queue", None)
    monkeypatch.setattr(automation_queue, "_worker", None)
    monkeypatch.setattr(automation_queue, "_worker_threads", [])
    world = world_model.WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(automation_queue, "_world", lambda: world)
    monkeypatch.setattr(
        "maverick_dashboard.auth.stored_automation_identity",
        lambda _owner: ("", None, None),
    )
    yield
    world.close()
    config.reset_config_cache()


def _arm(name: str, config: dict) -> None:
    from maverick_dashboard import event_triggers_store

    event_triggers_store.set_trigger(
        name,
        "triage",
        "file_dir",
        config=config,
        interval_seconds=3600,
    )


def _capture_source_polls(monkeypatch):
    from maverick import automation_events

    calls = []

    def poll(source, config, cursor):
        calls.append((source, dict(config), cursor))
        return automation_events.PollResult(events=[], cursor="accepted")

    monkeypatch.setattr(automation_events, "poll_source", poll)
    return calls


def _assert_refused_without_poll(name: str, calls: list) -> None:
    from maverick_dashboard import automation_queue, trigger_events_store

    assert calls == []
    assert automation_queue._due(name, 3600) is True
    history = trigger_events_store.history(name=name)
    assert history and history[0]["kind"] == trigger_events_store.POLL_ERROR
    assert "event-input root" in history[0]["note"]


def test_automatic_scheduler_rejects_legacy_arbitrary_directory(
    tmp_path, monkeypatch
):
    from maverick_dashboard import automation_queue

    outside = tmp_path / "legacy-outside"
    outside.mkdir()
    _arm("legacy-path", {"path": os.fspath(outside)})
    calls = _capture_source_polls(monkeypatch)

    automation_queue._poll_due_triggers()

    _assert_refused_without_poll("legacy-path", calls)


@pytest.mark.parametrize(
    ("source", "config"),
    [
        (
            "imap_email",
            {
                "host": "mail.example",
                "username": "operator",
                "password_env": "IMAP_PASSWORD",  # pragma: allowlist secret
            },
        ),
        ("github_issues", {"owner": "acme", "repo": "private"}),
    ],
)
def test_automatic_scheduler_revalidates_process_resource_authority(
    monkeypatch, source, config
):
    from maverick_dashboard import (
        auth,
        automation_queue,
        event_triggers_store,
        trigger_events_store,
    )

    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda _owner: "operator")
    trigger = event_triggers_store.set_trigger(
        f"process-{source}",
        "triage",
        source,
        config=config,
        owner="user:operator",
        interval_seconds=3600,
    )
    calls = _capture_source_polls(monkeypatch)

    automation_queue._poll_due_triggers()

    assert calls == []
    assert automation_queue._due(trigger["name"], 3600) is True
    history = trigger_events_store.history(name=trigger["name"])
    assert history and history[0]["kind"] == trigger_events_store.POLL_ERROR
    assert history[0]["note"] == "trigger authorization unavailable"


def test_automatic_scheduler_rejects_post_save_path_tamper(tmp_path, monkeypatch):
    from maverick.paths import data_dir
    from maverick_dashboard import automation_queue, event_triggers_store

    data_dir("event-input", "incoming").mkdir(parents=True)
    _arm("tampered-path", {"path": "incoming"})
    outside = tmp_path / "tampered-outside"
    outside.mkdir()

    store_path = event_triggers_store._path()
    original = json.dumps(json.dumps({"path": "incoming"}, sort_keys=True))
    replacement = json.dumps(
        json.dumps({"path": os.fspath(outside)}, sort_keys=True)
    )
    stored = store_path.read_text(encoding="utf-8")
    assert original in stored
    store_path.write_text(stored.replace(original, replacement), encoding="utf-8")
    calls = _capture_source_polls(monkeypatch)

    automation_queue._poll_due_triggers()

    _assert_refused_without_poll("tampered-path", calls)


def _make_directory_link(link, target) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError:
        if os.name != "nt":
            raise

    # Windows directory junctions are reparse points and do not require the
    # symbolic-link privilege. This exercises the Windows escape path directly.
    command = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    result = subprocess.run(  # noqa: S603
        [command, "/d", "/c", "mklink", "/J", os.fspath(link), os.fspath(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        pytest.skip(f"could not create a directory reparse point: {result.stderr}")


def test_automatic_scheduler_rejects_symlink_or_reparse_escape(
    tmp_path, monkeypatch
):
    from maverick.paths import data_dir
    from maverick_dashboard import automation_queue

    root = data_dir("event-input")
    root.mkdir(parents=True)
    outside = tmp_path / "reparse-outside"
    outside.mkdir()
    link = root / "escape"
    _make_directory_link(link, outside)
    assert link.resolve() == outside.resolve()
    _arm("reparse-path", {"path": "escape"})
    calls = _capture_source_polls(monkeypatch)

    automation_queue._poll_due_triggers()

    _assert_refused_without_poll("reparse-path", calls)


def test_automatic_scheduler_rejects_reparse_event_input_root(
    tmp_path, monkeypatch
):
    from maverick.paths import data_dir
    from maverick_dashboard import automation_queue, trigger_events_store

    outside = tmp_path / "root-reparse-outside"
    outside.mkdir()
    root = data_dir("event-input")
    _make_directory_link(root, outside)
    _arm("reparse-root", {"path": "incoming"})
    calls = _capture_source_polls(monkeypatch)

    automation_queue._poll_due_triggers()

    assert calls == []
    assert automation_queue._due("reparse-root", 3600) is True
    history = trigger_events_store.history(name="reparse-root")
    assert history and history[0]["kind"] == trigger_events_store.POLL_ERROR
    assert "symlink or reparse point" in history[0]["note"]


def test_automatic_scheduler_polls_valid_confined_directory(monkeypatch):
    from maverick.paths import data_dir
    from maverick_dashboard import (
        automation_queue,
        event_triggers_store,
        trigger_events_store,
    )

    confined = data_dir("event-input", "incoming")
    confined.mkdir(parents=True)
    _arm("confined-path", {"path": "incoming", "glob": "*.json"})
    calls = _capture_source_polls(monkeypatch)

    automation_queue._poll_due_triggers()

    assert calls == [
        (
            "file_dir",
            {"path": os.fspath(confined.resolve()), "glob": "*.json", "_lightwork_cursor_format": 0},
            "",
        )
    ]
    assert event_triggers_store.get_trigger("confined-path")["cursor"] == "accepted"
    assert automation_queue._due("confined-path", 3600) is False
    assert trigger_events_store.history(name="confined-path") == []
