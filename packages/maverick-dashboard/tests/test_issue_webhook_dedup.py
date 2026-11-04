"""Issue-webhook replay dedup: in-process window + shared store under HA."""
from __future__ import annotations

import maverick_dashboard.app as app_mod


class _FakeSharedWorld:
    """First-writer-wins stand-in for mark_message_processed."""

    def __init__(self):
        self.seen: set[tuple[str, str]] = set()

    def mark_message_processed(self, channel, external_id, goal_id=None):
        key = (channel, external_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


def test_in_process_window_is_default(monkeypatch):
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    app_mod._issue_webhook_seen.clear()

    assert app_mod._issue_webhook_replay_seen("sig-1", 300) is False  # first delivery
    assert app_mod._issue_webhook_replay_seen("sig-1", 300) is True   # replay
    assert "sig-1" in app_mod._issue_webhook_seen


def test_shared_store_used_under_postgres(monkeypatch):
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    fake = _FakeSharedWorld()
    monkeypatch.setattr(app_mod, "_world", lambda: fake)
    app_mod._issue_webhook_seen.clear()

    assert app_mod._issue_webhook_replay_seen("sig-A", 300) is False  # first
    assert app_mod._issue_webhook_replay_seen("sig-A", 300) is True   # replay
    # recorded in the shared store under the namespaced channel; in-process
    # window was bypassed entirely.
    assert (app_mod._ISSUE_WEBHOOK_CHANNEL, "sig-A") in fake.seen
    assert app_mod._issue_webhook_seen == {}


def test_falls_back_when_shared_store_errors(monkeypatch):
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)

    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(app_mod, "_world", _boom)
    app_mod._issue_webhook_seen.clear()

    assert app_mod._issue_webhook_replay_seen("sig-Z", 300) is False
    assert app_mod._issue_webhook_replay_seen("sig-Z", 300) is True
    assert "sig-Z" in app_mod._issue_webhook_seen  # fell back to in-process
