"""Security boundary for persisted browser cookies and localStorage."""
from __future__ import annotations

import json

from maverick.file_lock import private_path_is_restricted
from maverick.tools import browser


class _Context:
    def __init__(self):
        self.calls = 0

    def storage_state(self):
        self.calls += 1
        return {
            "cookies": [{"name": "session", "value": "secret-cookie"}],
            "origins": [],
        }


def test_save_state_is_published_privately(monkeypatch, tmp_path):
    path = tmp_path / "browser" / "state.json"
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(path))
    session = browser._BrowserSession()
    session._context = _Context()

    assert session.save_state() is True
    assert session._context.calls == 1
    assert json.loads(path.read_text(encoding="utf-8"))["cookies"][0]["value"] == (
        "secret-cookie"
    )
    assert private_path_is_restricted(path)


def test_restore_tightens_legacy_state_before_playwright_reads(monkeypatch, tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"cookies":[],"origins":[]}', encoding="utf-8")
    path.chmod(0o644)
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(path))

    assert browser._restore_state_arg() == str(path)
    assert private_path_is_restricted(path)
