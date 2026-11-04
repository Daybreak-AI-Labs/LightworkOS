"""Preference summaries report native memory ceilings without widening them."""
from __future__ import annotations

import pytest
from maverick_dashboard import preference_memory as module


@pytest.fixture
def setup(monkeypatch):
    state = {"current": True, "enabled": True, "admin": True, "source": None,
             "scopes": [{"id": "dashboard", "channel": "dashboard", "user_id": "owner"},
                        {"id": "verified-scope", "channel": "slack", "user_id": "verified-account-and-sender"}],
             "controls": {"dashboard": {"revision": 0, "recall": True}, "slack": {"revision": 2, "recall": False}}}
    monkeypatch.setattr(module.auth, "caller_principal", lambda request: "user:owner")
    monkeypatch.setattr(module.personal_identity, "principal_current", lambda principal: state["current"])
    monkeypatch.setattr(module.personal_identity, "enabled", lambda: state["enabled"])
    monkeypatch.setattr(module.config, "config_source_errors", lambda **kwargs: {})
    monkeypatch.setattr(module.config, "get_dreaming", lambda: {"user_notes": state["admin"]})
    monkeypatch.setattr(module.personal_memory, "owned_scopes", lambda principal: state["scopes"])
    monkeypatch.setattr(module.personal_memory, "profile", lambda principal: {"shared_source": state["source"]})
    monkeypatch.setattr(module.personal_memory, "controls", lambda channel, user_id: state["controls"][channel])
    return state


def test_only_verified_scopes_and_saved_sources_are_shown_without_note_content(setup):
    result = module.describe(object())
    assert result["available"] and len(result["scopes"]) == 2
    assert result["scopes"][0]["effective"] == "Allowed" and "Product default" in result["scopes"][0]["source"]
    assert result["scopes"][1]["effective"] == "Off" and result["scopes"][1]["source"] == "Your saved channel choice"
    assert "verified-account-and-sender" not in str(result)


@pytest.mark.parametrize("boundary", ["admin", "enabled", "current"])
def test_personal_choices_never_expand_administrator_or_identity_boundary(setup, boundary):
    setup[boundary] = False
    result = module.describe(object())
    assert not result["available"] if boundary != "admin" else all(row["effective"] == "Off" for row in result["scopes"])


def test_shared_source_off_narrows_recall_on_every_verified_destination(setup):
    setup["source"] = "verified-scope"
    assert all(row["effective"] == "Off" for row in module.describe(object())["scopes"])


def test_corrupt_or_unavailable_owned_state_is_not_reported_as_an_enabled_default(setup, monkeypatch):
    def broken(*args):
        raise ValueError("corrupt owner data")
    monkeypatch.setattr(module.personal_memory, "controls", broken)
    result = module.describe(object())
    assert not result["available"] and result["scopes"] == []
    assert "corrupt owner data" not in str(result)
