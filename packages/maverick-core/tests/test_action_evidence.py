"""Tests for tamper-evident before/after capture of governed actions."""
from __future__ import annotations

import base64

import pytest
from maverick.safety import action_evidence
from maverick.safety.action_gate import browser_action_risk, computer_action_risk

_FAKE_PNG = base64.b64encode(b"not-a-real-png-but-sealable").decode()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick.audit import writer as audit_writer
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    yield


def _events():
    from maverick.audit import iter_events
    return list(iter_events(all_days=True))


def _enable_sealing(monkeypatch):
    monkeypatch.setenv("MAVERICK_SCREENSHOT_KEY", "test-seal-key")  # pragma: allowlist secret


# --- risk classifiers (now exposed for the evidence hook) -------------------

def test_computer_action_risk():
    assert computer_action_risk("screenshot", {}) is None
    assert computer_action_risk("mouse_move", {"coordinate": [1, 2]}) == "medium"
    assert computer_action_risk("left_click", {"coordinate": [1, 2]}) == "medium"
    assert computer_action_risk("key", {"text": "Return"}) == "high"
    assert computer_action_risk("type", {"text": "please pay now"}) == "high"


def test_browser_action_risk():
    assert browser_action_risk("extract_text", {}) is None
    assert browser_action_risk("click", {"selector": "#search"}) == "medium"
    assert browser_action_risk("click", {"selector": "text=Pay now"}) == "high"
    assert browser_action_risk("fill_form", {"fields": {"#x": "wire transfer"}}) == "high"


# --- sealing on/off ---------------------------------------------------------

def test_sealing_disabled_without_key(monkeypatch):
    monkeypatch.delenv("MAVERICK_SCREENSHOT_KEY", raising=False)
    assert action_evidence.sealing_enabled() is False


def test_sealing_enabled_with_key(monkeypatch):
    _enable_sealing(monkeypatch)
    assert action_evidence.sealing_enabled() is True


def test_seal_bracketed_noop_without_key(monkeypatch):
    monkeypatch.delenv("MAVERICK_SCREENSHOT_KEY", raising=False)
    calls = []

    def capture():
        raise AssertionError("must not capture when sealing is off")

    out = action_evidence.seal_bracketed(
        capture, lambda: calls.append("ran") or "ok", action="browser.click",
    )
    assert out == "ok" and calls == ["ran"]
    assert [e for e in _events() if e.get("kind") == "evidence_capture"] == []


def test_seal_bracketed_seals_before_and_after(monkeypatch):
    _enable_sealing(monkeypatch)
    out = action_evidence.seal_bracketed(
        lambda: _FAKE_PNG, lambda: "ok", action="browser.click",
    )
    assert out == "ok"
    evs = [e for e in _events() if e.get("kind") == "evidence_capture"]
    assert sorted(e.get("phase") for e in evs) == ["after", "before"]
    assert all(e.get("action") == "browser.click" for e in evs)
    assert all(e.get("sha256") for e in evs)


def test_seal_bracketed_after_runs_even_on_error(monkeypatch):
    _enable_sealing(monkeypatch)

    def boom():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        action_evidence.seal_bracketed(lambda: _FAKE_PNG, boom, action="computer.left_click")
    evs = [e for e in _events() if e.get("kind") == "evidence_capture"]
    # before + after both sealed despite the action raising
    assert sorted(e.get("phase") for e in evs) == ["after", "before"]


def test_evidence_correlates_to_goal_context(monkeypatch):
    _enable_sealing(monkeypatch)
    from maverick.audit import goal_context
    with goal_context(55):
        action_evidence.seal_bracketed(lambda: _FAKE_PNG, lambda: "ok", action="computer.key")
    evs = [e for e in _events() if e.get("kind") == "evidence_capture"]
    assert evs and all(e.get("goal_id") == 55 for e in evs)
