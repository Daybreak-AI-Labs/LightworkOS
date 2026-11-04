"""The Ekko CLI keeps enrollment, observer selection, and drafts explicit."""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner
from maverick.cli import _ekko_groups, main


def _invoke(*args: str):
    return CliRunner().invoke(main, ["ekko", *args])


def test_ekko_help_surfaces_full_client_lifecycle():
    result = _invoke("--help")

    assert result.exit_code == 0, result.output
    for command in (
        "status", "enroll", "revoke", "run", "pause", "resume", "stop",
        "discover", "erase", "forget",
    ):
        assert command in result.output


def test_ekko_status_requires_explicit_device():
    result = _invoke("status")

    assert result.exit_code == 2
    assert "--device" in result.output


def test_ekko_cli_rejects_owner_impersonation_option():
    result = _invoke(
        "status", "--device", "laptop-1", "--owner", "user:mallory",
    )

    assert result.exit_code == 2
    assert "No such option '--owner'" in result.output


def test_ekko_status_reports_policy_without_echoing_scope_ids(monkeypatch):
    class Store:
        def status(self):
            return {
                "enrollment": None,
                "session": None,
                "event_count": 0,
            }

    monkeypatch.setattr(_ekko_groups, "_store", lambda *a, **k: Store())
    monkeypatch.setattr(
        "maverick.config.get_ekko",
        lambda: {"enable": False, "allowed_apps": [], "provider_egress": False},
    )

    result = _invoke("status", "--device", "laptop-1")

    assert result.exit_code == 0, result.output
    assert "policy: off" in result.output
    assert "enrollment: none" in result.output
    assert "alice" not in result.output
    assert "laptop-1" not in result.output


def test_ekko_enroll_narrows_apps_and_sets_bounded_expiry(monkeypatch):
    captured = {}
    policy = SimpleNamespace(fingerprint=lambda: "b" * 64)

    class Store:
        def enroll(self, selected, *, expires_at):
            captured["policy"] = selected
            captured["expires_at"] = expires_at
            return SimpleNamespace(expires_at=expires_at)

    def build_policy(*, allowed_apps=None):
        captured["apps"] = allowed_apps
        return policy

    monkeypatch.setattr(_ekko_groups, "_store", lambda *a, **k: Store())
    monkeypatch.setattr("maverick.config.get_ekko_policy", build_policy)
    monkeypatch.setattr(
        "maverick.config.get_ekko", lambda: {"enrollment_days": 30},
    )
    before = time.time()

    result = _invoke(
        "enroll", "--device", "laptop-1",
        "--apps", " Excel, POWERPOINT,excel ", "--days", "7",
    )

    assert result.exit_code == 0, result.output
    assert captured["apps"] == ["excel", "powerpoint"]
    assert captured["policy"] is policy
    assert before + 7 * 86_400 <= captured["expires_at"] <= time.time() + 7 * 86_400


def test_ekko_enroll_fails_closed_before_store_when_audit_is_unavailable(monkeypatch):
    touched = {"value": False}
    policy = SimpleNamespace(fingerprint=lambda: "a" * 64)

    class Store:
        def enroll(self, *_args, **_kwargs):
            touched["value"] = True

    monkeypatch.setattr(_ekko_groups, "_store", lambda *a, **k: Store())
    monkeypatch.setattr("maverick.config.get_ekko_policy", lambda **_k: policy)
    monkeypatch.setattr("maverick.config.get_ekko", lambda: {"enrollment_days": 30})
    monkeypatch.setattr("maverick.audit.record", lambda *_a, **_k: False)

    result = _invoke(
        "enroll", "--device", "laptop-1",
        "--apps", "excel",
    )

    assert result.exit_code == 1
    assert "audit" in result.output.lower()
    assert touched["value"] is False


def test_ekko_run_never_selects_an_observer_implicitly():
    result = _invoke("run", "--device", "laptop-1")

    assert result.exit_code == 2
    assert "choose an explicit observer" in result.output


def test_ekko_run_rejects_two_observers_before_touching_store(tmp_path: Path):
    events = tmp_path / "events.jsonl"
    events.write_text("", encoding="utf-8")

    result = _invoke(
        "run", "--device", "laptop-1",
        "--events", str(events), "--observer", "windows",
    )

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_guided_observer_rejects_forbidden_fields_without_echoing_them(tmp_path: Path):
    secret = "never-print-this-window-title"  # pragma: allowlist secret
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({
        "app": "excel",
        "action": "open",
        "window_title": secret,
    }) + "\n", encoding="utf-8")
    observer = _ekko_groups._GuidedJsonlObserver(path)

    try:
        try:
            observer.observe()
        except ValueError as exc:
            message = str(exc)
        else:  # pragma: no cover - regression diagnostic
            raise AssertionError("forbidden field was accepted")
    finally:
        observer.close()

    assert "line 1" in message
    assert secret not in message


def test_guided_observer_accepts_only_semantic_activity(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({
        "app": "excel",
        "action": "open",
        "object_type": "report",
        "duration_seconds": 2.5,
    }) + "\n", encoding="utf-8")
    observer = _ekko_groups._GuidedJsonlObserver(path)

    try:
        activity = observer.observe()
        assert activity.to_dict() == {
            "app": "excel",
            "action": "open",
            "object_type": "report",
            "duration_seconds": 2.5,
        }
        assert observer.observe() is None
        assert observer.exhausted is True
    finally:
        observer.close()


def test_ekko_erase_requires_irreversible_acknowledgement(monkeypatch):
    touched = {"value": False}

    class Store:
        def erase(self, **kwargs):
            touched["value"] = True
            return {"events": 0, "sessions": 0}

    monkeypatch.setattr(_ekko_groups, "_store", lambda *a, **k: Store())

    result = _invoke("erase", "--device", "laptop-1")

    assert result.exit_code == 1
    assert "without --yes" in result.output
    assert touched["value"] is False


def test_ekko_erase_reports_local_deletion(monkeypatch):
    class Store:
        def erase(self, *, session_id=None):
            assert session_id == "session-1"
            return {"events": 4, "sessions": 1}

    monkeypatch.setattr(_ekko_groups, "_store", lambda *a, **k: Store())

    result = _invoke(
        "erase", "--device", "laptop-1",
        "--session", "session-1", "--yes",
    )

    assert result.exit_code == 0, result.output
    assert "4 event(s)" in result.output
    assert "1 session(s)" in result.output
