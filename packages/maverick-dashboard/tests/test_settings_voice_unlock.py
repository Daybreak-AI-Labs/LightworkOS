"""Voice unlock: record your voice, then spoken requests are checked against it.

The speaker model sits behind ``maverick.voice_unlock``'s embedder interface;
these tests use a deterministic stub (``_embed``) so enrolment, accepting,
rejecting and the threshold are exact. Without the optional voice-unlock
extra the page says so, recording is refused and the switch can't be turned
on. The Settings > Budget form's protected change goes through the same
approval flow as All settings.
"""
from __future__ import annotations

import io
import json
import math

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

from test_support.settings_pages import save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
UNLOCK = "/api/v1/voice/unlock"
_ENV = ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
        "MAVERICK_VOICE_UNLOCK", "MAVERICK_VOICE_COMMANDS", "MAVERICK_QUORUM_REQUIRED",
        "MAVERICK_ALLOW_SELF_APPROVAL")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


# Deterministic stand-in for the speaker model: "alice..." recordings point
# one way, "bob..." another, and "alice-near" sits at cosine 0.7 from Alice.
_VOICES = {b"alice": [1.0, 0.0, 0.0], b"bob": [0.0, 1.0, 0.0],
           b"alice-near": [0.7, math.sqrt(1 - 0.49), 0.0]}


def _embed(audio: bytes) -> list[float]:
    for name in sorted(_VOICES, key=len, reverse=True):
        if audio.startswith(name):
            return _VOICES[name]
    raise ValueError("send the recording as a WAV file")


@pytest.fixture()
def model_ready(monkeypatch):
    from maverick import voice_unlock

    monkeypatch.setattr(voice_unlock, "readiness", lambda model_path=None: None)
    monkeypatch.setattr(voice_unlock, "configured_embedder", lambda: _embed)


def _save(changes, confirm=False):
    return save_catalog(client, API, json={"changes": changes, "confirm": confirm})


def _files(*clips):
    return [("files", (f"s{i}.wav", io.BytesIO(c), "audio/wav")) for i, c in enumerate(clips)]


def _check(clip):
    return client.post(UNLOCK + "/check", files={"file": ("c.wav", io.BytesIO(clip), "audio/wav")})


def _speak(clip):
    return client.post("/api/v1/voice/transcribe",
                       files={"file": ("voice.wav", io.BytesIO(clip), "audio/wav")})


def test_without_the_extra_the_page_says_so_and_nothing_turns_on(monkeypatch, audit_rows):
    from maverick import voice_unlock

    monkeypatch.setattr(voice_unlock, "extra_installed", lambda: False)
    page = client.get("/settings/voice-unlock")
    assert page.status_code == 200
    assert "needs the voice-unlock add-on" in page.text
    assert 'id="vu-record"' not in page.text  # no recording controls
    r = client.post(UNLOCK + "/enrol", files=_files(b"alice1", b"alice2", b"alice3"))
    assert r.status_code == 409 and "voice-unlock add-on" in r.json()["detail"]
    r = _save([{"id": "voice.biometric_unlock", "value": True}])
    assert r.status_code == 400 and "voice-unlock add-on" in r.json()["message"]
    assert audit_rows == []


def test_switch_needs_a_model_folder_even_with_the_extra(monkeypatch, tmp_path, audit_rows):
    from maverick import voice_unlock

    monkeypatch.setattr(voice_unlock, "extra_installed", lambda: True)
    r = _save([{"id": "voice.biometric_unlock", "value": True}])
    assert r.status_code == 400 and "speaker-recognition model" in r.json()["message"]
    folder = tmp_path / "ecapa"
    folder.mkdir()
    (folder / "hyperparams.yaml").write_text("x: 1\n", encoding="utf-8")
    r = _save([{"id": "voice.speaker_model_path", "value": str(folder)},
               {"id": "voice.biometric_unlock", "value": True}])
    assert r.status_code == 200, r.text
    assert voice_unlock.enabled() and voice_unlock.speaker_model_path() == str(folder)


def test_enrol_accept_reject_and_delete(model_ready, tmp_path, audit_rows):
    from maverick.paths import data_dir

    r = client.post(UNLOCK + "/enrol", files=_files(b"alice1", b"alice2"))
    assert r.status_code == 400  # at least three samples
    r = client.post(UNLOCK + "/enrol", files=_files(b"alice1", b"alice2", b"alice3"))
    assert r.status_code == 200, r.text
    assert r.json()["enrolled"] is True
    assert audit_rows[-1]["kind"] == "voice_profile_enrolled" and audit_rows[-1]["samples"] == 3
    stored = data_dir("voice_profiles.json").read_bytes()
    assert b"alice1" not in stored and b"sealed" in stored  # a sealed print, no audio

    assert _check(b"alice9").status_code == 409  # the switch is still off
    assert _save([{"id": "voice.biometric_unlock", "value": True}]).status_code == 200

    ok = _check(b"alice9").json()
    assert ok["matched"] is True and ok["score"] == pytest.approx(1.0)
    no = _check(b"bob1").json()
    assert no["matched"] is False
    assert [row["matched"] for row in audit_rows if row["kind"] == "voice_unlock_checked"] \
        == [True, False]

    r = client.delete(UNLOCK + "/profile")
    assert r.status_code == 200 and r.json()["removed"] is True
    assert audit_rows[-1]["kind"] == "voice_profile_deleted"
    assert _check(b"alice9").status_code == 409  # nothing left to check against


def test_spoken_requests_are_heard_only_in_the_recorded_voice(model_ready, monkeypatch,
                                                              audit_rows):
    import maverick.tools.voice as voice_mod

    monkeypatch.setattr(voice_mod, "_run_transcribe", lambda args, sandbox=None: "hello")
    assert client.post(UNLOCK + "/enrol",
                       files=_files(b"alice1", b"alice2", b"alice3")).status_code == 200
    assert _speak(b"bob1").status_code == 200  # switch off: nothing is checked
    assert _save([{"id": "voice.biometric_unlock", "value": True}]).status_code == 200
    refused = _speak(b"bob1")
    assert refused.status_code == 403 and "recorded voice" in refused.json()["detail"]
    assert _speak(b"alice7").json() == {"text": "hello"}
    assert audit_rows[-1]["surface"] == "spoken_request" and audit_rows[-1]["matched"]
    assert _speak(b"not a wav").status_code == 403  # unreadable: refused, not waved through
    client.delete(UNLOCK + "/profile")
    assert _speak(b"bob1").status_code == 200  # no recorded voice, no check


def test_threshold_decides_near_matches_and_lowering_it_is_confirmed(model_ready, audit_rows):
    assert client.post(UNLOCK + "/enrol",
                       files=_files(b"alice1", b"alice2", b"alice3")).status_code == 200
    assert _save([{"id": "voice.biometric_unlock", "value": True}]).status_code == 200
    near = _check(b"alice-near")
    assert near.json()["matched"] is True and near.json()["threshold"] == 0.6
    assert _save([{"id": "voice.unlock_threshold", "value": 80}]).status_code == 200
    assert _check(b"alice-near").json()["matched"] is False
    r = _save([{"id": "voice.unlock_threshold", "value": 50}])
    assert r.status_code == 409 and r.json()["confirm"][0]["id"] == "voice.unlock_threshold"
    assert _save([{"id": "voice.unlock_threshold", "value": 50}], confirm=True).status_code == 200
    assert _check(b"alice-near").json()["matched"] is True


def test_page_offers_recording_when_ready(model_ready):
    page = client.get("/settings/voice-unlock").text
    assert 'id="vu-record"' in page and 'for="vu-files"' in page
    assert "You haven't recorded your voice yet." in page


# ------------------------------------------------ budget form under a quorum
def test_budget_form_change_waits_for_approval(audit_rows):
    from maverick.runtime_overrides import budget_override
    from maverick_dashboard._shared import _world

    assert client.post("/settings/budget", data={"mode": "configured", "max_dollars": "5"},
                       follow_redirects=False).status_code == 303  # no quorum: saved
    assert budget_override() == 5.0
    assert _save([{"id": "safety.quorum_required", "value": "2"}]).status_code == 200

    form = {"mode": "disabled", "max_dollars": "5"}
    r = client.post("/settings/budget", data=form, follow_redirects=False)
    assert r.status_code == 202 and "needs 2 approvals" in r.text
    assert 'id="settings-notice"' in r.text
    held = client.post("/settings/budget", data=form, follow_redirects=False,
                       headers={"Accept": "application/json"})
    assert held.status_code == 202 and "0 of 2" in held.json()["message"]
    approval_id = held.json()["quorum"]["approval_id"]
    approval = _world().get_approval(approval_id)
    assert "Spending limit per task: " in approval.detail
    assert "No limit for each task" in approval.detail

    world = _world()
    assert world.decide_approval(approval_id, "approved", decided_by="user:alice")
    assert world.decide_approval(approval_id, "approved", decided_by="user:bob")
    r = client.post("/settings/budget", data=form, follow_redirects=False)
    assert r.status_code == 303
    from maverick.runtime_overrides import task_limits_override

    assert task_limits_override() is False
    # Re-saving what is already in place changes nothing and needs no approval.
    assert client.post("/settings/budget", data=form,
                       follow_redirects=False).status_code == 303


def test_budget_form_still_refuses_bad_amounts(audit_rows):
    assert _save([{"id": "safety.quorum_required", "value": "2"}]).status_code == 200
    r = client.post("/settings/budget", data={"mode": "configured", "max_dollars": "-3"},
                    follow_redirects=False)
    assert r.status_code == 400
    assert json.loads(r.text)["detail"] == "spend cap must be a positive number"
