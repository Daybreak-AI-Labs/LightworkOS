"""Content-access lists name people, never raw sign-in identities."""
from __future__ import annotations

import json
from types import SimpleNamespace

from maverick_dashboard import content_access_api as api

RAW = "user:google-oauth2|115836816027351327475"


def test_export_choices_name_the_person_not_the_identity(monkeypatch):
    from maverick_dashboard import _shared, compliance_controls_api

    world = SimpleNamespace(list_approvals=lambda limit: [], list_goals=lambda **k: [])
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr(compliance_controls_api, "_list_people", lambda: [
        {"channel": "web", "user": RAW + "/34", "person": RAW + "/34", "channel_label": "Web"}])
    (row,) = api._resources()
    assert "google-oauth2" not in row["label"] and "1158368160273" not in row["label"]
    assert row["label"].startswith("Google account")
    assert row["label"].endswith("Web data export")


def test_saved_records_show_readable_people(monkeypatch):
    record = {"id": "CA-1", "revision": 1, "requester": RAW, "owner": "channel:" + json.dumps(["web", RAW + "/34"]),
              "resource_kind": "subject_data", "resource_id": json.dumps(["web", RAW + "/34"]),
              "label": RAW + "/34 · Web data export", "purpose": "employee_support", "minutes": 15,
              "status": "requested"}
    monkeypatch.setattr(api.content_access, "_reviewer_current", lambda row: False)
    mine = api._public(record, RAW, True)
    assert mine["requester_label"] == "You"
    assert "google-oauth2" not in mine["label"]
    other = api._public(record, "user:someone-else", True)
    assert other["requester_label"].startswith("Google account")
