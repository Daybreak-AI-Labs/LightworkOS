"""Goal attachments panel API: upload → list → download round-trip."""
from __future__ import annotations

import io
from pathlib import Path

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import attachments, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(attachments, "DEFAULT_ROOT", tmp_path / "attach")


def test_upload_list_download_roundtrip(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    from maverick_dashboard import app as app_mod
    gid = app_mod._world().create_goal("with files", "")

    r = c.post(
        f"/api/v1/goals/{gid}/attachments",
        files={"file": ("notes.txt", io.BytesIO(b"remember the milk"), "text/plain")},
    )
    assert r.status_code == 201, r.text
    aid = r.json()["id"]

    listed = c.get(f"/api/v1/goals/{gid}/attachments").json()
    assert [a["filename"] for a in listed] == ["notes.txt"]

    dl = c.get(f"/api/v1/goals/{gid}/attachments/{aid}/download")
    assert dl.status_code == 200
    assert dl.content == b"remember the milk"
    assert "attachment" in dl.headers["content-disposition"]
    assert "notes.txt" in dl.headers["content-disposition"]
    assert dl.headers["x-content-type-options"] == "nosniff"


def test_download_unicode_filename_uses_rfc5987_header(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    from maverick_dashboard import app as app_mod

    gid = app_mod._world().create_goal("unicode file", "")
    uploaded = c.post(
        f"/api/v1/goals/{gid}/attachments",
        files={"file": ("資料.txt", io.BytesIO(b"evidence"), "text/plain")},
    )
    assert uploaded.status_code == 201, uploaded.text

    downloaded = c.get(
        f"/api/v1/goals/{gid}/attachments/{uploaded.json()['id']}/download"
    )

    assert downloaded.status_code == 200
    assert downloaded.content == b"evidence"
    disposition = downloaded.headers["content-disposition"]
    assert "filename*=UTF-8''%E8%B3%87%E6%96%99.txt" in disposition


def test_plaintext_download_streams_file_without_reading_all_bytes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    # Unsealed downloads stream; GCM-sealed blobs must authenticate in full
    # within the separate decrypt budget before any plaintext is released.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    c = _client()
    from maverick_dashboard import app as app_mod
    gid = app_mod._world().create_goal("streamed file", "")

    r = c.post(
        f"/api/v1/goals/{gid}/attachments",
        files={"file": ("large.txt", io.BytesIO(b"x" * 1024), "text/plain")},
    )
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    stored = Path(app_mod._world().list_attachments(gid)[0].path)
    from maverick.attachments import is_sealed_file

    assert not is_sealed_file(stored)
    original_read_bytes = Path.read_bytes

    def fail_read_bytes(self):
        if self == stored:
            raise AssertionError("plaintext attachment must stream instead of read_bytes")
        return original_read_bytes(self)

    monkeypatch.setattr("pathlib.Path.read_bytes", fail_read_bytes)

    dl = c.get(f"/api/v1/goals/{gid}/attachments/{aid}/download")
    assert dl.status_code == 200
    assert dl.content == b"x" * 1024
    assert "attachment" in dl.headers["content-disposition"]
    assert dl.headers["x-content-type-options"] == "nosniff"


def test_download_404_for_wrong_attachment(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    from maverick_dashboard import app as app_mod
    gid = app_mod._world().create_goal("empty", "")
    r = c.get(f"/api/v1/goals/{gid}/attachments/999/download")
    assert r.status_code == 404


def test_sealed_attachment_downloads_as_plaintext(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    c = _client()
    from maverick_dashboard import app as app_mod
    gid = app_mod._world().create_goal("sealed file", "")
    r = c.post(f"/api/v1/goals/{gid}/attachments",
               files={"file": ("notes.txt", io.BytesIO(b"board minutes"), "text/plain")})
    assert r.status_code == 201, r.text
    att = app_mod._world().list_attachments(gid)[0]
    assert b"board minutes" not in Path(att.path).read_bytes()  # sealed on disk
    dl = c.get(f"/api/v1/goals/{gid}/attachments/{r.json()['id']}/download")
    assert dl.status_code == 200 and dl.content == b"board minutes"


def test_tampered_sealed_download_releases_no_plaintext(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    client = _client()
    from maverick_dashboard import app as app_mod

    goal = app_mod._world().create_goal("authenticated file", "")
    payload = b"private attachment body"
    uploaded = client.post(f"/api/v1/goals/{goal}/attachments",
                           files={"file": ("notes.txt", io.BytesIO(payload), "text/plain")})
    assert uploaded.status_code == 201, uploaded.text
    path = Path(app_mod._world().list_attachments(goal)[0].path)
    from maverick.attachments import is_sealed_file

    assert is_sealed_file(path)
    sealed = path.read_bytes()
    assert payload not in sealed
    path.write_bytes(sealed[:-1] + bytes([sealed[-1] ^ 1]))
    assert is_sealed_file(path)

    downloaded = client.get(f"/api/v1/goals/{goal}/attachments/{uploaded.json()['id']}/download")
    assert downloaded.status_code == 409
    assert downloaded.json() == {"detail": "attachment could not be opened here"}
    assert payload not in downloaded.content
