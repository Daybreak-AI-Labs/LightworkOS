"""First-class email / form / file event sources (poll model)."""
from __future__ import annotations

import time

import pytest
from maverick import automation_events as ev

# ---- file_dir ---------------------------------------------------------------

def test_file_dir_baseline_then_fires_new_file(tmp_path):
    (tmp_path / "a.txt").write_text("one")
    src = ev.get_source("file_dir")
    cfg = {"path": str(tmp_path)}
    base = src.poll(cfg, "")                       # baseline: record, fire nothing
    assert base.events == [] and base.cursor
    time.sleep(0.01)
    (tmp_path / "b.txt").write_text("two")
    out = src.poll(cfg, base.cursor)
    names = sorted(e["name"] for e in out.events)
    assert names == ["b.txt"]                      # only the new file fired
    assert out.events[0]["path"].endswith("b.txt")


def test_file_dir_glob_filters(tmp_path):
    src = ev.get_source("file_dir")
    cfg = {"path": str(tmp_path), "glob": "*.csv"}
    base = src.poll(cfg, "")
    time.sleep(0.01)
    (tmp_path / "keep.csv").write_text("x")
    (tmp_path / "skip.txt").write_text("y")
    out = src.poll(cfg, base.cursor)
    assert [e["name"] for e in out.events] == ["keep.csv"]


def test_file_dir_missing_dir_errors(tmp_path):
    with pytest.raises(ev.EventSourceError):
        ev.get_source("file_dir").poll({"path": str(tmp_path / "nope")}, "")


# ---- imap_email -------------------------------------------------------------

def test_imap_baseline_then_fires_new_mail(monkeypatch):
    calls = {"since": []}

    def fake_fetch(config, since_uid, uidvalidity=None):
        calls["since"].append(since_uid)
        if since_uid is None:
            return [], 5, "123"                     # baseline: high-water 5
        return ([{"id": "6", "uid": 6, "from": "a@b.com",
                  "subject": "hi", "date": "", "message_id": "<6>"}], 6, "123")

    monkeypatch.setattr(ev, "_fetch_imap", fake_fetch)
    src = ev.get_source("imap_email")
    base = src.poll({"host": "h", "username": "u", "password_env": "P"}, "")
    assert base.events == [] and ev._decode_cursor(base.cursor, "imap") == ["123", 5]
    out = src.poll({"host": "h", "username": "u", "password_env": "P"}, base.cursor)
    assert len(out.events) == 1 and out.events[0]["subject"] == "hi"
    assert ev._decode_cursor(out.cursor, "imap") == ["123", 6]
    assert calls["since"] == [None, 5]


def test_imap_requires_config():
    with pytest.raises(ev.EventSourceError):
        # _fetch_imap validates required keys; password_env missing
        ev.get_source("imap_email").poll({"host": "h", "username": "u"}, "1")


# ---- form -------------------------------------------------------------------

def test_form_source_fires_new_submissions(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import form_store
    src = ev.get_source("form")
    cfg = {"token": "signup"}
    form_store.append("signup", {"email": "old@x.com"})
    base = src.poll(cfg, "")                        # baseline over existing rows
    assert base.events == [] and ev._decode_cursor(base.cursor, "form") == "1"
    form_store.append("signup", {"email": "new@x.com", "plan": "pro"})
    out = src.poll(cfg, base.cursor)
    assert len(out.events) == 1
    assert out.events[0]["email"] == "new@x.com" and out.events[0]["plan"] == "pro"
    assert ev._decode_cursor(out.cursor, "form") == "2"


def test_form_source_first_submission_fires_when_store_absent(tmp_path, monkeypatch):
    # The normal ordering: arm the trigger (no store file yet), THEN a submission
    # arrives. The baseline must lock a non-empty cursor so the FIRST real
    # submission fires rather than being swallowed as the baseline.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import form_store
    src = ev.get_source("form")
    cfg = {"token": "waitlist"}
    base = src.poll(cfg, "")                        # store file does not exist yet
    assert base.events == [] and ev._decode_cursor(base.cursor, "form") == "0"
    form_store.append("waitlist", {"email": "first@x.com"})
    out = src.poll(cfg, base.cursor)
    assert [e["email"] for e in out.events] == ["first@x.com"]   # the first one fires


def test_form_source_requires_token():
    with pytest.raises(ev.EventSourceError):
        ev.get_source("form").poll({}, "")


def test_new_sources_are_registered():
    for name in ("file_dir", "imap_email", "form"):
        assert name in ev.available_sources()


# ---- imap body (opt-in) -----------------------------------------------------

def test_imap_include_body_is_passed_and_surfaced(monkeypatch):
    captured = {}

    def fake_fetch(config, since_uid, uidvalidity=None):
        captured["include_body"] = config.get("include_body")
        if since_uid is None:
            return [], 1, "123"
        return ([{"id": "2", "uid": 2, "from": "a@b.com", "subject": "s",
                  "date": "", "message_id": "<2>", "body": "hello world"}], 2, "123")

    monkeypatch.setattr(ev, "_fetch_imap", fake_fetch)
    src = ev.get_source("imap_email")
    cfg = {"host": "h", "username": "u", "password_env": "P", "include_body": True}
    base = src.poll(cfg, "")
    out = src.poll(cfg, base.cursor)
    assert captured["include_body"] is True
    assert out.events[0]["body"] == "hello world"


def test_email_body_text_extracts_plain_part():
    import email
    raw = (b"From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\n"
           b"the body text")
    msg = email.message_from_bytes(raw)
    assert ev._email_body_text(msg) == "the body text"


# ---- http_json pagination ---------------------------------------------------

def test_http_json_follows_next_page(monkeypatch):
    pages = {
        "https://api/x?page=1": {"items": [{"id": "1"}, {"id": "2"}], "next": "https://api/x?page=2"},
        "https://api/x?page=2": {"items": [{"id": "3"}], "next": None},
    }
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: pages[url])
    src = ev.get_source("http_json")
    cfg = {"url": "https://api/x?page=1", "items_path": "items", "id_field": "id",
           "next_path": "next", "max_pages": 5, "newest_first": True}
    # baseline records the newest across BOTH pages
    base = src.poll(cfg, "")
    assert ev._decode_cursor(base.cursor, "feed") == "1"  # page1[0] id after full walk
    # a later poll that finds new items ahead of the cursor fires them
    pages["https://api/x?page=1"] = {"items": [{"id": "5"}, {"id": "1"}], "next": None}
    out = src.poll(cfg, base.cursor)
    assert [e["id"] for e in out.events] == ["5"]


def test_http_json_max_pages_caps_the_walk(monkeypatch):
    calls = []

    def fake(url, headers=None, timeout=15.0):
        calls.append(url)
        return {"items": [{"id": url}], "next": url + "n"}   # infinite next chain

    monkeypatch.setattr(ev, "_http_get_json", fake)
    src = ev.get_source("http_json")
    cfg = {"url": "u", "items_path": "items", "next_path": "next", "max_pages": 3}
    src.poll(cfg, "")
    assert len(calls) == 3             # stopped at max_pages, didn't follow forever


def test_http_json_resolves_relative_next_page(monkeypatch):
    calls = []
    pages = {
        "https://api.example.test/v1/items?page=1": {
            "items": [{"id": "1"}],
            "next": "/v1/items?page=2",
        },
        "https://api.example.test/v1/items?page=2": {"items": [{"id": "2"}], "next": None},
    }

    def fake(url, headers=None, timeout=15.0):
        calls.append(url)
        return pages[url]

    monkeypatch.setattr(ev, "_http_get_json", fake)
    src = ev.get_source("http_json")
    cfg = {
        "url": "https://api.example.test/v1/items?page=1",
        "items_path": "items",
        "next_path": "next",
        "max_pages": 2,
    }
    src.poll(cfg, "")
    assert calls == [
        "https://api.example.test/v1/items?page=1",
        "https://api.example.test/v1/items?page=2",
    ]


def test_http_json_rejects_cross_origin_next_page_before_forwarding_headers(monkeypatch):
    calls = []

    def fake(url, headers=None, timeout=15.0):
        calls.append((url, headers))
        return {"items": [{"id": "1"}], "next": "https://evil.example/steal"}

    monkeypatch.setattr(ev, "_http_get_json", fake)
    src = ev.get_source("http_json")
    cfg = {
        "url": "https://api.example.test/items",
        "items_path": "items",
        "next_path": "next",
        "max_pages": 2,
        "headers": {"Authorization": "Bearer secret"},
    }
    with pytest.raises(ev.EventSourceError, match="configured origin"):
        src.poll(cfg, "")
    assert calls == [("https://api.example.test/items", {"Authorization": "Bearer secret"})]
