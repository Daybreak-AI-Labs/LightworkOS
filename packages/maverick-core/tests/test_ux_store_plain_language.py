"""Tests for the UX store (pins / saved views / trace annotations) and the
plain-language run explainer."""
from __future__ import annotations

import types

import pytest
from maverick.plain_language import explain
from maverick.ux_store import MAX_VIEW_PARAMS, MAX_VIEWS, UxStore


def _store(tmp_path):
    return UxStore(path=tmp_path / "ux.json")


# ---- pins ----

def test_pin_unpin_roundtrip(tmp_path):
    s = _store(tmp_path)
    assert s.pins("alice") == []
    assert s.pin("alice", 7) == [7]
    assert s.pin("alice", 9) == [9, 7]      # most-recent first
    assert s.pin("alice", 7) == [7, 9]      # re-pin moves to front
    assert s.unpin("alice", 9) == [7]
    assert s.pins("bob") == []              # principals isolated


def test_pins_survive_reopen(tmp_path):
    _store(tmp_path).pin("alice", 1)
    assert _store(tmp_path).pins("alice") == [1]


def test_anon_principal_bucket(tmp_path):
    s = _store(tmp_path)
    s.pin(None, 3)
    assert s.pins(None) == [3]
    assert s.pins("") == [3]  # empty == anon bucket


# ---- saved views ----

def test_save_list_delete_view(tmp_path):
    s = _store(tmp_path)
    s.save_view("alice", "failures", {"status": "failed", "order": "desc"})
    views = s.views("alice")
    assert views["failures"]["params"] == {"status": "failed", "order": "desc"}
    assert s.delete_view("alice", "failures") is True
    assert s.delete_view("alice", "failures") is False


def test_view_validation_and_cap(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.save_view("a", "", {})
    with pytest.raises(ValueError):
        s.save_view("a", "x", "not-a-dict")  # type: ignore[arg-type]
    for i in range(MAX_VIEWS):
        s.save_view("a", f"v{i}", {})
    with pytest.raises(ValueError, match="too many"):
        s.save_view("a", "overflow", {})
    s.save_view("a", "v0", {"changed": "yes"})  # overwrite under cap is fine


def test_saved_view_params_are_bounded(tmp_path):
    s = _store(tmp_path)
    s.save_view("alice", "ok", {f"k{i}": "v" for i in range(MAX_VIEW_PARAMS)})
    with pytest.raises(ValueError, match="too many saved view params"):
        s.save_view("alice", "oversized", {f"k{i}": "v" for i in range(MAX_VIEW_PARAMS + 1)})
    assert "oversized" not in s.views("alice")


# ---- annotations ----

def test_annotate_and_order(tmp_path):
    s = _store(tmp_path)
    s.annotate(5, 12, "here it diverged", author="bob")
    s.annotate(5, 3, "plan looked off")
    notes = s.annotations(5)
    assert [n["seq"] for n in notes] == [3, 12]   # ordered by seq
    assert notes[1]["author"] == "bob"
    assert s.annotations(6) == []


def test_annotation_validation(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.annotate(1, 0, "")
    with pytest.raises(ValueError):
        s.annotate(1, 0, "x" * 3000)


# ---- plain-language explain ----

def _goal(**kw):
    base = {"title": "Migrate the billing DB", "status": "done", "result": ""}
    base.update(kw)
    return types.SimpleNamespace(**base)


def _ev(kind, content, agent="coder"):
    return types.SimpleNamespace(kind=kind, content=content, agent=agent)


def test_explain_full_story():
    events = [
        _ev("plan", "1. snapshot 2. migrate 3. verify"),
        _ev("finding", "the staging DB had drift"),
        _ev("error", "first migration attempt timed out"),
    ]
    out = explain(_goal(), events)
    assert "Migrate the billing DB" in out
    assert "finished successfully" in out
    assert "plan" in out and "snapshot" in out
    assert "drift" in out
    assert "timed out" in out and "recovered" in out


def test_explain_failure_and_empty():
    out = explain(_goal(status="failed"), [])
    assert "couldn't get past" in out
    assert "No detailed activity" in out


def test_explain_strips_markdown_and_clamps():
    long_note = "**bold** `code` " + "x" * 400
    out = explain(_goal(), [_ev("finding", long_note)])
    assert "**" not in out and "`" not in out
    assert "…" in out


def test_explain_dict_events_and_result():
    out = explain({"title": "T", "status": "running", "result": "half done"},
                  [{"kind": "observation", "content": "API is rate limited", "agent": "researcher"}])
    assert "still in progress" in out and "rate limited" in out and "half done" in out


# ---- run gallery ----

def test_gallery_add_list_remove(tmp_path, monkeypatch):
    # Windows can return the same timestamp for several immediate writes.
    monkeypatch.setattr("maverick.ux_store.time.time", lambda: 1_000.0)
    s = _store(tmp_path)
    s.gallery_add(7, blurb="great demo of the refund flow", curator="alice")
    s.gallery_add(9)
    items = s.gallery()
    assert [e["goal_id"] for e in items] == [9, 7]  # newest-curated first
    assert items[1]["blurb"].startswith("great demo")
    assert items[1]["curator"] == "alice"
    # Upsert: re-adding updates, doesn't duplicate.
    s.gallery_add(7, blurb="updated")
    assert len(s.gallery()) == 2
    assert s.gallery_remove(7) is True
    assert s.gallery_remove(7) is False


def test_gallery_validation_and_cap(tmp_path):
    from maverick.ux_store import MAX_GALLERY
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.gallery_add(1, blurb="x" * 600)
    for i in range(MAX_GALLERY):
        s.gallery_add(i)
    with pytest.raises(ValueError, match="full"):
        s.gallery_add(9999)
