"""The vendored DSAR engine: detector, clocks, verification, packages, and
the deliberately non-destructive erasure handoff."""
from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent

# The demo agents share module NAMES (backend, capabilities, ...) by
# design -- each directory is a self-contained deployable. In one pytest
# process that collides in sys.modules, so every loader purges the shared
# names before executing its app.
_SHARED_MODULES = ("backend", "capabilities", "mailsink",
                   "value_ledger", "dsar_engine", "serve_standalone")


def _purge_shared_modules():
    for _m in _SHARED_MODULES:
        sys.modules.pop(_m, None)



@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("DSAR_DATA_DIR", str(tmp_path / "store"))
    _purge_shared_modules()
    sys.path.insert(0, str(HERE))
    try:
        import dsar_engine
        importlib.reload(dsar_engine)
        yield dsar_engine
    finally:
        sys.path.remove(str(HERE))


def test_open_starts_the_clock_and_verification(engine):
    rec = engine.open_request("sam@example.com", "access")
    assert rec["status"] == "awaiting_verification"
    assert rec["due_at"] - rec["opened_at"] == pytest.approx(30 * 86400)
    assert rec["verify_token"]
    ver = engine.verify(rec["verify_token"])
    assert ver["status"] == "open" and ver["verified_at"]
    # Single-use: the same token never verifies twice.
    assert engine.verify(rec["verify_token"]) is None


def test_message_detector_finds_kind_and_subject(engine):
    rec = engine.from_message(
        "Under Article 17 please delete my data. — sam@example.com")
    assert rec["kind"] == "erasure"
    assert rec["subject_id"] == "sam@example.com"
    assert "article 17" in rec["intake"]["signals"]
    # No kind, or no subject -> None, never a guess.
    assert engine.from_message("the weather is nice") is None
    assert engine.from_message("please erase my data") is None
    assert engine.from_message("portability export please",
                               sender="a@b.co")["kind"] == "portability"


def test_aging_bands_and_overdue(engine, monkeypatch):
    rec = engine.open_request("late@example.com", "access")
    rec["due_at"] = time.time() - 86400          # already past due
    engine._save(rec)
    engine.open_request("fresh@example.com", "erasure")
    a = engine.aging()
    assert a["open"] == 2 and a["overdue"] == 1
    assert a["bands"]["overdue"] == 1
    rows = engine.list_requests()
    assert any(r["overdue"] for r in rows)


def test_access_package_only_contains_provided_extracts(engine):
    rec = engine.open_request("sam@example.com", "access")
    engine.verify(rec["verify_token"])
    out = engine.fulfill_access(rec["id"], {"CRM": "name, email",
                                            "Billing": "3 invoices",
                                            "Empty": "   "})
    assert out["status"] == "fulfilled"
    assert set(out["package"]["data"]) == {"CRM", "Billing"}
    assert "2 system(s)" in out["package"]["cover_note"]
    # Wrong-kind / wrong-state fulfillments refuse.
    era = engine.open_request("e@example.com", "erasure")
    engine.verify(era["verify_token"])
    assert engine.fulfill_access(era["id"], {"CRM": "x"}) is None


def test_erasure_handoff_is_never_destructive(engine):
    rec = engine.open_request("sam@example.com", "erasure")
    engine.verify(rec["verify_token"])
    out = engine.erasure_handoff(rec["id"], ["CRM", "  ", "Billing"])
    assert out["status"] == "awaiting_erasure"
    rows = out["erasure"]["systems"]
    assert [r["system"] for r in rows] == ["CRM", "Billing"]
    # Structured instructions only — no shell command anywhere.
    for r in rows:
        assert "rm " not in r["operator_instruction"]
        assert "authenticated deletion workflow" in r["operator_instruction"]
    closed = engine.close(rec["id"], reason="all confirmations recorded")
    assert closed["status"] == "closed"
    assert engine.close(rec["id"]) is None      # already closed


def test_store_path_traversal_guard(engine):
    with pytest.raises(ValueError):
        engine._path("../../etc/passwd")
    assert engine.get("../../etc/passwd") is None
