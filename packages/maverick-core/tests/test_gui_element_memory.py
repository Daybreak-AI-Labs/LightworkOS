"""Tests for the gui_element_memory tool (maverick.tools.gui_element_memory)."""
from __future__ import annotations

import json

from maverick.tools.gui_element_memory import gui_element_memory

# ---- gui_element_memory ----

def test_gui_put_get_roundtrip():
    t = gui_element_memory()
    store = t.fn({"op": "put", "app": "checkout", "screen": "pay", "name": "submit", "selector": "#pay-btn"})
    entries = json.loads(store)
    assert entries == [{"app": "checkout", "screen": "pay", "name": "submit", "selector": "#pay-btn"}]
    got = t.fn({"op": "get", "memory": entries, "app": "checkout", "screen": "pay", "name": "submit"})
    assert json.loads(got)["selector"] == "#pay-btn"
    assert t.fn({"op": "get", "memory": entries, "app": "x", "screen": "y", "name": "z"}) == "NOT FOUND"


def test_gui_put_upserts_and_lists():
    t = gui_element_memory()
    e1 = json.loads(t.fn({"op": "put", "app": "a", "screen": "s", "name": "btn", "selector": "#old"}))
    e2 = json.loads(t.fn({"op": "put", "memory": e1, "app": "a", "screen": "s", "name": "btn", "selector": "#new"}))
    assert len(e2) == 1 and e2[0]["selector"] == "#new"
    listing = t.fn({"op": "list", "memory": e2, "app": "a"})
    assert "a/s/btn: #new" in listing


def test_gui_validation():
    t = gui_element_memory()
    assert t.fn({"op": "put", "app": "a"}).startswith("ERROR")
    assert t.fn({"op": "bogus"}).startswith("ERROR")
    assert t.fn({"op": "list"}) == "(empty)"
