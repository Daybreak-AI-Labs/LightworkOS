"""Tests for the synthetic_data tool (maverick.tools.synthetic_data)."""
from __future__ import annotations

import json

from maverick.tools.synthetic_data import synthetic_data

# ---- synthetic_data ----

def test_synthetic_deterministic_json():
    spec = {"op": "generate", "rows": 3, "seed": 7, "fields": [
        {"name": "id", "type": "sequence", "start": 100},
        {"name": "age", "type": "int", "min": 18, "max": 65},
        {"name": "tier", "type": "choice", "options": ["free", "pro"]},
    ]}
    a = synthetic_data().fn(spec)
    b = synthetic_data().fn(spec)
    assert a == b  # reproducible
    rows = json.loads(a)
    assert len(rows) == 3
    assert [r["id"] for r in rows] == [100, 101, 102]
    assert all(18 <= r["age"] <= 65 for r in rows)
    assert all(r["tier"] in ("free", "pro") for r in rows)


def test_synthetic_csv_and_email():
    out = synthetic_data().fn({
        "op": "generate", "rows": 2, "seed": 1, "format": "csv",
        "fields": [{"name": "who", "type": "name"}, {"name": "mail", "type": "email"}],
    })
    lines = out.splitlines()
    assert lines[0] == "who,mail"
    assert len(lines) == 3
    assert "@example.com" in out


def test_synthetic_errors():
    t = synthetic_data()
    assert t.fn({"op": "generate", "fields": []}).startswith("ERROR")
    assert t.fn({"op": "generate", "fields": [{"name": "x", "type": "int"}], "rows": 0}).startswith("ERROR")
    assert t.fn({"op": "generate", "fields": [{"name": "x", "type": "int"}], "format": "xml"}).startswith("ERROR")
