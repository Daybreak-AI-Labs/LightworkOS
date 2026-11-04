"""key_rotation: key rotation planner."""
from __future__ import annotations

from maverick.tools.key_rotation import key_rotation


def _run(**kw):
    return key_rotation().fn({"op": "plan", **kw})


def test_overdue_and_ok_classification():
    out = _run(
        today="2026-06-09",
        keys=[
            {"id": "k-old", "created_iso": "2025-01-01", "max_age_days": 90},
            {"id": "k-new", "created_iso": "2026-06-01", "max_age_days": 90},
        ],
    )
    assert "k-old: OVERDUE" in out
    assert "k-new: OK" in out
    assert "1 overdue" in out


def test_due_within_stagger_window():
    # age = 88, max_age 90, default stagger 1 -> threshold 89 -> still OK;
    # bump stagger to 5 -> threshold 85 -> DUE.
    out = _run(
        today="2026-06-09",
        stagger_days=5,
        keys=[{"id": "k", "created_iso": "2026-03-13", "max_age_days": 90}],
    )
    assert "k: DUE" in out


def test_staggered_schedule_with_overlap():
    out = _run(
        today="2026-06-09",
        stagger_days=2,
        overlap_days=7,
        keys=[
            {"id": "a", "created_iso": "2025-01-01", "max_age_days": 30},
            {"id": "b", "created_iso": "2025-02-01", "max_age_days": 30},
        ],
    )
    # Both overdue; most-urgent (smaller deadline offset) first, 2 days apart.
    assert "a: rotate 2026-06-09, retire old 2026-06-16" in out
    assert "b: rotate 2026-06-11, retire old 2026-06-18" in out


def test_no_keys_due_schedule_empty():
    out = _run(
        today="2026-06-09",
        keys=[{"id": "fresh", "created_iso": "2026-06-08", "max_age_days": 365}],
    )
    assert "fresh: OK" in out
    assert "schedule:\n  - none due" in out


def test_errors():
    t = key_rotation()
    assert t.fn({"op": "plan", "keys": []}).startswith("ERROR")  # empty
    assert t.fn({"op": "plan", "keys": [{"id": "k", "created_iso": "2026-01-01", "max_age_days": 9}]}).startswith("ERROR")  # no today
    assert _run(today="not-a-date", keys=[{"id": "k", "created_iso": "2026-01-01", "max_age_days": 9}]).startswith("ERROR")
    assert _run(today="2026-06-09", keys=[{"id": "k", "created_iso": "bad", "max_age_days": 9}]).startswith("ERROR")
    assert t.fn({"op": "nope", "keys": [], "today": "2026-06-09"}).startswith("ERROR")


def test_factory_identity():
    t = key_rotation()
    assert t.name == "key_rotation"
    assert t.parallel_safe is True
