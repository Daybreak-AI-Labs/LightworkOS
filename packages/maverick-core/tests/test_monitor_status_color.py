"""monitor status->color map: single source for the status line + plan tree.

Regression: the live `'active'` status (set via `set_goal_status('active')`)
had no entry and rendered uncolored (white); `'blocked'` was missing from the
plan-tree map specifically. Both call sites now share `_status_color`.
"""
from __future__ import annotations

import pytest
from maverick.monitor import _status_color


@pytest.mark.parametrize("status,color", [
    ("active", "cyan"),        # the bug: normal running state was uncolored
    ("blocked", "red"),        # was missing from the plan-tree map
    ("pending", "yellow"),
    ("done", "green"),
    ("cancelled", "red"),
])
def test_known_statuses_have_colors(status, color):
    assert _status_color(status) == color


def test_never_written_statuses_default_white():
    # in_progress/running/succeeded/failed are never written by the orchestrator
    # (vocab is active/pending/blocked/done/cancelled); they no longer have map
    # entries and fall through to the default.
    for stale in ("in_progress", "running", "succeeded", "failed"):
        assert _status_color(stale) == "white"


def test_case_insensitive():
    assert _status_color("ACTIVE") == "cyan"
    assert _status_color("Blocked") == "red"


def test_unknown_status_defaults_white():
    assert _status_color("frobnicating") == "white"


def test_none_or_empty_is_white_not_crash():
    assert _status_color(None) == "white"  # type: ignore[arg-type]
    assert _status_color("") == "white"
