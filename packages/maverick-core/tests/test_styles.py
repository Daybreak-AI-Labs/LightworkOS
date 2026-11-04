"""User-selectable output styles: a runtime-overlay-selected response style
appended to the agent system prompt (tone/format only)."""
from __future__ import annotations

import pytest
from maverick import runtime_overrides as ro
from maverick import styles


@pytest.fixture
def overlay(tmp_path, monkeypatch):
    """Isolate the dashboard overlay file so tests don't touch the real one."""
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")


def test_builtins_present():
    s = styles.all_styles()
    assert {"concise", "explanatory", "formal", "executive", "technical"} <= set(s)


def test_no_active_by_default(overlay):
    assert styles.active_style_name() == ""
    assert styles.render_active_style_prompt() == ""


def test_set_select_and_render(overlay):
    ro.set_style("concise")
    assert styles.active_style_name() == "concise"
    block = styles.render_active_style_prompt()
    assert block.startswith("\n\n# Output style") and "brief" in block.lower()


def test_clear_reverts_to_default(overlay):
    ro.set_style("formal")
    ro.clear_style()
    assert ro.style_override() is None
    assert styles.render_active_style_prompt() == ""


def test_set_rejects_unknown(overlay):
    with pytest.raises(ValueError, match="unknown output style"):
        ro.set_style("nope")


def test_unknown_in_overlay_is_ignored(overlay, tmp_path):
    # A stale / hand-edited overlay naming an unknown style must not inject.
    (tmp_path / "runtime-overrides.toml").write_text('[styles]\nactive = "bogus"\n')
    assert styles.active_style_name() == "bogus"
    assert styles.render_active_style_prompt() == ""


def test_style_preserves_other_overlay_state(overlay):
    # The overlay re-renders wholesale on each write; a style write must not
    # drop an existing budget override (regression guard).
    ro.set_budget(7.0)
    ro.set_style("technical")
    assert ro.budget_override() == 7.0
    assert ro.style_override() == "technical"
