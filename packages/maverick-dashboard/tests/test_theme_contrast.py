"""Palette checks; runtime/browser qualification is tracked separately."""
import pytest
from maverick_dashboard.themes import (
    OPTIONAL_KEYS,
    contrast_issues,
    contrast_ratio,
    readable_palette,
    theme_css,
)


def test_white_on_white_is_refused_with_human_readable_reasons():
    palette = dict.fromkeys(("bg", "panel", "text", "accent"), "#ffffff")
    assert any("Text against page background" in issue for issue in contrast_issues(palette))
    assert contrast_ratio("#fff", "#000") == 21


def test_legacy_palette_stays_recoverable_on_both_surfaces():
    palette = readable_palette({"bg": "#000", "panel": "#fff", "text": "#000", "accent": "#000"})
    assert contrast_issues(palette) == []


def test_quiet_text_control_and_focus_pairs_are_checked():
    palette = {"bg": "#fff", "panel": "#fff", "text": "#111", "accent": "#fff", "border": "#eee", "muted": "#ddd"}
    issues = " ".join(contrast_issues(palette))
    assert "Quiet text" in issues
    assert "Highlights and focus" in issues
    assert "Control borders" in issues


@pytest.mark.parametrize("background,text", [("#fff", "#111"), ("#000", "#fff")])
def test_omitted_semantic_colours_are_explicit_and_readable(background, text):
    supplied = {"bg": background, "panel": background, "text": text, "accent": text}
    palette = readable_palette(supplied)
    assert set(OPTIONAL_KEYS) <= set(palette)
    assert contrast_issues(palette) == []
    css = theme_css({"custom": supplied})
    for key in OPTIONAL_KEYS:
        assert palette[key] == text
        assert f"--{key}: {text}" in css
