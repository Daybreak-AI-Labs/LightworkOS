"""Sanity checks for the community-maintained doc translations in docs/i18n/.

Guards, for every language:
  1. the translation exists, is non-empty, and starts with the HTML comment
     header carrying the source commit hash,
  2. no long English passage was left untranslated (heuristic: no 3+
     consecutive prose lines copied verbatim from the English source),
  3. the number of ``` fence lines matches the English source, so no code
     block was dropped, added, or split.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
ENGLISH_SOURCE = REPO_ROOT / "docs" / "getting-started.md"
LANGS = ("es", "ja", "de", "fr", "pt-BR", "ko", "ru", "it", "hi")


def _translation_path(lang: str) -> Path:
    return REPO_ROOT / "docs" / "i18n" / lang / "getting-started.md"


def _fence_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.lstrip().startswith("```"))


def _prose_lines(text: str) -> list[str]:
    """Lines outside ``` fences, the fence lines themselves excluded."""
    lines: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            lines.append(line)
    return lines


@pytest.mark.parametrize("lang", LANGS)
def test_exists_and_has_source_commit_header(lang):
    path = _translation_path(lang)
    assert path.is_file(), f"missing translation: {path}"
    text = path.read_text(encoding="utf-8")
    assert text.strip(), f"empty translation: {path}"
    first_line = text.splitlines()[0]
    assert first_line.startswith("<!--"), f"{lang}: must start with the HTML comment header"
    assert re.search(r"\b[0-9a-f]{7,40}\b", first_line), f"{lang}: header lacks a source commit hash"


@pytest.mark.parametrize("lang", LANGS)
def test_no_untranslated_english_passages(lang):
    english = {line for line in _prose_lines(ENGLISH_SOURCE.read_text(encoding="utf-8")) if line.strip()}
    streak = 0
    for line in _prose_lines(_translation_path(lang).read_text(encoding="utf-8")):
        streak = streak + 1 if line in english else 0
        assert streak < 3, f"{lang}: 3+ consecutive lines left verbatim from the English source, ending at {line!r}"


@pytest.mark.parametrize("lang", LANGS)
def test_code_fence_count_matches_english_source(lang):
    expected = _fence_count(ENGLISH_SOURCE.read_text(encoding="utf-8"))
    actual = _fence_count(_translation_path(lang).read_text(encoding="utf-8"))
    assert actual == expected, f"{lang}: {actual} ``` lines, English source has {expected}"
