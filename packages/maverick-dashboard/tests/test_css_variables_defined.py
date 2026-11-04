"""Every CSS custom property the dashboard reads without a fallback is defined.

``var(--name)`` with no fallback makes its whole declaration invalid when
``--name`` is not set, so the browser silently drops it: the privacy page lost
its spacing, the flow designer its panel backgrounds and the vendor page the
colour of its error message. This ratchet scans the stylesheets, the
templates (``<style>`` blocks, ``style=`` attributes, inline scripts), the
static scripts and Python-built HTML for such reads and fails when the name is
set nowhere in the dashboard.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
SOURCES = ("static/*.css", "static/*.js", "static/*.html", "templates/*.html", "*.py")

# A read with no fallback: var(--name). var(--name, fallback) may name a
# property that only some pages or themes set.
_READ = re.compile(r"var\(\s*(--[A-Za-z0-9_-]+)\s*\)")
# A definition: "--name: value" in a stylesheet, a <style> block, a style=
# attribute or a style string built by a script.
_DEFINE = re.compile(r"(?<![A-Za-z0-9_-])(--[A-Za-z0-9_-]+)\s*:")
# A definition made by a script: element.style.setProperty("--name", value).
_SET_PROPERTY = re.compile(r"setProperty\(\s*['\"](--[A-Za-z0-9_-]+)['\"]")

# Names a script sets in a way the patterns above cannot see. Each entry says
# where it is set. Keep this empty unless a name really is runtime-only.
RUNTIME_ONLY: dict[str, str] = {}


def _sources() -> list[Path]:
    files: set[Path] = set()
    for pattern in SOURCES:
        files.update(PACKAGE.glob(pattern))
    return sorted(files)


def _scan() -> tuple[set[str], dict[str, list[str]]]:
    defined: set[str] = set(RUNTIME_ONLY)
    reads: dict[str, list[str]] = {}
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        defined.update(_DEFINE.findall(text))
        defined.update(_SET_PROPERTY.findall(text))
        for match in _READ.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            where = f"{path.relative_to(PACKAGE)}:{line}"
            reads.setdefault(match.group(1), []).append(where)
    return defined, reads


def test_scan_sees_the_shared_tokens() -> None:
    defined, reads = _scan()
    for name in ("--space-3", "--surface-1", "--radius-md", "--danger", "--brand-fg"):
        assert name in defined, name
    assert "--text" in reads


def test_every_css_variable_read_without_a_fallback_is_defined() -> None:
    defined, reads = _scan()
    missing = {name: places for name, places in sorted(reads.items()) if name not in defined}
    assert not missing, "CSS variables read without a fallback but defined nowhere: " + "; ".join(
        f"{name} ({', '.join(places[:5])}{' …' if len(places) > 5 else ''})"
        for name, places in missing.items()
    )


def test_runtime_only_names_are_documented() -> None:
    for name, where in RUNTIME_ONLY.items():
        assert name.startswith("--") and where.strip(), name
