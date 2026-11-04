"""Guard the wheel/PyInstaller packaging of Jinja templates.

The dashboard ships as a wheel (and a PyInstaller app that bundles that wheel's
data files). Templates are declared in ``[tool.setuptools.package-data]``. A
``.js`` template that a ``.html`` template ``{% include %}``s but that ISN'T
covered by a package-data glob renders fine from a source checkout yet raises
``TemplateNotFound`` at runtime in a built app -- exactly the bug that 500'd the
flow designer (only ``templates/*.html`` was packaged, so the designer's
``flow_designer_core.js`` include was missing from the bundle).

This test fails in CI if any template a page includes wouldn't be packaged.
"""
from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # 3.10
    import tomli as tomllib

_PKG = Path(__file__).resolve().parents[1] / "maverick_dashboard"
_TEMPLATES = _PKG / "templates"
_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
_INCLUDE_RE = re.compile(r'{%-?\s*include\s*"([^"]+)"')


def _packaged_globs() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    globs = data["tool"]["setuptools"]["package-data"]["maverick_dashboard"]
    # globs are relative to the package dir; keep only the templates/ ones
    return [g for g in globs if g.startswith("templates/")]


def _is_packaged(rel_path: str, globs: list[str]) -> bool:
    return any(fnmatch(rel_path, g) for g in globs)


def test_every_included_template_is_packaged():
    globs = _packaged_globs()
    missing = []
    for html in _TEMPLATES.glob("*.html"):
        for inc in _INCLUDE_RE.findall(html.read_text(encoding="utf-8")):
            rel = f"templates/{inc}"
            if not (_TEMPLATES / inc).exists():
                missing.append(f"{html.name} includes '{inc}' which does not exist")
            elif not _is_packaged(rel, globs):
                missing.append(
                    f"{html.name} includes '{inc}' but no package-data glob covers "
                    f"'{rel}' (globs: {globs}) -> it will TemplateNotFound in a built app")
    assert not missing, "\n".join(missing)


def test_js_templates_are_covered_by_package_data():
    # Direct guard on the specific regression: the .js template files exist and
    # are each matched by a package-data glob.
    globs = _packaged_globs()
    js_files = sorted(p.name for p in _TEMPLATES.glob("*.js"))
    assert js_files, "expected at least one .js template (FDCore / designer / helpers)"
    for name in js_files:
        assert _is_packaged(f"templates/{name}", globs), (
            f"templates/{name} is not covered by package-data {globs}")


def test_every_static_asset_is_covered_by_package_data():
    """setuptools globs do not cross '/': ``static/*`` alone shipped a wheel
    with zero web fonts, so every page 404'd static/fonts/*.woff2 in production
    and rendered in fallback fonts."""
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    globs = data["tool"]["setuptools"]["package-data"]["maverick_dashboard"]
    static = _PKG / "static"
    missing = [
        str(path.relative_to(_PKG))
        for path in sorted(static.rglob("*"))
        if path.is_file() and not _is_packaged(str(path.relative_to(_PKG)), globs)
    ]
    assert not missing, f"not packaged: {missing} (globs: {globs})"
    assert any(f.suffix == ".woff2" for f in static.rglob("*")), "font files vanished"
