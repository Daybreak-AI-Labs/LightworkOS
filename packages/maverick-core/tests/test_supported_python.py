"""A customer on an untested Python is told so, at install and in `doctor`.

`requires-python` is ">=3.11" with no upper bound, so pip installs on 3.13 and
later without a word, although CI tests only 3.11 and 3.12. Both places warn
rather than refuse: a newer Python often works, and contributors use one.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import maverick.health as h

REPO_ROOT = Path(__file__).resolve().parents[3]


def _installer():
    path = REPO_ROOT / "scripts" / "install_release_cohort.py"
    spec = importlib.util.spec_from_file_location("install_release_cohort_python", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _rows(monkeypatch, version):
    rows = []
    monkeypatch.setattr(h, "_python_version", lambda: version)
    monkeypatch.setattr(h, "_row", lambda *a, **k: rows.append((a, k)))
    h._ATTENTION.clear()
    h._check_python()
    return rows


def test_doctor_reports_a_supported_python_as_ok(monkeypatch):
    rows = _rows(monkeypatch, (3, 12, 4))
    assert rows == [((h.GREEN, "python", "Python 3.12.4"), {})]
    assert "python" not in h._ATTENTION


def test_doctor_warns_on_an_untested_python_without_failing(monkeypatch):
    rows = _rows(monkeypatch, (3, 13, 1))
    (marker, label, detail), kwargs = rows[0]
    assert (marker, label) == (h.YELLOW, "python")
    assert "Python 3.13.1 is not tested" in detail
    assert "3.11 or 3.12" in kwargs["fix"]
    assert "python" in h._ATTENTION
    assert h._FAILURES.count("python") == 0


def test_install_warns_on_an_untested_python_and_continues():
    installer = _installer()
    assert installer.python_version_warning("3.12") is None
    assert installer.python_version_warning("3.11") is None
    warning = installer.python_version_warning("3.13")
    assert warning is not None and "Python 3.13" in warning and "3.11 or 3.12" in warning
    assert installer.python_version_warning(None) is None


def test_supported_versions_match_ci_and_the_install_guide():
    installer = _installer()
    assert installer.SUPPORTED_PYTHON == ("3.11", "3.12")
    assert tuple(f"{a}.{b}" for a, b in h.SUPPORTED_PYTHON) == installer.SUPPORTED_PYTHON
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    matrix = set(re.findall(r'python-version: \["(3\.\d+)"\]', ci))
    assert matrix == set(installer.SUPPORTED_PYTHON)
    assert "Python 3.11 or 3.12" in (REPO_ROOT / "docs/source-install.md").read_text(encoding="utf-8")
