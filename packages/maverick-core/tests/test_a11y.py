"""Tests for the a11y tool (maverick.tools.a11y)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

# ---------- A11y tool ----------

def test_a11y_requires_op():
    from maverick.tools.a11y import a11y
    assert "op is required" in a11y().fn({})


def test_a11y_missing_runner(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.a11y import a11y
    out = a11y().fn({"op": "check", "url": "https://example.com"})
    assert "pa11y not found" in out
    assert "npm install" in out


def test_a11y_pa11y_groups_by_code(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/pa11y")
    pa11y_output = json.dumps([
        {"code": "WCAG2AA.Principle1.G18", "type": "error",
         "message": "Insufficient contrast", "selector": "#h1"},
        {"code": "WCAG2AA.Principle1.G18", "type": "error",
         "message": "Insufficient contrast", "selector": ".btn"},
        {"code": "WCAG2AA.Principle4.NoARIA", "type": "warning",
         "message": "Missing aria-label", "selector": "input"},
    ])

    def _run(cmd, *a, **k):
        return MagicMock(returncode=2, stdout=pa11y_output, stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    from maverick.tools.a11y import a11y
    out = a11y().fn({"op": "check", "url": "https://example.com"})
    assert "3 a11y issue(s)" in out
    assert "WCAG2AA.Principle1.G18  ×2" in out


def test_a11y_axe_returns_violations(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/axe")
    axe_output = json.dumps([{
        "violations": [
            {"id": "color-contrast", "impact": "serious",
             "description": "Element has insufficient contrast",
             "nodes": [{"target": "#h1"}, {"target": ".btn"}]},
        ],
    }])

    def _run(cmd, *a, **k):
        return MagicMock(returncode=0, stdout=axe_output, stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    from maverick.tools.a11y import a11y
    out = a11y().fn({"op": "check", "url": "https://example.com",
                     "runner": "axe"})
    assert "1 a11y violation" in out
    assert "color-contrast" in out and "serious" in out
