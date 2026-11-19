"""The doctor shield row warns only about a real problem.

The bundled built-in rules are what the standard release runs (docs/safety.md);
the full agent-shield SDK is not publicly available. A fresh install used to
show a yellow row whose fix ("Use the built-in layer") asked for nothing.
"""
from __future__ import annotations

import sys
import types

import maverick.health as h


def _shield_rows(monkeypatch, backend: str):
    import maverick_shield

    rows = []
    monkeypatch.setattr(h, "_row", lambda *a, **k: rows.append((a, k)))
    monkeypatch.setattr(maverick_shield.Shield, "from_config",
                        classmethod(lambda cls, **_k: types.SimpleNamespace(backend=backend)))
    h._check_shield()
    return rows


def test_built_in_rules_are_reported_ok_without_a_fix(monkeypatch):
    rows = _shield_rows(monkeypatch, "builtin")
    (marker, label, detail), kwargs = rows[0]
    assert (marker, label) == (h.GREEN, "shield")
    assert "built-in rules" in detail
    assert not kwargs.get("fix")


def test_a_disabled_shield_is_still_a_failure(monkeypatch):
    rows = _shield_rows(monkeypatch, "none")
    assert rows[0][0][0] == h.RED


def test_a_missing_shield_package_still_warns_and_the_kernel_runs(monkeypatch):
    # Kernel rule 1: the kernel runs without the shield; doctor warns, not fails.
    rows = []
    monkeypatch.setattr(h, "_row", lambda *a, **k: rows.append((a, k)))
    monkeypatch.setitem(sys.modules, "maverick_shield", None)
    monkeypatch.setattr("maverick.shield_policy.shield_required", lambda: False)
    h._check_shield()
    (marker, label, detail), kwargs = rows[0]
    assert (marker, label) == (h.YELLOW, "shield") and "not installed" in detail
    assert kwargs.get("fix")
