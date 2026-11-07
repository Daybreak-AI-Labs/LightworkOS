"""Tests must hand back ``app.state`` attributes exactly as the app set them.

Starlette's ``State`` keeps its attributes in a ``_state`` mapping, not in the
instance ``__dict__``. Since pytest 9.2, ``monkeypatch.setattr`` takes the
value to restore from ``__dict__``, so its undo deleted attributes the app set
at import (``app.state.voice_setup``, the vendor onboarding binding factory)
and every later test in the worker that used them errored
(pytest-dev/pytest#15099). ``test_support.starlette_state.patch_state``
restores them under every pytest version; these tests pin that and keep new
tests from going back to ``monkeypatch.setattr`` on a ``State``.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from starlette.datastructures import State

from test_support.starlette_state import patch_state

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_patch_restores_an_attribute_the_app_set_before_the_test():
    state = State()
    state.service = "original"

    with pytest.MonkeyPatch.context() as monkeypatch:
        patch_state(monkeypatch, state, "service", "patched")
        assert state.service == "patched"

    assert state.service == "original"


def test_patch_removes_an_attribute_the_test_added():
    state = State()

    with pytest.MonkeyPatch.context() as monkeypatch:
        patch_state(monkeypatch, state, "added", 1, raising=False)
        assert state.added == 1

    assert not hasattr(state, "added")


def test_patch_refuses_a_missing_attribute_unless_raising_is_false():
    state = State()

    with pytest.MonkeyPatch.context() as monkeypatch:
        with pytest.raises(AttributeError, match="missing"):
            patch_state(monkeypatch, state, "missing", 1)

    assert not hasattr(state, "missing")


def _setattr_on_state(path: Path, source: str) -> list[str]:
    tree = ast.parse(source, filename=str(path))
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setattr"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "monkeypatch"
            and node.args
            and isinstance(node.args[0], ast.Attribute)
            and node.args[0].attr == "state"
        ):
            found.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    return found


def test_no_test_patches_a_starlette_state_with_monkeypatch_setattr():
    test_files = [
        *REPO_ROOT.glob("packages/*/tests/**/*.py"),
        *REPO_ROOT.glob("apps/*/tests/**/*.py"),
    ]
    offenders = [
        location
        for path in sorted(test_files)
        if "monkeypatch.setattr" in (source := path.read_text(encoding="utf-8"))
        and ".state" in source
        for location in _setattr_on_state(path, source)
    ]

    assert not offenders, (
        "use test_support.starlette_state.patch_state for app.state / "
        "request.state; monkeypatch.setattr deletes the app's value on undo "
        "under pytest 9.2:\n" + "\n".join(offenders)
    )
