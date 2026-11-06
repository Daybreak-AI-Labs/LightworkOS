"""Patch a Starlette ``State`` attribute for one test and hand it back intact."""
from __future__ import annotations

import pytest
from starlette.datastructures import State


def patch_state(
    monkeypatch: pytest.MonkeyPatch,
    state: State,
    name: str,
    value: object,
    *,
    raising: bool = True,
) -> None:
    """Set ``state.<name>`` like ``monkeypatch.setattr(state, name, value)``.

    ``State`` (``app.state``, ``request.state``) keeps its attributes in the
    ``_state`` mapping, not the instance ``__dict__``. Since pytest 9.2,
    ``monkeypatch.setattr`` takes the value to restore from ``__dict__``, so
    its undo deletes an attribute the app had set (pytest-dev/pytest#15099).
    Patching the mapping restores the previous value, or removes an attribute
    the test added, under every pytest version.
    """
    if raising and name not in state._state:
        raise AttributeError(f"{state!r} has no attribute {name!r}")
    monkeypatch.setitem(state._state, name, value)
