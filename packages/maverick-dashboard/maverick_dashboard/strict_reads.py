"""Tell "cannot be read" apart from "not allowed" for one check.

Access helpers deny when a roster, group mapping or grant store cannot be
read: for sign-in and page access that is the safe answer. A check that must
not present an outage as a refusal (for example whether someone may be
@mentioned) runs inside :func:`strict`, and those helpers raise instead.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

_STRICT = ContextVar("lightwork_strict_reads", default=False)


def active() -> bool:
    """Whether the current check asked for unreadable sources to raise."""
    return _STRICT.get()


@contextmanager
def strict():
    token = _STRICT.set(True)
    try:
        yield
    finally:
        _STRICT.reset(token)
