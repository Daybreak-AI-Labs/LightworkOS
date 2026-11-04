"""LIGHTWORK_* -> MAVERICK_* env-var compatibility shim tests.

The mirror runs once at ``import maverick`` time, so these tests exercise
the underlying function (``maverick._mirror_lightwork_env``) directly
against a monkeypatched environment.
"""
from __future__ import annotations

import os

from maverick import _mirror_lightwork_env


def test_lightwork_var_mirrors_when_maverick_unset(monkeypatch):
    monkeypatch.delenv("MAVERICK_FOO", raising=False)
    monkeypatch.setenv("LIGHTWORK_FOO", "1")
    _mirror_lightwork_env()
    assert os.environ.get("MAVERICK_FOO") == "1"


def test_existing_maverick_var_is_not_overwritten(monkeypatch):
    monkeypatch.setenv("MAVERICK_FOO", "explicit")
    monkeypatch.setenv("LIGHTWORK_FOO", "mirrored")
    _mirror_lightwork_env()
    assert os.environ.get("MAVERICK_FOO") == "explicit"


def test_non_lightwork_vars_untouched(monkeypatch):
    monkeypatch.setenv("SOME_OTHER_VAR", "keep")
    monkeypatch.delenv("MAVERICK_SOME_OTHER_VAR", raising=False)
    _mirror_lightwork_env()
    assert os.environ.get("SOME_OTHER_VAR") == "keep"
    assert os.environ.get("MAVERICK_SOME_OTHER_VAR") is None


def test_mirror_is_idempotent(monkeypatch):
    monkeypatch.delenv("MAVERICK_FOO", raising=False)
    monkeypatch.setenv("LIGHTWORK_FOO", "first")
    _mirror_lightwork_env()
    assert os.environ.get("MAVERICK_FOO") == "first"
    # A second run must not change anything, even if the LIGHTWORK_ source
    # has since diverged -- the mirror never overwrites.
    monkeypatch.setenv("LIGHTWORK_FOO", "second")
    _mirror_lightwork_env()
    assert os.environ.get("MAVERICK_FOO") == "first"
