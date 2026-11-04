"""A failed `from openai import ...` must not always blame a missing SDK.

ModuleNotFoundError subclasses ImportError, so `except ImportError` also
catches a missing *transitive* dependency (openai -> httpx -> idna). The old
message ("openai SDK not installed. Run: python -m pip install -e ./packages/maverick-core[openai]")
then misdirects the user, since openai IS installed.
"""
from __future__ import annotations

from maverick.providers.openai_provider import _openai_import_error_message


def test_message_when_openai_package_truly_missing(monkeypatch):
    monkeypatch.setattr(
        "importlib.util.find_spec",
        lambda name, *a, **k: None,
    )
    msg = _openai_import_error_message(ModuleNotFoundError("No module named 'openai'"))
    assert "not installed" in msg
    assert "packages/maverick-core[openai]" in msg


def test_message_when_openai_present_but_dependency_broken(monkeypatch):
    # openai is locatable; a transitive import (idna) is what failed.
    monkeypatch.setattr(
        "importlib.util.find_spec",
        lambda name, *a, **k: object(),
    )
    err = ModuleNotFoundError("No module named 'idna'")
    msg = _openai_import_error_message(err)
    assert "not installed" not in msg
    assert "installed but failed to import" in msg
    assert "idna" in msg  # surfaces the real culprit


def test_find_spec_crash_falls_back_to_not_installed(monkeypatch):
    def _boom(*a, **k):
        raise ValueError("borked finder")

    monkeypatch.setattr("importlib.util.find_spec", _boom)
    msg = _openai_import_error_message(ImportError("weird"))
    assert "not installed" in msg
