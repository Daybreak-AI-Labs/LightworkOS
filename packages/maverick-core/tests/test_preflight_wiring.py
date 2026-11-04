"""Preflight is wired onto the live LLM dispatch.

LLM.complete/complete_async must call preflight(), via llm._run_preflight,
mode-controlled by MAVERICK_PREFLIGHT (default 'warn').
"""
from __future__ import annotations

import pytest

# A system prompt far larger than any model's context window.
_HUGE = "x" * 5_000_000


def test_run_preflight_warn_default_does_not_raise(monkeypatch):
    monkeypatch.delenv("MAVERICK_PREFLIGHT", raising=False)
    from maverick.llm import _run_preflight
    # Default 'warn': logs but must NOT raise (no false refusal on the live path).
    _run_preflight("claude-opus-4-7", _HUGE, [], None, 4096)


def test_run_preflight_strict_raises(monkeypatch):
    monkeypatch.setenv("MAVERICK_PREFLIGHT", "strict")
    from maverick.llm import _run_preflight
    from maverick.preflight import PreflightFailed
    with pytest.raises(PreflightFailed):
        _run_preflight("claude-opus-4-7", _HUGE, [], None, 4096)


def test_run_preflight_off_skips(monkeypatch):
    monkeypatch.setenv("MAVERICK_PREFLIGHT", "off")
    from maverick.llm import _run_preflight
    _run_preflight("claude-opus-4-7", _HUGE, [], None, 4096)  # skipped -> no raise


def test_run_preflight_warn_passes_for_normal_request(monkeypatch):
    monkeypatch.setenv("MAVERICK_PREFLIGHT", "strict")
    from maverick.llm import _run_preflight
    # A normal-sized request fits and must not raise even in strict mode.
    _run_preflight("claude-opus-4-7", "Summarize this.", [], None, 4096)
