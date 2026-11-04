"""verify_final() dispatches to the adversarial ensemble when opted in.

The cross-family Multi-Agent Verification panel (verify_proposal_ensemble)
existed and was tested, but nothing in the live agent loop could reach it --
the FINAL handler always called the single verify_proposal. verify_final()
is the opt-in dispatch the agent loop now uses:

  - default: structured rubric judge (verify_proposal_structured), which falls
    back to the scalar verify_proposal for any non-rubric reply
  - MAVERICK_REASONING_REWARD=0: scalar single cross-family verifier
  - MAVERICK_VERIFY_ENSEMBLE=1 / [routing] verify_ensemble=true: MAV panel
    (takes precedence over both)

All paths share verify_proposal's signature + VerifierVerdict return, so
the call site is verifier-agnostic. The single-vs-ensemble tests below opt out
of the rubric judge (MAVERICK_REASONING_REWARD=0 in the _clean fixture) so they
exercise that axis directly; structured routing is covered separately.
"""
from __future__ import annotations

import asyncio

import pytest
from maverick import config, verifier
from maverick.verifier import VerifierVerdict


@pytest.fixture
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_VERIFY_ENSEMBLE", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-verify-final-test")  # no config
    # These tests exercise the single-vs-ensemble dispatch axis; opt out of the
    # (now default) rubric judge so verify_final routes to the scalar path.
    monkeypatch.setenv("MAVERICK_REASONING_REWARD", "0")


def _patch_both(monkeypatch):
    """Replace both verifier impls with markers so we can see which ran."""
    calls = []

    async def _single(*a, **k):
        calls.append("single")
        return VerifierVerdict(confidence=0.9, accepts=True, critique="")

    async def _ensemble(*a, **k):
        calls.append("ensemble")
        return VerifierVerdict(confidence=0.95, accepts=True, critique="")

    monkeypatch.setattr(verifier, "verify_proposal", _single)
    monkeypatch.setattr(verifier, "verify_proposal_ensemble", _ensemble)
    return calls


def test_default_uses_single_verifier(_clean, monkeypatch):
    calls = _patch_both(monkeypatch)
    v = asyncio.run(verifier.verify_final("brief", "answer", llm=None))
    assert calls == ["single"]
    assert v.accepts is True


def test_structured_is_default(_clean, monkeypatch):
    # With the rubric judge on (its default), verify_final routes there ahead of
    # the scalar single verifier. _clean disabled it, so re-enable for this test.
    monkeypatch.setenv("MAVERICK_REASONING_REWARD", "1")
    calls = _patch_both(monkeypatch)

    async def _structured(*a, **k):
        calls.append("structured")
        return VerifierVerdict(confidence=0.9, accepts=True, critique="")

    monkeypatch.setattr(verifier, "verify_proposal_structured", _structured)
    asyncio.run(verifier.verify_final("brief", "answer", llm=None))
    assert calls == ["structured"]


def test_env_opt_in_uses_ensemble(_clean, monkeypatch):
    monkeypatch.setenv("MAVERICK_VERIFY_ENSEMBLE", "1")
    calls = _patch_both(monkeypatch)
    v = asyncio.run(verifier.verify_final("brief", "answer", llm=None))
    assert calls == ["ensemble"]
    assert v.confidence == 0.95


def test_stringy_false_does_not_enable_ensemble(_clean, monkeypatch):
    # bool("false") is True; the gate must parse explicitly.
    monkeypatch.setenv("MAVERICK_VERIFY_ENSEMBLE", "false")
    calls = _patch_both(monkeypatch)
    asyncio.run(verifier.verify_final("brief", "answer", llm=None))
    assert calls == ["single"]


def test_config_stringy_false_does_not_enable_ensemble(_clean, monkeypatch):
    # TOML environment interpolation can leave string values such as "false";
    # those must not opt in to the more expensive ensemble verifier.
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"routing": {"verify_ensemble": "false"}},
    )
    calls = _patch_both(monkeypatch)
    asyncio.run(verifier.verify_final("brief", "answer", llm=None))
    assert calls == ["single"]


def test_config_true_string_enables_ensemble(_clean, monkeypatch):
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"routing": {"verify_ensemble": "true"}},
    )
    calls = _patch_both(monkeypatch)
    asyncio.run(verifier.verify_final("brief", "answer", llm=None))
    assert calls == ["ensemble"]


def test_verify_final_passes_proposer_model_through(_clean, monkeypatch):
    seen = {}

    async def _single(brief, proposal, llm, budget=None, *, proposer_model=None):
        seen["proposer_model"] = proposer_model
        return VerifierVerdict(confidence=1.0, accepts=True, critique="")

    monkeypatch.setattr(verifier, "verify_proposal", _single)
    asyncio.run(verifier.verify_final(
        "b", "a", llm=None, proposer_model="anthropic:claude-opus-4-8",
    ))
    assert seen["proposer_model"] == "anthropic:claude-opus-4-8"


def test_ensemble_filters_default_panel_to_allowed_providers(_clean, monkeypatch):
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"routing": {"allowed_providers": ["anthropic"]}},
    )

    calls = []

    class FakeResp:
        text = '{"confidence": 0.9, "accepts": true, "critique": "", "issues": []}'

    class FakeLLM:
        async def complete_async(self, **kwargs):
            calls.append(kwargs["model"])
            return FakeResp()

    v = asyncio.run(verifier.verify_proposal_ensemble(
        "private brief", "private answer", FakeLLM(), proposer_model="anthropic:claude-opus-4-8",
    ))

    assert v.accepts is True
    assert calls == ["anthropic:claude-sonnet-4-6"]


def test_ensemble_uses_selected_provider_outside_curated_panel(_clean, monkeypatch):
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"routing": {"allowed_providers": ["deepseek"]}},
    )

    calls = []

    class FakeResp:
        text = '{"confidence": 0.9, "accepts": true, "critique": "", "issues": []}'

    class FakeLLM:
        async def complete_async(self, **kwargs):
            calls.append(kwargs["model"])
            return FakeResp()

    v = asyncio.run(verifier.verify_proposal_ensemble(
        "private brief", "private answer", FakeLLM(), proposer_model="anthropic:claude-opus-4-8",
    ))

    assert v.accepts is True
    assert calls == ["deepseek:deepseek-v4-pro"]
