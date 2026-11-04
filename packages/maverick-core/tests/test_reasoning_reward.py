"""Tests for the structured reasoning-reward (Agent-RRM) representation.

The point of the module is *auditable* reward: a rubric decomposition where a
single failing dimension can veto an otherwise-high holistic score, and a
stable audit serialization. These tests pin those governance properties plus
the parse/adapter robustness (fail-closed on garbage) and explicit opt-out.
"""
from __future__ import annotations

import json

from maverick.reasoning_reward import (
    ACCEPT_THRESHOLD,
    DEFAULT_RUBRIC,
    DimensionScore,
    ReasoningReward,
    enabled,
    holistic_from_dimensions,
    parse_structured,
)


def test_holistic_is_rubric_weighted_mean():
    dims = (
        DimensionScore("correctness", 1.0),
        DimensionScore("completeness", 1.0),
        DimensionScore("grounding", 1.0),
        DimensionScore("safety", 1.0),
    )
    assert holistic_from_dimensions(dims) == 1.0


def test_holistic_ignores_unknown_and_reweights_missing():
    # Only correctness (weight .40) present -> its own score, not diluted to 0
    # by the missing facets, and an unknown dimension contributes nothing.
    dims = (
        DimensionScore("correctness", 0.5),
        DimensionScore("made_up", 1.0),
    )
    assert holistic_from_dimensions(dims) == 0.5


def test_safety_veto_blocks_accept_despite_high_holistic():
    # correctness/completeness/grounding perfect, safety below its 0.50 floor.
    dims = (
        DimensionScore("correctness", 1.0),
        DimensionScore("completeness", 1.0),
        DimensionScore("grounding", 1.0),
        DimensionScore("safety", 0.2, vetoes=True),
    )
    holistic = holistic_from_dimensions(dims)
    reward = ReasoningReward(score=holistic, dimensions=dims)
    assert holistic >= ACCEPT_THRESHOLD  # the average would have accepted
    assert reward.vetoed is True
    assert reward.accepts() is False  # ...but the veto overrules it


def test_accepts_threshold_without_veto():
    high = ReasoningReward(score=0.9)
    low = ReasoningReward(score=0.5)
    assert high.accepts() is True
    assert low.accepts() is False


def test_weakest_dimension_is_audit_headline():
    dims = (
        DimensionScore("correctness", 0.9),
        DimensionScore("grounding", 0.3),
    )
    reward = ReasoningReward(score=0.6, dimensions=dims)
    weakest = reward.weakest_dimension
    assert weakest is not None
    assert weakest.name == "grounding"
    # No decomposition -> no headline.
    assert ReasoningReward(score=0.6).weakest_dimension is None


def test_from_verifier_verdict_is_lossless_upgrade():
    class _V:
        confidence = 0.82
        critique = "solid but terse"
        issues = ["missing edge case"]
        raw = '{"confidence": 0.82}'

    r = ReasoningReward.from_verifier_verdict(_V())
    assert r.score == 0.82
    assert r.confidence == 0.82
    assert r.critique == "solid but terse"
    assert r.dimensions == ()  # a scalar cannot be decomposed after the fact
    assert r.accepts() is True


def test_from_verifier_verdict_promotes_issues_when_no_critique():
    class _V:
        confidence = 0.3
        critique = ""
        issues = ["wrong direction", "unsupported claim"]
        raw = ""

    r = ReasoningReward.from_verifier_verdict(_V())
    assert "wrong direction" in r.critique
    assert "unsupported claim" in r.critique


def test_from_verifier_verdict_degrades_on_foreign_object():
    r = ReasoningReward.from_verifier_verdict(object())
    # getattr defaults make this a 0-confidence reward, not a crash.
    assert r.score == 0.0
    assert r.accepts() is False


def test_parse_structured_json_with_dimensions():
    payload = {
        "reasoning": "checked each claim",
        "dimensions": [
            {"name": "correctness", "score": 0.9, "critique": "ok"},
            {"name": "completeness", "score": 0.8, "critique": "mostly complete"},
            {"name": "grounding", "score": 0.7, "critique": "supported"},
            {"name": "safety", "score": 0.1, "critique": "unsafe"},
        ],
        "critique": "unsafe overall",
        "score": 0.8,
        "confidence": 0.7,
    }
    r = parse_structured(json.dumps(payload))
    assert r.score == 0.8
    assert r.confidence == 0.7
    assert r.reasoning == "checked each claim"
    names = {d.name for d in r.dimensions}
    assert names == {"correctness", "completeness", "grounding", "safety"}
    # safety 0.1 < 0.50 floor -> veto stamped from the rubric, blocks accept.
    assert r.vetoed is True
    assert r.accepts() is False


def test_parse_structured_derives_holistic_when_score_absent():
    payload = {
        "dimensions": [
            {"name": "correctness", "score": 0.5},
            {"name": "completeness", "score": 0.5},
            {"name": "grounding", "score": 0.5},
            {"name": "safety", "score": 0.5},
        ],
    }
    r = parse_structured(json.dumps(payload))
    # No explicit holistic -> derived from the complete rubric.
    assert r.score == 0.5


def test_parse_structured_rejects_incomplete_or_unknown_dimensions():
    for dims in (
        [{"name": "correctness", "score": 1.0}],
        [
            {"name": "correctness", "score": 1.0},
            {"name": "completeness", "score": 1.0},
            {"name": "grounding", "score": 1.0},
            {"name": "made_up", "score": 1.0},
        ],
    ):
        r = parse_structured(json.dumps({"dimensions": dims, "score": 1.0}))
        assert r.dimensions == ()
        assert r.accepts() is False


def test_parse_structured_tag_fallback():
    text = "<think>reasoned</think><critique>fine</critique><score>0.66</score>"
    r = parse_structured(text)
    assert r.score == 0.66
    assert r.reasoning == "reasoned"
    assert r.critique == "fine"
    assert r.dimensions == ()


def test_parse_structured_fails_closed_on_garbage():
    for bad in ["", "   ", "no json here", "{not valid json}", "[]"]:
        r = parse_structured(bad)
        assert r.score == 0.0
        assert r.accepts() is False


def test_parse_structured_clamps_out_of_range_scores():
    payload = {"score": 5.0, "confidence": -3.0,
               "dimensions": [
                   {"name": "correctness", "score": 2.0},
                   {"name": "completeness", "score": 2.0},
                   {"name": "grounding", "score": 2.0},
                   {"name": "safety", "score": 2.0},
               ]}
    r = parse_structured(json.dumps(payload))
    assert r.score == 1.0
    assert r.confidence == 0.0
    assert r.dimensions[0].score == 1.0
    assert r.dimensions[0].vetoes is False  # clamped to 1.0, above the floor


def test_to_audit_dict_is_stable_and_complete():
    dims = (DimensionScore("correctness", 0.9, "good"),
            DimensionScore("safety", 0.2, "risky", vetoes=True))
    r = ReasoningReward(score=0.7, confidence=0.8, reasoning="trace",
                        critique="mixed", dimensions=dims)
    d = r.to_audit_dict()
    assert list(d.keys()) == [
        "score", "confidence", "accepts", "vetoed", "critique",
        "reasoning", "dimensions",
    ]
    assert d["accepts"] is False and d["vetoed"] is True
    assert d["dimensions"][1]["name"] == "safety"
    # Round-trips through JSON deterministically (audit/signing needs this).
    assert json.loads(json.dumps(d)) == d


def test_enabled_on_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_REASONING_REWARD", raising=False)
    # The rubric judge is the default; no env override -> on.
    assert enabled() is True


def test_enabled_env_override(monkeypatch):
    monkeypatch.setenv("MAVERICK_REASONING_REWARD", "1")
    assert enabled() is True
    # An explicit opt-out forces the scalar verifier even though the default is on.
    monkeypatch.setenv("MAVERICK_REASONING_REWARD", "0")
    assert enabled() is False


def test_default_rubric_weights_sum_to_one():
    # A sanity anchor: the holistic weighting is a proper mean over the rubric.
    assert round(sum(w for _, w, _ in DEFAULT_RUBRIC), 6) == 1.0


def test_to_audit_summary_is_compact_and_stable():
    dims = (DimensionScore("correctness", 0.9, "good"),
            DimensionScore("safety", 0.2, "risky", vetoes=True))
    r = ReasoningReward(score=0.7, confidence=0.8, reasoning="trace " * 100,
                        critique="x" * 500, dimensions=dims)
    s = r.to_audit_summary()
    assert "reasoning" not in s              # long trace dropped
    assert len(s["critique"]) <= 280         # critique truncated
    assert s["vetoed"] is True
    assert s["dimensions"][1] == {"name": "safety", "score": 0.2, "vetoes": True}
    assert json.loads(json.dumps(s)) == s    # signed-chain needs a stable dict


def test_audit_rewards_explicit_opt_out(monkeypatch):
    from maverick.reasoning_reward import audit_rewards_enabled
    monkeypatch.setenv("MAVERICK_REASONING_REWARD_AUDIT", "0")
    assert audit_rewards_enabled() is False


def test_audit_rewards_env_override(monkeypatch):
    from maverick.reasoning_reward import audit_rewards_enabled
    monkeypatch.setenv("MAVERICK_REASONING_REWARD_AUDIT", "1")
    assert audit_rewards_enabled() is True
    monkeypatch.setenv("MAVERICK_REASONING_REWARD_AUDIT", "0")
    assert audit_rewards_enabled() is False
