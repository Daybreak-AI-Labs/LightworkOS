"""Tests for anchor-gated evaluator co-evolution (maverick.evaluator_evolution).

Deterministic and offline: no LLM, no network. We exercise the epsilon-best-belief
math, the anchor + its immutability governance, selective erasure, the
challenger-selection rule, and the end-to-end promotion routed through the
self-improvement governance spine.
"""
from __future__ import annotations

import pytest
from maverick import evaluator_evolution as ee
from maverick.self_improvement import PromotionLedger, SelfImprovementController

# -- epsilon-best-belief --------------------------------------------------------

def test_best_belief_no_evidence_is_eps_quantile_of_uniform():
    # Beta(1,1) is uniform; its 0.05-quantile is 0.05.
    assert ee.best_belief(0, 0, 0.05) == pytest.approx(0.05, abs=0.01)


def test_best_belief_in_unit_interval():
    for s, f in [(0, 0), (10, 0), (0, 10), (7, 3), (100, 1)]:
        bb = ee.best_belief(s, f)
        assert 0.0 <= bb <= 1.0


def test_best_belief_more_evidence_raises_lower_bound_at_same_ratio():
    # Same 8:2 ratio, ten times the evidence -> a tighter, higher lower bound.
    assert ee.best_belief(80, 20) > ee.best_belief(8, 2)


def test_best_belief_higher_success_ratio_scores_higher():
    assert ee.best_belief(10, 0) > ee.best_belief(5, 5)


def test_best_belief_is_below_the_posterior_mean():
    # The 0.05-quantile is a conservative under-estimate of the mean (9/12=0.75).
    assert ee.best_belief(8, 3, 0.05) < (1 + 8) / (2 + 8 + 3)


# -- Anchor + checksum ----------------------------------------------------------

def _anchor(role="reviewer", n=14, true_every=2):
    items = tuple(
        ee.AnchorItem(id=f"{role}-{i:04d}", label=(i % true_every == 0), prompt=f"p{i}")
        for i in range(n)
    )
    return ee.Anchor(role=role, items=items)


def test_checksum_tracks_every_evaluator_visible_anchor_field():
    a = ee.Anchor("r", (ee.AnchorItem("x", True, "hello"),))
    same_label = ee.Anchor("r", (ee.AnchorItem("x", True, "WORLD"),))
    flipped = ee.Anchor("r", (ee.AnchorItem("x", False, "hello"),))
    assert a.checksum() != same_label.checksum()
    assert a.checksum() != flipped.checksum()


def test_checksum_is_order_independent():
    a = ee.Anchor("r", (ee.AnchorItem("a", True), ee.AnchorItem("b", False)))
    b = ee.Anchor("r", (ee.AnchorItem("b", False), ee.AnchorItem("a", True)))
    assert a.checksum() == b.checksum()


def test_load_anchor_skips_malformed_rows(tmp_path):
    p = tmp_path / "reviewer.ndjson"
    p.write_text(
        '{"id": "a", "label": true, "prompt": "x"}\n'
        "not json\n"
        '{"missing label": 1}\n'
        '{"id": "b", "label": false}\n',
        encoding="utf-8",
    )
    a = ee.load_anchor(p, "reviewer")
    assert {it.id for it in a.items} == {"a", "b"}


def test_load_anchor_missing_file_is_empty():
    a = ee.load_anchor("/no/such/file.ndjson", "reviewer")
    assert len(a) == 0


# -- scoring by agreement -------------------------------------------------------

def test_score_on_anchor_counts_agreement_and_abstention():
    anchor = ee.Anchor("r", (
        ee.AnchorItem("a", True), ee.AnchorItem("b", False), ee.AnchorItem("c", True),
    ))
    # agrees on a and b, missing c -> abstention counts as a failure.
    s, f = ee.score_on_anchor({"a": True, "b": False}, anchor)
    assert (s, f) == (2, 1)


# -- selective erasure ----------------------------------------------------------

def test_selective_erasure_only_drops_displaced_records():
    recs = [
        ee.EvaluatorRecord("r1", "old"),
        ee.EvaluatorRecord("r2", "other"),
        ee.EvaluatorRecord("r3", "old"),
    ]
    kept, erased = ee.selective_erasure(recs, "old")
    assert [r.record_id for r in kept] == ["r2"]
    assert {r.record_id for r in erased} == {"r1", "r3"}


# -- challenger selection (ties favour the incumbent) ---------------------------

def test_choose_challenger_picks_strictly_better():
    wid, bb = ee.choose_challenger(0.5, [("c1", 0.4), ("c2", 0.7), ("c3", 0.6)])
    assert wid == "c2" and bb == pytest.approx(0.7)


def test_choose_challenger_tie_favours_incumbent():
    wid, bb = ee.choose_challenger(0.7, [("c1", 0.7), ("c2", 0.69)])
    assert wid is None and bb == pytest.approx(0.7)


# -- anchor governance (immutability lock) --------------------------------------

def test_lock_problems_clean_when_nothing_committed():
    assert ee.lock_problems(None, {}) == []


def test_lock_problems_flags_edited_released_anchor():
    a = _anchor()
    lock = ee.anchor_fingerprint({"reviewer": a})
    edited = ee.Anchor("reviewer", a.items[:-1] + (ee.AnchorItem("reviewer-0013", True),))
    problems = ee.lock_problems(lock, {"reviewer": edited})
    assert any("checksum changed" in p for p in problems)


def test_lock_problems_flags_new_and_removed_anchors():
    a = _anchor()
    lock = ee.anchor_fingerprint({"reviewer": a})
    # a brand-new role -> must regen.
    new = ee.lock_problems(lock, {"reviewer": a, "grader": _anchor("grader")})
    assert any("regen" in p.lower() or "new anchor" in p.lower() for p in new)
    # a released role gone -> hard fail.
    removed = ee.lock_problems(lock, {})
    assert any("gone from the anchor dir" in p for p in removed)


def test_verify_anchor_integrity_requires_a_complete_matching_release_lock():
    a = _anchor()
    assert ee.verify_anchor_integrity(a, lock=None) is False
    good = ee.anchor_fingerprint({"reviewer": a})
    assert ee.verify_anchor_integrity(a, lock=good) is True
    tampered = ee.Anchor(
        "reviewer", a.items[:-1]
        + (ee.AnchorItem("reviewer-0013", False, "edited prompt"),))
    assert ee.verify_anchor_integrity(tampered, lock=good) is False
    assert ee.verify_anchor_integrity(a, lock={"checksums": {}, "sizes": {}}) is False
    assert ee.verify_anchor_integrity(a, lock={"checksums": {}}) is False


def test_committed_anchor_is_non_vacuous_reproducible_and_locked():
    lock = ee.load_lock()
    assert isinstance(lock, dict) and "checksums" in lock
    anchors = ee.discover_anchors()
    assert set(anchors) == {"self_harness_protocol_v1"}
    anchor = anchors["self_harness_protocol_v1"]
    assert len(anchor) == 16
    assert sum(item.label for item in anchor.items) == 8
    assert ee.verify_anchor_integrity(anchor, lock=lock) is True
    assert ee.lock_problems(lock, anchors) == []


# -- CLI: --regen must not launder an edited released anchor --------------------

def _cli_env(tmp_path, monkeypatch):
    """Isolate --regen's anchor dir + lock path so the test never touches the
    real committed evaluator_anchors/evaluator_anchors.lock.json."""
    anchor_dir = tmp_path / "anchors"
    anchor_dir.mkdir()
    monkeypatch.setenv("MAVERICK_EVALUATOR_ANCHOR_DIR", str(anchor_dir))
    lock_path = tmp_path / "evaluator_anchors.lock.json"
    monkeypatch.setattr(ee, "anchor_lock_path", lambda: lock_path)
    return anchor_dir, lock_path


def test_check_with_no_lock_and_no_anchor_reports_nothing_governed(tmp_path, monkeypatch, capsys):
    _cli_env(tmp_path, monkeypatch)
    assert ee.main(["--ci"]) == 0
    assert "NO ANCHORS COMMITTED" in capsys.readouterr().out


def test_regen_refuses_to_launder_an_edited_released_anchor(tmp_path, monkeypatch):
    anchor_dir, lock_path = _cli_env(tmp_path, monkeypatch)
    f = anchor_dir / "reviewer.ndjson"
    f.write_text('{"id": "case1", "label": true}\n')
    assert ee.main(["--regen"]) == 0
    original = lock_path.read_text()

    f.write_text('{"id": "case1", "label": false}\n')  # edit a released anchor
    assert ee.main(["--regen"]) == 1                    # refuses, not silently rewritten
    assert lock_path.read_text() == original


def test_regen_force_cannot_relock_an_edited_released_anchor(tmp_path, monkeypatch):
    anchor_dir, lock_path = _cli_env(tmp_path, monkeypatch)
    f = anchor_dir / "reviewer.ndjson"
    f.write_text('{"id": "case1", "label": true}\n')
    assert ee.main(["--regen"]) == 0
    original = lock_path.read_text()

    f.write_text('{"id": "case1", "label": false}\n')
    assert ee.main(["--regen", "--force"]) == 1
    assert lock_path.read_text() == original


def test_regen_without_prior_lock_is_unaffected(tmp_path, monkeypatch):
    # A brand-new anchor (nothing committed yet) must still regen cleanly
    # without needing --force -- only an edit to an *already-locked* role
    # should be refused.
    anchor_dir, lock_path = _cli_env(tmp_path, monkeypatch)
    f = anchor_dir / "reviewer.ndjson"
    f.write_text('{"id": "case1", "label": true}\n')
    assert ee.main(["--regen"]) == 0
    assert lock_path.exists()


def test_regen_cannot_erase_a_released_anchor_even_with_force(tmp_path, monkeypatch):
    anchor_dir, lock_path = _cli_env(tmp_path, monkeypatch)
    f = anchor_dir / "reviewer.ndjson"
    f.write_text('{"id": "case1", "label": true}\n')
    assert ee.main(["--regen"]) == 0
    original = lock_path.read_text()

    f.unlink()
    assert ee.main(["--regen"]) == 1
    assert ee.main(["--regen", "--force"]) == 1
    assert lock_path.read_text() == original


@pytest.mark.parametrize("contents", [
    "",
    '{"id": "case1", "label": "yes"}\n',
    '{"id": "case1", "label": true}\nnot-json\n',
])
def test_regen_refuses_empty_or_malformed_anchor_files(
    tmp_path, monkeypatch, contents,
):
    anchor_dir, lock_path = _cli_env(tmp_path, monkeypatch)
    (anchor_dir / "reviewer.ndjson").write_text(contents)

    assert ee.main(["--regen"]) == 1
    assert not lock_path.exists()


# -- end-to-end promotion through the governance spine --------------------------

def _ctrl(frozen=False, **kw):
    return SelfImprovementController(
        frozen_fn=lambda: frozen,
        audit_fn=lambda **k: None,
        **kw,
    )


def _verdicts(anchor, *, agree):
    """Build a verdict map that agrees on the first ``agree`` items (else flips)."""
    out = {}
    for i, it in enumerate(anchor.items):
        out[it.id] = it.label if i < agree else (not it.label)
    return out


def test_consider_promotion_no_op_when_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "0")
    monkeypatch.setenv("MAVERICK_EVALUATOR_EVOLUTION", "0")
    anchor = _anchor()
    slot = ee.EvaluatorSlot(role="reviewer", evaluator_id="old")
    res = ee.consider_promotion(
        slot, _verdicts(anchor, agree=8),
        {"new": _verdicts(anchor, agree=14)}, anchor, [],
    )
    assert res.promoted is False
    assert slot.evaluator_id == "old" and slot.epoch == 1


def test_consider_promotion_promotes_better_judge_and_erases(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    monkeypatch.setenv("MAVERICK_EVALUATOR_EVOLUTION", "1")
    monkeypatch.setattr(ee, "_audit", lambda *a, **k: None)
    anchor = _anchor(n=14)
    slot = ee.EvaluatorSlot(role="reviewer", evaluator_id="old")
    records = [ee.EvaluatorRecord("r1", "old"), ee.EvaluatorRecord("r2", "other")]
    # Controller that auto-promotes the evaluator rung (ceiling raised).
    ctrl = _ctrl(
        max_auto_rung="evaluator",
        ledger=PromotionLedger(path=tmp_path / "promotion-ledger.json"),
    )
    res = ee.consider_promotion(
        slot,
        _verdicts(anchor, agree=8),               # incumbent: 8/14 agree
        {"new": _verdicts(anchor, agree=14)},     # challenger: 14/14 agree
        anchor, records, lock=ee.anchor_fingerprint({"reviewer": anchor}),
        controller=ctrl,
    )
    assert res.promoted is True
    assert res.challenger_id == "new"
    assert res.challenger_bb > res.incumbent_bb
    assert slot.evaluator_id == "new" and slot.epoch == 2
    # Only the displaced evaluator's records were erased.
    assert {r.record_id for r in res.erased} == {"r1"}
    assert {r.record_id for r in res.kept} == {"r2"}


def test_consider_promotion_blocked_by_calibration_freeze(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    monkeypatch.setenv("MAVERICK_EVALUATOR_EVOLUTION", "1")
    monkeypatch.setattr(ee, "_audit", lambda *a, **k: None)
    anchor = _anchor(n=14)
    slot = ee.EvaluatorSlot(role="reviewer", evaluator_id="old")
    ctrl = _ctrl(frozen=True, max_auto_rung="evaluator")
    res = ee.consider_promotion(
        slot, _verdicts(anchor, agree=8), {"new": _verdicts(anchor, agree=14)},
        anchor, [], lock=ee.anchor_fingerprint({"reviewer": anchor}),
        controller=ctrl,
    )
    assert res.promoted is False
    assert "frozen" in res.reason or "calibration" in res.reason.lower()
    assert slot.evaluator_id == "old" and slot.epoch == 1


def test_consider_promotion_needs_human_above_default_ceiling(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    monkeypatch.setenv("MAVERICK_EVALUATOR_EVOLUTION", "1")
    monkeypatch.setattr(ee, "_audit", lambda *a, **k: None)
    anchor = _anchor(n=14)
    slot = ee.EvaluatorSlot(role="reviewer", evaluator_id="old")
    # Default ceiling is "policy", below "evaluator": a swap needs approval.
    ctrl = _ctrl(
        ledger=PromotionLedger(path=tmp_path / "promotion-ledger.json"),
    )  # max_auto_rung defaults to "policy"
    refused = ee.consider_promotion(
        slot, _verdicts(anchor, agree=8), {"new": _verdicts(anchor, agree=14)},
        anchor, [], lock=ee.anchor_fingerprint({"reviewer": anchor}),
        controller=ctrl,
    )
    assert refused.promoted is False
    # A bare boolean cannot stand in for a trusted signed approval.
    approved = ee.consider_promotion(
        slot, _verdicts(anchor, agree=8), {"new": _verdicts(anchor, agree=14)},
        anchor, [], lock=ee.anchor_fingerprint({"reviewer": anchor}),
        controller=ctrl, approved=True,
    )
    assert approved.promoted is False
    assert "signature" in approved.reason.lower()


def test_consider_promotion_refuses_tampered_anchor(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    monkeypatch.setenv("MAVERICK_EVALUATOR_EVOLUTION", "1")
    monkeypatch.setattr(ee, "_audit", lambda *a, **k: None)
    anchor = _anchor(n=14)
    # Lock pins a DIFFERENT anchor; the live one won't match -> refuse.
    other = _anchor(n=14, true_every=3)
    lock = ee.anchor_fingerprint({"reviewer": other})
    slot = ee.EvaluatorSlot(role="reviewer", evaluator_id="old")
    res = ee.consider_promotion(
        slot, _verdicts(anchor, agree=8), {"new": _verdicts(anchor, agree=14)},
        anchor, [], lock=lock, controller=_ctrl(max_auto_rung="evaluator"),
    )
    assert res.promoted is False
    assert "integrity" in res.reason


def test_prompt_only_anchor_edit_is_refused_before_any_scoring(monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    monkeypatch.setenv("MAVERICK_EVALUATOR_EVOLUTION", "1")
    monkeypatch.setattr(ee, "_audit", lambda *a, **k: None)
    released = _anchor(n=14)
    changed = ee.Anchor(
        role=released.role,
        items=(
            ee.AnchorItem(
                released.items[0].id, released.items[0].label,
                released.items[0].prompt + " changed",
            ),
            *released.items[1:],
        ),
    )
    monkeypatch.setattr(
        ee, "score_on_anchor",
        lambda *_: pytest.fail("anchor scoring must not start after integrity drift"),
    )

    result = ee.consider_promotion(
        ee.EvaluatorSlot(role="reviewer", evaluator_id="old"),
        {}, {"new": {}}, changed, [],
        lock=ee.anchor_fingerprint({"reviewer": released}),
        controller=_ctrl(max_auto_rung="evaluator"),
    )
    assert result.promoted is False
    assert "integrity" in result.reason
