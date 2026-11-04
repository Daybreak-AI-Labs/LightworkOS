"""Auto-skill distillation v2: evidence gate + dedup against the store."""
from __future__ import annotations

import pytest
from maverick.skill import distillation as v2


def _traj(goal, t=1.0, success=True, tools=None):
    return {"goal": goal, "success": success, "t": t, "tools": tools or []}


# ---- pure helpers ----

def test_overlap_coefficient():
    assert v2._overlap(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0
    assert v2._overlap(frozenset({"a"}), frozenset({"b"})) == 0.0
    assert v2._overlap(frozenset(), frozenset()) == 1.0
    # containment: the small set fully inside the large one -> 1.0
    assert v2._overlap(frozenset({"a"}), frozenset({"a", "b", "c"})) == 1.0


def test_signature_extracts_content_tokens():
    sig = v2._signature({"name": "deploy-staging-app", "summary": "deploy the app",
                         "triggers": ["deploy to staging"], "tools_needed": ["shell"]})
    assert "deploy" in sig and "staging" in sig and "shell" in sig
    assert "the" not in sig  # stop-word


def test_is_duplicate():
    a = frozenset({"deploy", "staging", "kubernetes", "app"})
    existing = [frozenset({"deploy", "staging", "kubernetes", "service"})]
    assert v2.is_duplicate(a, existing, threshold=0.5)
    assert not v2.is_duplicate(a, existing, threshold=0.9)
    assert not v2.is_duplicate(a, [], threshold=0.5)


# ---- gating ----

def test_gate_rejects_too_few_examples():
    skill, reason = v2.distill_gated([_traj("ship the release")], min_examples=2)
    assert skill is None and "too few examples" in reason


def test_gate_rejects_no_success():
    skill, reason = v2.distill_gated([_traj("x", success=False)], min_examples=1)
    assert skill is None and "no successful" in reason


def test_gate_passes_novel_skill():
    trajs = [_traj("deploy the billing service", t=2),
             _traj("deploy the billing api", t=1)]
    skill, reason = v2.distill_gated(trajs, min_examples=2)
    assert skill is not None and reason == "ok"


def test_gate_rejects_duplicate():
    trajs = [_traj("deploy the billing service", t=2),
             _traj("deploy the billing api", t=1)]
    skill, _ = v2.distill_gated(trajs, min_examples=2)
    # feed the just-distilled skill's signature back as "existing"
    existing = [v2._signature(skill)]
    skill2, reason = v2.distill_gated(trajs, existing_signatures=existing,
                                      min_examples=2, dedup_threshold=0.6)
    assert skill2 is None and "duplicate" in reason


# ---- quality gate (specificity / precision) ----

def test_passes_quality_accepts_specific_skill():
    skill = {"name": "reconcile-ledger",
             "summary": "reconcile the general ledger to the bank",
             "triggers": ["reconcile the general ledger"], "tools_needed": ["read_file"]}
    ok, reason = v2.passes_quality(skill)
    assert ok and reason == "ok"


def test_passes_quality_rejects_no_triggers():
    ok, reason = v2.passes_quality({"name": "x", "summary": "lots of specific words",
                                    "triggers": [], "tools_needed": []})
    assert not ok and "no triggers" in reason


def test_passes_quality_rejects_too_generic():
    # Content is almost all glue words -> too few signal tokens -> it would
    # over-fire on unrelated goals (the noise-injection failure mode).
    skill = {"name": "do-it", "summary": "use the tool to run the goal",
             "triggers": ["do the task"], "tools_needed": []}
    ok, reason = v2.passes_quality(skill)
    assert not ok and "too generic" in reason


def test_distill_gated_wires_quality_check():
    # A normally-acceptable skill is rejected when the signal bar is impossibly
    # high -> proves the quality gate is wired into distill_gated.
    trajs = [_traj("deploy the billing service", t=2),
             _traj("deploy the billing api", t=1)]
    skill, reason = v2.distill_gated(trajs, min_examples=2, min_signal=99)
    assert skill is None and "low quality" in reason


# ---- store integration ----

def test_signatures_from_store_reads_md(tmp_path):
    (tmp_path / "a.md").write_text("# deploy staging\ntriggers: deploy to staging",
                                   encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("not a skill", encoding="utf-8")
    sigs = v2.signatures_from_store(tmp_path)
    assert len(sigs) == 1 and "deploy" in sigs[0]


def test_signatures_from_store_missing_dir(tmp_path):
    assert v2.signatures_from_store(tmp_path / "nope") == []


def test_distill_and_save_gated_saves_then_dedups(tmp_path):
    trajs = [_traj("deploy the billing service", t=2),
             _traj("deploy the billing api", t=1)]
    path, reason = v2.distill_and_save_gated(trajs, store=tmp_path, min_examples=2)
    assert path is not None and reason == "ok" and path.exists()

    # second run with the same lesson -> recognized as duplicate, not saved again
    path2, reason2 = v2.distill_and_save_gated(trajs, store=tmp_path, min_examples=2)
    assert path2 is None and "duplicate" in reason2
    assert len(list(tmp_path.glob("*.md"))) == 1


def test_distill_and_save_gated_gate_blocks_one_off(tmp_path):
    path, reason = v2.distill_and_save_gated([_traj("one off")], store=tmp_path,
                                             min_examples=2)
    assert path is None and "too few examples" in reason
    assert list(tmp_path.glob("*.md")) == []


def test_distill_and_save_rechecks_immediately_before_write(tmp_path):
    trajs = [_traj("deploy the billing service", t=2),
             _traj("deploy the billing api", t=1)]

    def refuse():
        raise RuntimeError("operator stop")

    with pytest.raises(RuntimeError, match="operator stop"):
        v2.distill_and_save_gated(
            trajs, store=tmp_path, min_examples=2, before_save=refuse)
    assert list(tmp_path.glob("*.md")) == []


def test_direct_distillation_cannot_bypass_global_learning_halt(
    tmp_path, monkeypatch,
):
    from maverick.learning_guard import Halted

    trajs = [_traj("deploy the billing service", t=2),
             _traj("deploy the billing api", t=1)]
    monkeypatch.setattr(
        "maverick.learning_guard.check_learning_halt",
        lambda *_: (_ for _ in ()).throw(Halted("operator stop", "test")),
    )

    with pytest.raises(Halted, match="operator stop"):
        v2.distill_and_save_gated(trajs, store=tmp_path, min_examples=2)
    assert list(tmp_path.glob("*.md")) == []
