"""Unknown/private lesson sources never become shared prompt or dashboard content."""
from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick import memory_ownership
from maverick import self_harness as sh


@pytest.fixture
def lessons(tmp_path, monkeypatch):
    path = tmp_path / "addenda.json"
    allowed = {0, 11}
    monkeypatch.setattr(sh, "enabled", lambda: True)
    monkeypatch.setattr(memory_ownership, "source_allowed", lambda goal_id, owner: owner == "" and goal_id in allowed)
    return path, allowed


def proposal(line="Verify the input format.", sources=(11,)):
    return sh.HarnessProposal("model", "format", line, "three failures", source_goal_ids=sources)


def test_legacy_sidecar_does_not_grant_shared_recall_or_search(lessons):
    path, _ = lessons
    sh._apply_addendum(proposal(sources=()), path, provenance={"samples": 20})
    assert sh.load_addenda(path)  # evidence retained, no inferred local owner
    assert sh.recall_addendum("model", path) == ""
    assert sh.list_learned(path) == {}
    assert sh.line_provenance("model", path) == []
    assert sh.line_efficacy("model", path) == []
    assert sh.detect_store_conflicts(path=path) == []
    assert sh.transferable_lines("model", path) == []


def test_current_sources_are_rechecked_before_every_shared_read(lessons):
    path, allowed = lessons
    sh._apply_addendum(proposal(), path)
    assert "Verify the input" in sh.recall_addendum("model", path)
    assert sh.list_learned(path)["model"] == [proposal().addendum_line]
    allowed.remove(11)  # deleted, private or excluded since promotion
    assert sh.recall_addendum("model", path) == ""
    assert sh.line_efficacy("model", path) == []
    assert sh.transferable_lines("model", path) == []
    assert sh.load_addenda(path)


def test_mining_carries_only_current_explicit_unowned_sources(lessons):
    rows = [{"owner": owner, "goal_id": goal_id, "model_id": "model", "goal_text": "format data", "failure_class": "format"}
            for owner, goal_id in [("", 11), ("user:alice", 11), (None, 11), ("", 12)]]
    signatures = sh.mine_failures(rows, model_id="model", min_support=1)
    assert len(signatures) == 1 and signatures[0].support == 1
    p = sh.propose_addendum(signatures[0], propose_fn=lambda sig: "Verify the input format.")
    assert p.source_goal_ids == (11,)


def test_private_or_unknown_promotion_refuses_before_controller(lessons, monkeypatch):
    path, _ = lessons
    monkeypatch.setattr(sh, "check_learning_halt", lambda *args: None)
    for sources in [(), (12,), (True,), (-1,), (None,)]:
        ok, reason = sh._gate_and_apply(proposal(sources=sources), SimpleNamespace(), path=path)
        assert not ok and "source ownership" in reason
    assert not path.exists()


def test_corrupt_or_mismatched_source_meta_is_withheld(lessons):
    path, _ = lessons
    p = proposal()
    sh._apply_addendum(p, path)
    meta = sh.load_line_meta(path)
    rec = meta[sh._line_id("model", p.addendum_line)]
    rec["text"] = "Different private content"
    sh._write_line_meta(meta, path)
    assert sh.recall_addendum("model", path) == ""
    sh._meta_path(path).write_text("not json", encoding="utf-8")
    assert sh.list_learned(path) == {}


def test_source_receipt_failure_never_claims_published_line(lessons, monkeypatch):
    path, _ = lessons
    monkeypatch.setattr(sh, "_write_line_meta", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        sh._apply_addendum(proposal(), path)
    assert sh.recall_addendum("model", path) == ""


def test_lineage_survives_transfer_without_trusting_proposer_text(lessons, monkeypatch):
    path, _ = lessons
    sh._apply_addendum(proposal(), path)
    captured = []
    monkeypatch.setattr(sh, "validate_proposal", lambda *args, **kw: SimpleNamespace(accepted=True))
    monkeypatch.setattr(sh, "_gate_and_apply", lambda p, *args, **kw: (captured.append(p) is not None, "test"))
    sh.run_transfer("model", ["second"], path=path, eval_for_target=lambda model: (["case"], ["holdout"], None, None))
    assert len(captured) == 1
    assert captured[0].source_goal_ids == (11,)
    assert captured[0].model_id == "second"


def test_normalized_repromotion_does_not_inherit_old_authority(lessons):
    path, _ = lessons
    sh._apply_addendum(proposal(), path)
    sh._apply_addendum(replace(proposal(), source_goal_ids=()), path)
    assert sh.recall_addendum("model", path) == ""


def test_harvest_staging_and_review_preserve_current_source_lineage(lessons):
    import json

    from maverick import self_harness_eval as ev
    path, allowed = lessons
    corpus = path.with_name("corpus.json")
    goals = [SimpleNamespace(id=11, owner="", title="format data", description="", result="valid result", updated_at=20)]
    failures = [{"owner": "", "goal_id": 11, "goal_text": "format data", "ts": 10}]
    candidates = ev.harvest_corpus_candidates(failures, goals)
    assert candidates[0]["source_goal_ids"] == [11]
    assert ev.stage_candidates(corpus, "model", candidates) == 1
    raw = ev._load_raw(ev.pending_corpus_path(corpus))
    legacy = {"goal": "old private task", "expected": "secret", "added_at": 1}
    raw["model"].append(legacy)
    ev._write_corpus_file(ev.pending_corpus_path(corpus), raw)
    assert len(ev.load_pending(corpus)["model"]) == 1
    result = ev.resolve_pending(corpus, "model", accept=[1])
    assert result["merged"] == 1
    assert ev._load_raw(ev.pending_corpus_path(corpus))["model"] == [legacy]
    assert ev.load_eval_corpus(corpus)["model"][0]["source_goal_ids"] == [11]
    allowed.remove(11)
    assert ev.load_eval_corpus(corpus) == {}
    assert json.loads(corpus.read_text())["model"][0]["goal"] == "format data"


def test_unknown_machine_corpus_is_withheld_manual_operator_cases_remain(lessons):
    import json

    from maverick import self_harness_eval as ev
    path, _ = lessons
    manual = {"goal": "manually authored shared exercise", "expected": "sample"}
    old = {"goal": "old automatic private case", "expected": "private", "added_at": 1}
    path.write_text(json.dumps({"model": [manual, old]}), encoding="utf-8")
    assert ev.load_eval_corpus(path) == {"model": [manual]}
    ev.pending_corpus_path(path).write_text(json.dumps({"model": [manual, old]}), encoding="utf-8")
    assert ev.load_pending(path) == {}
    assert ev.stage_candidates(path, "model", [old]) == 0


def test_harvest_denies_other_owners_unknown_owners_and_lost_sources(lessons):
    from maverick import self_harness_eval as ev
    _, allowed = lessons
    failures = [{"owner": "", "goal_id": 11, "goal_text": "format data", "ts": 10}]
    for owner in [None, "user:alice"]:
        goal = SimpleNamespace(id=11, owner=owner, title="format data", description="", result="secret", updated_at=20)
        assert ev.harvest_corpus_candidates(failures, [goal]) == []
    allowed.remove(11)
    goal.owner = ""
    assert ev.harvest_corpus_candidates(failures, [goal]) == []


def test_scoring_and_memoized_results_recheck_original_source(lessons):
    import math

    from maverick import self_harness_eval as ev
    from maverick import self_improvement_runner as runner
    _, allowed = lessons
    cases = [{"goal": "task", "expected": "yes", "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [11]}]
    sent = []
    with_line, _ = ev.corpus_ab_scorers(cases, run_fn=lambda line, goal: sent.append(goal) or "yes")
    memo = runner._memo_scorer(with_line, by_line=True)
    assert memo("line", ["task"]) == 1
    before = len(sent)
    allowed.remove(11)
    with pytest.raises(PermissionError):
        memo("line", ["task"])
    assert math.isnan(with_line("line", ["task"]))
    assert len(sent) == before
    assert ev.corpus_quality(cases, run_fn=lambda *args: sent.append("should not dispatch")) == []


def test_risk_limited_manifest_keeps_lineage_and_hides_old_harvest(lessons):
    from maverick import self_improvement_runner as runner
    _, allowed = lessons
    shared = {"goal": "shared", "expected": "yes", "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [11]}
    legacy = {"goal": "private old", "expected": "private", "added_at": 2}
    assert runner._normalize_eval_manifest({"model": [shared, legacy]}) == {"model": [shared]}
    allowed.remove(11)
    assert runner._normalize_eval_manifest({"model": [shared, legacy]}) == {}


def test_proposer_stops_before_dispatch_when_source_loses_permission(lessons):
    _, allowed = lessons
    calls = []
    proposer = sh.llm_proposer(SimpleNamespace(complete=lambda *args, **kwargs: calls.append(args)))
    sig = sh.FailureSignature("model", "format", "failure", 1, ("private source",), source_goal_ids=(11,))
    allowed.remove(11)
    assert proposer(sig) == ""
    assert calls == []
