"""DGM cycle driver + proof-gated surface widening.

These pin the research loop's contract: OFF by default, control-plane edits are
refused before evaluation, live adoption seams stay inert, research candidates
accumulate in the archive, and any wider research surface derives only from the
authoritative ledger rather than archive self-attestation.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from maverick import learning_guard
from maverick import self_improvement as si
from maverick import self_modify as sm
from maverick import self_modify_loop as loop
from maverick.self_modify_archive import CodeArchive, CodeCandidate
from maverick.self_modify_context import ContextFile, ProposalContext
from maverick.self_modify_loop import (
    Proposal,
    SurfaceTier,
    WideningPolicy,
    earned_surface,
    run_cycle,
    run_loop,
)

EDIT = "packages/maverick-core/maverick/domains/foo.py"


@dataclass
class FakeEval:
    ok: bool = True
    baseline_score: float = 0.5
    candidate_score: float = 0.9
    samples: int = 8
    reason: str = ""


def _patch(path: str = EDIT, added: str = "TUNING = 0.7") -> str:
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1 +1,2 @@\n old\n+{added}\n")


def _tiers() -> WideningPolicy:
    return WideningPolicy(tiers=(
        SurfaceTier("t0", (), 0),
        SurfaceTier("t1", ("packages/maverick-core/maverick/domains/*.py",), 1),
        SurfaceTier("t2", ("packages/maverick-core/maverick/**",), 3),
    ))


def _controller(tmp_path, *, ledger=None):
    durable_ledger = ledger if ledger is not None else si.PromotionLedger(
        path=tmp_path / "promotion-ledger.json")
    return si.SelfImprovementController(
        min_improvement=0.0, max_auto_rung="policy",
        frozen_fn=lambda: False, audit_fn=lambda **k: None,
        ledger=durable_ledger)


@pytest.fixture
def _on(monkeypatch):
    monkeypatch.setattr(sm, "enabled", lambda: True)
    monkeypatch.setattr(si, "enabled", lambda: True)


class TestWideningPolicy:
    def test_earned_grows_with_promotions(self):
        p = _tiers()
        assert p.earned(promotions=0, had_rollback=False).name == "t0"
        assert p.earned(promotions=1, had_rollback=False).name == "t1"
        assert p.earned(promotions=3, had_rollback=False).name == "t2"

    def test_rollback_freezes_at_tier0(self):
        p = _tiers()
        assert p.earned(promotions=100, had_rollback=True).name == "t0"

    def test_empty_policy_grants_nothing(self):
        t = WideningPolicy().earned(promotions=5, had_rollback=False)
        assert t.editable_globs == ()

    def test_earned_surface_reads_the_archive(self):
        a = CodeArchive()
        a.add(CodeCandidate(summary="p1", patch="+a", score=1.0, promoted=True))
        tier, surface = earned_surface(a, _tiers())
        assert tier.name == "t1"
        assert surface.editable_globs == (
            "packages/maverick-core/maverick/domains/*.py",)

    def test_earned_surface_freezes_after_rollback(self):
        a = CodeArchive()
        for i in range(5):
            a.add(CodeCandidate(summary=f"p{i}", patch=f"+a{i}", score=1.0,
                                promoted=True))
        a.add(CodeCandidate(summary="bad", patch="+bad", score=1.0,
                            promoted=True, rolled_back=True))
        tier, _ = earned_surface(a, _tiers())
        assert tier.name == "t0"             # a regression forfeits widening


class TestRunCycleDisabled:
    def test_off_by_default_is_a_noop(self, monkeypatch):
        monkeypatch.setattr(sm, "enabled", lambda: False)
        called = []
        rep = run_cycle(
            archive=CodeArchive(),
            proposer=lambda parent, surface: called.append(1) or Proposal(_patch()),
            evaluate=lambda p, s: FakeEval(), policy=_tiers())
        assert rep.proposed is False
        assert called == []                  # the proposer never ran
        assert "disabled" in rep.reason

    def test_explicit_tenant_env_refuses_all_public_entry_points(
        self, _on, monkeypatch,
    ):
        monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
        called = []

        rep = run_cycle(
            archive=CodeArchive(),
            proposer=lambda *_: called.append("proposal"),
            evaluate=lambda *_: called.append("evaluation"),
        )
        reports = run_loop(
            archive=CodeArchive(),
            proposer=lambda *_: called.append("loop-proposal"),
            evaluate=lambda *_: called.append("loop-evaluation"),
            cycles=2,
        )

        assert "explicit tenant" in rep.reason
        assert len(reports) == 1
        assert "explicit tenant" in reports[0].reason
        assert called == []


class TestRunCycle:
    def test_no_surface_yet_skips(self, _on):
        # Empty track record -> tier 0 grants no surface -> proposer never runs.
        called = []
        rep = run_cycle(
            archive=CodeArchive(),
            proposer=lambda parent, surface: called.append(1) or Proposal(_patch()),
            evaluate=lambda p, s: FakeEval(), policy=_tiers())
        assert called == []
        assert "no editable surface" in rep.reason

    def test_proposer_none_is_reported(self, _on):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        rep = run_cycle(archive=a, proposer=lambda p, s: None,
                        evaluate=lambda p, s: FakeEval(), policy=_tiers())
        assert rep.proposed is False and "no patch" in rep.reason

    def test_boundary_refuses_control_plane_in_loop(self, _on):
        # Even inside the loop, a control-plane edit is refused structurally.
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        # A permissive tier so ONLY the boundary (not the allowlist) can refuse.
        policy = WideningPolicy(tiers=(SurfaceTier("wide", ("**",), 0),))
        cp = _patch("packages/maverick-core/maverick/verifier.py")
        rep = run_cycle(archive=a, proposer=lambda p, s: Proposal(cp),
                        evaluate=lambda p, s: FakeEval(), policy=policy)
        assert rep.proposed is True
        assert rep.review_ok is False
        assert "protected" in rep.reason

    def test_secret_patch_never_reaches_evaluator_or_archive(self, _on, tmp_path):
        archive = CodeArchive()
        archive.add(CodeCandidate(
            summary="seed", patch="+a", score=1.0, promoted=True))
        evaluated = []
        secret = "not-a-real-password-" + ("z" * 24)  # pragma: allowlist secret
        patch = _patch(added=f'DB_PASSWORD="{secret}"')

        rep = run_cycle(
            archive=archive,
            proposer=lambda p, s: Proposal(patch, "bad output"),
            evaluate=lambda p, s: evaluated.append(True) or FakeEval(),
            policy=_tiers(), rung="code", controller=_controller(tmp_path),
        )

        assert rep.review_ok is False
        assert rep.evaluated is False
        assert "detected secret material" in rep.reason
        assert evaluated == []
        assert len(archive.candidates) == 1

    def test_halt_armed_during_evaluation_prevents_archive_write(
        self, _on, tmp_path, monkeypatch,
    ):
        archive = CodeArchive()
        archive.add(CodeCandidate(
            summary="seed", patch="+a", score=1.0, promoted=True))
        phases = []

        def guard(_job, phase):
            phases.append(phase)
            if phase == "after-evaluation":
                raise learning_guard.Halted("operator stop", "test")

        monkeypatch.setattr(loop, "check_learning_halt", guard)
        with pytest.raises(learning_guard.Halted):
            run_cycle(
                archive=archive,
                proposer=lambda p, s: Proposal(_patch(), "candidate"),
                evaluate=lambda p, s: FakeEval(),
                policy=_tiers(), rung="code", controller=_controller(tmp_path),
            )

        assert "after-evaluation" in phases
        assert len(archive.candidates) == 1

    @pytest.mark.parametrize("rung", ["prompt", "policy", "tool", "weights"])
    def test_rung_downgrade_is_refused_before_proposal_or_evaluation(
        self, _on, tmp_path, rung,
    ):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        calls = []
        rep = run_cycle(
            archive=a,
            proposer=lambda p, s: calls.append("proposal") or Proposal(_patch()),
            evaluate=lambda p, s: calls.append("evaluation") or FakeEval(),
            policy=_tiers(), rung=rung, controller=_controller(tmp_path),
        )
        assert rep.proposed is False and rep.evaluated is False
        assert rep.promoted is False and rep.applied is False
        assert "require rung='code'" in rep.reason
        assert calls == []
        assert len(a.candidates) == 1

    def test_code_rung_without_signature_archives_but_does_not_promote(
        self, _on, tmp_path,
    ):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        rep = run_cycle(
            archive=a, proposer=lambda p, s: Proposal(_patch(), "risky"),
            evaluate=lambda p, s: FakeEval(), policy=_tiers(),
            rung="code", controller=_controller(tmp_path))
        assert rep.evaluated is True
        assert rep.promoted is False         # stock loop has no adoption path
        cand = a.get(rep.candidate_id)
        assert cand is not None and cand.promoted is False   # kept as an ancestor

    def test_legacy_code_approval_is_inert_and_never_receipted(
        self, _on, tmp_path,
    ):
        archive = CodeArchive()
        archive.add(CodeCandidate(
            summary="seed", patch="+a", score=1.0, promoted=True))
        controller = _controller(tmp_path)
        called = []

        def legacy_approve(*_args):
            called.append(True)
            return "replayable-v1-signature", "00" * 32

        rep = run_cycle(
            archive=archive,
            proposer=lambda p, s: Proposal(_patch(), "legacy code"),
            evaluate=lambda p, s: FakeEval(samples=20),
            policy=_tiers(), rung="code", approve=legacy_approve,
            controller=controller,
        )

        assert rep.promoted is False
        assert rep.applied is False
        assert "legacy live code approval/apply is disabled" in rep.reason
        assert called == []
        assert rep.candidate_id is None
        assert len(archive.candidates) == 1
        assert controller.ledger.all() == []

    def test_code_approval_replay_cannot_upgrade_evidence(
        self, _on, tmp_path,
    ):
        archive = CodeArchive()
        archive.add(CodeCandidate(
            summary="seed", patch="+a", score=1.0, promoted=True))
        controller = _controller(tmp_path)
        called = []

        def replay(*_args):
            called.append(True)
            return "same-signature", "00" * 32

        rejected = run_cycle(
            archive=archive,
            proposer=lambda p, s: Proposal(_patch(), "same patch"),
            evaluate=lambda p, s: FakeEval(candidate_score=0.4, samples=20),
            policy=_tiers(), rung="code", approve=replay,
            controller=controller,
        )
        upgraded = run_cycle(
            archive=archive,
            proposer=lambda p, s: Proposal(_patch(), "same patch"),
            evaluate=lambda p, s: FakeEval(candidate_score=0.99, samples=20),
            policy=_tiers(), rung="code", approve=replay,
            controller=controller,
        )

        assert not rejected.promoted and not upgraded.promoted
        assert called == []
        assert controller.ledger.all() == []

    def test_archive_branching_can_be_disabled_for_independent_evaluation(
        self, _on, tmp_path,
    ):
        archive = CodeArchive()
        archive.add(CodeCandidate(
            summary="high hidden score", patch="+secret-selection",
            score=1.0, promoted=False))
        parents = []

        rep = run_cycle(
            archive=archive,
            proposer=lambda parent, surface: parents.append(parent) or Proposal(_patch()),
            evaluate=lambda p, s: FakeEval(),
            policy=WideningPolicy(tiers=(SurfaceTier("wide", (EDIT,), 0),)),
            rung="code",
            controller=_controller(tmp_path), branch_from_archive=False,
        )

        assert rep.evaluated is True
        assert parents == [None]

    def test_failed_evaluation_is_not_promoted(self, _on, tmp_path):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        rep = run_cycle(
            archive=a, proposer=lambda p, s: Proposal(_patch(), "x"),
            evaluate=lambda p, s: FakeEval(ok=False, reason="did not apply"),
            policy=_tiers(), rung="code", controller=_controller(tmp_path))
        assert rep.evaluated is False
        assert rep.promoted is False
        assert "did not apply" in rep.reason

    def test_widening_construct_blocks_promotion(self, _on, tmp_path):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        rep = run_cycle(
            archive=a,
            proposer=lambda p, s: Proposal(_patch(added="os.system('x')"), "sneaky"),
            evaluate=lambda p, s: FakeEval(), policy=_tiers(),
            rung="code", controller=_controller(tmp_path))
        assert rep.evaluated is True
        assert rep.promoted is False
        cand = a.get(rep.candidate_id)
        assert cand.capability_widens is True


class TestRunLoop:
    def test_disabled_returns_single_inert_report(self, monkeypatch):
        monkeypatch.setattr(sm, "enabled", lambda: False)
        reps = run_loop(archive=CodeArchive(), proposer=lambda p, s: None,
                        evaluate=lambda p, s: FakeEval(), cycles=5)
        assert len(reps) == 1 and "disabled" in reps[0].reason

    def test_threads_generation_and_accumulates(self, _on, tmp_path):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        # Each cycle proposes a distinct patch so the archive grows.
        n = {"i": 0}

        def propose(parent, surface):
            n["i"] += 1
            return Proposal(_patch(added=f"TUNING = {n['i']}"), f"tune {n['i']}")

        reps = run_loop(
            archive=a, proposer=propose, evaluate=lambda p, s: FakeEval(),
            policy=_tiers(), cycles=3, rung="code", controller=_controller(tmp_path))
        assert len(reps) == 3
        assert all(r.evaluated and not r.promoted for r in reps)
        # seed + three research candidates; only the pre-existing seed is marked promoted.
        assert len(a.candidates) == 4
        assert len([c for c in a.candidates if c.promoted]) == 1

    @pytest.mark.parametrize("cycles", [0, -1, 101, True, "2"])
    def test_invalid_cycle_count_fails_closed_without_work(self, _on, cycles):
        called = []
        reports = run_loop(
            archive=CodeArchive(),
            proposer=lambda *_: called.append("proposal"),
            evaluate=lambda *_: called.append("evaluation"),
            cycles=cycles,
        )

        assert len(reports) == 1
        assert "cycles must be an integer from 1 to 100" in reports[0].reason
        assert called == []


# --- Gap 1: the live-model proposer seam ------------------------------------

class _Resp:
    def __init__(self, text):
        self.text = text


class _FakeLLM:
    def __init__(self, text):
        self._text = text
        self.calls = []

    def complete(self, system, messages, **kw):
        self.calls.append((system, messages, kw))
        return _Resp(self._text)


_DIFF = ("diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
         "@@ -1 +1 @@\n-x = 1\n+x = 2\n")


def _context_factory():
    context = ProposalContext(
        objective="Improve pkg/a.py",
        base_revision="0" * 40,
        snapshot_sha256="1" * 64,
        files=(ContextFile("pkg/a.py", "2" * 64, "x = 1\n"),),
    )
    return lambda _surface: context


class TestExtractDiff:
    def test_plain_diff(self):
        assert loop._extract_diff(_DIFF).startswith("diff --git")

    def test_strips_markdown_fence(self):
        fenced = f"Here you go:\n```diff\n{_DIFF}```\nDone."
        out = loop._extract_diff(fenced)
        assert out.startswith("diff --git") and "```" not in out

    def test_no_diff_is_empty(self):
        assert loop._extract_diff("I could not find an improvement.") == ""

    def test_leading_prose_before_diff_is_dropped(self):
        out = loop._extract_diff("Reasoning: improve X.\n" + _DIFF)
        assert out.startswith("diff --git")


class TestLlmProposer:
    def test_returns_a_proposal_from_the_model_diff(self):
        prop = loop.llm_proposer(_FakeLLM(_DIFF), context_factory=_context_factory())
        surface = sm.EditableSurface(editable_globs=("pkg/*.py",))
        p = prop(None, surface)
        assert p is not None and p.patch.startswith("diff --git")

    def test_non_diff_reply_is_no_proposal(self):
        prop = loop.llm_proposer(
            _FakeLLM("no change needed"), context_factory=_context_factory())
        assert prop(None, sm.EditableSurface(editable_globs=("**",))) is None

    def test_provider_error_is_no_proposal(self):
        class Boom:
            def complete(self, *a, **k):
                raise RuntimeError("provider down")
        prop = loop.llm_proposer(Boom(), context_factory=_context_factory())
        assert prop(None, sm.EditableSurface(editable_globs=("**",))) is None

    def test_surface_globs_are_in_the_prompt(self):
        llm = _FakeLLM(_DIFF)
        prop = loop.llm_proposer(llm, context_factory=_context_factory())
        prop(None, sm.EditableSurface(editable_globs=("pkg/only/*.py",)))
        system = llm.calls[0][0]
        assert "pkg/only/*.py" in system
        assert "control-plane" in system.lower()

    def test_parent_patch_is_referenced(self):
        llm = _FakeLLM(_DIFF)
        prop = loop.llm_proposer(llm, context_factory=_context_factory())
        parent = CodeCandidate(summary="prior", patch="+prior line", score=1.0)
        prop(parent, sm.EditableSurface(editable_globs=("**",)))
        user = llm.calls[0][1][0]["content"]
        assert "prior" in user


# --- Gap 6: proof-gated widening bound to the SIGNED ledger ------------------

class TestLedgerBoundWidening:
    def _ledger(self, tmp_path):
        return si.PromotionLedger(path=tmp_path / "ledger.json")

    def _rec(self, rid, rung, rolled_back=False):
        return si.PromotionRecord(
            id=rid, rung=rung, summary="s", baseline_score=0.5,
            candidate_score=0.9, promoted_at=1.0, rolled_back=rolled_back)

    def test_ledger_drives_the_tier_not_the_archive(self, tmp_path):
        # The archive falsely claims 5 promotions; the SIGNED ledger has 1.
        archive = CodeArchive()
        for i in range(5):
            archive.add(CodeCandidate(summary=f"forged{i}", patch=f"+a{i}",
                                      score=1.0, promoted=True))
        ledger = self._ledger(tmp_path)
        ledger.add(self._rec("r1", "code"))
        tier, _ = earned_surface(archive, _tiers(), ledger=ledger)
        assert tier.name == "t1"     # 1 real promotion -> t1, NOT t2 (the forged 5)

    def test_ledger_rollback_freezes_widening(self, tmp_path):
        ledger = self._ledger(tmp_path)
        for i in range(4):
            ledger.add(self._rec(f"ok{i}", "code"))
        ledger.add(self._rec("bad", "code", rolled_back=True))
        tier, _ = earned_surface(CodeArchive(), _tiers(), ledger=ledger)
        assert tier.name == "t0"     # a rolled-back code promotion forfeits widening

    def test_only_code_rung_promotions_count(self, tmp_path):
        ledger = self._ledger(tmp_path)
        ledger.add(self._rec("p1", "prompt"))   # not the code rung
        ledger.add(self._rec("p2", "config"))
        tier, _ = earned_surface(CodeArchive(), _tiers(), ledger=ledger)
        assert tier.name == "t0"     # no CODE promotions -> narrowest tier


# --- Legacy inline live-adoption paths remain disabled -----------------------

class TestLiveAdoptionDisabled:
    def _tree(self, root):
        t = root / "tree"
        t.mkdir()
        (t / "f.py").write_text("VALUE = 1\n", encoding="utf-8")
        return t

    def _apply_patch(self):
        return ("diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n"
                "@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n")

    def test_live_tree_is_refused_before_proposal(self, _on, tmp_path):
        tree = self._tree(tmp_path)
        store = tmp_path / "snaps"
        store.mkdir()
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        policy = WideningPolicy(tiers=(SurfaceTier("wide", ("f.py",), 0),))
        called = []
        rep = run_cycle(
            archive=a,
            proposer=lambda p, s: called.append("proposal") or Proposal(
                self._apply_patch(), "bump"),
            evaluate=lambda p, s: called.append("evaluation") or FakeEval(),
            policy=policy, rung="code", controller=_controller(tmp_path),
            tree=tree, store=store,
        )
        assert rep.proposed is False and rep.applied is False
        assert "legacy live code approval/apply is disabled" in rep.reason
        assert called == []
        assert (tree / "f.py").read_text() == "VALUE = 1\n"
        assert list(store.iterdir()) == []

    def test_legacy_approval_callback_is_never_called(self, _on, tmp_path):
        a = CodeArchive()
        a.add(CodeCandidate(summary="seed", patch="+a", score=1.0, promoted=True))
        policy = WideningPolicy(tiers=(SurfaceTier("wide", ("f.py",), 0),))
        called = []
        rep = run_cycle(
            archive=a, proposer=lambda p, s: Proposal(self._apply_patch(), "bump"),
            evaluate=lambda p, s: FakeEval(), policy=policy,
            rung="code", controller=_controller(tmp_path),
            approve=lambda *_: called.append(True),
        )
        assert rep.proposed is False and rep.applied is False
        assert called == []

    def test_non_code_rung_with_tree_cannot_bypass_refusal(self, _on, tmp_path):
        tree = self._tree(tmp_path)
        ledger = si.PromotionLedger(path=tmp_path / "ledger.json")
        controller = _controller(tmp_path, ledger=ledger)
        archive = CodeArchive()
        called = []
        rep = run_cycle(
            archive=archive,
            proposer=lambda p, s: called.append("proposal") or Proposal(
                self._apply_patch()),
            evaluate=lambda p, s: called.append("evaluation") or FakeEval(),
            policy=WideningPolicy(tiers=(SurfaceTier("wide", ("*",), 0),)),
            rung="prompt", controller=controller, ledger=ledger, tree=tree)
        assert rep.promoted is False
        assert rep.applied is False
        assert "require rung='code'" in rep.reason
        assert called == []
        assert ledger.all() == []
        assert (tree / "f.py").read_text() == "VALUE = 1\n"


class TestUnverifiedAuditCannotWiden:
    def test_external_track_record_override_is_not_supported(self):
        with pytest.raises(TypeError, match="track_record"):
            earned_surface(
                CodeArchive(), _tiers(), track_record=(50, False))

    def test_unverified_audit_reader_is_never_authoritative(self):
        assert loop._audit_track_record("code") is None
