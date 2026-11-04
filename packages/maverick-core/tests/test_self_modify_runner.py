"""Research DGM runner: config → policy and an end-to-end governed run.

Pins: the widening ladder is built from config, the runner is a no-op while OFF,
and an enabled run proposes → evaluates → archives (persisting lineage) while the
code rung has no live-adoption integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from maverick import learning_guard
from maverick import self_improvement as si
from maverick import self_modify as sm
from maverick import self_modify_runner as runner
from maverick.self_modify_eval import EvalSandboxError
from maverick.self_modify_loop import Proposal


@dataclass
class FakeEval:
    ok: bool = True
    baseline_score: float = 0.5
    candidate_score: float = 0.9
    samples: int = 12
    reason: str = ""


def _patch(path="pkg/a.py", added="TUNING = 0.7"):
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1 +1,2 @@\n old\n+{added}\n")


class TestBuildPolicy:
    def test_tiers_from_config(self):
        cfg = {"tiers": [
            {"name": "narrow", "editable_paths": ["pkg/a/*.py"], "min_promotions": 1},
            {"name": "wide", "editable_paths": ["pkg/**"], "min_promotions": 5},
        ]}
        pol = runner.build_policy(cfg)
        names = [t.name for t in pol.tiers]
        assert names == ["none", "narrow", "wide"]     # tier 0 empty, then ascending
        assert pol.tiers[0].editable_globs == ()

    def test_editable_paths_fallback_single_tier(self):
        pol = runner.build_policy({"editable_paths": ["pkg/*.py"]})
        assert [t.name for t in pol.tiers] == ["none", "configured"]
        assert pol.tiers[1].min_promotions == 0

    def test_empty_config_grants_nothing(self):
        pol = runner.build_policy({})
        assert all(t.editable_globs == () for t in pol.tiers)


class TestRun:
    def test_noop_while_disabled(self, monkeypatch):
        monkeypatch.setattr(sm, "enabled", lambda: False)
        summ = runner.run(cycles=3)
        assert summ.ran is False and "disabled" in summ.reason
        assert summ.reports == []

    @pytest.mark.parametrize("cycles", [0, -1, 101, True, "2"])
    def test_invalid_cycle_count_fails_closed(self, _enabled, cycles):
        summ = runner.run(cycles=cycles)
        assert summ.ran is False
        assert "cycles must be an integer from 1 to 100" in summ.reason

    @pytest.fixture
    def _enabled(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sm, "enabled", lambda: True)
        monkeypatch.setattr(si, "enabled", lambda: True)
        monkeypatch.setattr(runner, "_self_modify_config",
                            lambda: {
                                "enable": True,
                                "editable_paths": ["pkg/*.py"],
                                "eval_tests": ["tests/test_x.py::a", "tests/test_x.py::b"],
                            })
        monkeypatch.setattr(runner, "archive_path", lambda: tmp_path / "arch.json")
        return tmp_path

    def _controller(self, tmp_path):
        return si.SelfImprovementController(
            min_improvement=0.0, max_auto_rung="policy",
            frozen_fn=lambda: False, audit_fn=lambda **k: None,
            ledger=si.PromotionLedger(path=tmp_path / "ledger.json"))

    def test_enabled_run_evaluates_and_archives(self, _enabled, monkeypatch):
        tmp_path = _enabled
        summ = runner.run(
            cycles=2,
            proposer=lambda parent, surface: Proposal(_patch(), "tune"),
            evaluate=lambda p, s: FakeEval(),
            controller=self._controller(tmp_path))
        assert summ.ran is True
        assert len(summ.reports) == 2
        assert summ.evaluated == 2
        # The stock code rung has no adoption path; it archives research lineage.
        assert summ.promoted == 0
        arch = runner.load_archive()
        assert len(arch.candidates) >= 1
        assert (tmp_path / "arch.json").exists()      # lineage persisted

    def test_run_persists_across_invocations(self, _enabled, monkeypatch):
        tmp_path = _enabled
        ctrl = self._controller(tmp_path)
        runner.run(cycles=1, proposer=lambda p, s: Proposal(_patch(added="A = 1"), "a"),
                   evaluate=lambda p, s: FakeEval(), controller=ctrl)
        n1 = len(runner.load_archive().candidates)
        runner.run(cycles=1, proposer=lambda p, s: Proposal(_patch(added="B = 2"), "b"),
                   evaluate=lambda p, s: FakeEval(), controller=ctrl)
        n2 = len(runner.load_archive().candidates)
        assert n2 > n1                                # archive accumulated

    def test_control_plane_proposal_is_refused_in_run(self, _enabled, monkeypatch):
        tmp_path = _enabled
        cp = _patch("packages/maverick-core/maverick/verifier.py")
        # widen the surface so only the boundary (not the allowlist) can refuse
        monkeypatch.setattr(runner, "_self_modify_config",
                            lambda: {"enable": True, "editable_paths": ["**"]})
        summ = runner.run(
            cycles=1, proposer=lambda p, s: Proposal(cp, "sneaky"),
            evaluate=lambda p, s: FakeEval(), controller=self._controller(tmp_path))
        assert summ.promoted == 0
        assert summ.reports[0].review_ok is False

    def test_default_budget_is_built_and_threaded_to_dgm_seams(
            self, _enabled, monkeypatch):
        tmp_path = _enabled
        capture_root = tmp_path / "captured-root"
        captured_tree = capture_root / "source"
        captured_tree.mkdir(parents=True)
        (captured_tree / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")
        from maverick.self_modify_corpus import _captured_tree_manifest
        captured_digest = _captured_tree_manifest(captured_tree)
        captured_revision = "a" * 40
        monkeypatch.setattr(
            runner,
            "_capture_stock_tree",
            lambda _tree: (
                capture_root, captured_tree, captured_digest, captured_revision,
            ),
        )

        class FakeBudget:
            def __init__(self):
                self.checks = 0

            def check(self):
                self.checks += 1

        built = FakeBudget()
        captured = {}
        monkeypatch.setattr(
            "maverick.budget.budget_from_config",
            lambda **kwargs: captured.update(config_kwargs=kwargs) or built)

        def fake_proposer(
            *, tree, objective, feedback, budget=None,
            require_tracked_source=True, base_revision=None,
            source_snapshot=None,
        ):
            captured["proposer_tree"] = tree
            captured["proposer_objective"] = objective
            captured["feedback"] = feedback
            captured["proposer_budget"] = budget
            captured["proposer_requires_tracked"] = require_tracked_source
            captured["base_revision"] = base_revision
            captured["source_snapshot"] = source_snapshot
            return lambda *_: None

        def fake_evaluate(**kwargs):
            captured["evaluator_budget"] = kwargs.get("budget")
            captured["evaluator_tree"] = kwargs.get("tree")
            captured["evaluator_requires_tracked"] = kwargs.get(
                "require_tracked_source"
            )
            captured["evaluator_snapshot"] = kwargs.get(
                "expected_source_manifest"
            )
            return lambda *_: FakeEval()

        monkeypatch.setattr(runner, "_default_proposer", fake_proposer)
        monkeypatch.setattr(runner, "_default_evaluate", fake_evaluate)
        summ = runner.run(
            cycles=1, objective="Fix the challenge failure",
            controller=self._controller(tmp_path), persist=False)

        assert summ.ran is True
        assert captured["config_kwargs"] == {"task_class": "self_modify"}
        assert captured["proposer_budget"] is built
        assert captured["proposer_tree"] == captured_tree
        assert captured["evaluator_tree"] == captured_tree
        assert captured["proposer_requires_tracked"] is False
        assert captured["evaluator_requires_tracked"] is False
        assert captured["base_revision"] == captured_revision
        assert captured["source_snapshot"] == captured_digest
        assert captured["evaluator_snapshot"] == captured_digest
        assert captured["proposer_objective"] == "Fix the challenge failure"
        assert captured["feedback"] == ""
        assert captured["evaluator_budget"] is built
        assert built.checks == 1
        assert not capture_root.exists()

    def test_stock_capture_rejects_revision_change(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
        revisions = iter(("a" * 40, "b" * 40))
        monkeypatch.setattr(
            "maverick.self_modify_context._git_revision",
            lambda _tree: next(revisions),
        )

        def materialize(_source, destination, *, require_tracked_source):
            assert require_tracked_source is True
            destination.mkdir(parents=True)
            (destination / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")

        monkeypatch.setattr(
            "maverick.self_modify_eval._default_materialize", materialize
        )

        with pytest.raises(ValueError, match="revision changed"):
            runner._capture_stock_tree(tmp_path)
        assert list((tmp_path / "home" / "self_modify_work").iterdir()) == []

    def test_stock_proposer_refuses_missing_objective(
            self, _enabled, monkeypatch):
        tmp_path = _enabled
        monkeypatch.setattr(
            runner, "_default_proposer",
            lambda **_kwargs: (_ for _ in ()).throw(
                AssertionError("ungrounded proposer must not be built")),
        )
        summ = runner.run(
            cycles=1, controller=self._controller(tmp_path), persist=False)
        assert summ.ran is False
        assert "explicit operator objective" in summ.reason

    def test_stock_source_capture_change_aborts_before_evaluation(
        self, _enabled, monkeypatch,
    ):
        tmp_path = _enabled
        capture_root = tmp_path / "capture-mutation"
        captured_tree = capture_root / "source"
        captured_tree.mkdir(parents=True)
        source = captured_tree / "tracked.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        from maverick.self_modify_corpus import _captured_tree_manifest
        digest = _captured_tree_manifest(captured_tree)
        monkeypatch.setattr(
            runner,
            "_capture_stock_tree",
            lambda _tree: (capture_root, captured_tree, digest, "b" * 40),
        )
        evaluated = []

        def fake_default_proposer(**_kwargs):
            def mutate_then_propose(*_args, **_inner_kwargs):
                source.write_text("VALUE = 2\n", encoding="utf-8")
                return Proposal(_patch("tracked.py"), "candidate")

            return mutate_then_propose

        monkeypatch.setattr(runner, "_default_proposer", fake_default_proposer)
        monkeypatch.setattr(
            runner,
            "_default_evaluate",
            lambda **_kwargs: lambda *_args: evaluated.append(True) or FakeEval(),
        )

        summary = runner.run(
            cycles=1,
            objective="Improve tracked source",
            controller=self._controller(tmp_path),
            persist=False,
        )

        assert summary.ran is False
        assert summary.reason == (
            "stock self-modification source capture changed; run refused"
        )
        assert evaluated == []
        assert not capture_root.exists()

    def test_stock_proposer_requires_git_tracked_context(self, tmp_path, monkeypatch):
        from maverick.self_modify_context import ContextFile, ProposalContext

        captured = {}

        class FakeLLM:
            def complete(self, *_args, **_kwargs):
                return SimpleNamespace(text=_patch())

        def fake_build(tree, surface, **kwargs):
            captured.update(tree=tree, surface=surface, kwargs=kwargs)
            return ProposalContext(
                objective="Improve feature",
                base_revision="0" * 40,
                snapshot_sha256="1" * 64,
                files=(ContextFile("pkg/a.py", "2" * 64, "old\n"),),
            )

        monkeypatch.setattr("maverick.llm.LLM", lambda _model: FakeLLM())
        monkeypatch.setattr("maverick.llm.model_for_role", lambda _role: "coding")
        monkeypatch.setattr(
            "maverick.self_modify_context.build_proposal_context", fake_build)

        surface = sm.EditableSurface(editable_globs=("pkg/*.py",))
        propose = runner._default_proposer(
            tree=tmp_path, objective="Improve feature")
        proposal = propose(None, surface)

        assert proposal is not None
        assert captured["kwargs"]["require_tracked_source"] is True

    def test_stock_evaluator_refuses_missing_challenge_corpus(
            self, _enabled, monkeypatch):
        tmp_path = _enabled
        monkeypatch.setattr(
            runner, "_self_modify_config",
            lambda: {"enable": True, "editable_paths": ["pkg/*.py"]})
        summ = runner.run(
            cycles=1, proposer=lambda *_: None,
            controller=self._controller(tmp_path), persist=False)
        assert summ.ran is False
        assert "challenge corpus" in summ.reason
        assert "eval_tests" in summ.reason

    def test_stock_evaluator_reports_evidence_contract_and_closes_backend(
        self, tmp_path, monkeypatch,
    ):
        closed = []

        class BooleanOnlySandbox:
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 32
            memory = "256m"
            bounded_output = True
            authenticated_test_results = True

            def close(self):
                closed.append(True)

        monkeypatch.setattr(runner, "_work_root", lambda: str(tmp_path))
        monkeypatch.setattr(
            "maverick.sandbox.build_sandbox",
            lambda **_kwargs: BooleanOnlySandbox(),
        )
        with pytest.raises(EvalSandboxError) as caught:
            runner._default_evaluate(
                tree=tmp_path,
                cfg={"eval_tests": ["tests/test_x.py::a", "tests/test_x.py::b"]},
            )
        message = str(caught.value)
        assert "exec_authenticated_tests" in message
        assert "controller-owned runner/sidecar" in message
        assert closed == [True]

    def test_stock_evaluator_refuses_non_git_source_before_candidate_exec(
        self, tmp_path, monkeypatch,
    ):
        tree = tmp_path / "plain-tree"
        (tree / "pkg").mkdir(parents=True)
        (tree / "pkg" / "a.py").write_text("old\n", encoding="utf-8")
        calls = []

        class SecureSandbox:
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 32
            memory = "256m"
            bounded_output = True
            authenticated_test_results = True
            test_evidence_protocol = "maverick.test-evidence.v1"
            test_evidence_authority = "runner-test-controller-key-1"

            def exec(self, *_args, **_kwargs):
                calls.append("candidate-exec")
                raise AssertionError("non-Git source must fail before execution")

            def exec_authenticated_tests(self, request, timeout=None):
                raise AssertionError("non-Git source must fail before tests")

            def close(self):
                pass

        monkeypatch.setattr(runner, "_work_root", lambda: str(tmp_path))
        monkeypatch.setattr(
            "maverick.sandbox.build_sandbox", lambda **_kwargs: SecureSandbox())
        evaluate = runner._default_evaluate(
            tree=tree,
            cfg={
                "eval_tests": ["tests/test_x.py::a", "tests/test_x.py::b"],
            },
        )
        result = evaluate(_patch())
        assert result.ok is False and result.applied is False
        assert "securely isolate" in result.reason
        assert calls == []

    def test_stock_evaluator_pins_one_sandbox_policy_snapshot(
        self, tmp_path, monkeypatch,
    ):
        config_loads = []
        built_configs = []
        built_ids = []
        evidence = {}

        def changing_config():
            marker = len(config_loads) + 1
            config_loads.append(marker)
            return {
                "backend": "ep:attested",
                "options": {"marker": marker},
                "api_key": f"secret-{marker}",
            }

        class SecureSandbox:
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 32
            memory = "256m"
            bounded_output = True
            authenticated_test_results = True
            test_evidence_protocol = "maverick.test-evidence.v1"
            test_evidence_authority = "runner-test-controller-key-1"

            def exec_authenticated_tests(self, request, timeout=None):
                raise AssertionError("mock corpus owns evaluation")

            def close(self):
                pass

        def build_sandbox(**kwargs):
            cfg = kwargs["sandbox_config"]
            built_configs.append(cfg)
            built_ids.append(id(cfg))
            return SecureSandbox()

        def evaluate_on_corpus(_patch_text, **kwargs):
            kwargs["sandbox_factory"](tmp_path / "baseline")
            kwargs["sandbox_factory"](tmp_path / "candidate")
            evidence["policy"] = kwargs["sandbox_policy_identity"]
            return FakeEval()

        monkeypatch.setattr(runner, "_work_root", lambda: str(tmp_path))
        monkeypatch.setattr(runner, "_sandbox_config", changing_config)
        monkeypatch.setattr("maverick.sandbox.build_sandbox", build_sandbox)
        monkeypatch.setattr(
            "maverick.self_modify_corpus.evaluate_on_corpus", evaluate_on_corpus,
        )

        evaluate = runner._default_evaluate(
            tree=tmp_path,
            cfg={"eval_tests": ["tests/test_x.py::a", "tests/test_x.py::b"]},
        )
        result = evaluate(_patch())

        assert result.ok is True
        assert config_loads == [1]
        assert len(built_configs) == 3  # preflight + baseline + candidate
        assert all(cfg == built_configs[0] for cfg in built_configs)
        assert len(set(built_ids)) == 3
        assert len(evidence["policy"]) == 64
        assert runner._sandbox_policy_digest({
            "backend": "ep:attested", "api_key": "one",  # pragma: allowlist secret
        }) == runner._sandbox_policy_digest({
            "backend": "ep:attested", "api_key": "two",  # pragma: allowlist secret
        })

    def test_inline_approval_and_live_apply_fail_closed(self, _enabled):
        tmp_path = _enabled
        ctrl = self._controller(tmp_path)

        approved = runner.run(
            proposer=lambda *_: None, evaluate=lambda *_: FakeEval(),
            controller=ctrl, approve=lambda *_: ("sig", "digest"), persist=False)
        applied = runner.run(
            proposer=lambda *_: None, evaluate=lambda *_: FakeEval(),
            controller=ctrl, apply=True, persist=False)

        assert approved.ran is False and "approval is disabled" in approved.reason
        assert applied.ran is False and "PREPARE/CAS/COMMIT" in applied.reason

    def test_persistent_archive_branching_is_disabled(self, _enabled):
        tmp_path = _enabled
        refused = runner.run(
            proposer=lambda *_: None, evaluate=lambda *_: FakeEval(),
            controller=self._controller(tmp_path),
            objective="Improve development score",
            branch_from_archive=True,
            persist=False,
        )
        assert refused.ran is False
        assert "provenance is durably partitioned" in refused.reason

    def test_controller_without_authoritative_ledger_is_refused(
        self, _enabled,
    ):
        calls = []
        controller = SimpleNamespace(ledger=None)
        refused = runner.run(
            proposer=lambda *_: calls.append("proposal"),
            evaluate=lambda *_: calls.append("evaluation") or FakeEval(),
            controller=controller,
            persist=False,
        )
        assert refused.ran is False
        assert "authoritative promotion ledger" in refused.reason
        assert calls == []

    def test_halt_before_persist_leaves_archive_unwritten(
        self, _enabled, monkeypatch,
    ):
        tmp_path = _enabled
        phases = []

        def guard(_job, phase):
            phases.append(phase)
            if phase == "before-archive-persist":
                raise learning_guard.Halted("operator stop", "test")

        monkeypatch.setattr(runner, "check_learning_halt", guard)
        monkeypatch.setattr(
            runner, "run_loop", lambda **_kwargs: [SimpleNamespace(
                promoted=False, evaluated=True)])
        refused = runner.run(
            proposer=lambda *_: None,
            evaluate=lambda *_: FakeEval(),
            controller=self._controller(tmp_path),
            persist=True,
        )

        assert refused.ran is False
        assert "before-archive-persist" in phases
        assert not (tmp_path / "arch.json").exists()

    def test_halt_inside_cycle_is_not_reported_as_success(
        self, _enabled, monkeypatch,
    ):
        tmp_path = _enabled
        monkeypatch.setattr(
            runner,
            "run_loop",
            lambda **_kwargs: (_ for _ in ()).throw(
                learning_guard.Halted("secret operator text", "test")),
        )

        summary = runner.run(
            proposer=lambda *_: None,
            evaluate=lambda *_: FakeEval(),
            controller=self._controller(tmp_path),
        )

        assert summary.ran is False
        assert "global learning HALT" in summary.reason
        assert "secret operator text" not in summary.reason

    def test_cycle_exception_is_generic_and_non_successful(
        self, _enabled, monkeypatch,
    ):
        tmp_path = _enabled
        monkeypatch.setattr(
            runner,
            "run_loop",
            lambda **_kwargs: (_ for _ in ()).throw(
                RuntimeError("candidate-controlled secret")),
        )

        summary = runner.run(
            proposer=lambda *_: None,
            evaluate=lambda *_: FakeEval(),
            controller=self._controller(tmp_path),
        )

        assert summary.ran is False
        assert summary.reason == "runner safety check or execution failed closed"
        assert "candidate-controlled secret" not in summary.reason

    def test_archive_persistence_failure_fails_run(
        self, _enabled, monkeypatch,
    ):
        tmp_path = _enabled
        monkeypatch.setattr(
            runner.CodeArchive,
            "save",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                runner.ArchivePersistenceError("hidden detail")),
        )
        summary = runner.run(
            proposer=lambda *_: Proposal(_patch(), "candidate"),
            evaluate=lambda *_: FakeEval(),
            controller=self._controller(tmp_path),
        )

        assert summary.ran is False
        assert summary.reports
        assert summary.reason == "research archive persistence failed closed"


def test_self_modify_cli_builds_config_budget_and_honors_overrides(monkeypatch):
    from maverick import budget as budget_mod
    from maverick.cli import main

    class FakeBudget:
        def summary(self):
            return "bounded"

    built = FakeBudget()
    captured = {}

    def fake_budget(**kwargs):
        captured["budget_kwargs"] = kwargs
        return built

    def fake_run(**kwargs):
        captured["run_kwargs"] = kwargs
        return SimpleNamespace(
            ran=True, reports=[], evaluated=0, promoted=0, reason="")

    monkeypatch.setattr(budget_mod, "budget_from_config", fake_budget)
    monkeypatch.setattr(runner, "run", fake_run)
    result = CliRunner().invoke(main, [
        "self-modify", "run", "--cycles", "2",
        "--objective", "Fix the challenge failure", "--max-dollars", "1.25",
        "--max-wall-seconds", "90", "--max-tool-calls", "12",
    ])

    assert result.exit_code == 0, result.output
    assert captured["budget_kwargs"] == {
        "task_class": "self_modify", "max_dollars": 1.25,
        "max_wall_seconds": 90.0, "max_tool_calls": 12,
    }
    assert captured["run_kwargs"]["budget"] is built
    assert captured["run_kwargs"]["cycles"] == 2
    assert captured["run_kwargs"]["objective"] == "Fix the challenge failure"
    assert "budget used: bounded" in result.output


def test_self_modify_cli_refusal_is_nonzero(monkeypatch):
    from maverick.cli import main

    monkeypatch.setattr(
        runner,
        "run",
        lambda **_kwargs: SimpleNamespace(
            ran=False, reports=[], evaluated=0, promoted=0,
            reason="safety posture refused",
        ),
    )
    result = CliRunner().invoke(main, [
        "self-modify", "run", "--objective", "Improve safely",
    ])

    assert result.exit_code != 0
    assert "safety posture refused" in result.output


@pytest.mark.parametrize("threshold", [-5, "0", 0.0, False, None])
def test_invalid_min_promotions_can_never_unlock_a_surface(threshold):
    policy = runner.build_policy({
        "tiers": [{
            "name": "invalid",
            "editable_paths": ["**"],
            "min_promotions": threshold,
        }],
        # A present tier policy owns the decision; invalid entries must not
        # fall through to this legacy zero-proof allowlist.
        "editable_paths": ["**"],
    })

    assert [tier.name for tier in policy.tiers] == ["none"]
    assert policy.earned(
        promotions=1_000_000,
        had_rollback=False,
    ).editable_globs == ()


@pytest.mark.parametrize("editable_paths", ["**", ["**", 1], {"all": "**"}])
def test_malformed_tier_editable_paths_cannot_fall_through(editable_paths):
    policy = runner.build_policy({
        "tiers": [{
            "name": "invalid",
            "editable_paths": editable_paths,
            "min_promotions": 0,
        }],
        "editable_paths": ["**"],
    })

    assert [tier.name for tier in policy.tiers] == ["none"]
    assert policy.earned(
        promotions=1_000_000,
        had_rollback=False,
    ).editable_globs == ()


@pytest.mark.parametrize("tiers", [{"name": "not-a-list"}, "not-a-list", True])
def test_malformed_tier_container_cannot_fall_through(tiers):
    policy = runner.build_policy({"tiers": tiers, "editable_paths": ["**"]})

    assert [tier.name for tier in policy.tiers] == ["none"]
    assert policy.earned(
        promotions=1_000_000,
        had_rollback=False,
    ).editable_globs == ()


@pytest.mark.parametrize("editable_paths", ["**", ["**", 1], {"all": "**"}])
def test_malformed_legacy_editable_paths_grant_nothing(editable_paths):
    policy = runner.build_policy({"editable_paths": editable_paths})

    assert [tier.name for tier in policy.tiers] == ["none"]
