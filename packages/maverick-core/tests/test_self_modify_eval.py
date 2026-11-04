"""Sandbox eval harness: isolated-copy baseline-vs-candidate scoring.

The load-bearing safety property is that a proposed patch is measured on a
THROWAWAY copy, never the live tree. These pin: isolation (src untouched),
git-apply through the sandbox with a --check gate, fail-closed on a
non-applying patch / scorer error, the pytest pass-rate scorer, and that the
produced scores are exactly what the governed gate consumes.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import self_modify_eval as ev
from maverick.self_modify_eval import EvalResult, Score, evaluate_patch

_TEST_SUBJECT = "1" * 64
_TEST_EXECUTION_CONTEXT = "2" * 64


def _pytest_score(**kwargs):
    return ev.pytest_score(
        subject_sha256=_TEST_SUBJECT,
        execution_context_sha256=_TEST_EXECUTION_CONTEXT,
        **kwargs,
    )


def _seed_repo(root: Path) -> Path:
    src = root / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    (src / "pkg" / "b.py").write_text("x = 2\n", encoding="utf-8")
    return src


def _edit_patch() -> str:
    return ("diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
            "@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 99\n")


class _EvidenceBackend:
    authenticated_test_results = True
    test_evidence_protocol = "maverick.test-evidence.v1"
    test_evidence_authority = "test-controller-key-1"

    def __init__(self, counts=None, *, evidence=True):
        self.counts = counts
        self.evidence = evidence
        self.seen_request = None

    def exec_authenticated_tests(self, request, timeout=None):
        self.seen_request = request
        if not self.evidence:
            return object()
        return ev.AuthenticatedTestEvidence.for_request(
            request,
            authority=self.test_evidence_authority,
            counts=self.counts,
        )


class TestMaterializationBoundary:
    def test_rejects_linked_source_without_touching_target(self, tmp_path):
        src = _seed_repo(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_text("DO NOT TOUCH", encoding="utf-8")
        try:
            (src / "linked.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
        with pytest.raises(ValueError, match="linked file"):
            ev._default_materialize(src, tmp_path / "copy")
        assert outside.read_text(encoding="utf-8") == "DO NOT TOUCH"
        assert not (tmp_path / "copy").exists()

    def test_rejects_source_file_over_quota(self, tmp_path, monkeypatch):
        src = _seed_repo(tmp_path)
        monkeypatch.setattr(ev, "_MAX_MATERIALIZE_FILE_BYTES", 4)
        with pytest.raises(ValueError, match="size limit"):
            ev._default_materialize(src, tmp_path / "copy")
        assert not (tmp_path / "copy").exists()


class TestScorers:
    def test_default_score_counts_python_files(self, tmp_path):
        src = _seed_repo(tmp_path)
        s = ev._default_score(src)
        assert isinstance(s, Score) and s.value == 2.0 and s.samples == 2

    def test_pytest_score_pass_rate(self, tmp_path):
        backend = _EvidenceBackend(ev.AuthenticatedTestCounts(8, 2))
        score = _pytest_score(sandbox=backend)(tmp_path)
        assert score.samples == 10
        assert abs(score.value - 0.8) < 1e-9
        assert backend.seen_request.command == "python3 -m pytest -q"

    def test_pytest_score_no_summary_is_zero(self, tmp_path):
        score = _pytest_score(
            sandbox=_EvidenceBackend(None, evidence=False),
        )(tmp_path)
        assert score == Score(0.0, 0)

    def test_spoofed_stdout_cannot_inflate_authenticated_counts(self, tmp_path):
        class Backend(_EvidenceBackend):
            def exec(self, _cmd, timeout=None):
                raise AssertionError("generic candidate output must not be read")

        backend = Backend(ev.AuthenticatedTestCounts(1, 1))
        assert _pytest_score(sandbox=backend)(tmp_path) == Score(0.5, 2)

    def test_spoofed_stdout_without_backend_authentication_is_unavailable(
        self, tmp_path,
    ):
        class FakeSB:
            def exec(self, _cmd, timeout=None):
                class R:
                    stdout = "100 passed, 0 failed in 0.1s"
                    stderr = ""
                    exit_code = 0
                return R()

        assert _pytest_score(sandbox=FakeSB())(tmp_path) == Score(0.0, 0)

    def test_nonterminal_or_malformed_authenticated_counts_are_unavailable(
        self, tmp_path,
    ):
        backend = _EvidenceBackend(
            ev.AuthenticatedTestCounts(100, 0, terminal=False),
        )
        assert _pytest_score(sandbox=backend)(tmp_path) == Score(0.0, 0)

    def test_replayed_or_cross_command_evidence_is_unavailable(self, tmp_path):
        first_request = ev.AuthenticatedTestRequest.issue(
            "pytest first",
            subject_sha256=_TEST_SUBJECT,
            execution_context_sha256=_TEST_EXECUTION_CONTEXT,
        )
        replay = ev.AuthenticatedTestEvidence.for_request(
            first_request,
            authority=_EvidenceBackend.test_evidence_authority,
            counts=ev.AuthenticatedTestCounts(100, 0),
        )

        class ReplayBackend(_EvidenceBackend):
            def exec_authenticated_tests(self, request, timeout=None):
                return replay

        assert _pytest_score(
            sandbox=ReplayBackend(ev.AuthenticatedTestCounts(100, 0)),
            command="pytest second",
        )(tmp_path) == Score(0.0, 0)

    def test_boolean_only_backend_is_not_authenticated(self, tmp_path):
        class BooleanOnly:
            authenticated_test_results = True

            def exec(self, _cmd, timeout=None):
                raise AssertionError("ordinary exec must not be trusted")

        assert _pytest_score(sandbox=BooleanOnly())(tmp_path) == Score(0.0, 0)


class TestBudgetedExec:
    def test_clamps_requested_timeout_to_remaining_wall_budget(self):
        class Sandbox:
            timeout = 60.0

            def __init__(self):
                self.seen_timeout = None

            def exec(self, _cmd, timeout=None):
                self.seen_timeout = timeout
                return object()

        class Budget:
            def record_tool_call(self):
                pass

            @staticmethod
            def remaining_wall():
                return 0.25

        sandbox = Sandbox()
        ev._budgeted_exec(sandbox, "true", budget=Budget(), timeout=600.0)
        assert sandbox.seen_timeout == pytest.approx(0.25)

    def test_exhausted_wall_budget_refuses_before_exec(self):
        class Sandbox:
            called = False

            def exec(self, _cmd, timeout=None):
                self.called = True

        class Budget:
            def record_tool_call(self):
                pass

            @staticmethod
            def remaining_wall():
                return 0.0

        sandbox = Sandbox()
        with pytest.raises(TimeoutError, match="wall-clock budget exhausted"):
            ev._budgeted_exec(sandbox, "true", budget=Budget(), timeout=600.0)
        assert sandbox.called is False


class TestStockSandboxProfile:
    def test_refuses_host_visible_backend(self, tmp_path):
        from maverick.sandbox.local import LocalBackend

        with pytest.raises(ev.EvalSandboxError, match="non-host"):
            ev.require_secure_eval_sandbox(LocalBackend(tmp_path), tmp_path)

    def test_refuses_egress_or_root_opt_in(self, tmp_path):
        class Backend:
            host_visible_fs = False
            allow_network = True
            allow_root = False

        with pytest.raises(ev.EvalSandboxError, match="egress"):
            ev.require_secure_eval_sandbox(Backend(), tmp_path)
        Backend.allow_network = False
        Backend.allow_root = True
        with pytest.raises(ev.EvalSandboxError, match="root"):
            ev.require_secure_eval_sandbox(Backend(), tmp_path)

    def test_accepts_bounded_non_host_no_egress_backend(self, tmp_path):
        class Backend(_EvidenceBackend):
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 128
            memory = "1g"
            bounded_output = True

        backend = Backend(ev.AuthenticatedTestCounts(1, 0))
        assert ev.require_secure_eval_sandbox(backend, tmp_path) is backend

    def test_refuses_backend_without_bounded_host_output_capture(self, tmp_path):
        class Backend:
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 128
            memory = "1g"

        with pytest.raises(ev.EvalSandboxError, match="bounded host-output"):
            ev.require_secure_eval_sandbox(Backend(), tmp_path)

    def test_refuses_backend_without_authenticated_test_results(self, tmp_path):
        class Backend:
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 128
            memory = "1g"
            bounded_output = True

        with pytest.raises(ev.EvalSandboxError, match="authenticated evaluator evidence"):
            ev.require_secure_eval_sandbox(Backend(), tmp_path)

    def test_refuses_boolean_only_evidence_claim_with_actionable_contract(
        self, tmp_path,
    ):
        class Backend:
            host_visible_fs = False
            allow_network = False
            allow_root = False
            pids_limit = 128
            memory = "1g"
            bounded_output = True
            authenticated_test_results = True

        with pytest.raises(ev.EvalSandboxError) as caught:
            ev.require_secure_eval_sandbox(Backend(), tmp_path)
        message = str(caught.value)
        assert "exec_authenticated_tests" in message
        assert "JUnit/workspace files" in message

    def test_policy_lookup_failure_requires_container(self, monkeypatch):
        monkeypatch.setattr(
            "maverick.sandbox.container_backend_required",
            lambda: (_ for _ in ()).throw(RuntimeError("config unavailable")),
        )
        assert ev.container_required() is True


def _strict_git_apply_check(patch: str, workdir: Path) -> int:
    """Run plain (NO --recount) ``git apply --check -p1`` and return git's exit
    code. Used to PROVE a miscounted-header patch is rejected by strict git
    apply, so the recount test genuinely exercises the fallback and would fail
    against the unpatched ``run_git_apply`` (which had no recount rung)."""
    import subprocess
    pf = Path(workdir) / ".strict-check.diff"
    pf.write_text(patch, encoding="utf-8")
    try:
        return subprocess.run(
            ["git", "apply", "--check", "-p1", pf.name],
            cwd=str(workdir), capture_output=True, text=True,
        ).returncode
    finally:
        pf.unlink()


class TestGitApply:
    def test_applies_a_clean_patch(self, tmp_path):
        src = _seed_repo(tmp_path)
        res = ev.git_apply(_edit_patch(), src)   # default LocalBackend
        assert res.ok is True
        assert (src / "pkg" / "a.py").read_text() == "VALUE = 99\n"

    def test_applies_a_miscounted_header_patch(self, tmp_path):
        # Recount rescue: a patch whose hunk header OVER-COUNTS the new side
        # (claims 4 new lines while the body has only 3) is REJECTED by strict
        # `git apply` ("corrupt patch") because git hits EOF still expecting a
        # line. `git apply --recount` re-derives the counts from the body and
        # applies it — the LLM-miscounted-header failure mode the fallback
        # exists for. The change/context are otherwise correct.
        src = _seed_repo(tmp_path)
        (src / "pkg" / "c.py").write_text("A = 1\nB = 2\nC = 3\n", encoding="utf-8")
        miscounted = (
            "diff --git a/pkg/c.py b/pkg/c.py\n--- a/pkg/c.py\n+++ b/pkg/c.py\n"
            "@@ -1,3 +1,4 @@\n"   # +1,4 over-counts: the body has only 3 new lines
            " A = 1\n"
            "-B = 2\n"
            "+B = 99\n"
            " C = 3\n"
        )
        # Guard: prove the miscount is REAL — strict git apply rejects it, so
        # this test passes only because of the --recount fallback (it would fail
        # against the pre-fix run_git_apply that had no recount rung).
        assert _strict_git_apply_check(miscounted, src) != 0
        res = ev.git_apply(miscounted, src)   # default LocalBackend
        assert res.ok is True
        assert (src / "pkg" / "c.py").read_text() == "A = 1\nB = 99\nC = 3\n"

    def test_rejects_a_non_applying_patch(self, tmp_path):
        # A wrong-CONTEXT patch fails strict AND recount — recount only fixes
        # header line counts, never a context mismatch — so it stays fail-closed
        # and leaves the file untouched.
        src = _seed_repo(tmp_path)
        bad = ("diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
               "@@ -1 +1 @@\n-DOES_NOT_MATCH\n+new\n")
        res = ev.git_apply(bad, src)
        assert res.ok is False
        assert (src / "pkg" / "a.py").read_text() == "VALUE = 1\n"   # untouched

    def test_recount_does_not_rescue_context_mismatch(self, tmp_path):
        # Explicit: a patch with correct line counts but WRONG context lines
        # fails both the strict and the recount gate. Recount re-derives counts,
        # not context — so a genuine mismatch must never sneak through.
        src = _seed_repo(tmp_path)
        (src / "pkg" / "c.py").write_text("A = 1\nB = 2\nC = 3\n", encoding="utf-8")
        wrong_context = (
            "diff --git a/pkg/c.py b/pkg/c.py\n--- a/pkg/c.py\n+++ b/pkg/c.py\n"
            "@@ -1,3 +1,3 @@\n"
            " A = 1\n"
            "-DOES_NOT_MATCH\n"   # this line isn't in the file → context mismatch
            "+B = 99\n"
            " C = 3\n"
        )
        res = ev.git_apply(wrong_context, src)
        assert res.ok is False
        assert "patch does not apply" in res.reason
        assert (src / "pkg" / "c.py").read_text() == "A = 1\nB = 2\nC = 3\n"

    def test_empty_patch_refused(self, tmp_path):
        assert ev.git_apply("", tmp_path).ok is False

    def test_candidate_planted_staging_symlink_cannot_clobber_host_file(
        self, tmp_path,
    ):
        src = _seed_repo(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_text("DO NOT TOUCH", encoding="utf-8")
        planted = src / ".maverick-eval-patch.diff"
        try:
            planted.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")

        result = ev.git_apply(_edit_patch(), src)

        assert result.ok is True
        assert outside.read_text(encoding="utf-8") == "DO NOT TOUCH"

    def test_apply_is_charged_to_shared_tool_budget(self, tmp_path):
        class Meter:
            tool_calls = 0

            def record_tool_call(self):
                self.tool_calls += 1

        src = _seed_repo(tmp_path)
        budget = Meter()
        res = ev.git_apply(_edit_patch(), src, budget=budget)
        assert res.ok is True
        assert budget.tool_calls == 2  # --check, then the real apply

    def test_fresh_halt_refuses_candidate_apply(self, tmp_path, monkeypatch):
        from maverick.learning_guard import Halted

        src = _seed_repo(tmp_path)
        monkeypatch.setattr(
            "maverick.learning_guard.check_learning_halt",
            lambda *_: (_ for _ in ()).throw(Halted("operator stop", "test")))
        res = ev.git_apply(_edit_patch(), src)
        assert res.ok is False and "halted" in res.reason
        assert (src / "pkg" / "a.py").read_text() == "VALUE = 1\n"

    def test_halt_after_check_refuses_the_real_apply(self, tmp_path, monkeypatch):
        from maverick.learning_guard import Halted

        src = _seed_repo(tmp_path)
        checks = 0

        def halt_on_prewrite(*_args):
            nonlocal checks
            checks += 1
            if checks == 2:
                raise Halted("operator stop after check", "test")

        monkeypatch.setattr(
            "maverick.learning_guard.check_learning_halt", halt_on_prewrite)
        res = ev.git_apply(_edit_patch(), src)
        assert res.ok is False and "operator stop after check" in res.reason
        assert checks == 2
        assert (src / "pkg" / "a.py").read_text() == "VALUE = 1\n"

    def test_halt_after_recount_check_refuses_the_real_apply(
        self, tmp_path, monkeypatch,
    ):
        from maverick.learning_guard import Halted

        checks = 0
        commands: list[str] = []

        def halt_on_prewrite(*_args):
            nonlocal checks
            checks += 1
            if checks == 2:
                raise Halted("operator stop after recount check", "test")

        class Result:
            stderr = "strict rejected"

            def __init__(self, ok):
                self.ok = ok

        class RecountOnlySandbox:
            def exec(self, command, timeout=None):
                commands.append(command)
                return Result("--check --recount" in command)

        monkeypatch.setattr(
            "maverick.learning_guard.check_learning_halt", halt_on_prewrite)
        ok, reason = ev.run_git_apply(
            _edit_patch(), tmp_path, RecountOnlySandbox())
        assert ok is False and "operator stop after recount check" in reason
        assert checks == 2
        assert len(commands) == 2
        assert commands[0].startswith(
            "git apply --check -p1 .maverick-patch-")
        assert commands[1].startswith(
            "git apply --check --recount -p1 .maverick-patch-")
        assert commands[0].split()[-1] == commands[1].split()[-1]


class TestEvaluatePatch:
    def test_isolation_source_is_untouched(self, tmp_path):
        src = _seed_repo(tmp_path)
        evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "work")
        assert (src / "pkg" / "a.py").read_text() == "VALUE = 1\n"   # never mutated

    def test_scores_from_injected_scorer(self, tmp_path):
        src = _seed_repo(tmp_path)

        def score(workdir):
            # candidate copy has VALUE=99 after the patch; baseline has VALUE=1
            text = (Path(workdir) / "pkg" / "a.py").read_text()
            return Score(1.0 if "99" in text else 0.0, samples=4)

        res = evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "w",
                             score_fn=score)
        assert isinstance(res, EvalResult)
        assert res.ok is True and res.applied is True
        assert res.baseline_score == 0.0 and res.candidate_score == 1.0
        assert res.samples == 4
        assert res.improvement == 1.0

    def test_non_applying_patch_fails_closed(self, tmp_path):
        src = _seed_repo(tmp_path)
        bad = ("diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
               "@@ -1 +1 @@\n-NOPE\n+new\n")
        res = evaluate_patch(bad, src=src, workroot=tmp_path / "w")
        assert res.ok is False and res.applied is False

    def test_scorer_error_fails_closed(self, tmp_path):
        src = _seed_repo(tmp_path)

        def boom(workdir):
            raise RuntimeError("scorer blew up")

        res = evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "w",
                             score_fn=boom)
        assert res.ok is False
        assert "scorer error" in res.reason

    def test_samples_is_the_min_of_the_two_arms(self, tmp_path):
        src = _seed_repo(tmp_path)
        calls = {"n": 0}

        def score(workdir):
            calls["n"] += 1
            return Score(0.5, samples=10 if calls["n"] == 1 else 6)

        res = evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "w",
                             score_fn=score)
        assert res.samples == 6


class _FakeContainerSB(_EvidenceBackend):
    """A non-host-visible backend stand-in (like docker/gvisor)."""
    host_visible_fs = False
    def __init__(self):
        super().__init__(ev.AuthenticatedTestCounts(3, 0))
        self.calls = []

    def exec(self, cmd, timeout=None):
        self.calls.append(cmd)
        class R:
            stdout = "3 passed in 0.1s"
            stderr = ""
            exit_code = 0
        return R()

    def exec_authenticated_tests(self, request, timeout=None):
        self.calls.append(request.command)
        return super().exec_authenticated_tests(request, timeout=timeout)


class TestIsolationPolicy:
    def test_no_policy_defaults_to_host_with_warning(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: False)
        sb = ev.resolve_eval_sandbox(None, tmp_path)
        from maverick.sandbox.local import LocalBackend
        assert isinstance(sb, LocalBackend)

    def test_require_container_refuses_host_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: True)
        with pytest.raises(ev.EvalSandboxError, match="require-container"):
            ev.resolve_eval_sandbox(None, tmp_path)

    def test_require_container_refuses_host_visible_backend(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: True)
        from maverick.sandbox.local import LocalBackend
        with pytest.raises(ev.EvalSandboxError):
            ev.resolve_eval_sandbox(LocalBackend(workdir=tmp_path), tmp_path)

    def test_container_backend_is_accepted_under_policy(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: True)
        sb = _FakeContainerSB()
        assert ev.resolve_eval_sandbox(sb, tmp_path) is sb

    def test_evaluate_patch_fails_closed_under_policy(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: True)
        src = _seed_repo(tmp_path)
        res = evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "w")
        assert res.ok is False and res.applied is False
        assert "require-container" in res.reason
        # and it must NOT have copied/executed anything on the host
        assert not (tmp_path / "w" / "candidate").exists()

    def test_git_apply_refuses_host_under_policy(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: True)
        src = _seed_repo(tmp_path)
        res = ev.git_apply(_edit_patch(), src)   # no sandbox -> would be host
        assert res.ok is False
        assert (src / "pkg" / "a.py").read_text() == "VALUE = 1\n"  # untouched

    def test_pytest_score_uses_container_and_scores(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: True)
        sb = _FakeContainerSB()
        score = _pytest_score(sandbox=sb)(tmp_path)
        assert score.samples == 3 and score.value == 1.0
        assert sb.calls  # ran in the container, not the host

    def test_pytest_score_budget_stop(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ev, "container_required", lambda: False)

        class Budget:
            def check(self):
                raise RuntimeError("budget exhausted")
        score = _pytest_score(budget=Budget())(tmp_path)
        assert score == Score(0.0, 0)


class TestBaselineCache:
    def test_cached_baseline_skips_the_baseline_arm(self, tmp_path):
        src = _seed_repo(tmp_path)
        calls = {"n": 0}

        def score(workdir):
            calls["n"] += 1
            text = (Path(workdir) / "pkg" / "a.py").read_text()
            return Score(1.0 if "99" in text else 0.0, samples=4)

        cached = Score(0.5, samples=7)
        res = evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "w",
                             score_fn=score, baseline=cached)
        assert res.ok is True
        assert calls["n"] == 1                      # only the CANDIDATE was scored
        assert res.baseline_score == 0.5            # used the cached baseline
        assert res.candidate_score == 1.0
        assert res.samples == 4                     # min(cached 7, cand 4)
        assert not (tmp_path / "w" / "baseline").exists()   # no baseline copy made

    def test_result_exposes_baseline_for_caching(self, tmp_path):
        src = _seed_repo(tmp_path)
        res = evaluate_patch(_edit_patch(), src=src, workroot=tmp_path / "w",
                             score_fn=lambda wd: Score(0.3, samples=5))
        assert res.baseline.value == 0.3 and res.baseline.samples == 5
