"""Targeted code-eval corpus + held-in/held-out split (Gap 2).

Pins the deterministic development split and that a candidate which only gains
on the adaptive subset is flagged OVERFIT. Cases remain candidate-visible, so
these scores are research telemetry and never authorize adoption.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from maverick.self_modify_corpus import CodeEvalCorpus, evaluate_on_corpus
from maverick.self_modify_eval import (
    AuthenticatedTestCounts,
    AuthenticatedTestEvidence,
)

IDS = tuple(f"tests/test_x.py::test_{i}" for i in range(6))


def _seed(root: Path) -> Path:
    src = root / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    return src


def _patch() -> str:
    return ("diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
            "@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n")


class _FakeSB:
    """Returns canned pytest counts keyed on candidate-vs-baseline and whether
    the command targets the held-out subset."""
    host_visible_fs = False
    authenticated_test_results = True
    test_evidence_protocol = "maverick.test-evidence.v1"
    test_evidence_authority = "corpus-test-controller-key-1"

    def __init__(self, workdir: Path, is_candidate: bool,
                 held_out: set[str], scenario: str, *,
                 image: str | None = None,
                 toolchain_version: str = "pytest 8.0"):
        self.workdir = Path(workdir)
        self.is_candidate = is_candidate
        self.held_out = held_out
        self.scenario = scenario
        self.image = image
        self.toolchain_version = toolchain_version
        self.calls: list[str] = []
        self.requests = []
        self.closed = False

    def exec(self, cmd, timeout=None):
        self.calls.append(cmd)

        # Model the real mounted-workspace contract. Binding probes and patch
        # application must flow through this SAME fake backend as scoring.
        if cmd.startswith(("cat -- ", "type ")):
            marker_name = cmd.split()[-1].strip("'\"")
            marker = self.workdir / marker_name
            text = marker.read_text(encoding="ascii") if marker.exists() else ""

            class R:
                stdout = text
                stderr = "" if text else "missing marker"
                exit_code = 0 if text else 1
            return R()
        if cmd.startswith("git apply"):
            from maverick.sandbox.local import LocalBackend
            return LocalBackend(workdir=self.workdir).exec(cmd, timeout=timeout)
        if "--version" in cmd:
            class R:
                stdout = self.toolchain_version
                stderr = ""
                exit_code = 1 if self.scenario == "missing_env" else 0
            return R()

        raise AssertionError(
            "test commands must use the authenticated controller channel",
        )

    def exec_authenticated_tests(self, request, timeout=None):
        cmd = request.command
        self.calls.append(cmd)
        self.requests.append(request)
        is_out = any(i in cmd for i in self.held_out)
        # baseline: 1/2 pass on both splits.
        passed, failed = 1, 1
        if self.scenario == "saturated" and not self.is_candidate:
            passed, failed = 2, 0
        if self.is_candidate:
            if self.scenario == "genuine":
                passed, failed = 2, 0            # improves on BOTH splits
            elif self.scenario == "overfit":
                passed, failed = (2, 0) if not is_out else (1, 1)  # held-in only
            elif self.scenario == "attrition" and is_out:
                passed, failed = 1, 0            # a held-out test stopped running
        if self.scenario == "no_results":
            return object()
        return AuthenticatedTestEvidence.for_request(
            request,
            authority=self.test_evidence_authority,
            counts=AuthenticatedTestCounts(passed, failed),
        )

    def close(self):
        self.closed = True


def _factory(
    held_out: set[str], scenario: str, created: list[_FakeSB] | None = None,
    *, image: str | None = None, toolchain_version: str = "pytest 8.0",
):
    def make(copy_dir):
        sb = _FakeSB(
            copy_dir, "candidate" in str(copy_dir), held_out, scenario,
            image=image, toolchain_version=toolchain_version,
        )
        if created is not None:
            created.append(sb)
        return sb
    return make


class TestSplit:
    def test_split_is_deterministic_and_nonempty(self):
        c = CodeEvalCorpus(test_ids=IDS)
        a1 = c.split()
        a2 = c.split()
        assert a1 == a2
        held_in, held_out = a1
        assert held_in and held_out
        assert set(held_in).isdisjoint(held_out)
        assert set(held_in) | set(held_out) == set(IDS)

    def test_empty_corpus_has_no_holdout(self):
        assert CodeEvalCorpus(test_ids=()).split() == ([], [])


class TestEvaluateOnCorpus:
    def _run(self, tmp_path, scenario):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        return evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), scenario))

    def test_genuine_improvement_promotes_on_heldout(self, tmp_path):
        res = self._run(tmp_path, "genuine")
        assert res.ok is True and res.applied is True
        assert res.candidate_score > res.baseline_score   # held-OUT gain
        assert res.overfit is False

    def test_overfit_is_flagged_and_refused(self, tmp_path):
        res = self._run(tmp_path, "overfit")
        assert res.overfit is True
        assert res.ok is False                            # refused despite held-in gain
        assert res.held_in_candidate > res.held_in_baseline
        assert res.candidate_score <= res.baseline_score  # no held-out gain
        assert "OVERFIT" in res.reason

    def test_candidate_stdout_cannot_spoof_stock_corpus_score(self, tmp_path):
        result = self._run(tmp_path, "spoof")
        assert result.samples == 2
        assert result.baseline_score == 0.5
        assert result.candidate_score == 0.5

    def test_source_is_untouched(self, tmp_path):
        self._run(tmp_path, "genuine")
        assert (tmp_path / "src" / "pkg" / "a.py").read_text() == "VALUE = 1\n"

    def test_expected_source_manifest_mismatch_fails_before_sandbox(self, tmp_path):
        src = _seed(tmp_path)
        sandbox_calls = []

        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w",
            corpus=CodeEvalCorpus(test_ids=IDS),
            sandbox_factory=lambda path: sandbox_calls.append(path),
            expected_source_manifest="0" * 64,
        )

        assert result.ok is False and result.applied is False
        assert result.reason == (
            "captured evaluation source does not match expected snapshot"
        )
        assert sandbox_calls == []

    def test_untracked_env_and_tracked_private_key_path_never_enter_either_arm(
        self, tmp_path,
    ):
        src = _seed(tmp_path)
        (src / ".env").write_text(
            "OPENAI_API_KEY=do-not-copy\n",  # pragma: allowlist secret
            encoding="utf-8",
        )
        (src / "private.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",  # pragma: allowlist secret
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q"], cwd=src, check=True)
        subprocess.run(
            ["git", "add", "--", "pkg/a.py", "private.pem"], cwd=src, check=True)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine"),
        )
        assert result.ok is True
        for arm in ("baseline", "candidate"):
            assert not (tmp_path / "w" / arm / ".env").exists()
            assert not (tmp_path / "w" / arm / "private.pem").exists()

    def test_private_key_marker_in_tracked_ordinary_file_fails_closed(
        self, tmp_path,
    ):
        src = _seed(tmp_path)
        (src / "pkg" / "notes.txt").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n",  # pragma: allowlist secret
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q"], cwd=src, check=True)
        subprocess.run(
            ["git", "add", "--", "pkg/a.py", "pkg/notes.txt"],
            cwd=src, check=True,
        )
        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w",
            corpus=CodeEvalCorpus(test_ids=IDS),
        )
        assert result.ok is False
        assert not (tmp_path / "w" / "baseline").exists()
        assert not (tmp_path / "w" / "candidate").exists()

    def test_evidence_scope_binds_held_out_fraction(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out_30 = corpus.split(held_out_frac=0.3)
        _, held_out_50 = corpus.split(held_out_frac=0.5)
        first = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w30", corpus=corpus,
            held_out_frac=0.3,
            sandbox_factory=_factory(set(held_out_30), "genuine"),
        )
        second = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w50", corpus=corpus,
            held_out_frac=0.5,
            sandbox_factory=_factory(set(held_out_50), "genuine"),
        )
        assert first.ok is True and second.ok is True
        assert first.evidence_scope and second.evidence_scope
        assert first.evidence_scope != second.evidence_scope

    def test_evidence_scope_binds_dirty_captured_tests(self, tmp_path):
        src = _seed(tmp_path)
        tests = src / "tests"
        tests.mkdir()
        dirty_test = tests / "test_dirty.py"
        dirty_test.write_text("EXPECTED = 1\n", encoding="utf-8")
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        first = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w1", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine"),
        )
        dirty_test.write_text("EXPECTED = 2\n", encoding="utf-8")
        second = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w2", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine"),
        )
        assert first.ok is True and second.ok is True
        assert first.evidence_scope != second.evidence_scope

    def test_evidence_scope_binds_sandbox_and_toolchain_identity(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        first = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w1", corpus=corpus,
            sandbox_factory=_factory(
                set(held_out), "genuine", image="eval@sha256:one",
                toolchain_version="pytest 8.0"),
        )
        sandbox_changed = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w2", corpus=corpus,
            sandbox_factory=_factory(
                set(held_out), "genuine", image="eval@sha256:two",
                toolchain_version="pytest 8.0"),
        )
        toolchain_changed = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w3", corpus=corpus,
            sandbox_factory=_factory(
                set(held_out), "genuine", image="eval@sha256:one",
                toolchain_version="pytest 9.0"),
        )
        assert first.ok is True
        assert sandbox_changed.ok is True and toolchain_changed.ok is True
        assert first.evidence_scope != sandbox_changed.evidence_scope
        assert first.evidence_scope != toolchain_changed.evidence_scope

    def test_requests_bind_distinct_baseline_and_candidate_subjects_and_contexts(
        self, tmp_path,
    ):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        created: list[_FakeSB] = []
        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine", created),
            sandbox_policy_identity="a" * 64,
        )
        assert result.ok is True
        baseline = next(sb for sb in created if not sb.is_candidate)
        candidate = next(sb for sb in created if sb.is_candidate)
        assert baseline.requests and candidate.requests
        assert len({request.subject_sha256 for request in baseline.requests}) == 1
        assert len({request.subject_sha256 for request in candidate.requests}) == 1
        assert baseline.requests[0].subject_sha256 != candidate.requests[0].subject_sha256
        assert (
            baseline.requests[0].execution_context_sha256
            != candidate.requests[0].execution_context_sha256
        )

    def test_mismatched_sandbox_identity_refuses_comparison(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()

        def mismatched_factory(copy_dir):
            is_candidate = "candidate" in str(copy_dir)
            return _FakeSB(
                copy_dir, is_candidate, set(held_out), "genuine",
                image="candidate@sha256:two" if is_candidate else "baseline@sha256:one",
            )

        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=mismatched_factory,
        )
        assert result.ok is False and result.applied is False
        assert "sandbox identities differ" in result.reason

    def test_internal_exception_text_is_not_returned(self, tmp_path):
        src = _seed(tmp_path)

        def materialize_with_secret(_src, _dest):
            raise RuntimeError("sk-proj-secret-must-not-escape")  # pragma: allowlist secret

        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w",
            corpus=CodeEvalCorpus(test_ids=IDS),
            materialize=materialize_with_secret,
        )
        assert result.ok is False
        assert "sk-proj-secret-must-not-escape" not in result.reason  # pragma: allowlist secret

    def test_planted_binding_symlink_cannot_clobber_host_file(self, tmp_path):
        src = _seed(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_text("DO NOT TOUCH", encoding="utf-8")
        planted = src / ".maverick-eval-binding"
        try:
            planted.symlink_to(outside)
        except (OSError, NotImplementedError):
            import pytest
            pytest.skip("symlinks unavailable")
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()

        result = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine"),
        )

        assert result.ok is False
        assert outside.read_text(encoding="utf-8") == "DO NOT TOUCH"

    def test_empty_holdout_fails_closed(self, tmp_path):
        src = _seed(tmp_path)
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w",
            corpus=CodeEvalCorpus(test_ids=("tests/test_x.py::only",)),
            sandbox_factory=_factory(set(), "genuine"))
        assert res.ok is False and "held-out" in res.reason

    def test_denominator_attrition_fails_closed(self, tmp_path):
        # Candidate makes a held-out test stop being collected -> its pass-rate
        # rises by attrition, not merit. Different denominators -> refuse.
        res = self._run(tmp_path, "attrition")
        assert res.ok is False
        assert "different denominators" in res.reason

    def test_non_applying_patch_fails_closed(self, tmp_path):
        src = _seed(tmp_path)
        bad = ("diff --git a/pkg/a.py b/pkg/a.py\n--- a/pkg/a.py\n+++ b/pkg/a.py\n"
               "@@ -1 +1 @@\n-NOPE\n+x\n")
        res = evaluate_on_corpus(
            bad, src=src, workroot=tmp_path / "w",
            corpus=CodeEvalCorpus(test_ids=IDS),
            sandbox_factory=_factory(set(), "genuine"))
        assert res.ok is False and res.applied is False

    def test_patch_and_scoring_share_candidate_sandbox_and_close(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS, bootstrap_command="prepare-offline-env")
        _, held_out = corpus.split()
        created: list[_FakeSB] = []
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine", created))
        assert res.ok is True
        candidate = next(sb for sb in created if sb.is_candidate)
        assert any(cmd.startswith("git apply --check") for cmd in candidate.calls)
        assert any("prepare-offline-env &&" in cmd and "-- " in cmd
                   for cmd in candidate.calls)
        assert all(sb.closed for sb in created)

    def test_missing_evaluator_environment_fails_closed(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "missing_env"))
        assert res.ok is False
        assert "evaluator command/bootstrap unavailable" in res.reason

    def test_zero_observed_cases_fail_closed(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "no_results"))
        assert res.ok is False
        assert "no comparable test results" in res.reason

    def test_saturated_baseline_requires_challenge_corpus(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        created: list[_FakeSB] = []
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "saturated", created))
        assert res.ok is False and res.applied is False
        assert "saturated" in res.reason and "challenge corpus" in res.reason
        candidate = next(sb for sb in created if sb.is_candidate)
        # The binding probe is allowed, but no candidate test-set command or
        # patch apply should be spent once baseline headroom is zero.
        assert not any("tests/test_x.py" in cmd for cmd in candidate.calls)
        assert not any(cmd.startswith("git apply") for cmd in candidate.calls)

    def test_misbound_candidate_sandbox_fails_nonce_probe(self, tmp_path):
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        base_copy = tmp_path / "w" / "baseline"

        def misbound_factory(requested):
            # Both backends point at baseline. The candidate nonce lives in the
            # candidate copy, so the trusted controller detects the mismatch.
            return _FakeSB(
                base_copy, "candidate" in str(requested), set(held_out), "genuine")

        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=misbound_factory)
        assert res.ok is False and res.applied is False
        assert "candidate sandbox cannot read" in res.reason

    def test_require_container_rejects_host_visible_factory(
            self, tmp_path, monkeypatch):
        from maverick.sandbox.local import LocalBackend

        monkeypatch.setattr(
            "maverick.self_modify_eval.container_required", lambda: True)
        src = _seed(tmp_path)
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w",
            corpus=CodeEvalCorpus(test_ids=IDS),
            sandbox_factory=lambda wd: LocalBackend(workdir=wd))
        assert res.ok is False and res.applied is False
        assert "host-visible sandbox" in res.reason

    def test_every_sandbox_exec_is_charged_to_tool_budget(self, tmp_path):
        class Meter:
            tool_calls = 0

            def record_tool_call(self):
                self.tool_calls += 1

        budget = Meter()
        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine"), budget=budget)
        assert res.ok is True
        # 2 binding probes + 2 git apply calls + 2 environment preflights +
        # 4 split score runs. This pins metering across apply and evaluation.
        assert budget.tool_calls == 10

    def test_exhausted_tool_budget_fails_closed_before_apply(self, tmp_path):
        class Limit:
            tool_calls = 0

            def record_tool_call(self):
                self.tool_calls += 1
                if self.tool_calls > 1:
                    raise RuntimeError("tool budget exhausted")

        src = _seed(tmp_path)
        corpus = CodeEvalCorpus(test_ids=IDS)
        _, held_out = corpus.split()
        res = evaluate_on_corpus(
            _patch(), src=src, workroot=tmp_path / "w", corpus=corpus,
            sandbox_factory=_factory(set(held_out), "genuine"), budget=Limit())
        assert res.ok is False and res.applied is False
        assert "budget exhausted" in res.reason
