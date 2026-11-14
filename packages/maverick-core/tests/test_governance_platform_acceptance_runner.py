from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.acceptance import run_governance_platform_acceptance as runner


def _fixed_source_binding(_root: Path) -> dict[str, object]:
    return {
        "schema": "lightwork.application-test-source-binding.v1",
        "head_commit": "a" * 40,
        "worktree_manifest_sha256": "b" * 64,
        "git_index_sha256": "c" * 64,
        "git_status_sha256": "d" * 64,
    }


class _FakeProcess:
    def __init__(self, output: bytes, *, timeout: bool = False):
        self.stdout = io.BytesIO(output)
        self.returncode = None
        self._timeout = timeout
        self._waits = 0
        self.terminated = False
        self.killed = False

    def wait(self, timeout):
        self._waits += 1
        if self._timeout and self._waits == 1:
            raise subprocess.TimeoutExpired("pytest", timeout)
        self.returncode = -15 if self.terminated else 0
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.returncode = -9

    def poll(self):
        return self.returncode


def test_fixed_runner_uses_current_interpreter_and_retains_only_output_digest():
    marker = b"private failure material must not enter evidence\n12 passed, 2 skipped in 1.2s\n"
    process = _FakeProcess(marker)
    captured = {}

    def factory(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return process

    result = runner._run_suite(
        runner.SUITES[0],
        repo_root=runner.REPO_ROOT,
        environment={"TEST_ENV": "1"},
        timeout_seconds=30,
        popen_factory=factory,
        monotonic=iter((1.0, 2.25)).__next__,
    )

    assert captured["command"][0:3] == [sys.executable, "-m", "pytest"]
    assert captured["command"][-3:] == list(runner.SUITES[0].test_paths)
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert result["status"] == "passed"
    assert result["pytest_counts"] == {"passed": 12, "skipped": 2}
    assert result["output_sha256"] == hashlib.sha256(marker).hexdigest()
    assert result["duration_seconds"] == 1.25
    assert "private failure material" not in json.dumps(result)


def test_timeout_terminates_the_fixed_child_and_reports_no_raw_output():
    marker = b"sensitive timeout diagnostic"
    process = _FakeProcess(marker, timeout=True)

    result = runner._run_suite(
        runner.SUITES[1],
        repo_root=runner.REPO_ROOT,
        environment={},
        timeout_seconds=10,
        popen_factory=lambda *_args, **_kwargs: process,
        monotonic=iter((5.0, 16.0)).__next__,
    )

    assert process.terminated is True
    assert process.killed is False
    assert result["status"] == "timed_out"
    assert result["timed_out"] is True
    assert "sensitive timeout diagnostic" not in json.dumps(result)


@pytest.mark.parametrize("summary", [
    b"1 test collected in 0.1s\n", b"1 skipped in 0.1s\n",
    b"1 passed, 1 failed in 0.1s\n", b"1 passed, 1 error in 0.1s\n",
])
def test_zero_exit_without_a_successful_test_run_cannot_pass_acceptance(summary):
    report = runner.run_acceptance(
        categories=["audit-export"], popen_factory=lambda *_args, **_kwargs: _FakeProcess(summary),
        source_binding_factory=_fixed_source_binding,
    )
    assert report["suites"][0]["status"] == "failed"
    assert report["summary"]["all_selected_test_suites_passed"] is False
    assert report["summary"]["all_selected_suites_passed"] is False


def test_acceptance_child_does_not_inherit_pytest_options():
    environments = []

    def factory(*_args, **kwargs):
        environments.append(kwargs["env"])
        return _FakeProcess(b"1 passed in 0.1s\n")

    runner.run_acceptance(
        categories=["audit-export"], base_environment={"PYTEST_ADDOPTS": "--collect-only", "KEPT": "1"},
        popen_factory=factory, source_binding_factory=_fixed_source_binding,
    )
    assert len(environments) == 1
    assert "PYTEST_ADDOPTS" not in environments[0]
    assert environments[0]["KEPT"] == "1"


def test_allowlist_resolves_inside_the_repository_and_rejects_unknown_category():
    manifests = {
        suite.category: runner._suite_manifest(runner.REPO_ROOT, suite)
        for suite in runner.SUITES
    }
    assert len(manifests) == 5
    assert all(len(digest) == 64 for digest in manifests.values())
    recovery = next(suite for suite in runner.SUITES if suite.category == "recovery")
    assert (
        "packages/maverick-dashboard/tests/test_external_gateway_runtime.py"
        in recovery.test_paths
    )

    try:
        runner._selected_suites(["arbitrary-test-path"])
    except ValueError as exc:
        assert "allowlisted" in str(exc)
    else:  # pragma: no cover - must fail closed
        raise AssertionError("unknown acceptance category was accepted")


def test_report_labels_runtime_gateway_scope_as_local_and_not_customer_live():
    marker = b"1 passed in 0.1s\n"

    def factory(*_args, **_kwargs):
        return _FakeProcess(marker)

    report = runner.run_acceptance(
        categories=["recovery"],
        timeout_seconds=30,
        popen_factory=factory,
        source_binding_factory=_fixed_source_binding,
    )

    runtime_scope = report["runtime_gateway_acceptance"]
    assert runtime_scope == {
        "scope": "isolated_local_fastapi_test_estate",
        "real_external_gateway_routes_exercised": True,
        "authentication_approval_and_execution_ledger_exercised": True,
        "connector_and_runtime_policy_dependencies": "controlled_test_doubles",
        "external_or_customer_gateway_run": False,
        "external_credentials_used": False,
    }
    assert report["live_acceptance_status"] == "not_run"
    assert report["external_credentials_requested"] is False
    assert report["application_test_source_binding"] == _fixed_source_binding(
        runner.REPO_ROOT
    )
    assert report["source_state_stable_during_run"] is True


def test_source_binding_changes_with_worktree_content_and_index_state(tmp_path):
    repo = tmp_path / "source-binding-repo"
    source = repo / "packages" / "example" / "application.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 'first'\n", encoding="utf-8")

    def git(*arguments):
        subprocess.run(
            ["git", *arguments],
            cwd=repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=True,
        )

    git("init", "-q")
    git("add", "packages/example/application.py")
    git(
        "-c",
        "user.name=Lightwork Acceptance",
        "-c",
        "user.email=acceptance@example.invalid",
        "commit",
        "-q",
        "-m",
        "initial",
    )
    clean = runner._application_test_binding(repo)

    source.write_text("VALUE = 'second'\n", encoding="utf-8")
    modified = runner._application_test_binding(repo)
    git("add", "packages/example/application.py")
    staged = runner._application_test_binding(repo)
    (repo / "proof").mkdir()
    (repo / "proof" / "generated-evidence.json").write_text(
        "{\"volatile\":true}\n", encoding="utf-8"
    )
    (repo / "docs").mkdir()
    (repo / "docs" / "volatile.md").write_text("changed\n", encoding="utf-8")
    after_evidence_write = runner._application_test_binding(repo)

    assert clean["head_commit"] == modified["head_commit"] == staged["head_commit"]
    assert clean["dirty"] is False
    assert modified["dirty"] is True
    assert clean["worktree_manifest_sha256"] != modified[
        "worktree_manifest_sha256"
    ]
    assert modified["worktree_manifest_sha256"] == staged[
        "worktree_manifest_sha256"
    ]
    assert clean["git_index_sha256"] == modified["git_index_sha256"]
    assert modified["git_index_sha256"] != staged["git_index_sha256"]
    assert after_evidence_write == staged
    assert "application.py" not in json.dumps(staged)


def test_source_change_during_acceptance_invalidates_passing_test_suites():
    marker = b"1 passed in 0.1s\n"
    bindings = iter((
        _fixed_source_binding(runner.REPO_ROOT),
        {
            **_fixed_source_binding(runner.REPO_ROOT),
            "worktree_manifest_sha256": "e" * 64,
        },
    ))
    report = runner.run_acceptance(
        categories=["audit-export"],
        timeout_seconds=30,
        popen_factory=lambda *_args, **_kwargs: _FakeProcess(marker),
        source_binding_factory=lambda _root: next(bindings),
    )

    assert report["summary"]["all_selected_test_suites_passed"] is True
    assert report["source_state_stable_during_run"] is False
    assert report["summary"]["all_selected_suites_passed"] is False
