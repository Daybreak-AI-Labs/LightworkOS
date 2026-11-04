"""Kubernetes sandbox: allow_network=false runs under a deny-all NetworkPolicy.

The backend used to refuse EVERY command when
allow_network=false (the default the wizard writes), so a config produced by
the UX source of truth could not run anything. It now verifies the namespace
carries a deny-all NetworkPolicy and runs under it, and only fails closed --
with the manifest to apply -- when none is present.
"""
from __future__ import annotations

import json
import tarfile
from unittest.mock import MagicMock

import pytest

from .test_kubernetes_workspace_transfer import _capture_using_fake_run
from .test_sandbox_kubernetes import _calls_with, _subcommand


@pytest.fixture(autouse=True)
def _synthetic_archive_capture(monkeypatch):
    monkeypatch.setattr("maverick.sandbox.workspace_transfer.capture_archive", _capture_using_fake_run)


def _policy(*, pod_selector=None, policy_types=("Ingress", "Egress"), egress=None):
    spec = {"podSelector": pod_selector or {}, "policyTypes": list(policy_types)}
    if egress is not None:
        spec["egress"] = egress
    return {"metadata": {"name": "p"}, "spec": spec}


def _fake_kubectl(monkeypatch, *, policies, get_rc=0, get_stdout=None):
    calls: list[list] = []

    def _fake_run(args, *a, **k):
        calls.append(list(args))
        sub = _subcommand(args)
        if sub == "version":
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        if sub == "get":
            body = get_stdout if get_stdout is not None else json.dumps({"items": policies})
            return MagicMock(returncode=get_rc, stdout=body, stderr="")
        if sub in ("run", "wait", "cp", "delete"):
            return MagicMock(returncode=0, stdout="", stderr="")
        if sub == "exec":
            if "tar" in args:
                with tarfile.open(fileobj=k["stdout"], mode="w"):
                    pass
                return MagicMock(returncode=0, stderr=b"")
            return MagicMock(returncode=0, stdout="ran\n", stderr="")
        raise AssertionError(f"unexpected kubectl invocation: {args}")

    monkeypatch.setattr("subprocess.run", _fake_run)
    monkeypatch.setattr("maverick.sandbox.workspace_transfer.capture_archive", _capture_using_fake_run)
    return calls


def test_runs_under_a_present_deny_all_policy(monkeypatch, tmp_path):
    from maverick.sandbox.kubernetes import KubernetesBackend

    calls = _fake_kubectl(monkeypatch, policies=[_policy()])
    backend = KubernetesBackend(namespace="agents", workdir=tmp_path / "workspace")  # allow_network=False
    first = backend.exec("echo hi")
    assert first.exit_code == 0 and first.stdout == "ran\n"
    get = _calls_with(calls, "get")[0]
    assert "networkpolicy" in get and "agents" in get
    assert _calls_with(calls, "exec")
    # Verify each command: administrators can change policy between calls.
    backend.exec("echo again")
    assert len(_calls_with(calls, "get")) == 2
    assert len(_calls_with(calls, "exec")) == 4  # command + archive per run


def test_fails_closed_with_the_manifest_when_no_policy_exists(monkeypatch, tmp_path):
    from maverick.sandbox.kubernetes import KubernetesBackend

    calls = _fake_kubectl(monkeypatch, policies=[])
    backend = KubernetesBackend(namespace="agents", workdir=tmp_path / "workspace")
    result = backend.exec("echo hi")
    assert result.exit_code == 2
    assert "kind: NetworkPolicy" in result.stderr
    assert "namespace: agents" in result.stderr
    assert "allow_network=true" in result.stderr
    assert not _calls_with(calls, "run") and not _calls_with(calls, "exec")


@pytest.mark.parametrize(
    "policy",
    [
        _policy(pod_selector={"matchLabels": {"app": "web"}}),   # scoped, not namespace-wide
        _policy(policy_types=("Ingress",)),                        # ingress only
        _policy(egress=[{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]),  # allows egress
    ],
)
def test_policies_that_do_not_deny_all_egress_do_not_count(monkeypatch, tmp_path, policy):
    from maverick.sandbox.kubernetes import KubernetesBackend

    _fake_kubectl(monkeypatch, policies=[policy])
    backend = KubernetesBackend(namespace="agents", workdir=tmp_path / "workspace")
    assert backend.exec("echo hi").exit_code == 2


def test_kubectl_failure_or_garbage_counts_as_absent(monkeypatch, tmp_path):
    from maverick.sandbox.kubernetes import KubernetesBackend

    _fake_kubectl(monkeypatch, policies=[], get_rc=1)
    assert KubernetesBackend(namespace="a", workdir=tmp_path / "workspace").exec("true").exit_code == 2
    _fake_kubectl(monkeypatch, policies=[], get_stdout="not json")
    assert KubernetesBackend(namespace="a", workdir=tmp_path / "workspace").exec("true").exit_code == 2


def test_allow_network_true_skips_the_check(monkeypatch, tmp_path):
    from maverick.sandbox.kubernetes import KubernetesBackend

    calls = _fake_kubectl(monkeypatch, policies=[])
    backend = KubernetesBackend(namespace="agents", allow_network=True, workdir=tmp_path / "workspace")
    assert backend.exec("echo hi").exit_code == 0
    assert not _calls_with(calls, "get")
