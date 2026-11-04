"""Production cannot fall back into its credential-bearing application task."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from maverick import config
from maverick.sandbox import SandboxPolicyError, build_sandbox, container_backend_required
from maverick.sandbox.kubernetes import KubernetesBackend
from maverick.sandbox.kubernetes_authority import _kubeconfig
from maverick.sandbox.local import scrub_env


def _credential():
    return {"kind": "Config", "apiVersion": "v1", "current-context": "execution",
            "contexts": [{"name": "execution", "context": {"user": "worker-controller", "cluster": "isolated"}}],
            "users": [{"name": "worker-controller", "user": {"token": "synthetic-credential"}}],
            "clusters": [{"name": "isolated", "cluster": {
                "server": "https://cluster.invalid", "certificate-authority-data": "synthetic-CA"}}]}


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv("MAVERICK_DEPLOYMENT_ISOLATION", "kubernetes")
    monkeypatch.setenv("MAVERICK_EXECUTOR_IMAGE", "registry.invalid/worker@sha256:" + "a" * 64)
    monkeypatch.setenv("MAVERICK_EXECUTOR_NAMESPACE", "lightwork-execution")
    monkeypatch.setenv("MAVERICK_EXECUTOR_KUBECONFIG_SECRET", json.dumps(_credential()))
    monkeypatch.setattr(config, "load_config", lambda: {"sandbox": {
        "backend": "local", "allow_network": True, "extra_kubectl_args": ["--context", "wrong"]}})
    monkeypatch.setattr(KubernetesBackend, "_verify_kubectl", lambda self: None)


def test_production_pins_separate_offline_executor_and_private_credential(production, tmp_path):
    backend = build_sandbox(workdir=tmp_path / "workspace")
    assert isinstance(backend, KubernetesBackend)
    assert container_backend_required()
    assert config.get_sandbox()["backend"] == "kubernetes"
    assert not backend.allow_network
    assert backend.extra_kubectl_args == []
    assert backend.namespace == "lightwork-execution"
    path = Path(backend.kubeconfig)
    assert not path.is_relative_to(backend.workdir)
    assert json.loads(path.read_text())["users"][0]["user"]["token"] == "synthetic-credential"
    assert "--kubeconfig" in backend._kubectl_prefix()
    assert "MAVERICK_EXECUTOR_KUBECONFIG_SECRET" not in scrub_env()
    manifest = backend._pod_overrides("test")
    assert manifest["spec"]["automountServiceAccountToken"] is False
    assert manifest["spec"]["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert manifest["spec"]["volumes"] == [{"name": "workspace", "emptyDir": {}}]


@pytest.mark.parametrize("backend", ["local", "docker", "ssh", "firecracker", "typo"])
def test_explicit_backend_cannot_bypass_production_policy(production, tmp_path, backend):
    with pytest.raises(SandboxPolicyError, match="separate Kubernetes"):
        build_sandbox(workdir=tmp_path, backend=backend)


def test_privileged_evaluator_policy_is_refused_instead_of_silently_rebound(production, tmp_path):
    with pytest.raises(SandboxPolicyError, match="pinned evaluator"):
        build_sandbox(workdir=tmp_path, sandbox_config={"backend": "gvisor"})


@pytest.mark.parametrize("key,value", [("MAVERICK_EXECUTOR_KUBECONFIG_SECRET", ""),
    ("MAVERICK_EXECUTOR_IMAGE", "worker:latest"), ("MAVERICK_EXECUTOR_NAMESPACE", "default"),
    ("MAVERICK_DEPLOYMENT_ISOLATION", "disabled")])
def test_missing_or_invalid_production_config_fails_closed(production, tmp_path, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(SandboxPolicyError):
        build_sandbox(workdir=tmp_path)


@pytest.mark.parametrize("field,value", [("exec", {"command": "arbitrary"}),
    ("auth-provider", {"name": "oidc"}), ("tokenFile", "/private/key"),
    ("client-key", "/private/key"), ("token", ["invalid"]), ("username", "user")])
def test_kubeconfig_refuses_host_command_and_file_credential_sources(field, value):
    credential = _credential()
    credential["users"][0]["user"][field] = value
    with pytest.raises(ValueError):
        _kubeconfig(json.dumps(credential))


@pytest.mark.parametrize("field,value", [("insecure-skip-tls-verify", True),
    ("certificate-authority", "/private/file"), ("proxy-url", "https://proxy.invalid"),
    ("server", "http://cluster.invalid"),
    ("server", "https://user:password@cluster.invalid"),  # pragma: allowlist secret -- invalid-host fixture
    ("certificate-authority-data", ""), ("server", ["invalid"])])
def test_kubeconfig_requires_direct_verified_tls(field, value):
    credential = _credential()
    credential["clusters"][0]["cluster"][field] = value
    with pytest.raises(ValueError):
        _kubeconfig(json.dumps(credential))
