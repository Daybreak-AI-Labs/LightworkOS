"""pick_sandbox() lets container users pick a coding language.

The sandbox has per-language images (sandbox._IMAGE_BY_LANGUAGE: rust ->
rust:1, go -> golang:1, ...). For container backends only, the wizard asks
for the language and writes [sandbox] language, so a non-Python user gets a
cargo/go toolchain instead of python:3.12-slim.

Python is the default image, so picking it (or a non-container backend) writes
no [sandbox] language.
"""
from __future__ import annotations

import pytest


def _answers(monkeypatch, backend_choice: str, language_choice: str | None):
    """Stub the interactive prompts: first _q_select is the backend, the
    second (if reached) is the language. _q_text is the workspace dir."""
    from maverick_installer import wizard

    picks = [backend_choice]
    if language_choice is not None:
        picks.append(language_choice)
    it = iter(picks)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **k: next(it))
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: "/tmp/ws")
    return wizard


def test_container_backend_writes_chosen_language(monkeypatch):
    wizard = _answers(
        monkeypatch,
        "docker - Throwaway Docker container (recommended)",
        "rust       - rust:1",
    )
    cfg = wizard.pick_sandbox()
    assert cfg["backend"] == "docker"
    assert cfg["language"] == "rust"


def test_python_default_omits_language_key(monkeypatch):
    # Python is already the default image -- don't clutter the config, and keep
    # existing/Python installs producing the same [sandbox] section as before.
    wizard = _answers(
        monkeypatch,
        "docker - Throwaway Docker container (recommended)",
        "python     - python:3.12-slim (default)",
    )
    cfg = wizard.pick_sandbox()
    assert "language" not in cfg


def test_local_backend_skips_language_question(monkeypatch):
    # The language only changes a container image; local runs on the host, so
    # the question must not be asked (a second _q_select call would raise here).
    wizard = _answers(
        monkeypatch,
        "local  - Subprocess on this machine (fastest, least isolated)",
        None,
    )
    cfg = wizard.pick_sandbox()
    assert cfg["backend"] == "local"
    assert "language" not in cfg


def test_offered_languages_are_real_sandbox_keys(monkeypatch):
    # Contract: every language the wizard offers must resolve to a real image in
    # sandbox._IMAGE_BY_LANGUAGE, or the user picks a toolchain that silently
    # falls back to python:3.12-slim.
    sandbox = pytest.importorskip("maverick.sandbox")
    for key in ("python", "javascript", "go", "rust", "java", "ruby"):
        assert key in sandbox._IMAGE_BY_LANGUAGE


# ---- kubernetes: networking must be asked, not silently defaulted ----

_K8S = "kubernetes - Pod-per-command in a cluster (kubectl)"
_PY = "python     - python:3.12-slim (default)"
_DENY = "deny  - No network: apply the deny-all NetworkPolicy shown next (recommended)"
_ALLOW = "allow - Pods may use the cluster network (package installs, HTTP fetches)"


def _k8s_answers(monkeypatch, network_choice: str, namespace: str = "agents"):
    from maverick_installer import wizard

    selects = iter([_K8S, _PY, network_choice])
    texts = iter(["/tmp/ws", namespace])
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **k: next(selects))
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(texts))
    printed: list[str] = []
    monkeypatch.setattr(wizard.console, "print", lambda *a, **k: printed.append(str(a[0]) if a else ""))
    return wizard, printed


def test_kubernetes_deny_writes_namespace_and_prints_the_policy(monkeypatch):
    # The backend fails closed without a deny-all NetworkPolicy, so the wizard
    # must write the namespace, keep allow_network=false, and hand the operator
    # the exact manifest for that namespace.
    wizard, printed = _k8s_answers(monkeypatch, _DENY, namespace="agents")
    cfg = wizard.pick_sandbox()
    assert cfg["backend"] == "kubernetes"
    assert cfg["namespace"] == "agents"
    assert cfg["allow_network"] is False
    manifest = "\n".join(printed)
    assert "kind: NetworkPolicy" in manifest
    assert "namespace: agents" in manifest
    assert "policyTypes: [Ingress, Egress]" in manifest


def test_kubernetes_allow_writes_allow_network_true(monkeypatch):
    wizard, printed = _k8s_answers(monkeypatch, _ALLOW)
    cfg = wizard.pick_sandbox()
    assert cfg["allow_network"] is True
    assert "kind: NetworkPolicy" not in "\n".join(printed)


def test_kubernetes_manifest_matches_the_backend(monkeypatch):
    # The wizard's manifest is the kernel's own, so what the operator applies
    # is exactly what KubernetesBackend checks for.
    kubernetes = pytest.importorskip("maverick.sandbox.kubernetes")
    from maverick_installer import wizard

    assert wizard.kubernetes_deny_all_manifest("ci") == kubernetes._DENY_ALL_NETWORKPOLICY.format(ns="ci")


def test_other_backends_do_not_ask_about_kubernetes(monkeypatch):
    wizard = _answers(
        monkeypatch,
        "docker - Throwaway Docker container (recommended)",
        _PY,
    )
    cfg = wizard.pick_sandbox()
    assert "namespace" not in cfg and "allow_network" not in cfg
