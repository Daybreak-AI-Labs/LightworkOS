"""Sandbox SDK v2: contract conformance + entry-point loading."""
from __future__ import annotations

import pytest
from maverick.sandbox import sdk
from maverick.sandbox.devcontainer import DevcontainerBackend
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.firecracker import FirecrackerBackend
from maverick.sandbox.kubernetes import KubernetesBackend
from maverick.sandbox.local import ExecResult, LocalBackend
from maverick.sandbox.modal_backend import ModalBackend
from maverick.sandbox.podman import PodmanBackend
from maverick.sandbox.ssh import SSHBackend

_IN_TREE = [LocalBackend, DockerBackend, PodmanBackend, DevcontainerBackend,
            KubernetesBackend, FirecrackerBackend, SSHBackend]


@pytest.mark.parametrize("backend_cls", _IN_TREE)
def test_every_in_tree_backend_conforms(backend_cls):
    assert sdk.conformance(backend_cls) == []


def test_local_instance_satisfies_protocol(tmp_path):
    sb = LocalBackend(workdir=tmp_path)
    assert isinstance(sb, sdk.SandboxV2)
    assert sdk.conformance(sb) == []
    assert "exec" in sdk.capabilities(sb)


def test_remote_backends_without_workspace_transfer_do_not_claim_local_workspace(tmp_path):
    # Construct without external provider credentials or starting a VM.
    modal = ModalBackend(workdir=tmp_path)
    firecracker = object.__new__(FirecrackerBackend)
    assert not sdk.workdir_is_local(modal)
    assert not sdk.workdir_is_local(firecracker)


def test_conformance_flags_missing_exec():
    class Bad:
        workdir = "."

    problems = sdk.conformance(Bad)
    assert any("missing exec" in p for p in problems)


def test_conformance_flags_missing_timeout_kwarg():
    class NoTimeout:
        workdir = "."

        def exec(self, cmd):
            return ExecResult(stdout="", stderr="", exit_code=0)

    problems = sdk.conformance(NoTimeout)
    assert any("timeout" in p for p in problems)


def test_conformance_accepts_var_keyword():
    class Kw:
        workdir = "."

        def exec(self, cmd, **kw):
            return ExecResult(stdout="", stderr="", exit_code=0)

    assert sdk.conformance(Kw) == []


@pytest.mark.parametrize("kind", ["positional_timeout", "required_extra", "keyword_command"])
def test_conformance_rejects_unbindable_execution_shape(kind):
    class Backend:
        workdir = "."

    if kind == "positional_timeout":
        def execute(self, cmd, timeout, /):
            raise AssertionError("conformance must not execute")
    elif kind == "required_extra":
        def execute(self, cmd, extra, timeout=None):
            raise AssertionError("conformance must not execute")
    else:
        def execute(self, *, cmd, timeout=None):
            raise AssertionError("conformance must not execute")
    Backend.exec = execute
    assert any("bind" in problem for problem in sdk.conformance(Backend))


def test_conformance_flags_missing_workdir():
    class NoWd:
        def exec(self, cmd, timeout=None):
            return ExecResult(stdout="", stderr="", exit_code=0)

    assert any("workdir" in p for p in sdk.conformance(NoWd))


def test_capabilities_reports_optional_methods(tmp_path):
    class WithFiles:
        workdir = "."

        def exec(self, cmd, timeout=None):
            return ExecResult(stdout="", stderr="", exit_code=0)

        def put_file(self, src, dst):
            pass

        def exec_authenticated_tests(self, request, timeout=None):
            pass

    assert sdk.capabilities(WithFiles()) == {
        "exec", "local_workdir", "put_file", "exec_authenticated_tests",
    }


def test_capabilities_reports_workspace_locality():
    class Remote:
        workdir_is_local = False

        def exec(self, cmd, timeout=None):
            return ExecResult(stdout="", stderr="", exit_code=0)

    assert sdk.capabilities(Remote()) == {"exec"}


class _GoodExternal:
    def __init__(self, workdir, timeout, **options):
        self.workdir = workdir
        self.timeout = timeout
        self.options = options

    def exec(self, cmd, timeout=None):
        return ExecResult(stdout="ok", stderr="", exit_code=0)


class _BadExternal:
    def __init__(self, workdir, timeout, **options):
        self.workdir = workdir

    def exec(self, cmd):  # no timeout kwarg -> non-conformant
        return ExecResult(stdout="", stderr="", exit_code=0)


class _FakeEP:
    def __init__(self, name, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


def _install_eps(monkeypatch, *eps):
    class _EPs:
        def select(self, group):
            return list(eps) if group == "maverick.sandboxes" else []

    import importlib.metadata as md
    monkeypatch.setattr(md, "entry_points", lambda: _EPs())


def test_entry_point_backend_loads_and_conforms(monkeypatch, tmp_path):
    _install_eps(monkeypatch, _FakeEP("warm", _GoodExternal))
    assert sdk.installed_entry_point_names() == ("warm",)
    sb = sdk.load_entry_point_backend("warm", workdir=tmp_path, timeout=30,
                                      options={"region": "eu"})
    assert isinstance(sb, _GoodExternal)
    assert sb.options == {"region": "eu"}


def test_entry_point_missing_raises_with_available(monkeypatch, tmp_path):
    _install_eps(monkeypatch, _FakeEP("warm", _GoodExternal))
    with pytest.raises(RuntimeError, match="not found.*warm"):
        sdk.load_entry_point_backend("nope", workdir=tmp_path, timeout=30)


def test_entry_point_nonconformant_refused(monkeypatch, tmp_path):
    _install_eps(monkeypatch, _FakeEP("bad", _BadExternal))
    with pytest.raises(RuntimeError, match="does not conform"):
        sdk.load_entry_point_backend("bad", workdir=tmp_path, timeout=30)


def test_build_sandbox_ep_prefix_routes_to_loader(monkeypatch, tmp_path):
    _install_eps(monkeypatch, _FakeEP("warm", _GoodExternal))
    from maverick.sandbox import build_sandbox
    sb = build_sandbox(workdir=tmp_path, backend="ep:warm")
    assert isinstance(sb, _GoodExternal)


def test_sdk_exports():
    import maverick.sandbox as s
    assert s.SDK_VERSION == 2
    assert s.SandboxV2 is sdk.SandboxV2
