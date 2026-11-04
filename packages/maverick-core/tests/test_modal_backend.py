"""Modal sandbox backend: exec via a fake modal client; SDK conformance."""
from __future__ import annotations

from types import SimpleNamespace

from maverick.sandbox.modal_backend import ModalBackend
from maverick.sandbox.sdk import conformance


class _FakeStream:
    def __init__(self, text):
        self._t = text

    def read(self):
        return self._t


class _FakeSandbox:
    def __init__(self, *cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.stdout = _FakeStream("out: " + " ".join(cmd))
        self.stderr = _FakeStream("")
        self.returncode = 0
        self.terminated = False

    def wait(self):
        pass

    def terminate(self):
        self.terminated = True


def _fake_modal(created):
    class _SandboxFactory:
        @staticmethod
        def create(*cmd, **kwargs):
            sb = _FakeSandbox(*cmd, **kwargs)
            created.append(sb)
            return sb

    return SimpleNamespace(
        App=SimpleNamespace(lookup=lambda name, create_if_missing: f"app:{name}"),
        Image=SimpleNamespace(from_registry=lambda img: f"img:{img}"),
        Sandbox=_SandboxFactory,
    )


def test_exec_runs_sh_dash_c(tmp_path):
    created: list = []
    sb = ModalBackend(workdir=tmp_path, client=_fake_modal(created), allow_network=True)
    res = sb.exec("echo hi")
    assert res.exit_code == 0
    assert created[0].cmd == ("sh", "-c", "echo hi")
    assert "echo hi" in res.stdout
    assert created[0].terminated is True  # always torn down


def test_timeout_and_resources_plumbed(tmp_path):
    created: list = []
    sb = ModalBackend(workdir=tmp_path, client=_fake_modal(created),
                      image="node:22", cpu=2.0, memory_mb=2048, timeout=30,
                      allow_network=True)
    sb.exec("npm test", timeout=90)
    kw = created[0].kwargs
    assert kw["timeout"] == 90
    assert kw["image"] == "img:node:22"
    assert kw["cpu"] == 2.0 and kw["memory"] == 2048


def test_infra_error_is_failed_command_not_crash(tmp_path):
    class _Boom:
        App = SimpleNamespace(lookup=lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("no modal token")))

    sb = ModalBackend(workdir=tmp_path, client=_Boom(), allow_network=True)
    res = sb.exec("echo hi")
    assert res.exit_code == 125
    assert "modal sandbox error" in res.stderr


def test_missing_modal_actionable(tmp_path, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "modal", None)
    sb = ModalBackend(workdir=tmp_path, allow_network=True)
    res = sb.exec("echo hi")
    assert res.exit_code == 125 and "packages/maverick-core[modal]" in res.stderr


def test_sdk_v2_conformance(tmp_path):
    assert conformance(ModalBackend) == []
    assert conformance(ModalBackend(workdir=tmp_path, client=object())) == []


def test_build_sandbox_routes_modal(tmp_path, monkeypatch):
    import maverick.sandbox as s
    sb = s.build_sandbox(workdir=tmp_path, backend="modal")
    assert isinstance(sb, ModalBackend)


def test_exec_fails_closed_when_network_disabled(tmp_path):
    created: list = []
    sb = ModalBackend(workdir=tmp_path, client=_fake_modal(created))
    res = sb.exec("curl https://example.invalid")
    assert res.exit_code == 2
    assert "allow_network=false" in res.stderr
    assert created == []


def test_build_sandbox_modal_preserves_allow_network_default(tmp_path):
    import maverick.sandbox as s
    sb = s.build_sandbox(workdir=tmp_path, backend="modal")
    assert isinstance(sb, ModalBackend)
    assert sb.allow_network is False
