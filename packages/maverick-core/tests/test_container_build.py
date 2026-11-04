"""container_build: sandbox-mediated, workspace-confined docker build."""
from __future__ import annotations

from types import SimpleNamespace

from maverick.tools.container_build import container_build


class _Res:
    def __init__(self, code=0, out="Successfully built abc123", err=""):
        self.exit_code, self.stdout, self.stderr = code, out, err


class _FakeSandbox:
    """Records the shell command sandbox_run hands to exec(); workdir-scoped."""

    def __init__(self, workdir, res=None):
        self.workdir = str(workdir)
        self.cmd = None
        self._res = res or _Res()

    def exec(self, cmd, timeout=None):
        self.cmd = cmd
        return self._res


def _ctx(tmp_path, name="ctx"):
    d = tmp_path / name
    d.mkdir(exist_ok=True)
    (d / "Dockerfile").write_text("FROM scratch\n")
    return name  # workspace-relative


def _approve_as_human(monkeypatch):
    import maverick.safety.consent as consent

    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        ),
    )


def test_build_issues_validated_docker_command(tmp_path, monkeypatch):
    # This test is about command construction, not the consent gate (covered
    # below); model one explicit human decision around the effect.
    _approve_as_human(monkeypatch)
    sb = _FakeSandbox(tmp_path)
    out = container_build(sb).fn(
        {
            "op": "build",
            "context": _ctx(tmp_path),
            "tag": "myapp:dev",
            "build_args": {"VERSION": "1.2"},
        }
    )
    assert "docker build" in sb.cmd
    assert "-t myapp:dev" in sb.cmd
    assert "--build-arg VERSION=1.2" in sb.cmd
    assert "docker build ok for myapp:dev" in out


def test_build_reports_failure(tmp_path, monkeypatch):
    _approve_as_human(monkeypatch)
    sb = _FakeSandbox(tmp_path, _Res(code=1, out="step 2/3", err="boom"))
    out = container_build(sb).fn(
        {"op": "build", "context": _ctx(tmp_path), "tag": "x:y"}
    )
    assert "FAILED (exit 1)" in out and "boom" in out


def test_rejects_bad_tag_and_missing_context(tmp_path):
    sb = _FakeSandbox(tmp_path)
    assert container_build(sb).fn(
        {"op": "build", "context": _ctx(tmp_path), "tag": "Bad Tag!"}
    ).startswith("ERROR")
    assert container_build(sb).fn(
        {"op": "build", "context": "nope", "tag": "x"}
    ).startswith("ERROR")
    bad = container_build(sb).fn(
        {
            "op": "build",
            "context": _ctx(tmp_path),
            "tag": "x",
            "build_args": {"bad key": "v"},
        }
    )
    assert bad.startswith("ERROR")


def test_rejects_workspace_escape(tmp_path):
    sb = _FakeSandbox(tmp_path)
    # absolute path outside the workspace
    out = container_build(sb).fn({"op": "build", "context": "/etc", "tag": "x"})
    assert out.startswith("ERROR") and "escapes the workspace" in out
    # ..-escape via dockerfile
    out2 = container_build(sb).fn(
        {
            "op": "build",
            "context": _ctx(tmp_path),
            "dockerfile": "../../../../etc/hosts",
            "tag": "x",
        }
    )
    assert out2.startswith("ERROR") and "escapes the workspace" in out2


def test_missing_dockerfile(tmp_path):
    sb = _FakeSandbox(tmp_path)
    (tmp_path / "empty").mkdir()
    out = container_build(sb).fn({"op": "build", "context": "empty", "tag": "x"})
    assert "Dockerfile not found" in out


def test_container_build_is_high_risk():
    from maverick.safety.tool_risk import tool_risk

    assert tool_risk("container_build") == "high"


def test_consent_denial_blocks_docker_build(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    sb = _FakeSandbox(tmp_path)

    out = container_build(sb).fn(
        {"op": "build", "context": _ctx(tmp_path), "tag": "x:y"}
    )

    assert "container build was not approved" in out
    assert sb.cmd is None


def test_silent_auto_approve_does_not_start_docker_build(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    sb = _FakeSandbox(tmp_path)

    out = container_build(sb).fn(
        {"op": "build", "context": _ctx(tmp_path), "tag": "x:y"}
    )

    assert "container build was not approved" in out
    assert sb.cmd is None


def test_context_change_after_approval_blocks_docker(tmp_path, monkeypatch):
    import maverick.safety.consent as consent

    context_name = _ctx(tmp_path)
    dockerfile = tmp_path / context_name / "Dockerfile"
    sb = _FakeSandbox(tmp_path)

    def approve(*_args, **_kwargs):
        dockerfile.write_text("FROM scratch\nLABEL changed=yes\n")
        return SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        )

    monkeypatch.setattr(consent, "require_consent", approve)
    out = container_build(sb).fn({
        "op": "build", "context": context_name, "tag": "reviewed:test",
    })

    assert "target or approval authority changed" in out
    assert sb.cmd is None


def test_medium_risk_ceiling_drops_container_build(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir()
    (cfg_dir / "config.toml").write_text('[security]\nmax_risk = "medium"\n')

    from maverick.tools import base_registry

    class _W:
        pass

    names = set(
        getattr(base_registry(world=_W(), sandbox=_FakeSandbox(tmp_path)), "_tools", {})
    )

    assert "container_build" not in names
    assert "shell" not in names


def test_registered(tmp_path):
    from maverick.tools import base_registry

    class _W:
        pass

    names = set(
        getattr(base_registry(world=_W(), sandbox=_FakeSandbox(tmp_path)), "_tools", {})
    )
    assert "container_build" in names
