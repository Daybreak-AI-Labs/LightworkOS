"""Shell commands in a closed container run without a person's approval
(maverick.sandbox.contained_commands); everything else still asks."""
from __future__ import annotations

import pytest
from maverick.sandbox import contained_commands as cc
from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.local import ExecResult, LocalBackend


@pytest.fixture(autouse=True)
def _docker_present(monkeypatch):
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    from maverick import config

    cfg = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)

    def write(text: str = "") -> None:
        cfg.write_text(text, encoding="utf-8")
        config.reset_config_cache()

    write()
    yield write
    config.reset_config_cache()


def _closed(tmp_path, ran):
    box = DockerBackend(workdir=tmp_path / "work")
    box.exec = lambda cmd, **kw: ran.append(cmd) or ExecResult(stdout="ok\n", stderr="", exit_code=0)
    return box


def test_only_a_container_with_its_network_off_counts(tmp_path, settings):
    assert cc.closed_container(DockerBackend(workdir=tmp_path / "a"))
    assert not cc.closed_container(DockerBackend(workdir=tmp_path / "b", allow_network=True))
    assert not cc.closed_container(LocalBackend(workdir=tmp_path))
    assert cc.runs_without_asking(DockerBackend(workdir=tmp_path / "c"))
    assert not cc.runs_without_asking(LocalBackend(workdir=tmp_path))


def test_the_setting_enterprise_and_explicit_consent_choices_keep_asking(tmp_path, settings, monkeypatch):
    from maverick.safety.consent import task_consent_mode

    box = DockerBackend(workdir=tmp_path / "work")
    settings("[sandbox]\ncontained_commands_without_approval = false\n")
    assert not cc.runs_without_asking(box)
    settings()
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    assert not cc.runs_without_asking(box)
    settings("[sandbox]\ncontained_commands_without_approval = true\n")
    assert cc.runs_without_asking(box)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    for mode in ("ask", "auto-deny", "dashboard"):
        settings(f'[safety]\nconsent_mode = "{mode}"\n')
        assert not cc.runs_without_asking(box), mode
    settings()
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "ask")
    assert not cc.runs_without_asking(box)
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    assert cc.runs_without_asking(box)
    monkeypatch.delenv("MAVERICK_CONSENT_MODE")
    with task_consent_mode("dashboard"):
        assert not cc.runs_without_asking(box)


def test_the_shell_tool_runs_a_contained_command_at_once_and_audits_it(tmp_path, settings, monkeypatch):
    # Live: tasks that needed a short script stalled on the Approvals page
    # although the command would run in a container with no network.
    from maverick.tools.shell import shell

    audited = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: audited.append((kind, kw)) or True)

    def must_not_ask(*a, **k):
        raise AssertionError("a contained command asked for approval")

    monkeypatch.setattr("maverick.safety.require_operation_consent", must_not_ask)
    ran: list[str] = []
    out = shell(_closed(tmp_path, ran)).fn({"cmd": "python make_chart.py"})
    assert out == "ok\n\n[exit 0]" and ran == ["python make_chart.py"]
    [(kind, payload)] = audited
    assert kind == "shell_contained_run" and payload["command"] == "python make_chart.py"
    assert payload["backend"].endswith("DockerBackend")


def test_a_host_command_still_asks(tmp_path, settings, monkeypatch):
    from maverick.safety import ConsentDenied
    from maverick.tools.shell import shell

    asked = []

    def deny(*a, **k):
        asked.append(a[0])
        raise ConsentDenied("shell", source="no-decision")

    monkeypatch.setattr("maverick.safety.require_operation_consent", deny)
    out = shell(LocalBackend(workdir=tmp_path)).fn({"cmd": "echo hi"})
    assert asked == ["shell"] and out.startswith("ERROR: shell command was not approved")
