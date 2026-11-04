"""CLI acknowledgement means checked local state, never completed shutdown."""
import json
from contextlib import contextmanager

import pytest
from click.testing import CliRunner
from maverick import agent_control_plane as acp
from maverick import config, file_lock, killswitch
from maverick.cli import main


@pytest.fixture(autouse=True)
def _local_cli_without_control_plane(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "owned-HALT"))
    monkeypatch.setenv("MAVERICK_CONTROL_PLANE", "0")
    monkeypatch.setattr("maverick.audit.record_global", lambda *args, **kwargs: True)
    config.reset_config_cache()
    yield
    killswitch.clear()
    config.reset_config_cache()


def test_halt_and_clear_machine_acknowledgements_check_actual_local_state(monkeypatch, tmp_path):
    assert acp.enabled() is False
    path = tmp_path / "owned-HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(path))
    for command, present in (("halt", True), ("unhalt", False), ("unhalt", False)):
        result = CliRunner().invoke(main, [command, "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == {"command": command, "acknowledged": True,
            "halt_file_present": present, "scope": "local", "work_stopped": False,
            "audit_written": True}
        assert path.exists() is present


def test_cli_records_global_actor_intention_and_outcome(monkeypatch):
    from maverick.cli import _agent_control_plane_groups as cli_control

    seen = []
    monkeypatch.setattr(cli_control, "_actor", lambda: "cli:operator")

    def record(kind, **payload):
        seen.append((str(kind), payload))
        return True

    monkeypatch.setattr("maverick.audit.record_global", record)
    for args in (["halt", "--reason", "incident 42", "--json"],
                 ["unhalt", "--reason", "review complete", "--json"]):
        response = CliRunner().invoke(main, args)
        assert response.exit_code == 0, response.output

    assert [kind for kind, _ in seen] == ["control_plane_action"] * 3
    assert [payload["verb"] for _, payload in seen] == [
        "halt", "clear-halt-request", "clear-halt",
    ]
    assert [payload["detail"] for _, payload in seen] == [
        "incident 42", "review complete", "review complete",
    ]
    assert all(payload["actor"] == "cli:operator" for _, payload in seen)
    assert [payload["ok"] for _, payload in seen] == [True, False, True]
    assert all(payload["scope"] == "local-deployment" for _, payload in seen)
    assert [payload["outcome_detail"] for _, payload in (seen[0], seen[2])] == [
        "durable local HALT file armed", "local HALT file cleared",
    ]


def test_cli_discloses_fail_soft_audit_outage_without_claiming_it_was_written(monkeypatch):
    monkeypatch.setattr("maverick.audit.record_global", lambda *args, **kwargs: False)
    response = CliRunner().invoke(main, ["halt", "--json"])
    assert response.exit_code == 0, response.output
    assert json.loads(response.output)["audit_written"] is False
    assert killswitch._halt_file_path().exists()


def test_cli_unhalt_refuses_when_audit_cannot_record_intent(monkeypatch):
    assert CliRunner().invoke(main, ["halt", "--json"]).exit_code == 0
    path = killswitch._halt_file_path()
    before = path.read_bytes()
    monkeypatch.setattr("maverick.audit.record_global", lambda *args, **kwargs: False)
    response = CliRunner().invoke(main, ["unhalt", "--json"])
    assert response.exit_code != 0
    assert '"acknowledged": true' not in response.output
    assert path.read_bytes() == before


def test_cli_unhalt_preserves_stop_on_strict_audit_refusal(monkeypatch):
    from maverick.audit import AuditRefused

    assert CliRunner().invoke(main, ["halt", "--json"]).exit_code == 0
    path = killswitch._halt_file_path()
    before = path.read_bytes()

    def refuse(*args, **kwargs):
        raise AuditRefused("strict audit signing unavailable")

    monkeypatch.setattr("maverick.audit.record_global", refuse)
    response = CliRunner().invoke(main, ["unhalt", "--json"])
    assert response.exit_code != 0
    assert "audit was refused" in response.output
    assert '"acknowledged": true' not in response.output
    assert path.read_bytes() == before


def test_cli_does_not_claim_stop_remained_if_outcome_audit_refuses(monkeypatch):
    from maverick.audit import AuditRefused

    assert CliRunner().invoke(main, ["halt", "--json"]).exit_code == 0
    calls = 0

    def refuse_outcome(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise AuditRefused("outcome signing unavailable")
        return True

    monkeypatch.setattr("maverick.audit.record_global", refuse_outcome)
    response = CliRunner().invoke(main, ["unhalt", "--json"])
    assert response.exit_code != 0
    assert "state may have changed" in response.output
    assert '"acknowledged": true' not in response.output
    assert not killswitch._halt_file_path().exists()


def test_cli_halt_refuses_an_unowned_parent_without_changing_it(monkeypatch, tmp_path):
    parent = tmp_path / "existing-shared"
    parent.mkdir()
    path = parent / "HALT"
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(path))

    def refuse_parent(_path):
        raise PermissionError("existing parent is not private")

    monkeypatch.setattr(file_lock, "prepare_private_directory", refuse_parent)
    response = CliRunner().invoke(main, ["halt", "--json"])
    assert response.exit_code != 0
    assert '"acknowledged": true' not in response.output
    assert not path.exists()


@pytest.mark.parametrize("command", ["halt", "unhalt"])
def test_cli_refuses_unsafe_lock_without_falsely_acknowledging(monkeypatch, command):
    path = killswitch._halt_file_path()
    if command == "unhalt":
        path.write_text("existing incident", encoding="utf-8")

    @contextmanager
    def refuse_lock(*args, **kwargs):
        raise OSError("strict lock unavailable")
        yield

    with monkeypatch.context() as scoped:
        scoped.setattr(file_lock, "cross_process_lock", refuse_lock)
        response = CliRunner().invoke(main, [command, "--json"])
    assert response.exit_code != 0
    assert '"acknowledged": true' not in response.output
    assert path.exists() is (command == "unhalt")


def test_cli_unhalt_preserves_newer_generation_that_arms_before_its_lock(monkeypatch):
    assert CliRunner().invoke(main, ["halt", "--json"]).exit_code == 0
    path = killswitch._halt_file_path()
    authority = killswitch._halt_authority_lock_path(path)
    real_lock = file_lock.cross_process_lock
    replacement = "newer incident"

    @contextmanager
    def replace_before_clear_lock(target, *, strict=False):
        if target == authority:
            assert strict is True
            file_lock.atomic_write_text(path, replacement, mode=0o600)
        with real_lock(target, strict=strict):
            yield

    monkeypatch.setattr(file_lock, "cross_process_lock", replace_before_clear_lock)
    response = CliRunner().invoke(main, ["unhalt", "--json"])
    assert response.exit_code != 0
    assert '"acknowledged": true' not in response.output
    assert path.read_text(encoding="utf-8") == replacement


@pytest.mark.parametrize("command", ["halt", "unhalt"])
def test_state_read_failure_cannot_be_reported_as_an_acknowledgement(monkeypatch, tmp_path, command):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "owned-HALT"))
    def fail(*args):
        raise OSError("synthetic observation failure")
    monkeypatch.setattr(killswitch, "_halt_file_generation", fail)
    result = CliRunner().invoke(main, [command, "--json"])
    assert result.exit_code != 0 and '"acknowledged": true' not in result.output


@pytest.mark.parametrize("command, observed", [("halt", None), ("unhalt", (1,))])
def test_concurrently_changed_state_is_unconfirmed(monkeypatch, tmp_path, command, observed):
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "owned-HALT"))
    monkeypatch.setattr(killswitch, "_halt_file_generation", lambda *args: observed)
    result = CliRunner().invoke(main, [command, "--json"])
    assert result.exit_code != 0 and "not confirmed" in result.output
