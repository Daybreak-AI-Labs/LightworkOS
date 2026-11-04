"""The shell tool routes through the exact-operation consent gate.

The consent/approval system existed but was wired to nothing, so no
destructive action was ever gated. shell() now requires a fresh human decision;
silent auto-approval and standing grants cannot authorize a command.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from maverick.sandbox import LocalBackend
from maverick.tools.shell import shell


def test_shell_default_follows_the_posture(tmp_path: Path, monkeypatch):
    """An unset mode cannot silently authorize an external effect."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    out = shell(LocalBackend(workdir=tmp_path)).fn({"cmd": "echo hello-shell"})
    assert "shell command was not approved" in out


def test_shell_silent_auto_approve_is_not_human_consent(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    out = shell(LocalBackend(workdir=tmp_path)).fn({"cmd": "echo hello-shell"})
    assert "shell command was not approved" in out


def test_shell_runs_after_human_approval(tmp_path: Path, monkeypatch):
    import maverick.safety.consent as consent

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        ),
    )
    out = shell(LocalBackend(workdir=tmp_path)).fn({"cmd": "echo hello-shell"})
    assert "hello-shell" in out
    assert "was not approved" not in out


def test_shell_gated_when_consent_denies(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    out = shell(LocalBackend(workdir=tmp_path)).fn({"cmd": "echo should-not-run"})
    assert "shell command was not approved" in out
    # The command must NOT have executed.
    assert "should-not-run" not in out


def test_shell_target_drift_after_approval_never_executes(tmp_path: Path, monkeypatch):
    import maverick.safety.consent as consent

    backend = LocalBackend(workdir=tmp_path)
    calls = []

    def approve(*_args, **_kwargs):
        backend.workdir = tmp_path / "changed-after-review"
        return SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        )

    monkeypatch.setattr(consent, "require_consent", approve)
    monkeypatch.setattr(
        backend,
        "exec",
        lambda *_args, **_kwargs: calls.append(True),
    )

    out = shell(backend).fn({"cmd": "echo must-not-run"})

    assert "target, command, or approval authority changed" in out
    assert calls == []


def test_shell_never_requests_approval_for_hidden_command_content(tmp_path, monkeypatch):
    import maverick.safety as safety

    calls = []
    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: calls.append(kw))
    tool = shell(LocalBackend(workdir=tmp_path))
    for cmd in (
        "x" * 3801,
        "echo safe\u202e; touch hidden",
        "echo safe\u2028; touch hidden",
        "echo safe\u00a0; touch hidden",
        "printf '-----BEGIN PRIVATE KEY-----'; touch hidden; printf '-----END PRIVATE KEY-----'",  # pragma: allowlist secret
    ):
        assert "ERROR:" in tool.fn({"cmd": cmd})
    assert calls == []
    assert not (tmp_path / "hidden").exists()


def test_shell_full_length_command_is_supplied_to_review(tmp_path, monkeypatch):
    import maverick.safety as safety

    calls = []
    def deny(*args, **kwargs):
        calls.append(kwargs)
        raise safety.ConsentDenied("shell")
    monkeypatch.setattr(safety, "require_operation_consent", deny)
    cmd = "echo " + "x" * 3795
    assert "not approved" in shell(LocalBackend(workdir=tmp_path)).fn({"cmd": cmd})
    assert calls[0]["display_command"] == cmd
