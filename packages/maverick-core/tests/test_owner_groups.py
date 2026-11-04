"""``maverick owner reset-authenticator``: the host-only reset after a lost phone."""
from __future__ import annotations

import json
import os
import time

import pytest
from click.testing import CliRunner

pytest.importorskip("maverick_dashboard.local_owner_second_factor")

PASSPHRASE = "a long local owner fixture phrase"  # pragma: allowlist secret - test fixture passphrase
EMAIL = "owner@example.com"
ORIGIN = "http://127.0.0.1:8765"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    from maverick_dashboard import local_passphrases
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.load_global_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.config_source_errors", lambda **k: [])
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: True)
    local_passphrases.reset_attempt_limit()
    yield
    local_passphrases.reset_attempt_limit()


def enrolled_owner(monkeypatch):
    """An owner with an authenticator app on. Returns (secret, recovery codes)."""
    from maverick_dashboard import local_owner, owner_totp
    from maverick_dashboard import local_owner_second_factor as second
    from starlette.requests import Request
    scope = {"type": "http", "method": "POST", "scheme": "http", "path": "/auth/local-owner",
             "query_string": b"", "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 1234),
             "headers": [(b"host", b"127.0.0.1:8765"), (b"origin", ORIGIN.encode())]}
    local_owner.enroll(Request(scope), email=EMAIL, password=PASSPHRASE, confirm=True)
    secret, _uri = second.start_setup(PASSPHRASE)
    key = owner_totp.decode_secret(secret)
    codes = second.confirm_setup(owner_totp.totp(key, time.time()))
    return secret, codes


def record():
    from maverick_dashboard import local_owner
    return json.loads(local_owner.path().read_text())


def test_the_owner_group_lists_the_reset_command():
    from maverick.cli import main
    result = CliRunner().invoke(main, ["owner", "--help"])
    assert result.exit_code == 0 and "reset-authenticator" in result.output


def test_a_wrong_email_changes_nothing(monkeypatch):
    from maverick.cli import main
    enrolled_owner(monkeypatch)
    before = record()
    result = CliRunner().invoke(main, ["owner", "reset-authenticator"], input="someone@example.com\n")
    assert result.exit_code == 2
    assert "does not match" in result.output
    assert record() == before


def test_the_right_email_turns_the_app_off_and_says_the_owner_must_set_it_up_again(monkeypatch):
    from maverick.cli import main
    events = []
    monkeypatch.setattr("maverick.audit.audit_event", lambda kind, **kw: events.append((kind, kw)) or True)
    secret, codes = enrolled_owner(monkeypatch)
    result = CliRunner().invoke(main, ["owner", "reset-authenticator"], input="Owner@Example.com\n")
    assert result.exit_code == 0, result.output
    assert "must set up the authenticator app again" in result.output
    assert 'totp = "required"' in result.output and "next passphrase sign-in" in result.output
    # Until set-up, the owner has no app: the passphrase alone opens the restricted steps, as for any owner without one.
    assert "passphrase alone opens company sign-in" in result.output
    stored = record()
    for key in ("totp", "totp_step", "totp_setup", "recovery", "second_factor", "flow_proofs"):
        assert key not in stored
    reset = [kw for kind, kw in events if kw.get("verb") == "owner_authenticator_reset"]
    assert len(reset) == 1 and reset[0]["actor"].startswith("os:")
    shown = result.output + json.dumps(events, default=str)
    assert secret not in shown and codes[0] not in shown


def test_a_refused_audit_stops_the_reset(monkeypatch):
    from maverick.audit import AuditRefused
    from maverick.cli import main
    enrolled_owner(monkeypatch)
    before = record()

    def refuse(*a, **k):
        raise AuditRefused("log unavailable")

    monkeypatch.setattr("maverick.audit.audit_event", refuse)
    result = CliRunner().invoke(main, ["owner", "reset-authenticator"], input="owner@example.com\n")
    assert result.exit_code == 2 and "activity log refused" in result.output
    assert record() == before


def test_with_no_owner_there_is_nothing_to_reset():
    from maverick.cli import main
    result = CliRunner().invoke(main, ["owner", "reset-authenticator"], input="owner@example.com\n")
    assert result.exit_code == 2 and "No local owner" in result.output
