"""`maverick tenant onboard` — provision a tenant AND mint its first admin.

One command wraps ``tenant create`` + the dashboard invite flow: it creates the
tenant and mints a single-use invite link for the first admin, printed once.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main

# The invite half lives in the dashboard package; skip cleanly if it isn't
# installed (the CLI command itself degrades with a clear error in that case).
pytest.importorskip("maverick_dashboard")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for var in ("MAVERICK_TENANT", "MAVERICK_PUBLIC_URL",
                "MAVERICK_DASHBOARD_INVITES"):
        monkeypatch.delenv(var, raising=False)


def _run(*args):
    return CliRunner().invoke(main, ["tenant", "onboard", *args])


def test_onboard_creates_tenant_and_emits_invite(monkeypatch):
    monkeypatch.setenv("MAVERICK_PUBLIC_URL", "https://dash.acme.example")
    res = _run("acme", "--admin-email", "admin@acme.example",
               "--plan", "pro", "--name", "Acme Inc")
    assert res.exit_code == 0, res.output

    # The tenant is really provisioned.
    from maverick.tenant.registry import get_tenant
    rec = get_tenant("acme")
    assert rec is not None
    assert rec.plan == "pro"
    assert rec.display_name == "Acme Inc"

    # An admin invite was minted and is pending.
    from maverick_dashboard import invites
    pending = [i for i in invites.list_invites() if i.pending]
    assert len(pending) == 1
    assert pending[0].email == "admin@acme.example"
    assert pending[0].role == "admin"
    # The role is granted inside the new tenant only, never dashboard-wide.
    assert pending[0].tenant == "acme"

    # The link is printed once, built from the configured public URL.
    assert "https://dash.acme.example/auth/invite/" in res.output
    assert "shown ONCE" in res.output


def test_onboard_without_public_url_prints_relative_link_and_note(monkeypatch):
    res = _run("beta", "--admin-email", "boss@beta.example")
    assert res.exit_code == 0, res.output
    assert "/auth/invite/" in res.output
    # No base URL configured -> tell the operator to prepend their host.
    assert "no dashboard public URL configured" in res.output


def test_onboard_duplicate_tenant_errors(monkeypatch):
    assert _run("acme", "--admin-email", "a@acme.example").exit_code == 0
    res = _run("acme", "--admin-email", "b@acme.example")
    assert res.exit_code == 2
    assert "already exists" in res.output


def test_onboard_rejects_bad_admin_email_but_leaves_tenant(monkeypatch):
    # The tenant is created first; a bad email fails the invite half with a
    # clear error and a non-zero exit, and the operator can re-run.
    res = _run("gamma", "--admin-email", "not-an-email")
    assert res.exit_code == 2, res.output
    assert "invite" in res.output.lower()
    from maverick.tenant.registry import get_tenant
    assert get_tenant("gamma") is not None
