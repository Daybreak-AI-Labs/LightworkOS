"""`maverick tenant quota` input validation and display consistency.

(1) A negative cap is refused rather than clamped to 0 -- i.e. UNLIMITED --
so a typo'd `-5` cannot quietly remove the cap; (2) a cap of 0 reads
"unlimited" both when it is set and in `tenant list`, not "$0/day" in one place
and "unlimited" in the other.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


def _provision(tenant_id="acme"):
    from maverick.tenant import registry as tr
    tr.create_tenant(tenant_id, plan="pro", max_daily_dollars=0)


def test_tenant_create_has_no_cap_unless_one_is_given():
    from maverick.tenant.registry import get_tenant

    default = CliRunner().invoke(main, ["tenant", "create", "default"])
    bounded = CliRunner().invoke(
        main,
        ["tenant", "create", "bounded", "--max-daily-dollars", "5"],
    )

    assert default.exit_code == 0, default.output
    assert bounded.exit_code == 0, bounded.output
    assert get_tenant("default").max_daily_dollars == 0.0
    assert get_tenant("bounded").max_daily_dollars == 5.0


def test_quota_rejects_negative_instead_of_silently_unlimiting():
    _provision()
    res = CliRunner().invoke(main, ["tenant", "quota", "acme", "--", "-5"])
    assert res.exit_code == 2, res.output
    assert "negative" in res.output
    # The cap must be unchanged (still unlimited == 0), not the clamped value.
    from maverick.tenant.registry import get_tenant
    assert get_tenant("acme").max_daily_dollars == 0.0


def test_quota_zero_reads_as_unlimited_consistently():
    _provision()
    res = CliRunner().invoke(main, ["tenant", "quota", "acme", "0"])
    assert res.exit_code == 0, res.output
    assert "unlimited" in res.output
    assert "$0/day" not in res.output
    # ...and the listing agrees.
    lst = CliRunner().invoke(main, ["tenant", "list"])
    assert "quota=unlimited" in lst.output


def test_quota_positive_is_shown_per_day():
    _provision()
    res = CliRunner().invoke(main, ["tenant", "quota", "acme", "25"])
    assert res.exit_code == 0, res.output
    assert "$25/day" in res.output


def test_tenant_list_flags_over_quota():
    # Enforcement is at serve time, but the operator must be able to SEE which
    # tenants are over their daily cap from `tenant list`.
    from datetime import datetime, timezone

    from maverick.billing import ledger_for_tenant
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", plan="pro")
    tr.set_quota("acme", 1.0)
    tr.create_tenant(
        "beta", plan="free", max_daily_dollars=0
    )  # explicit unlimited -> never flagged
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ledger_for_tenant("acme").record("user:x", 5.0, 1000, 200, day=today)

    res = CliRunner().invoke(main, ["tenant", "list"])
    assert res.exit_code == 0, res.output
    assert "OVER QUOTA" in res.output
    # The flag is on acme's line, not beta's.
    acme_line = next(ln for ln in res.output.splitlines() if ln.strip().startswith("acme"))
    beta_line = next(ln for ln in res.output.splitlines() if ln.strip().startswith("beta"))
    assert "OVER QUOTA" in acme_line and "OVER QUOTA" not in beta_line


def test_tenant_delete_reports_a_refusal_as_a_message(monkeypatch):
    from maverick.tenant import registry as tr

    def _refuse(tenant_id, *, purge=False):
        raise tr.TenantRegistryError("an active legal hold covers this tenant")
    monkeypatch.setattr(tr, "delete_tenant", _refuse)
    r = CliRunner().invoke(main, ["tenant", "delete", "acme", "--purge", "--yes"])
    assert r.exit_code == 1 and "active legal hold" in r.output
    assert isinstance(r.exception, SystemExit)
