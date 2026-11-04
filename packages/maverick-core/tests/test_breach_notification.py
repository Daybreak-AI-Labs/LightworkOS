"""Breach planner: verified regimes, computed clocks, honest refusals.

The assertions that matter: the fixed clocks compute exactly (72 hours,
calendar days, weekend-skipping business days, the malicious 60-day
Japan branch, determination anchors); thresholds annotate instead of
silently dropping; unknown regimes are refused naming the absent-by-
design set; the feature is off by default.
"""
from __future__ import annotations

import datetime

import pytest
from maverick import breach_notification as bn
from maverick import config

#: Tuesday 2026-08-25 12:00:00 UTC.
_TUESDAY = 1787659200.0
_DAY = 86_400.0


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[breach_notification]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _day_name(stamp: float) -> str:
    return datetime.datetime.fromtimestamp(
        stamp, tz=datetime.timezone.utc).strftime("%a")


def test_off_by_default(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert bn.enabled() is False
    with pytest.raises(bn.BreachNotificationConfigError, match="enable"):
        bn.assess_breach(["eu_gdpr"])


def test_all_fourteen_regimes_list_with_citations():
    rows = bn.list_regimes()
    assert len(rows) == 15
    assert all(row["citations"] for row in rows)


def test_fixed_clocks_compute_exactly():
    plan = bn.assess_breach(
        ["eu_gdpr", "kr_pipa", "us_tx", "sg_pdpa", "us_hipaa"],
        subjects_affected=1200, discovered_at=_TUESDAY,
    )
    d = {o["regime"]: o for o in plan["obligations"]}
    assert d["eu_gdpr"]["authority_due_at"] == _TUESDAY + 72 * 3600
    assert d["kr_pipa"]["subjects_due_at"] == _TUESDAY + 72 * 3600
    assert d["us_tx"]["authority_due_at"] == _TUESDAY + 30 * _DAY
    assert d["us_hipaa"]["subjects_due_at"] == _TUESDAY + 60 * _DAY
    assert d["sg_pdpa"]["assessment_due_at"] == _TUESDAY + 30 * _DAY
    # Sorted by soonest authority clock first.
    assert plan["obligations"][0]["regime"] in {"eu_gdpr", "kr_pipa"}


def test_business_days_skip_weekends_both_directions():
    tuesday = bn.assess_breach(["br_lgpd"], discovered_at=_TUESDAY)
    due = tuesday["obligations"][0]["authority_due_at"]
    assert _day_name(due) == "Fri" and due == _TUESDAY + 3 * _DAY
    friday = bn.assess_breach(["br_lgpd"], discovered_at=_TUESDAY + 3 * _DAY)
    due = friday["obligations"][0]["authority_due_at"]
    assert _day_name(due) == "Wed" and due == _TUESDAY + 8 * _DAY


def test_japan_malicious_branch_extends_to_sixty_days():
    calm = bn.assess_breach(["jp_appi"], discovered_at=_TUESDAY)
    attacked = bn.assess_breach(
        ["jp_appi"], malicious=True, discovered_at=_TUESDAY)
    assert calm["obligations"][0]["authority_due_at"] == _TUESDAY + 30 * _DAY
    assert attacked["obligations"][0]["authority_due_at"] == _TUESDAY + 60 * _DAY


def test_determination_anchor_moves_the_clock():
    plan = bn.assess_breach(
        ["us_tx"], discovered_at=_TUESDAY, determined_at=_TUESDAY + 5 * _DAY,
    )
    assert plan["obligations"][0]["authority_due_at"] == _TUESDAY + 35 * _DAY
    with pytest.raises(ValueError, match="precede"):
        bn.assess_breach(["us_tx"], discovered_at=_TUESDAY,
                         determined_at=_TUESDAY - 1)


def test_thresholds_annotate_instead_of_dropping():
    plan = bn.assess_breach(
        ["us_tx"], subjects_affected=10, discovered_at=_TUESDAY)
    row = plan["obligations"][0]
    assert row["authority_below_threshold"] is True
    assert "250" in row["threshold_note"]
    unknown_count = bn.assess_breach(["us_tx"], discovered_at=_TUESDAY)
    unknown_row = unknown_count["obligations"][0]
    assert unknown_count["subjects_affected"] is None
    assert unknown_row["authority_below_threshold"] is None
    assert "count not provided" in unknown_row["threshold_note"]
    zero_count = bn.assess_breach(
        ["us_tx"], subjects_affected=0, discovered_at=_TUESDAY)
    assert zero_count["obligations"][0]["authority_below_threshold"] is True


def test_cli_omitted_count_stays_unknown():
    from click.testing import CliRunner
    from maverick.cli import main

    runner = CliRunner()
    unknown = runner.invoke(main, ["breach", "plan", "--jurisdiction", "us_ca"])
    assert unknown.exit_code == 0, unknown.output
    assert "count not provided" in unknown.output
    zero = runner.invoke(main, ["breach", "plan", "--jurisdiction", "us_ca",
                                "--subjects", "0"])
    assert zero.exit_code == 0, zero.output
    assert "Reported subject count (0) is below" in zero.output


def test_qualitative_standards_carry_the_statutes_words():
    plan = bn.assess_breach(["us_ca", "ca_pipeda"], discovered_at=_TUESDAY)
    d = {o["regime"]: o for o in plan["obligations"]}
    assert d["us_ca"]["authority_due_at"] is None
    assert "expedient" in d["us_ca"]["subjects_deadline"]["text"]
    assert d["ca_pipeda"]["records_duty"].startswith("Keep records")


def test_unknown_regimes_are_refused_naming_the_absent_set():
    with pytest.raises(ValueError) as excinfo:
        bn.assess_breach(["in_dpdp"], discovered_at=_TUESDAY)
    assert "Absent by design" in str(excinfo.value)
    assert "qc_law25" in str(excinfo.value)


def test_notification_contents_where_the_statute_enumerates_them():
    plan = bn.assess_breach(
        ["eu_gdpr", "us_hipaa", "us_ca", "br_lgpd"], discovered_at=_TUESDAY)
    d = {o["regime"]: o for o in plan["obligations"]}
    gdpr = d["eu_gdpr"]["notification_contents"]
    assert gdpr["basis"] == "GDPR Art. 33(3)" and len(gdpr["elements"]) == 4
    hipaa = d["us_hipaa"]["notification_contents"]
    assert hipaa["basis"].startswith("45 CFR") and len(hipaa["elements"]) == 5
    ca = d["us_ca"]["notification_contents"]
    assert "Notice of Data Breach" in ca["elements"][0]
    # Regimes without an encoded checklist say so instead of guessing.
    assert d["br_lgpd"]["notification_contents"] is None


def test_verified_at_feeds_the_freshness_ratchet():
    import datetime

    from maverick import deprecations

    # Fresh today: nothing stale.
    assert deprecations.stale_verified_content() == []
    # Push "now" past the cap: the matrix must show up by name.
    anchor = datetime.datetime.strptime(
        bn.VERIFIED_AT, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
    future = anchor.timestamp() + (
        deprecations.VERIFIED_CONTENT_MAX_AGE_DAYS + 2) * 86_400
    stale = deprecations.stale_verified_content(now=future)
    assert [row[0] for row in stale] == ["maverick.breach_notification"]


def test_quebec_law25_is_verified_and_standard_based():
    """Added only after the regulator's own guidance was read: the CAI
    fixes no clock, so no clock is invented."""
    plan = bn.assess_breach(
        jurisdictions=["ca_quebec"], subjects_affected=10,
        discovered_at=1_700_000_000.0)
    entry = plan["obligations"][0]
    assert entry["authority"].startswith("Commission")
    assert entry["authority_due_at"] is None      # no invented deadline
    assert entry["subjects_due_at"] is None
    assert "five years" in entry["records_duty"].lower()
    assert any("CAI guidance" in c for c in entry["citations"])


def test_brazil_business_days_skip_verified_national_holidays():
    """LGPD counts business days; a computed date must step over Brazil's
    fixed national holidays, not just weekends."""
    import datetime

    # Thursday 2026-12-24 09:00Z; 25 Dec is a feriado nacional.
    discovered = datetime.datetime(
        2026, 12, 24, 9, 0, tzinfo=datetime.timezone.utc).timestamp()
    plan = bn.assess_breach(
        jurisdictions=["br_lgpd"], subjects_affected=10,
        discovered_at=discovered)
    entry = plan["obligations"][0]
    due = datetime.datetime.fromtimestamp(
        entry["authority_due_at"], tz=datetime.timezone.utc)
    assert entry["holiday_calendar"] == "BR"
    assert due.strftime("%Y-%m-%d") == "2026-12-30"
    # Weekends-only math would have said the 29th.
    assert bn._add_business_days(discovered, 3) < entry["authority_due_at"]
    assert "at or before the true deadline" in plan["business_day_note"]


def test_unmodelled_calendars_fall_back_to_weekends_only():
    assert bn._is_working_day(
        __import__("datetime").datetime(
            2026, 12, 25, 12, 0,
            tzinfo=__import__("datetime").timezone.utc).timestamp(), "") is True
    assert bn._is_working_day(
        __import__("datetime").datetime(
            2026, 12, 25, 12, 0,
            tzinfo=__import__("datetime").timezone.utc).timestamp(), "BR") is False
