"""Per-jurisdiction rights-request clocks, table-driven against the cited law.

Every expected number below is the one written in the statute or regulator
page named in ``REGIMES[...]["source"]``; a row without a fetched source is
deliberately absent from the table (see ``UNVERIFIED``), never guessed.
"""
from __future__ import annotations

import calendar
import datetime as dt

import pytest
from maverick import rights_deadlines as rd

_DAY = 86_400.0
# Tuesday 2026-10-06 00:00 UTC -- a weekday, so business-day maths is visible.
_TUESDAY = calendar.timegm((2026, 10, 6, 0, 0, 0))
# Friday 2026-10-09: 10 business days from here must skip two weekends.
_FRIDAY = calendar.timegm((2026, 10, 9, 0, 0, 0))


def _date(stamp: float) -> str:
    return dt.datetime.fromtimestamp(stamp, tz=dt.timezone.utc).strftime("%Y-%m-%d")


def test_every_regime_cites_a_fetched_source_and_verification_date():
    for regime_id, regime in rd.REGIMES.items():
        assert regime["source"].startswith("http"), regime_id
        assert regime["verified_at"] == rd.VERIFIED_AT, regime_id
        assert regime["citation"], regime_id
        assert regime["family"] in rd.FAMILIES, regime_id
        assert set(regime["rights"]) <= set(rd.REQUEST_TYPES), regime_id


def test_unverified_regimes_are_listed_not_computed():
    assert "ca_quebec" in rd.UNVERIFIED
    assert "sg_pdpa" in rd.UNVERIFIED
    assert not set(rd.UNVERIFIED) & set(rd.REGIMES)
    for entry in rd.UNVERIFIED.values():
        assert entry["attempted_sources"]


@pytest.mark.parametrize(("regime", "kind", "days", "ext_days"), [
    # Cal. Civ. Code 1798.130(a)(2)(A): 45 days, extendable once by 45.
    ("us_ca_ccpa", "access", 45, 45),
    ("us_ca_ccpa", "deletion", 45, 45),
    # Va. Code 59.1-577(B)(1); C.R.S. 6-1-1306(2)(a); Conn. AG summary of
    # 42-522(b); Utah 13-61-203; Tex. Bus. & Com. 541.052(b); ORS 646A.576(5)(a).
    ("us_va", "access", 45, 45),
    ("us_co", "deletion", 45, 45),
    ("us_ct", "correction", 45, 45),
    ("us_ut", "access", 45, 45),
    ("us_tx", "portability", 45, 45),
    ("us_or", "access", 45, 45),
    # PIPEDA s. 8(3)-(4): 30 days, extendable by a maximum of 30 more.
    ("ca_pipeda", "access", 30, 30),
    # LGPD Art. 19 II: complete declaration within 15 days; no extension.
    ("br_lgpd", "access", 15, 0),
    # OAIC APP 12 guidance: reasonable period should not exceed 30 days.
    ("au_privacy", "access", 30, 0),
])
def test_calendar_day_regimes(regime, kind, days, ext_days):
    clock = rd.compute_clock(regime, kind, _TUESDAY)
    assert clock["due_at"] == _TUESDAY + days * _DAY
    assert clock["due_basis"] in ("statutory", "regulator_guidance")
    assert clock["extension_max_days"] == ext_days
    assert clock["jurisdiction"] == regime


@pytest.mark.parametrize("regime", ["eu_gdpr", "uk_gdpr"])
def test_gdpr_one_month_is_a_calendar_month(regime):
    # GDPR Art. 12(3) / UK GDPR Art. 12A(1): "one month" -- the same date
    # next month, not 30 days.
    jan_31 = calendar.timegm((2027, 1, 31, 9, 0, 0))
    clock = rd.compute_clock(regime, "access", jan_31)
    # February 2027 has 28 days: the corresponding date is the month's end.
    assert _date(clock["due_at"]) == "2027-02-28"
    mar_15 = calendar.timegm((2027, 3, 15, 9, 0, 0))
    assert _date(rd.compute_clock(regime, "erasure", mar_15)["due_at"]) == "2027-04-15"
    # Extension: "two further months", notice before the first month ends.
    assert clock["extension_max_days"] is None
    assert clock["extension_months"] == 2
    assert clock["extension_notice_by"] == clock["due_at"]


def test_ccpa_acknowledgement_and_opt_out_use_business_days():
    # 11 CCR 7021(a): confirm receipt within 10 business days.
    clock = rd.compute_clock("us_ca_ccpa", "access", _FRIDAY)
    # Fri 9 Oct -> 10 business days -> Fri 23 Oct (two weekends skipped).
    assert _date(clock["acknowledge_by"]) == "2026-10-23"
    # 11 CCR 7026(f)(1): opt-out honoured no later than 15 business days.
    opt_out = rd.compute_clock("us_ca_ccpa", "opt_out", _FRIDAY)
    assert _date(opt_out["due_at"]) == "2026-10-30"
    assert opt_out["extension_max_days"] == 0


def test_no_fixed_period_regimes_fall_back_to_an_internal_target():
    # APPI Art. 28(2) (June 2020 PPC translation): "without delay".
    clock = rd.compute_clock("jp_appi", "access", _TUESDAY, internal_target_days=20)
    assert clock["due_basis"] == "internal_target"
    assert clock["due_at"] == _TUESDAY + 20 * _DAY
    assert clock["extension_max_days"] == 0
    assert "without delay" in clock["statutory_text"]


def test_rights_not_granted_by_a_regime_are_refused():
    with pytest.raises(ValueError):
        rd.compute_clock("eu_gdpr", "opt_out", _TUESDAY)
    with pytest.raises(ValueError):
        rd.compute_clock("us_va", "restriction", _TUESDAY)
    with pytest.raises(KeyError):
        rd.compute_clock("ca_quebec", "access", _TUESDAY)


def test_extension_rules():
    ccpa = rd.compute_clock("us_ca_ccpa", "access", _TUESDAY)
    # Notice must land inside the first 45 days; total cannot exceed 90.
    ext = rd.extension_for(ccpa, days=45, now=_TUESDAY + 10 * _DAY)
    assert ext["extended_until"] == _TUESDAY + 90 * _DAY
    with pytest.raises(ValueError):
        rd.extension_for(ccpa, days=46, now=_TUESDAY + 10 * _DAY)
    with pytest.raises(ValueError):
        rd.extension_for(ccpa, days=45, now=_TUESDAY + 46 * _DAY)
    lgpd = rd.compute_clock("br_lgpd", "access", _TUESDAY)
    with pytest.raises(ValueError):
        rd.extension_for(lgpd, days=5, now=_TUESDAY)
    gdpr = rd.compute_clock("eu_gdpr", "access", _TUESDAY)
    ext = rd.extension_for(gdpr, days=None, now=_TUESDAY + _DAY)
    assert _date(ext["extended_until"]) == _date(rd.add_months(_TUESDAY, 3))


def test_form_choices_expose_only_granted_rights():
    choices = {row["id"]: row for row in rd.form_choices()}
    assert "opt_out" in choices["us_ca_ccpa"]["rights"]
    assert "opt_out" not in choices["eu_gdpr"]["rights"]
    assert "ca_quebec" not in choices
