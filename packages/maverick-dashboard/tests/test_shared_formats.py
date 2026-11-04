"""One date format and one money format on every page.

Dates on pages go through the shared ``|datetime`` filter (or
``mvTimeAbsolute``/``mvDateAbsolute`` in scripts), which the browser rewrites
in the viewer's zone as "Oct 6, 2026, 1:46 PM UTC"; money goes through
``|money`` or ``mvMoney`` ("$75.00", "EUR 75.00"). The print reports, the audit
binder, the audit checkpoint days, the performance table and the savings
basis used their own formats; this keeps them on the shared ones.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


def _read(name: str) -> str:
    return (PACKAGE / name).read_text(encoding="utf-8")


def test_no_template_formats_dates_itself():
    found = [path.name for path in (PACKAGE / "templates").glob("*.html") if "strftime(" in path.read_text(encoding="utf-8")]
    assert found == []


@pytest.mark.parametrize(("template", "stamp"), [
    ("templates/privacy_report.html", "r.generated_at | datetime('absolute')"),
    ("templates/security_report.html", "r.generated_at | datetime('absolute')"),
    ("templates/audit_binder.html", "b.generated_at | datetime('absolute')"),
    ("templates/audit_binder.html", "f.day | datetime('date')"),
])
def test_reports_say_when_in_the_shared_date_format(template, stamp):
    source = _read(template)
    assert stamp in source
    assert "r.generated }}" not in source and "{{ generated }}" not in source and "'generated'" not in source


def test_script_tables_show_days_in_the_shared_date_format():
    assert "mvDateAbsolute(d.day)" in _read("static/lightwork-insights-ops.js")
    panels = _read("static/lightwork-ops-panels.js")
    assert "function dayText(day)" in panels and "el('option', null, d.day" not in panels


def test_the_savings_basis_shows_the_hourly_cost_as_money():
    source = _read("templates/savings.html")
    assert not re.search(r"\{\{\s*cfg\.currency\s*\}\}\s*\{\{\s*cfg\.hourly_rate\s*\}\}", source)
    assert "{{ cfg.hourly_rate | money(currency=cfg.currency) }} an hour, minus what" in source
