"""Template runtime can be used without constructing the dashboard app."""
from __future__ import annotations

from maverick_dashboard.template_runtime import _format_datetime


def test_date_filter_preserves_calendar_dates_and_escapes_the_mode():
    date = str(_format_datetime("2026-10-04", "date"))
    assert 'datetime="2026-10-04"' in date
    assert ">4 Oct 2026</time>" in date
    rendered = str(_format_datetime(1791122472, 'relative" onmouseover="bad'))
    assert 'onmouseover="bad' not in rendered
    assert "&#34;" in rendered


def test_date_filter_returns_unparseable_values_for_template_autoescaping():
    assert _format_datetime(None) == "-"
    assert _format_datetime("unknown") == "unknown"
