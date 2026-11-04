"""Times people see go through the shared client formatter.

``lightwork-ui.js`` writes every ``data-mv-time`` in the reader's own style
(their browser's regional setting and time zone). A date the server wrote out
itself stayed in one fixed style ("4 Oct 2026", or a raw "2026-10-04"), so a
US reader saw two styles on one page. Deadlines that are calendar days carry
the day itself, so no time zone can move them.
"""
from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    for name in ("MAVERICK_ENTERPRISE", "MAVERICK_DASHBOARD_TOKEN",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text(
        "[privacy_ops]\nenable = true\n\n[dsar_fulfillment]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _main(html: str) -> str:
    return html[html.index("<main"):html.index("</main>")]


def _visible(html: str) -> str:
    """Text a reader sees: no tags, attributes, scripts or styles."""
    html = re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.DOTALL)
    return re.sub(r"<[^>]+>", " ", html)


def _calendar_day(html: str, day: str) -> bool:
    return f'<time datetime="{day}" data-mv-time="{day}" data-mv-time-mode="date">' in html


def test_request_dates_and_deadlines_read_in_the_readers_style():
    from maverick import privacy_ops

    request = privacy_ops.open_dsar("max@example.com", "access", opened_by="ops")
    record = privacy_ops.get_dsar(request["id"])
    due = time.strftime("%Y-%m-%d", time.gmtime(privacy_ops.dsar_clock(record)["effective_due_at"]))
    today = time.strftime("%Y-%m-%d", time.gmtime())
    privacy_ops.close_dsar(request["id"], closed_by="ops", outcome={
        "kind": "answered", "answered_on": today, "reference": "CRM ticket 77"})
    main = _main(client.get(f"/privacy/dsar/{request['id']}").text)
    assert re.search(r'Opened <time datetime="[^"]+" data-mv-time="[\d.]+" data-mv-time-mode="date">', main)
    assert _calendar_day(main, due)      # the answer deadline stays its calendar day
    assert _calendar_day(main, today)    # "Answered on" too
    # No date is left for the server's own fixed style or as a raw ISO string.
    visible = _visible(main)
    assert not re.search(r"\b\d{4}-\d{2}-\d{2}\b", visible), visible


def test_privacy_register_rows_show_created_dates_through_the_formatter():
    from maverick import privacy_ops

    privacy_ops.review_dpa("Acme Corp", "audit rights and retention only")
    page = client.get("/privacy")
    assert page.status_code == 200
    assert "Acme Corp" in page.text
    assert re.search(r'<td[^>]*>\s*<time datetime="[^"]+" data-mv-time="[\d.]+" data-mv-time-mode="date">',
                     page.text)
    unformatted = re.findall(r"<td[^>]*>\s*\d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sept?|Oct|Nov|Dec) \d{4}\s*</td>",
                             page.text)
    assert not unformatted, unformatted
