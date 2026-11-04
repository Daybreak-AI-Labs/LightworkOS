"""The activity log shows 50 entries at a time with one disclosure each.

It rendered 200 rows with two "details" disclosures apiece (405 KB of HTML,
5,742 elements, 0.7 s of blocked main thread on a phone), and the
disclosure labels were 20 px tall, under the 24 px target size. The page now
starts at 50 rows, keeps every filter in the address of its "Show older
activity" link, and folds each row's technical identifiers and protection
fingerprints into one disclosure. Downloads are separate and unaffected.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

TEMPLATE = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "audit.html"


@pytest.fixture
def client(monkeypatch, tmp_path):
    import maverick.audit as audit
    from maverick.audit import reader
    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    log = AuditLog(tmp_path / "audit", sign=True)  # signed: rows carry fingerprints
    monkeypatch.setattr(audit, "default_audit_log", lambda: log)
    monkeypatch.setattr(reader, "resolve_audit_dir", lambda tenant: log.audit_dir)
    start = time.time() - 120
    for index in range(60):
        log.record(AuditEvent(ts=start + index, kind="setting_changed",
                              payload={"section": "features", "key": f"setting{index:02d}", "event_id": f"{index:032x}"}))
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _rows(page):
    table = page[page.index('<table id="audit-table">'):]
    body = table[table.index("<tbody>"):table.index("</tbody>")]
    return re.findall(r"<tr>(.*?)</tr>", body, re.DOTALL)


def _older_link(page):
    match = re.search(r'<a class="btn" href="([^"]+)">Show older activity</a>', page)
    return match and match.group(1).replace("&amp;", "&")


def _settings(rows):
    """The seeded entries on a page (the app records a few of its own)."""
    return [key for row in rows for key in re.findall(r"setting\d\d", row)]


def test_first_page_shows_fifty_rows_with_one_disclosure_each(client):
    page = client.get("/audit").text
    rows = _rows(page)
    assert len(rows) == 50
    for row in rows:
        assert row.count("<details") <= 1
    seeded = [row for row in rows if _settings([row])]
    assert len(seeded) >= 45
    for row in seeded:
        assert row.count("<details") == 1
        assert "<summary>Technical details</summary>" in row
        assert "Event ID" in row
        if "Fingerprint" in row:
            assert "How this entry is protected" in row
    # Identifiers and fingerprints now share the one disclosure.
    assert sum("Event ID" in row and "Fingerprint" in row for row in seeded) >= 45
    assert "setting59" in page and "setting00" not in page  # newest first
    assert '<option value="50" selected>50 entries</option>' in page


def test_show_older_continues_after_the_table_and_returns_to_the_newest(client):
    page = client.get("/audit").text
    older = _older_link(page)
    assert older is not None
    assert page.index("Show older activity") > page.index("</table>")  # where the reading ends
    query = parse_qs(urlparse(older).query)
    assert query["before_event"] and query["day"]
    second = client.get(older).text
    first_keys, second_keys = _settings(_rows(page)), _settings(_rows(second))
    assert "setting00" in second_keys and not set(first_keys) & set(second_keys)
    assert len(first_keys) + len(second_keys) == 60  # every entry, once
    assert _older_link(second) is None
    assert re.search(r'<a class="btn btn--ghost" href="/audit\?day=[0-9-]+">Newest activity</a>', second)


def test_show_older_keeps_every_filter_in_the_address(client):
    page = client.get("/audit", params={"q": "features", "order": "oldest", "person": ""}).text
    query = parse_qs(urlparse(_older_link(page)).query, keep_blank_values=True)
    assert query["q"] == ["features"] and query["order"] == ["oldest"] and query["person"] == [""]
    filtered = client.get(_older_link(page)).text
    assert set(_settings(_rows(filtered))) <= {f"setting{index:02d}" for index in range(10)}
    bigger = client.get("/audit", params={"n": "200"}).text
    assert len(_settings(_rows(bigger))) == 60 and _older_link(bigger) is None  # a larger page still works


def test_disclosure_labels_meet_the_target_size():
    style = TEMPLATE.read_text(encoding="utf-8").split("<style>", 1)[1].split("</style>", 1)[0]
    rule = re.search(r"\.aud-sig summary\s*\{([^}]*)\}", style).group(1)
    assert "min-height: 24px" in rule
