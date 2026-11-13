"""Deterministic regulatory-change feed ingestion and review queue."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from maverick.finance.regulatory_change import (
    FeedFetchError,
    FeedParseError,
    FeedSource,
    RegulatoryChangeEngine,
    ScopeRule,
    fetch_and_ingest,
    fetch_feed,
)
from maverick.privacy_ops import RecordConflict

_FETCHED_AT = "2026-07-22T12:00:00Z"


def _engine(tmp_path):
    return RegulatoryChangeEngine(
        tmp_path / "regulatory-change.sqlite3",
        scope_rules=(
            ScopeRule("dora", "regime", ("digital operational resilience", "dora")),
            ScopeRule("money_transmitter", "domain", ("money transmitter",)),
            ScopeRule("insurance", "domain", ("insurance producer",)),
        ),
    )


def test_federal_register_ingestion_is_idempotent_and_cited(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource.federal_register()
    payload = json.dumps({
        "results": [{
            "document_number": "2026-12345",
            "title": "Money Transmitter Recordkeeping Rule",
            "abstract": "A proposed rule for money transmitter records.",
            "publication_date": "2026-07-22",
            "html_url": "https://www.federalregister.gov/documents/2026/07/22/2026-12345/example",
            "citation": "91 FR 12345",
            "agencies": [{"name": "Financial Crimes Enforcement Network"}],
            "topics": ["Money Services Businesses"],
        }],
    }).encode()

    first = engine.ingest(
        source,
        payload,
        enabled_domains={"money_transmitter"},
        fetched_at=_FETCHED_AT,
    )
    second = engine.ingest(
        source,
        payload,
        enabled_domains={"money_transmitter"},
        fetched_at="2026-07-22T12:05:00Z",
    )

    assert first.items_seen == 1
    assert first.versions_created == 1
    assert first.alerts_created == 1
    assert second.versions_created == 0
    assert second.alerts_created == 0
    assert second.unchanged == 1

    [alert] = engine.list_alerts()
    assert alert.change_kind == "new"
    assert alert.matched_domains == ("money_transmitter",)
    assert alert.official_citation == "91 FR 12345"
    assert alert.citations[0].url.startswith("https://www.federalregister.gov/documents/")
    assert alert.citations[0].feed_url == source.url
    assert len(alert.citations[0].content_sha256) == 64
    assert len(alert.citations[0].payload_sha256) == 64
    assert len(alert.citations[0].source_record_sha256) == 64
    assert alert.citations[0].acquisition == "operator_supplied"
    assert alert.citations[0].retrieval_url == (
        "urn:lightwork:regulatory-acquisition:operator-supplied"
    )
    assert engine.get_alert(alert.alert_id) == alert
    assert engine.get_alert("missing") is None


def test_changed_item_gets_version_and_field_diff(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="ny-register",
        name="New York State Register fixture",
        jurisdiction="US-NY",
        url="https://dos.ny.gov/state-register",
        format="json",
        default_domains=("insurance",),
    )
    initial = {"items": [{
        "id": "rule-7",
        "title": "Insurance producer renewal rule",
        "summary": "Comment period remains open.",
        "published_at": "2026-07-01",
        "url": "https://dos.ny.gov/rule-7",
        "citation": "NY Register rule 7",
    }]}
    changed = json.loads(json.dumps(initial))
    changed["items"][0]["summary"] = "Final rule adopted."

    engine.ingest(source, json.dumps(initial).encode(), enabled_domains={"insurance"},
                  fetched_at=_FETCHED_AT)
    result = engine.ingest(source, json.dumps(changed).encode(),
                           enabled_domains={"insurance"},
                           fetched_at="2026-07-23T12:00:00Z")

    assert result.versions_created == 1
    assert result.alerts_created == 1
    alerts = engine.list_alerts()
    assert [a.change_kind for a in alerts] == ["updated", "new"]
    assert alerts[0].diff == {
        "summary": {"before": "Comment period remains open.",
                    "after": "Final rule adopted."},
    }
    versions = engine.document_versions("ny-register", "rule-7")
    assert [v.version for v in versions] == [1, 2]


def test_source_digest_versions_changes_beyond_normalized_summary_limit(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="long-json", name="Long JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
        default_domains=("insurance",),
    )
    common_prefix = "x" * 100_000
    initial = {"items": [{
        "id": "long-1", "title": "Insurance producer update",
        "summary": common_prefix + "first source suffix",
        "url": "https://example.gov/long-1",
    }]}
    changed = json.loads(json.dumps(initial))
    changed["items"][0]["summary"] = common_prefix + "second source suffix"

    engine.ingest(source, json.dumps(initial), enabled_domains={"insurance"},
                  fetched_at=_FETCHED_AT)
    result = engine.ingest(source, json.dumps(changed), enabled_domains={"insurance"},
                           fetched_at="2026-07-23T12:00:00Z")

    assert result.versions_created == 1
    assert result.alerts_created == 1
    versions = engine.document_versions("long-json", "long-1")
    assert len(versions) == 2
    assert versions[0].document.summary == versions[1].document.summary
    assert versions[0].content_sha256 != versions[1].content_sha256
    assert (
        versions[0].document.source_record_sha256
        != versions[1].document.source_record_sha256
    )
    updated_alert = engine.list_alerts()[0]
    assert (
        updated_alert.citations[0].source_record_sha256
        == versions[1].document.source_record_sha256
    )
    publisher_diff = updated_alert.diff["_publisher_record"]
    assert publisher_diff["changed_paths"] == ["/summary"]
    assert publisher_diff["paths_available"] is True
    assert publisher_diff["canonical_snapshots_retained"] is True
    assert "first source suffix" in versions[0].document.source_record_snapshot
    assert "second source suffix" in versions[1].document.source_record_snapshot


def test_source_digest_versions_unmapped_publisher_field_changes(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="publisher-json", name="Publisher JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
        default_domains=("insurance",),
    )
    initial = {"items": [{
        "id": "publisher-1", "title": "Insurance producer update",
        "summary": "No normalized field changed.",
        "url": "https://example.gov/publisher-1",
        "publisher_workflow_state": "draft",
    }]}
    changed = json.loads(json.dumps(initial))
    changed["items"][0]["publisher_workflow_state"] = "final"

    engine.ingest(source, json.dumps(initial), enabled_domains={"insurance"},
                  fetched_at=_FETCHED_AT)
    reordered = {"items": [dict(reversed(list(initial["items"][0].items())))]}
    canonical_replay = engine.ingest(
        source,
        json.dumps(reordered),
        enabled_domains={"insurance"},
        fetched_at="2026-07-22T13:00:00Z",
    )
    result = engine.ingest(source, json.dumps(changed), enabled_domains={"insurance"},
                           fetched_at="2026-07-23T12:00:00Z")

    assert canonical_replay.versions_created == 0
    assert result.versions_created == 1
    versions = engine.document_versions("publisher-json", "publisher-1")
    assert len(versions) == 2
    assert versions[0].content_sha256 != versions[1].content_sha256
    assert (
        versions[0].document.source_record_sha256
        != versions[1].document.source_record_sha256
    )
    publisher_diff = engine.list_alerts()[0].diff["_publisher_record"]
    assert publisher_diff["changed_paths"] == ["/publisher_workflow_state"]
    assert publisher_diff["paths_available"] is True
    assert '"publisher_workflow_state":"draft"' in (
        versions[0].document.source_record_snapshot
    )


def test_source_digest_covers_unmapped_xml_fields_and_attributes(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="publisher-rss", name="Publisher RSS", jurisdiction="US",
        url="https://example.gov/feed.xml", format="rss",
        default_domains=("insurance",),
    )
    initial = b"""<rss><channel><item workflow='draft'>
      <guid>xml-1</guid><title>Insurance producer update</title>
      <description>No normalized field changed.</description>
      <link>https://example.gov/xml-1</link>
      <publisherMetadata stage='proposal'>internal note</publisherMetadata>
      </item></channel></rss>"""
    changed = initial.replace(b"stage='proposal'", b"stage='final'")

    engine.ingest(source, initial, enabled_domains={"insurance"},
                  fetched_at=_FETCHED_AT)
    result = engine.ingest(source, changed, enabled_domains={"insurance"},
                           fetched_at="2026-07-23T12:00:00Z")

    assert result.versions_created == 1
    versions = engine.document_versions("publisher-rss", "xml-1")
    assert len(versions) == 2
    assert versions[0].content_sha256 != versions[1].content_sha256
    assert (
        versions[0].document.source_record_sha256
        != versions[1].document.source_record_sha256
    )
    publisher_diff = engine.list_alerts()[0].diff["_publisher_record"]
    assert publisher_diff["changed_paths"] == []
    assert publisher_diff["paths_available"] is False
    assert "stage=\"proposal\"" in versions[0].document.source_record_snapshot


def test_sqlite_connections_release_database_for_windows_cleanup():
    directory: str
    with TemporaryDirectory() as directory:
        db_path = Path(directory) / "regulatory-change.sqlite3"
        engine = RegulatoryChangeEngine(db_path)
        source = FeedSource(
            key="cleanup", name="Cleanup", jurisdiction="US",
            url="https://example.gov/feed.json", format="json",
            default_domains=("insurance_producer",),
        )
        payload = json.dumps({"items": [{
            "id": "cleanup-1", "title": "Insurance producer update",
            "url": "https://example.gov/cleanup-1",
        }]})
        engine.ingest(source, payload, enabled_domains={"insurance_producer"},
                      fetched_at=_FETCHED_AT)
        [alert] = engine.list_alerts()
        assert engine.get_alert(alert.alert_id) == alert
        assert engine.document_versions("cleanup", "cleanup-1")
        engine.disposition_alert(
            alert.alert_id,
            status="accepted",
            reviewer="cleanup@example.com",
            expected_revision=alert.revision,
        )
        assert engine.alert_review_history(alert.alert_id)

    # Windows refuses to remove a directory containing an open SQLite handle.
    assert not Path(directory).exists()


def test_disabled_scope_is_stored_but_not_queued_then_can_be_enabled(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="state-atom",
        name="State register fixture",
        jurisdiction="US-CA",
        url="https://oal.ca.gov/register/feed.atom",
        format="atom",
        default_regimes=("dora",),
    )
    atom = b"""<?xml version='1.0'?>
      <feed xmlns='http://www.w3.org/2005/Atom'>
        <entry><id>tag:example,2026:1</id><title>Digital operational resilience</title>
        <summary>Reporting change</summary><updated>2026-07-22T00:00:00Z</updated>
        <link href='https://oal.ca.gov/register/1'/></entry>
      </feed>"""

    disabled = engine.ingest(source, atom, fetched_at=_FETCHED_AT)
    enabled = engine.ingest(source, atom, enabled_regimes={"dora"},
                            fetched_at="2026-07-22T13:00:00Z")

    assert disabled.versions_created == 1
    assert disabled.alerts_created == 0
    assert enabled.versions_created == 0
    assert enabled.alerts_created == 1
    assert engine.list_alerts()[0].matched_regimes == ("dora",)


def test_rss_and_configured_json_field_map_are_normalized(tmp_path):
    engine = _engine(tmp_path)
    rss_source = FeedSource(
        key="tx-rss", name="Texas Register fixture", jurisdiction="US-TX",
        url="https://www.sos.state.tx.us/texreg/rss.xml", format="rss",
    )
    rss = b"""<rss><channel><item><guid>tx-1</guid>
      <title>Money transmitter rule</title><description>Notice</description>
      <pubDate>Wed, 22 Jul 2026 00:00:00 GMT</pubDate>
      <link>https://www.sos.state.tx.us/texreg/tx-1</link>
      <category>money transmitter</category></item></channel></rss>"""
    json_source = FeedSource(
        key="ma-json", name="Massachusetts Register fixture", jurisdiction="US-MA",
        url="https://www.mass.gov/regulations/feed.json", format="json",
        field_map={"items": "records", "id": "ruleId", "title": "heading",
                   "summary": "description", "url": "permalink",
                   "published_at": "issued"},
    )
    custom = {"records": [{"ruleId": "ma-1", "heading": "Insurance producer update",
                            "description": "Notice", "issued": "2026-07-22",
                            "permalink": "https://www.mass.gov/regulations/ma-1"}]}

    assert engine.ingest(rss_source, rss, enabled_domains={"money_transmitter"},
                         fetched_at=_FETCHED_AT).alerts_created == 1
    assert engine.ingest(json_source, json.dumps(custom).encode(),
                         enabled_domains={"insurance"},
                         fetched_at=_FETCHED_AT).alerts_created == 1
    assert {a.external_id for a in engine.list_alerts()} == {"tx-1", "ma-1"}


def test_builtin_texas_register_routes_issues_with_safe_https_citations(tmp_path):
    engine = RegulatoryChangeEngine(tmp_path / "texas.sqlite3")
    source = FeedSource.texas_register()
    payload = b"""<rss version='2.0'><channel>
      <title>Current Issue of the Texas Register</title>
      <item><title>HTML format</title>
        <link>http://www.sos.state.tx.us/texreg/archive/July172026/index.html</link>
        <description>Texas Register issue for July 17, 2026 in html format</description>
      </item>
      <item><title>All Texas Register issues available electronically</title>
        <link>http://texashistory.unt.edu/explore/collections/TR/</link>
        <description>Historical archive</description>
      </item>
    </channel></rss>"""

    result = engine.ingest(
        source,
        payload,
        enabled_domains={"finance"},
        fetched_at=_FETCHED_AT,
    )

    assert source.url == "https://www.sos.state.tx.us/texreg/texreg.xml"
    assert source.default_domains == ("finance",)
    assert result.items_seen == 2
    assert result.alerts_created == 2
    alerts = {alert.title: alert for alert in engine.list_alerts()}
    html = alerts["HTML format"]
    assert html.jurisdiction == "US-TX"
    assert html.matched_domains == ("finance",)
    assert html.record_url == (
        "https://www.sos.state.tx.us/texreg/archive/July172026/index.html"
    )
    assert html.citations[0].feed_url == source.url
    assert alerts["All Texas Register issues available electronically"].record_url == source.url


def test_scope_matching_is_token_bounded_not_substring(tmp_path):
    engine = RegulatoryChangeEngine(
        tmp_path / "q.sqlite3",
        scope_rules=(ScopeRule("pci", "regime", ("pci",)),),
    )
    source = FeedSource(
        key="json", name="JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
    )
    payload = json.dumps({"items": [{
        "id": "1", "title": "Municipal update", "summary": "No card rule",
        "url": "https://example.gov/1",
    }]}).encode()
    result = engine.ingest(source, payload, enabled_regimes={"pci"},
                           fetched_at=_FETCHED_AT)
    assert result.alerts_created == 0


def test_queue_disposition_is_auditable_and_validated(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="json", name="JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
        default_domains=("insurance",),
    )
    payload = json.dumps({"items": [{
        "id": "1", "title": "Insurance producer update", "summary": "Notice",
        "url": "https://example.gov/1",
    }]}).encode()
    engine.ingest(source, payload, enabled_domains={"insurance"},
                  fetched_at=_FETCHED_AT)
    [alert] = engine.list_alerts()

    reviewed = engine.disposition_alert(
        alert.alert_id, status="accepted", reviewer="compliance@example.com",
        note="Mapped to control FIN-42", reviewed_at="2026-07-22T14:00:00Z",
        expected_revision=alert.revision,
    )
    assert reviewed.status == "accepted"
    assert reviewed.revision == alert.revision + 1
    assert reviewed.reviewer == "compliance@example.com"
    [event] = engine.alert_review_history(alert.alert_id)
    assert event.from_status == "open"
    assert event.to_status == "accepted"
    assert event.note == "Mapped to control FIN-42"
    assert engine.list_alerts(status="open") == []
    with pytest.raises(ValueError, match="status"):
        engine.disposition_alert(
            alert.alert_id,
            status="deleted",
            reviewer="x",
            expected_revision=reviewed.revision,
        )


def test_alert_queue_has_exact_counts_and_cursor_traversal(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="json",
        name="JSON",
        jurisdiction="US",
        url="https://example.gov/feed.json",
        format="json",
        default_domains=("insurance",),
    )
    payload = json.dumps({
        "items": [
            {
                "id": f"page-{index}",
                "title": f"Insurance producer update {index}",
                "url": f"https://example.gov/page-{index}",
            }
            for index in range(3)
        ]
    }).encode()
    engine.ingest(
        source,
        payload,
        enabled_domains={"insurance"},
        fetched_at=_FETCHED_AT,
    )

    first = engine.list_alert_page(limit=2)
    assert first.has_more is True
    assert first.next_cursor
    assert len(first.alerts) == 2
    second = engine.list_alert_page(limit=2, cursor=first.next_cursor)
    assert second.has_more is False
    assert second.next_cursor == ""
    assert len(second.alerts) == 1
    assert {row.alert_id for row in first.alerts}.isdisjoint(
        row.alert_id for row in second.alerts
    )
    assert engine.alert_status_counts() == {"open": 3}

    with pytest.raises(ValueError, match="cursor"):
        engine.list_alert_page(cursor="not-a-valid-cursor")


def test_concurrent_review_uses_revision_cas(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="json", name="JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
        default_domains=("insurance",),
    )
    payload = json.dumps({"items": [{
        "id": "cas-1", "title": "Insurance producer update",
        "url": "https://example.gov/cas-1",
    }]}).encode()
    engine.ingest(source, payload, enabled_domains={"insurance"}, fetched_at=_FETCHED_AT)
    [alert] = engine.list_alerts()

    def decide(status):
        try:
            return engine.disposition_alert(
                alert.alert_id,
                status=status,
                reviewer=f"{status}@example.com",
                expected_revision=alert.revision,
            )
        except RecordConflict as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, ("accepted", "dismissed")))

    assert sum(isinstance(item, RecordConflict) for item in results) == 1
    [saved] = engine.list_alerts()
    assert saved.status in {"accepted", "dismissed"}
    assert saved.revision == alert.revision + 1
    assert len(engine.alert_review_history(alert.alert_id)) == 1


def test_new_scope_reopens_final_alert_and_records_history(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="json", name="JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
    )
    payload = json.dumps({"items": [{
        "id": "scope-1",
        "title": "DORA insurance producer update",
        "url": "https://example.gov/scope-1",
    }]}).encode()
    engine.ingest(source, payload, enabled_regimes={"dora"}, fetched_at=_FETCHED_AT)
    [alert] = engine.list_alerts()
    accepted = engine.disposition_alert(
        alert.alert_id,
        status="accepted",
        reviewer="reviewer@example.com",
        expected_revision=alert.revision,
    )

    replay = engine.ingest(
        source,
        payload,
        enabled_regimes={"dora"},
        enabled_domains={"insurance"},
        fetched_at="2026-07-22T15:00:00Z",
    )
    assert replay.versions_created == 0
    [reopened] = engine.list_alerts()
    assert reopened.status == "open"
    assert reopened.revision == accepted.revision + 1
    assert reopened.matched_regimes == ("dora",)
    assert reopened.matched_domains == ("insurance",)
    history = engine.alert_review_history(alert.alert_id)
    assert [(event.from_status, event.to_status) for event in history] == [
        ("open", "accepted"),
        ("accepted", "open"),
    ]
    assert "scope_set_changed" in history[-1].note


def test_disabled_scopes_are_removed_and_alert_is_system_dismissed(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="json",
        name="JSON",
        jurisdiction="US",
        url="https://example.gov/feed.json",
        format="json",
    )
    payload = json.dumps({"items": [{
        "id": "scope-removal-1",
        "title": "DORA insurance producer update",
        "url": "https://example.gov/scope-removal-1",
    }]}).encode()
    engine.ingest(
        source,
        payload,
        enabled_regimes={"dora"},
        enabled_domains={"insurance"},
        fetched_at=_FETCHED_AT,
    )
    [alert] = engine.list_alerts()

    replay = engine.ingest(
        source,
        payload,
        enabled_regimes=set(),
        enabled_domains=set(),
        fetched_at="2026-07-22T16:00:00Z",
    )

    assert replay.unmatched == 1
    [dismissed] = engine.list_alerts()
    assert dismissed.status == "inactive"
    assert dismissed.matched_regimes == ()
    assert dismissed.matched_domains == ()
    assert dismissed.reviewer == "system:scope-change"
    assert dismissed.revision == alert.revision + 1
    [event] = engine.alert_review_history(alert.alert_id)
    note = json.loads(event.note)
    assert event.from_status == "open"
    assert event.to_status == "inactive"
    assert note["removed_regimes"] == ["dora"]
    assert note["removed_domains"] == ["insurance"]


def test_parser_rejects_unsafe_or_uncited_input(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="bad", name="Bad", jurisdiction="US",
        url="https://example.gov/feed.xml", format="rss",
    )
    with pytest.raises(FeedParseError, match="DTD"):
        engine.ingest(source, b"<!DOCTYPE rss><rss/>", fetched_at=_FETCHED_AT)
    # The refusal must not depend on the payload encoding: UTF-16 carries no
    # ASCII "<!DOCTYPE" byte run, and its entity would otherwise be expanded.
    utf16 = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!DOCTYPE rss [<!ENTITY a "expanded">]>'
        "<rss><channel><item><guid>1</guid><title>&a;</title></item></channel></rss>"
    ).encode("utf-16")
    with pytest.raises(FeedParseError, match="DTD"):
        engine.ingest(source, utf16, fetched_at=_FETCHED_AT)

    json_source = FeedSource(
        key="strict-json",
        name="Strict JSON",
        jurisdiction="US",
        url="https://example.gov/feed.json",
        format="json",
    )
    with pytest.raises(FeedParseError, match="duplicate object key"):
        engine.ingest(
            json_source,
            b'{"items":[{"id":"one","id":"two","title":"duplicate"}]}',
            fetched_at=_FETCHED_AT,
        )
    with pytest.raises(FeedParseError, match="non-finite"):
        engine.ingest(
            json_source,
            b'{"items":[{"id":"one","title":"bad","value":NaN}]}',
            fetched_at=_FETCHED_AT,
        )

    no_url = FeedSource(
        key="json", name="JSON", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
        default_domains=("insurance",),
    )
    payload = json.dumps({"items": [{"id": "1", "title": "Notice"}]}).encode()
    # Feed URL is an explicit, official fallback citation; provenance is never empty.
    engine.ingest(no_url, payload, enabled_domains={"insurance"},
                  fetched_at=_FETCHED_AT)
    assert engine.list_alerts()[0].citations[0].url == no_url.url


def test_concurrent_pollers_create_one_version_and_one_alert(tmp_path):
    path = tmp_path / "shared.sqlite3"
    rules = (ScopeRule("insurance", "domain", ("insurance producer",)),)
    # Point two independently constructed workers at the same persisted queue.
    engines = [RegulatoryChangeEngine(path, scope_rules=rules) for _ in range(2)]
    source = FeedSource(
        key="shared", name="Shared", jurisdiction="US",
        url="https://example.gov/feed.json", format="json",
        default_domains=("insurance",),
    )
    payload = json.dumps({"items": [{
        "id": "same", "title": "Insurance producer update",
        "url": "https://example.gov/same",
    }]}).encode()

    def poll(index):
        return engines[index % 2].ingest(
            source, payload, enabled_domains={"insurance"}, fetched_at=_FETCHED_AT,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(poll, range(16)))

    assert sum(result.versions_created for result in results) == 1
    assert sum(result.alerts_created for result in results) == 1
    assert len(engines[0].document_versions("shared", "same")) == 1
    assert len(engines[0].list_alerts()) == 1


def test_fetch_and_ingest_accepts_injected_offline_transport(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource.federal_register()
    seen = []

    def transport(selected):
        seen.append(selected.url)
        return json.dumps({"results": [{
            "document_number": "2026-99999",
            "title": "Money transmitter official notice",
            "html_url": "https://www.federalregister.gov/documents/2026/example",
        }]})

    result = fetch_and_ingest(
        engine,
        source,
        enabled_domains={"money_transmitter"},
        fetched_at=_FETCHED_AT,
        transport=transport,
    )
    assert seen == [source.url]
    assert result.alerts_created == 1
    assert engine.list_alerts()[0].citations[0].feed_url == source.url


def test_federal_register_pagination_is_complete_same_host_and_bounded(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource.federal_register()
    page_two = source.url + "?page=2"
    payloads = {
        source.url: json.dumps({
            "results": [{
                "document_number": "page-1",
                "title": "Money transmitter first page notice",
                "html_url": "https://www.federalregister.gov/documents/page-1",
            }],
            "next_page_url": page_two,
        }),
        page_two: json.dumps({
            "results": [{
                "document_number": "page-2",
                "title": "Money transmitter second page notice",
                "html_url": "https://www.federalregister.gov/documents/page-2",
            }],
            "next_page_url": None,
        }),
    }
    seen = []

    def transport(selected):
        seen.append(selected.url)
        return payloads[selected.url]

    result = fetch_and_ingest(
        engine,
        source,
        enabled_domains={"money_transmitter"},
        fetched_at=_FETCHED_AT,
        transport=transport,
    )
    assert seen == [source.url, page_two]
    assert result.items_seen == 2
    assert result.alerts_created == 2
    alerts = {row.external_id: row for row in engine.list_alerts()}
    assert set(alerts) == {"page-1", "page-2"}
    assert alerts["page-1"].citations[0].retrieval_url == source.url
    assert alerts["page-2"].citations[0].retrieval_url == page_two
    assert all(row.citations[0].feed_url == source.url for row in alerts.values())
    assert all(
        row.citations[0].acquisition == "network_retrieved"
        for row in alerts.values()
    )

    def hostile_transport(_selected):
        return json.dumps({
            "results": [{
                "document_number": "must-not-commit",
                "title": "Money transmitter partial page",
                "html_url": "https://www.federalregister.gov/documents/partial",
            }],
            "next_page_url": "https://attacker.example.invalid/page-2",
        })

    atomic_engine = _engine(tmp_path / "atomic-hostile")
    with pytest.raises(FeedFetchError, match="source host"):
        fetch_and_ingest(atomic_engine, source, transport=hostile_transport)
    assert atomic_engine.list_alerts() == []
    assert atomic_engine.document_versions("federal-register", "must-not-commit") == []


def test_failed_second_page_and_conflicting_duplicate_are_atomic(tmp_path):
    source = FeedSource.federal_register()
    page_two = source.url + "?page=2"
    first = json.dumps({
        "results": [{
            "document_number": "atomic-1",
            "title": "Money transmitter first page",
            "html_url": "https://www.federalregister.gov/documents/atomic-1",
        }],
        "next_page_url": page_two,
    })

    broken = _engine(tmp_path / "broken")

    def broken_transport(selected):
        return first if selected.url == source.url else "{not-json"

    with pytest.raises(FeedParseError, match="Federal Register"):
        fetch_and_ingest(
            broken,
            source,
            enabled_domains={"money_transmitter"},
            transport=broken_transport,
        )
    assert broken.list_alerts() == []
    assert broken.document_versions("federal-register", "atomic-1") == []

    conflicting = _engine(tmp_path / "conflicting")
    pages = [
        (
            json.dumps({"results": [{
                "document_number": "same-id",
                "title": "Money transmitter version one",
                "html_url": "https://www.federalregister.gov/documents/same-id",
            }]}),
            source.url,
        ),
        (
            json.dumps({"results": [{
                "document_number": "same-id",
                "title": "Money transmitter conflicting version",
                "html_url": "https://www.federalregister.gov/documents/same-id",
            }]}),
            page_two,
        ),
    ]
    with pytest.raises(FeedParseError, match="conflicting versions"):
        conflicting.ingest_pages(
            source,
            pages,
            enabled_domains={"money_transmitter"},
            fetched_at=_FETCHED_AT,
        )
    assert conflicting.list_alerts() == []


def test_single_page_ingest_rejects_conflicting_duplicate_atomically(tmp_path):
    engine = _engine(tmp_path / "single-conflicting")
    source = FeedSource(
        key="manual-json",
        name="Manual JSON fixture",
        jurisdiction="US",
        url="https://example.gov/register.json",
        format="json",
    )
    payload = json.dumps({
        "items": [
            {
                "id": "same-id",
                "title": "Money transmitter first version",
                "url": "https://example.gov/notices/same-id",
            },
            {
                "id": "same-id",
                "title": "Money transmitter conflicting version",
                "url": "https://example.gov/notices/same-id",
            },
        ]
    })

    with pytest.raises(FeedParseError, match="conflicting versions"):
        engine.ingest(
            source,
            payload,
            enabled_domains={"money_transmitter"},
            fetched_at=_FETCHED_AT,
        )

    assert engine.list_alerts() == []


def test_default_scope_rules_cover_all_shipped_finance_regimes_and_domains(tmp_path):
    engine = RegulatoryChangeEngine(tmp_path / "default-scopes.sqlite3")
    source = FeedSource(
        key="scope-catalog",
        name="Scope Catalog Fixture",
        jurisdiction="US",
        url="https://example.gov/scopes.json",
        format="json",
    )
    title = " ".join((
        "Sarbanes-Oxley COSO framework US GAAP GLBA anti-money laundering",
        "SEC rule IRS notice Digital Operational Resilience Act Basel III",
        "IFRS 17 PCI DSS money transmitter insurance producer consumer lending",
        "financial institution",
    ))
    result = engine.ingest(
        source,
        json.dumps({"items": [{
            "id": "all-scopes",
            "title": title,
            "url": "https://example.gov/scopes/all",
        }]}),
        enabled_regimes={
            "sox", "coso", "gaap", "glba", "aml", "sec", "irs", "dora",
            "basel_iii", "ifrs_17", "pci",
        },
        enabled_domains={
            "money_transmitter", "insurance_producer", "lending", "finance",
        },
        fetched_at=_FETCHED_AT,
    )

    assert result.alerts_created == 1
    [alert] = engine.list_alerts()
    assert set(alert.matched_regimes) == {
        "sox", "coso", "gaap", "glba", "aml", "sec", "irs", "dora",
        "basel_iii", "ifrs_17", "pci",
    }
    assert set(alert.matched_domains) == {
        "money_transmitter", "insurance_producer", "lending", "finance",
    }


def test_global_scope_reconciliation_covers_absent_records_and_preserves_narrowing(
    tmp_path,
):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="state-register",
        name="State Register",
        jurisdiction="US-NY",
        url="https://example.gov/feed.json",
        format="json",
    )
    payload = json.dumps({"items": [
        {
            "id": "a",
            "title": "DORA insurance producer update A",
            "url": "https://example.gov/a",
        },
        {
            "id": "b",
            "title": "DORA insurance producer update B",
            "url": "https://example.gov/b",
        },
    ]})
    engine.ingest(
        source,
        payload,
        enabled_regimes={"dora"},
        enabled_domains={"insurance"},
        fetched_at=_FETCHED_AT,
    )
    alerts = {row.external_id: row for row in engine.list_alerts()}
    accepted = engine.disposition_alert(
        alerts["a"].alert_id,
        status="accepted",
        reviewer="reviewer@example.com",
        expected_revision=alerts["a"].revision,
    )

    narrowed = engine.reconcile_scopes(enabled_regimes={"dora"})
    assert narrowed.documents_seen == 2
    narrowed_alerts = {row.external_id: row for row in engine.list_alerts()}
    assert narrowed_alerts["a"].status == "accepted"
    assert narrowed_alerts["a"].revision == accepted.revision + 1
    assert narrowed_alerts["b"].status == "open"
    assert all(row.matched_domains == () for row in narrowed_alerts.values())

    disabled = engine.reconcile_scopes()
    assert disabled.alerts_updated == 2
    assert {row.status for row in engine.list_alerts()} == {"inactive"}

    enabled = engine.reconcile_scopes(enabled_domains={"insurance"})
    assert enabled.alerts_updated == 2
    assert {row.status for row in engine.list_alerts()} == {"open"}
    assert {row.external_id for row in engine.list_alerts()} == {"a", "b"}


def test_global_scope_reconciliation_queues_previously_unmatched_document(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="state-register",
        name="State Register",
        jurisdiction="US-NY",
        url="https://example.gov/feed.json",
        format="json",
    )
    engine.ingest(
        source,
        json.dumps({"items": [{
            "id": "historical",
            "title": "Insurance producer historical notice",
            "url": "https://example.gov/historical",
        }]}),
        fetched_at=_FETCHED_AT,
    )
    assert engine.list_alerts() == []

    result = engine.reconcile_scopes(enabled_domains={"insurance"})

    assert result.alerts_created == 1
    [alert] = engine.list_alerts()
    assert alert.external_id == "historical"
    assert alert.change_kind == "scope_enabled"


def test_scope_reconciliation_is_bounded_and_updates_every_alert_version(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="versioned-state-register",
        name="Versioned State Register",
        jurisdiction="US-NY",
        url="https://example.gov/feed.json",
        format="json",
    )
    for title, fetched_at in (
        ("Insurance producer notice v1", "2026-07-20T12:00:00Z"),
        ("Insurance producer notice v2", "2026-07-21T12:00:00Z"),
    ):
        engine.ingest(
            source,
            json.dumps({"items": [{
                "id": "versioned",
                "title": title,
                "url": "https://example.gov/versioned",
            }]}),
            enabled_domains={"insurance"},
            fetched_at=fetched_at,
        )
    assert len(engine.list_alerts()) == 2

    first = engine.reconcile_scopes(batch_size=1)
    second = engine.reconcile_scopes(batch_size=1)

    assert first.documents_seen == 1 and first.complete is False
    assert second.documents_seen == 1 and second.complete is True
    assert {row.status for row in engine.list_alerts()} == {"inactive"}

    reopened_first = engine.reconcile_scopes(
        enabled_domains={"insurance"}, batch_size=1
    )
    reopened_second = engine.reconcile_scopes(
        enabled_domains={"insurance"}, batch_size=1
    )
    no_work = engine.reconcile_scopes(
        enabled_domains={"insurance"}, batch_size=1
    )
    assert reopened_first.complete is False
    assert reopened_second.complete is True
    assert {row.status for row in engine.list_alerts()} == {"open"}
    assert no_work.documents_seen == 0 and no_work.complete is True


def test_completed_scope_reconciliation_resumes_for_new_documents(tmp_path):
    engine = _engine(tmp_path)
    source = FeedSource(
        key="incremental-state-register",
        name="Incremental State Register",
        jurisdiction="US-NY",
        url="https://example.gov/feed.json",
        format="json",
    )
    engine.ingest(
        source,
        json.dumps({"items": [{
            "id": "first",
            "title": "Insurance producer first",
            "url": "https://example.gov/first",
        }]}),
        fetched_at=_FETCHED_AT,
    )
    assert engine.reconcile_scopes(enabled_domains={"insurance"}).alerts_created == 1

    engine.ingest(
        source,
        json.dumps({"items": [{
            "id": "second",
            "title": "Insurance producer second",
            "url": "https://example.gov/second",
        }]}),
        fetched_at="2026-07-23T12:00:00Z",
    )
    resumed = engine.reconcile_scopes(enabled_domains={"insurance"})

    assert resumed.documents_seen == 1
    assert resumed.alerts_created == 1
    assert {row.external_id for row in engine.list_alerts()} == {"first", "second"}


def test_guarded_fetch_enforces_declared_response_limit(monkeypatch):
    class Response:
        headers = {"Content-Length": str(5 * 1024 * 1024 + 1)}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            raise AssertionError("oversized response must not be read")

    from maverick.tools import http_fetch

    monkeypatch.setattr(http_fetch, "guarded_urlopen", lambda *_args, **_kwargs: Response())
    with pytest.raises(FeedFetchError, match="5 MiB"):
        fetch_feed(FeedSource.federal_register())


def test_builtin_edpb_news_routes_privacy_guidance(tmp_path):
    engine = RegulatoryChangeEngine(tmp_path / "edpb.sqlite3")
    source = FeedSource.edpb_news()
    payload = b"""<rss version='2.0'><channel>
      <title>EDPB news</title>
      <item><title>Guidelines 01/2026 on AI model training under the GDPR</title>
        <link>https://www.edpb.europa.eu/news/2026/guidelines-ai-training</link>
        <description>Adopted guidelines on lawful bases for model training</description>
      </item>
    </channel></rss>"""

    result = engine.ingest(
        source, payload, enabled_domains={"privacy"}, fetched_at=_FETCHED_AT)
    assert result.alerts_created == 1
    alert = engine.list_alerts()[0]
    assert alert.matched_domains == ("privacy",)
    assert alert.citations[0].source_name == "EDPB news"
    assert alert.citations[0].feed_url.startswith("https://www.edpb.europa.eu/")


def test_builtin_eur_lex_source_is_valid_and_unclaimed(tmp_path):
    source = FeedSource.eur_lex_legislation()
    assert source.jurisdiction == "EU" and source.format == "rss"
    # Cross-domain feed: claims no default domain; scope rules decide.
    assert source.default_domains == ()
    engine = RegulatoryChangeEngine(tmp_path / "eurlex.sqlite3")
    payload = b"""<rss version='2.0'><channel><title>legislation</title>
      <item><title>CELEX:32026R0001: Regulation (EU) 2026/1</title>
        <link>https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R0001</link>
        <description>A new regulation</description>
      </item></channel></rss>"""
    result = engine.ingest(source, payload, enabled_domains=set(),
                           fetched_at=_FETCHED_AT)
    # No domain claimed and none enabled: versioned but unmatched, no alert.
    assert result.items_seen == 1 and result.alerts_created == 0
