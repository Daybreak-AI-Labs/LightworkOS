"""Connected-app event sources: what counts as new, and what is remembered."""
from __future__ import annotations

import hashlib

import pytest
from maverick import automation_connected_events as connected
from maverick import automation_events as events


def _config(source, selection):
    return {"connection": "sales", "revision": "r1", "connector": connected.SOURCES[source]["connector"],
            "origin": "https://acme.my.salesforce.com" if source == "salesforce_records" else "https://graph.microsoft.com",
            "selection": selection, "_lightwork_cursor_format": 1}


def _cursor(ids):
    return events._encode_cursor("connected_app", sorted(hashlib.sha256(i.encode()).hexdigest() for i in ids))


def _lead(number):
    return {"Id": f"lead{number:06d}", "Name": f"Lead {number}", "CreatedDate": f"2026-01-01T00:00:00.{number:06d}"}


def test_new_records_are_found_in_a_table_larger_than_one_check_reads(monkeypatch):
    """A Salesforce table with more than 5,000 rows used to be refused. The
    newest 5,000 are read instead, and only rows newer than a known row count
    as new: an older row that moves into view when newer rows are deleted is
    not an event."""
    table = [_lead(n) for n in range(6000)]  # oldest first
    queries: list[str] = []

    def listing(source, config, path, **_kwargs):
        queries.append(path)
        rows = list(reversed(table))  # newest first, as the query asks
        if "LIMIT+5000" in path:
            return rows[:5000]
        if len(rows) > connected.MAX_ITEMS:  # what the real reader does
            raise events.EventSourceError("This source contains more than 5,000 items.")
        return rows

    monkeypatch.setattr(connected, "collection", listing)
    source = connected.ConnectedAppSource("salesforce_records")
    config = _config("salesforce_records", {"object": "Lead", "closed_only": False})

    first = source.poll(config, "")
    assert first.events == []

    table.extend([_lead(6000), _lead(6001)])
    del table[5990:5995]  # five recent rows deleted: five older rows move into view
    second = source.poll(config, first.cursor)
    assert second.event_ids == ["lead006000", "lead006001"]

    third = source.poll(config, second.cursor)
    assert third.events == []

    # Nothing known is left in view: more arrived than one check reads. That
    # stays a refusal, because the rows below the newest 5,000 were never read.
    table.extend(_lead(n) for n in range(7000, 12001))
    with pytest.raises(events.EventSourceError, match="None of the remembered items"):
        source.poll(config, third.cursor)


def test_a_list_that_shrinks_below_one_check_does_not_report_its_old_rows(monkeypatch):
    """5,200 tickets, then 300 deleted and none created: the 200 oldest came
    into view, the view was no longer full, and they were reported as new. A
    source that was once longer than one check keeps the newest-first rule."""
    from urllib.parse import parse_qsl

    def ticket(number):
        return {"sys_id": f"inc{number:06d}", "number": f"INC{number}",
                "sys_created_on": f"2026-01-01 00:00:00.{number:06d}"}

    table = [ticket(n) for n in range(5200)]  # oldest first

    def listing(source, config, path, **_kwargs):
        offset = int(dict(parse_qsl(path.split("?", 1)[1]))["sysparm_offset"])
        return list(reversed(table))[offset:offset + 1000]

    monkeypatch.setattr(connected, "collection", listing)
    source = connected.ConnectedAppSource("servicenow_tickets")
    config = {"connection": "sn", "revision": "r1", "connector": "servicenow",
              "origin": "https://acme.service-now.com", "selection": {"table": "incident"},
              "_lightwork_cursor_format": 1}
    first = source.poll(config, "")

    del table[1000:1300]
    second = source.poll(config, first.cursor)
    assert second.events == []
    table.append(ticket(5200))
    third = source.poll(config, second.cursor)
    assert third.event_ids == ["inc005200"]

    # The dashboard's dated baseline carries the same mark, and a position
    # saved before the mark existed still loads.
    assert connected.validate("servicenow_tickets", {
        **{k: v for k, v in config.items() if k != "_lightwork_cursor_format"},
        "baseline": connected.baseline("servicenow_tickets", config["selection"],
                                       [row["sys_id"] for row in reversed(table)][:5000])})
    old_position = _cursor([row["sys_id"] for row in table])
    assert source.poll(config, old_position).events == []


def test_remembered_items_roll_over_instead_of_stopping_the_source(monkeypatch):
    """The remembered identities only grew, and at 20,000 the source stopped
    for good. Above that size the ones gone from the source are forgotten."""
    present = [{"id": f"file{n}", "name": f"f{n}", "file": {}, "createdDateTime": f"2026-01-01T00:00:{n:02d}Z"}
               for n in range(3)]
    monkeypatch.setattr(connected, "collection", lambda *args, **kwargs: list(present))
    monkeypatch.setattr(connected, "MAX_SEEN", 50)
    source = connected.ConnectedAppSource("sharepoint_files")
    config = _config("sharepoint_files", {"site": "s1", "drive": "d1", "folder": "root"})
    gone = [f"deleted{n}" for n in range(48)]  # with the two below: at the limit

    result = source.poll(config, _cursor(gone + ["file0", "file1"]))
    assert result.event_ids == ["file2"]
    assert result.cursor == _cursor(["file0", "file1", "file2"])
    assert source.poll(config, result.cursor).events == []
