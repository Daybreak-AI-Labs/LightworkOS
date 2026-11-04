"""The independent standard-library SDK consumes the shared wire fixtures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_python_sdk_reads_shared_goal_event_pages(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "sdks/python-client"))
    from lightwork_client import GoalEventsResponse, Lightwork

    fixture = json.loads((ROOT / "apps/client-contract-tests/contracts/goal-events-v1.json").read_text())
    pages = iter(fixture["pages"])
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append((method, url))
        return 200, {}, json.dumps(next(pages)).encode()

    client = Lightwork("http://127.0.0.1:8765", transport=transport)
    first = client.goal_events(7, since=0)
    second = client.goal_events(7, since=first["next_id"])
    assert [event["id"] for page in (first, second) for event in page["events"]] == [1, 2, 3]
    assert first["has_more"] and not first["terminal"] and second["terminal"]
    assert "since=0" in calls[0][1] and "since=2" in calls[1][1]
    assert {"status", "result", "next_id", "events"} <= GoalEventsResponse.__required_keys__


def test_python_sdk_recovers_a_lost_write_using_the_shared_receipt(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "sdks/python-client"))
    from lightwork_client import Lightwork, LightworkError

    fixture = json.loads((ROOT / "apps/client-contract-tests/contracts/goal-submission-recovery-v1.json").read_text())
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append((method, url, dict(headers), timeout))
        if method == "POST":
            raise TimeoutError("response lost after dispatch")
        return 200, {}, json.dumps(fixture["receipt"]).encode()

    client = Lightwork("http://127.0.0.1:8765", timeout=3, transport=transport)
    with pytest.raises(LightworkError) as error:
        client.submit_goal(fixture["title"], fixture["description"], idempotency_key=fixture["idempotency_key"])
    assert error.value.status is None
    assert len(calls) == fixture["write_count_after_interruption"]
    receipt = client.goal_receipt(fixture["idempotency_key"])
    assert receipt == fixture["receipt"] and receipt["execution_confirmed"] is False
    assert [call[0] for call in calls] == ["POST", "GET"]
    assert all(call[2]["Idempotency-Key"] == fixture["idempotency_key"] and call[3] == 3 for call in calls)
