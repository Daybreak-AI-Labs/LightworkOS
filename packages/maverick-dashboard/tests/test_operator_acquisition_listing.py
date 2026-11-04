"""The teaching-question picker lists what it can check; one flow it cannot
check is left out of the reference list, not the whole picker."""
from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import operator_acquisition as oa


def _flow(flow_id):
    return SimpleNamespace(id=flow_id, name=flow_id.title(), nodes={
        "step": SimpleNamespace(output="answer", label="Step", kind="agent", learned_operator=None)})


@pytest.fixture
def picker(monkeypatch):
    rows = [{"id": "good", "name": "Good"}, {"id": "bad", "name": "Bad"}, {"id": "also-good", "name": "Also-Good"}]
    monkeypatch.setattr(oa, "authority", lambda request, context=None, **_kw: ("user:owner", "ctx"))
    monkeypatch.setattr(oa.store, "list_flow_summaries", lambda **_kw: rows)
    monkeypatch.setattr(oa.STORE, "list", lambda **_kw: [])
    monkeypatch.setattr(oa, "_writer", lambda request, **_kw: contextlib.nullcontext())
    monkeypatch.setattr(oa, "_reference", lambda request, flow_id, output: {})
    return monkeypatch


@pytest.mark.parametrize("status", [404, 409])
def test_one_flow_that_cannot_be_loaded_does_not_abort_the_picker(picker, status):
    def load(request, flow_id):
        if flow_id == "bad":
            raise HTTPException(status, "unavailable")
        return _flow(flow_id)

    picker.setattr(oa, "_flow", load)
    result = oa.listing(None)
    assert [row["value"] for row in result["flows"]] == ["good", "bad", "also-good"]
    assert [row["value"] for row in result["references"]] == ["good", "also-good"]


def test_a_failure_that_is_not_about_one_flow_still_aborts(picker):
    def load(request, flow_id):
        raise HTTPException(503, "storage unavailable")

    picker.setattr(oa, "_flow", load)
    with pytest.raises(HTTPException) as exc:
        oa.listing(None)
    assert exc.value.status_code == 503
