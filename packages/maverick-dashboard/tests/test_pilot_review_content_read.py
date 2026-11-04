"""Pilot votes read approved sources without acquiring task mutation rights."""
from types import SimpleNamespace

import pytest
from maverick_dashboard import auth, content_access, outcome_pilot_sources, outcome_pilots_api


@pytest.fixture
def review(monkeypatch):
    request = SimpleNamespace(method="POST", state=SimpleNamespace())
    goal = SimpleNamespace(id=12, owner="user:employee")
    monkeypatch.setattr(auth, "_authorization_principal", lambda _: "user:reviewer")
    monkeypatch.setattr(auth, "has_global_permission", lambda *_: True)
    reads = []
    monkeypatch.setattr(content_access, "may_read_employee_content", lambda req, owner, **scope: reads.append((req, owner, scope)) or True)
    return request, goal, reads


def test_review_source_read_is_explicit_and_never_authorizes_task_mutation(review):
    request, goal, reads = review
    assert not outcome_pilot_sources._can_read_source(request, goal)
    assert reads == []
    assert outcome_pilot_sources._can_read_source(request, goal, independent_review=True)
    assert reads == [(request, "user:employee", {"resource_kind": "goal", "resource_id": "12"})]
    assert request.method == "POST"
    assert not auth.can_access_goal(request, goal)


def test_expired_denied_or_unacknowledged_read_cannot_vote(review, monkeypatch):
    request, goal, _ = review
    monkeypatch.setattr(content_access, "may_read_employee_content", lambda *_args, **_kwargs: False)
    assert not outcome_pilot_sources._can_read_source(request, goal, independent_review=True)


def test_paired_device_never_inherits_exceptional_admin_reads(review):
    request, goal, reads = review
    request.state.paired_device_id = "paired"
    assert not outcome_pilot_sources._can_read_source(request, goal, independent_review=True)
    assert reads == []


def test_other_pilot_mutations_do_not_enable_independent_source_reads(review, monkeypatch):
    request, _, _ = review
    calls = []
    monkeypatch.setattr(outcome_pilot_sources, "resolve", lambda *args, **kw: calls.append((args, kw)))
    outcome_pilots_api._resolver(request)("goal", "12")
    outcome_pilots_api._resolver(request, independent_review=True)("goal", "12")
    assert calls == [((request, "goal", "12"), {}), ((request, "goal", "12"), {"independent_review": True})]
