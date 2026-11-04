"""Privacy and draft-safety invariants for Ekko work discovery."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest
from maverick.flow.runner import (
    STATUS_COMPLETED,
    STATUS_PAUSED_APPROVAL,
    STATUS_REJECTED,
    run_flow,
)
from maverick.work_discovery import (
    CapturePolicy,
    ObservedActivity,
    WorkEvent,
    build_draft_bundle,
    discover_candidates,
)


def _timestamp(day: int, hour: int = 12) -> float:
    return datetime(2026, 1, day, hour, tzinfo=timezone.utc).timestamp()


def _event(
    event_id: str,
    session_id: str,
    sequence: int,
    day: int,
    app: str,
    action: str,
    object_type: str,
    duration: float = 60.0,
) -> WorkEvent:
    return WorkEvent(
        event_id=event_id,
        session_id=session_id,
        sequence=sequence,
        occurred_at=_timestamp(day),
        app=app,
        action=action,
        object_type=object_type,
        duration_seconds=duration,
    )


def test_observation_schema_rejects_content_bearing_extension_fields():
    secret = "Quarterly Board Deck - confidential"  # pragma: allowlist secret

    with pytest.raises(ValueError, match="forbidden fields") as exc:
        ObservedActivity.from_mapping({
            "app": "powerpoint",
            "action": "edit",
            "window_title": secret,
        })

    assert secret not in str(exc.value)


def test_persisted_policy_parser_restores_sensitive_block_floor():
    original = CapturePolicy(
        enabled=True,
        capture_level="guided",
        allowed_apps=frozenset({"excel"}),
        blocked_apps=frozenset(),
        allowed_actions=frozenset({"open"}),
        allowed_object_types=frozenset({"report"}),
        retention_days=14,
        min_occurrences=2,
        min_distinct_days=2,
        poll_interval_seconds=5,
        provider_egress=False,
    )

    policy = CapturePolicy.from_dict(original.to_dict())

    assert "email" in policy.blocked_apps
    assert "slack" in policy.blocked_apps
    assert policy.fingerprint() == original.fingerprint()


def test_persisted_policy_parser_uses_sensitive_floor_when_field_missing():
    policy = CapturePolicy.from_dict({
        "enabled": True,
        "capture_level": "guided",
        "allowed_apps": ["excel", "email"],
        "allowed_actions": ["open"],
        "allowed_object_types": ["report"],
        "retention_days": 14,
        "min_occurrences": 2,
        "min_distinct_days": 2,
        "poll_interval_seconds": 5,
        "provider_egress": False,
    })

    assert policy.allows(ObservedActivity("excel", "open", "report"))
    assert not policy.allows(ObservedActivity("email", "open", "report"))


def test_application_metadata_policy_cannot_smuggle_guided_labels():
    policy = CapturePolicy(
        enabled=True,
        capture_level="application_metadata",
        allowed_apps=frozenset({"chrome"}),
        allowed_actions=frozenset({"switch", "download"}),
        allowed_object_types=frozenset({"none", "report"}),
    )

    with pytest.raises(ValueError, match="application_metadata"):
        policy.require_valid(require_enabled=True)


def test_guided_policy_rejects_sensitive_object_metadata():
    policy = CapturePolicy(
        enabled=True,
        capture_level="guided",
        allowed_apps=frozenset({"chrome"}),
        allowed_actions=frozenset({"open"}),
        allowed_object_types=frozenset({"report", "email"}),
    )

    with pytest.raises(ValueError, match="sensitive object kinds"):
        policy.require_valid(require_enabled=True)
    assert not policy.allows(ObservedActivity("chrome", "open", "email"))


def test_discovery_requires_recurrence_across_distinct_days():
    same_day = [
        _event("one", "s1", 1, 1, "chrome", "download", "report"),
        _event("two", "s1", 2, 1, "powerpoint", "create", "presentation"),
        _event("three", "s1", 3, 1, "chrome", "download", "report"),
        _event("four", "s1", 4, 1, "powerpoint", "create", "presentation"),
    ]

    assert discover_candidates(
        same_day, min_occurrences=2, min_distinct_days=2,
    ) == []


def test_report_to_presentation_becomes_an_evidence_backed_unsaved_draft():
    events = []
    for day in (1, 2, 3):
        session = f"session-{day}"
        events.extend([
            _event(f"download-{day}", session, 1, day, "chrome", "download", "report", 90),
            _event(f"build-{day}", session, 2, day, "powerpoint", "create", "presentation", 510),
        ])

    opportunities = discover_candidates(
        events, min_occurrences=3, min_distinct_days=2,
    )

    assert len(opportunities) == 1
    opportunity = opportunities[0]
    assert opportunity.title == "Automate recurring report-to-presentation workflow"
    assert opportunity.occurrences == 3
    assert opportunity.distinct_days == 3
    assert opportunity.risk == "low"
    assert len(opportunity.evidence) == 3

    bundle = build_draft_bundle(opportunity, owner="alice")
    assert bundle.unsaved is True
    assert bundle.requires_human_approval is True
    assert bundle.flow.owner == "alice"
    assert bundle.flow.schedule == ""
    assert bundle.flow.nodes["human-review"].kind == "approval"
    assert bundle.flow.start == "human-review"
    assert bundle.flow.nodes["human-review"].next == "observed-1"
    assert bundle.flow.nodes["observed-1"].next == "observed-2"
    assert bundle.flow.nodes["observed-2"].next is None
    assert bundle.flow.validate() == []
    assert bundle.demonstration.source == "ekko-semantic-observation"

    calls = []

    def run_agent(node, brief, data):
        calls.append(node.id)
        return "draft", 0.9

    flow = bundle.flow.copy()
    paused = run_flow(flow, agent_fn=run_agent, action_fn=lambda *_: ("", 0.0))
    assert paused.status == STATUS_PAUSED_APPROVAL
    assert paused.cursor == "human-review"
    assert calls == []

    rejected = run_flow(flow, agent_fn=run_agent, action_fn=lambda *_: ("", 0.0),
                        resume={"node_id": paused.cursor, "data": paused.data,
                                "decision": "rejected"})
    assert rejected.status == STATUS_REJECTED
    assert calls == []

    approved = run_flow(flow, agent_fn=run_agent, action_fn=lambda *_: ("", 0.0),
                        resume={"node_id": paused.cursor, "data": paused.data,
                                "decision": "approved"})
    assert approved.status == STATUS_COMPLETED
    assert calls == ["observed-1", "observed-2"]


def test_discovery_deduplicates_event_ids_instead_of_double_counting():
    event = _event("duplicate", "s1", 1, 1, "excel", "open", "report")

    assert discover_candidates([event, event], min_occurrences=2) == []


def _switches(apps, days=(1, 2)):
    return [
        _event(f"e-{day}-{index}", f"s-{day}", index, day, app, "switch", "none", 600)
        for day in days for index, app in enumerate(apps, 1)
    ]


def test_overlapping_windows_do_not_inflate_recurrence():
    opportunities = discover_candidates(
        _switches(["excel", "powerpoint", "excel", "powerpoint", "excel"]),
        min_occurrences=3,
    )
    assert opportunities
    assert all(len(item.pattern) == 2 for item in opportunities)
    assert all(item.occurrences == 4 for item in opportunities)


@pytest.mark.parametrize("gap", [-1, 1801])
def test_clock_reversal_and_idle_gaps_do_not_join_work(gap):
    events = _switches(["excel", "powerpoint"])
    events = [replace(e, occurred_at=e.occurred_at + gap) if e.sequence == 2 else e
              for e in events]
    assert discover_candidates(events, min_occurrences=2) == []


def test_one_app_repetition_and_tandem_loops_are_not_long_workflows():
    assert discover_candidates(_switches(["excel"] * 6), min_occurrences=2) == []
    opportunities = discover_candidates(
        _switches(["excel", "powerpoint"] * 3), min_occurrences=2,
    )
    assert all(len(item.pattern) < 4 for item in opportunities)


def test_app_switches_do_not_claim_task_time_or_automation_readiness():
    candidate, = discover_candidates(_switches(["excel", "powerpoint"]), min_occurrences=2)
    assert candidate.estimated_minutes_per_run is None
    assert candidate.to_dict()["observation_basis"] == "application_metadata"
    assert candidate.to_dict()["review_required"] is True
    assert "switch item" not in candidate.title
    with pytest.raises(ValueError, match="Describe the job"):
        build_draft_bundle(candidate)


def test_discovery_stops_consuming_at_the_event_bound(monkeypatch):
    import maverick.work_discovery as discovery

    monkeypatch.setattr(discovery, "MAX_DISCOVERY_EVENTS", 4)
    consumed = []

    def source():
        for event in _switches(["excel", "powerpoint"] * 3):
            consumed.append(event)
            yield event

    with pytest.raises(ValueError, match="at most 4"):
        discover_candidates(source())
    assert len(consumed) == 5


def test_review_turns_observations_into_an_unsaved_goal_based_proposal():
    from maverick.work_discovery import DraftReview

    candidate, = discover_candidates(_switches(["excel", "powerpoint"]), min_occurrences=2)
    review = DraftReview(
        goal="Prepare the weekly sales summary",
        inputs="The sales export I choose for this run",
        output="A presentation with totals and exceptions",
        approval="I check figures before sharing with the team",
    )
    bundle = build_draft_bundle(candidate, owner="alice", review=review)
    assert bundle.unsaved
    assert bundle.flow.name == review.goal
    assert bundle.flow.start == "human-review"
    assert bundle.flow.nodes["review-result"].kind == "approval"
    assert bundle.flow.nodes["check-result"].next == "review-result"
    assert review.output in bundle.flow.nodes["draft-result"].brief
    assert bundle.flow.validate() == []
    assert all(not step.tool for step in bundle.demonstration.steps)
    calls = []

    def run_agent(node, _brief, _data):
        calls.append(node.id)
        return "Draft result for review", 0.9

    paused = run_flow(bundle.flow.copy(), agent_fn=run_agent, action_fn=lambda *_: ("", 0.0))
    assert paused.status == STATUS_PAUSED_APPROVAL
    assert calls == []
    drafted = run_flow(bundle.flow.copy(), agent_fn=run_agent, action_fn=lambda *_: ("", 0.0),
                       resume={"node_id": paused.cursor, "data": paused.data, "decision": "approved"})
    assert drafted.status == STATUS_PAUSED_APPROVAL
    assert drafted.cursor == "review-result"
    assert calls == ["prepare-inputs", "draft-result", "check-result"]
    completed = run_flow(bundle.flow.copy(), agent_fn=run_agent, action_fn=lambda *_: ("", 0.0),
                         resume={"node_id": drafted.cursor, "data": drafted.data, "decision": "approved"})
    assert completed.status == STATUS_COMPLETED
    assert len(calls) == 3


def test_more_frequent_shorter_work_is_not_hidden_by_a_longer_sequence():
    events = _switches(["excel", "powerpoint", "chrome", "word", "finder", "tableau"], days=(1, 2, 3))
    events += [replace(event, event_id="extra-" + event.event_id, session_id="extra")
               for event in _switches(["excel", "powerpoint"], days=(1,))]
    opportunities = discover_candidates(events)
    assert any(len(item.pattern) == 6 for item in opportunities)
    assert any([step.app for step in item.pattern] == ["excel", "powerpoint"]
               and item.occurrences == 4 for item in opportunities)


@pytest.mark.parametrize("task_type,expected", [
    ("reporting", "reporting period"), ("reconciliation", "matching keys"),
    ("document_review", "document"),
])
def test_task_type_changes_the_draft_without_granting_tools(task_type, expected):
    from maverick.work_discovery import DraftReview

    candidate, = discover_candidates(_switches(["excel", "powerpoint"]), min_occurrences=2)
    review = DraftReview(goal="Prepare an auditable result", inputs="My approved source files",
                        output="A result with source references", approval="I check all exceptions", task_type=task_type)
    bundle = build_draft_bundle(candidate, owner="alice", review=review)
    assert expected in bundle.flow.nodes["prepare-inputs"].brief.lower()
    assert bundle.flow.nodes["review-result"].kind == "approval"
    assert all(not step.tool for step in bundle.demonstration.steps)
    assert bundle.flow.validate() == []


def test_evidence_preview_represents_days_and_is_stable_when_events_are_reordered():
    events = _switches(["excel", "powerpoint"])
    for index in range(22):
        events += [replace(event, event_id=f"extra-{index}-" + event.event_id, session_id=f"extra-{index}")
                   for event in _switches(["excel", "powerpoint"], days=(1,))]
    candidate, = discover_candidates(events)
    assert len(candidate.evidence) == 20
    assert {item.day for item in candidate.evidence} == {"2026-01-01", "2026-01-02"}
    reversed_candidate, = discover_candidates(reversed(events))
    assert candidate.to_dict() == reversed_candidate.to_dict()
