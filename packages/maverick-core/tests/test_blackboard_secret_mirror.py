"""Secrets posted to the blackboard must not PERSIST/DISPLAY in cleartext.

Previously, Blackboard.post() mirrored content
verbatim into world.goal_events (persisted to world.db and streamed live to
the dashboard), the replay trace, and the observation channel -- none
redacted. An agent that reports a credential it found ("the DB password is X")
leaked that secret to disk and to any dashboard viewer, even in a fully local
deployment, and regardless of the audit log's own redaction.

The in-memory blackboard (the agents' shared working memory) stays verbatim so
agent workflows that legitimately pass a value between siblings are unbroken --
same split the audit log uses (the live agent operates on real data; the
persisted/displayed record is redacted).
"""
from __future__ import annotations

from maverick import ai_evidence_gateway, observation_channel
from maverick.blackboard import Blackboard
from maverick.safety import secret_detector
from maverick.world_model import WorldModel

_SECRET = "sk-ant-api03-LEAKED1234567890abcdefABCDEFGHIJKLMNOP"  # pragma: allowlist secret


def test_secret_not_persisted_to_goal_events(tmp_path):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("t", "")
    bb = Blackboard()
    bb.attach_world(world, gid)

    bb.post("worker-1", "finding", f"Found the API key: {_SECRET} in config")

    events = world.goal_events(gid)
    assert events, "post should mirror to goal_events"
    blob = "\n".join(e.content for e in events)
    assert _SECRET not in blob, "secret leaked into persisted/displayed goal_events"
    assert "[REDACTED" in blob


def test_in_memory_blackboard_preserves_content_for_agents(tmp_path):
    # The agents' shared working memory is intentionally verbatim so a value
    # passed between siblings still works; only the persisted mirror redacts.
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("t", "")
    bb = Blackboard()
    bb.attach_world(world, gid)
    bb.post("worker-1", "finding", f"value={_SECRET}")
    assert _SECRET in bb.render(10)


def test_no_world_still_works(tmp_path):
    # Detached blackboard (no world) must not crash on a secret post.
    bb = Blackboard()
    bb.post("a", "finding", f"key {_SECRET}")
    assert _SECRET in bb.render(10)


def test_redaction_failure_fails_closed_for_every_mirror(tmp_path, monkeypatch):
    """A detector failure must never copy raw content across the mirror boundary."""

    monkeypatch.setattr(
        secret_detector,
        "redact",
        lambda _content: (_ for _ in ()).throw(RuntimeError("detector unavailable")),
    )
    monkeypatch.setattr(ai_evidence_gateway, "enabled", lambda: False)
    published = []
    monkeypatch.setattr(
        observation_channel,
        "maybe_publish",
        lambda kind, agent, content: published.append((kind, agent, content)),
    )

    class Trace:
        def __init__(self):
            self.rows = []

        def record(self, kind, **payload):
            self.rows.append((kind, payload["agent"], payload["content"]))

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("redaction-failure", "")
    trace = Trace()
    bb = Blackboard()
    bb.attach_world(world, goal_id)
    bb.attach_trace(trace)

    raw = f"detector failed while processing {_SECRET}"
    bb.post("guard", "error", raw, provenance="safety")

    placeholder = Blackboard._REDACTION_UNAVAILABLE_CONTENT
    assert [event.content for event in world.goal_events(goal_id)] == [placeholder]
    assert [row[2] for row in trace.rows] == [placeholder]
    assert [row[2] for row in published] == [placeholder]
    assert _SECRET in bb.entries[0].content


def test_gateway_withholds_only_model_derived_mirrors(
    tmp_path,
    monkeypatch,
):
    """Every live transport consumes the same provenance-safe event mirror."""

    monkeypatch.setattr(ai_evidence_gateway, "enabled", lambda: True)
    published = []
    monkeypatch.setattr(
        observation_channel,
        "maybe_publish",
        lambda kind, agent, content: published.append(
            (kind, agent, content)
        ),
    )

    class Trace:
        def __init__(self):
            self.rows = []

        def record(self, kind, **payload):
            self.rows.append((kind, payload["agent"], payload["content"]))

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("provenance", "")
    trace = Trace()
    bb = Blackboard()
    bb.attach_world(world, goal_id)
    bb.attach_trace(trace)

    model_excerpt = "unreceipted model conclusion"
    denial = "capability denied: shell is outside this agent's grant"
    compartment = "worker compartment sealed after deterministic policy check"
    progress = "completed 3 of 5 deterministic checks"
    bb.post("reviewer", "finding", model_excerpt)
    bb.post("guard", "error", denial, provenance="capability")
    bb.post(
        "orchestrator",
        "observation",
        compartment,
        provenance="compartment",
    )
    bb.post("operator", "status", progress, provenance="progress")

    expected = [
        Blackboard._WITHHELD_CONTENT,
        denial,
        compartment,
        progress,
    ]
    events = world.goal_events(goal_id)
    assert [event.content for event in events] == expected
    assert [row[2] for row in trace.rows] == expected
    assert [row[2] for row in published] == expected

    # Agent coordination remains verbatim; only persisted/live mirrors are
    # governed. The world event seam feeds dashboard, SSE, WebSocket, and gRPC.
    assert [entry.content for entry in bb.entries] == [
        model_excerpt,
        denial,
        compartment,
        progress,
    ]
