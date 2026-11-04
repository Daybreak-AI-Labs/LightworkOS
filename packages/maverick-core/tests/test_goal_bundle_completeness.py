"""Complete native snapshot exports, bounded refusal and compatible integrity."""
import hashlib
import json

import pytest
from maverick import goal_archive
from maverick.goal_bundle import (
    MAX_EPISODES,
    MAX_EVENTS,
    IncompleteGoalBundle,
    build_goal_bundle,
    prepare_goal_archive,
)
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    with WorldModel(tmp_path / "world.db") as value:
        goal_id = value.create_goal("Export this task")
        value.set_goal_status(goal_id, "done", result="Saved before export")
        yield value, goal_id


def seed(world, goal_id, events, episodes):
    with world._writing() as connection:
        connection.executemany("INSERT INTO goal_events(goal_id,agent,kind,content,ts) VALUES(?,?,?,?,?)",
                               [(goal_id,"test","observation","Recorded evidence",float(i)) for i in range(events)])
        connection.executemany("INSERT INTO episodes(goal_id,started_at) VALUES(?,?)",
                               [(goal_id,float(i)) for i in range(episodes)])


@pytest.mark.parametrize("events,episodes", [(MAX_EVENTS + 1, 0), (0, MAX_EPISODES + 1)])
def test_oversized_archive_visibly_refuses(world, events, episodes):
    store, goal = world
    seed(store, goal, events, episodes)
    with pytest.raises(IncompleteGoalBundle, match="No partial history"):
        build_goal_bundle(store, goal)


def test_archive_manifest_matches_v1_body_and_chunked_output(world):
    store, goal = world
    seed(store, goal, 18, 19)
    prepared = prepare_goal_archive(store, goal)
    chunks = list(prepared.chunks())
    assert all(len(chunk) <= 65536 for chunk in chunks)
    assert prepared.stream.closed
    bundle = json.loads(b"".join(chunks))
    manifest = bundle.pop("manifest")
    assert manifest["event_count"] == 18 and manifest["episode_count"] == 19
    assert manifest["snapshot_consistent"] is True
    assert manifest["redacted"] is False and manifest["resumable"] is False
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str).encode()
    assert hashlib.sha256(canonical).hexdigest() == manifest["sha256"]
    assert bundle["v"] == 1 and bundle["goal"]["id"] == goal


def test_concurrent_goal_and_event_writes_do_not_mix_into_snapshot(world, monkeypatch):
    store, goal = world
    seed(store, goal, 18, 2)
    original = goal_archive._events
    with WorldModel(store.path) as writer:
        def events(*args):
            for index, event in enumerate(original(*args)):
                if index == 0:
                    writer.set_goal_status(goal, "done", result="Changed after snapshot")
                    seed(writer, goal, 1, 0)
                yield event
        monkeypatch.setattr(goal_archive, "_events", events)
        bundle = build_goal_bundle(store, goal)
        assert bundle["goal"]["result"] == "Saved before export"
        assert len(bundle["events"]) == 18
        assert store.get_goal(goal).result == "Changed after snapshot"
        assert len(store.goal_events(goal, limit=30)) == 19


def test_byte_limit_refuses_before_any_download_is_available(world, monkeypatch):
    store, goal = world
    seed(store, goal, 8, 2)
    monkeypatch.setattr(goal_archive, "MAX_ARCHIVE_BYTES", 256)
    with pytest.raises(IncompleteGoalBundle, match="No partial history"):
        prepare_goal_archive(store, goal)
