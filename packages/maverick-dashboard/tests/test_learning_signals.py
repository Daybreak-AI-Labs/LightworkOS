"""Tier-1 grounded-learning wiring: thumbs up/down feedback, the system-of-record
outcome-by-key loop, and per-trigger outcome attribution -- all feeding the
Consequence Engine, all off unless [consequence] is enabled."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def _isolate(tmp_path, monkeypatch):
    # consequence + the NDJSON stores resolve their paths under HOME at call time.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(
        "maverick.config.dashboard_overrides_path",
        lambda: tmp_path / "dashboard" / "overrides.toml",
    )
    from maverick import consequence
    consequence.reset_shared()
    return consequence


def _rate(gid, body):
    """Give feedback the way the answer page does: on the reviewed answer."""
    from uuid import uuid4

    review = client.get(f"/api/v1/goals/{gid}/answer-feedback")
    if review.status_code != 200:
        return review
    return client.post(f"/api/v1/goals/{gid}/feedback", json={
        **body, "revision": review.json()["revision"],
        "expected_context": review.json()["context"], "operation_id": uuid4().hex})


class TestFeedbackGroundsLearning:
    def test_thumbs_up_records_reward_1(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        eid = w.start_episode(gid)
        # Feedback grounds only the completed run that produced the answer.
        w.end_episode(eid, "the memo", "success")
        w.set_goal_status(gid, "done", result="the memo")
        r = _rate(gid, {"rating": "up"})
        assert r.status_code == 200
        assert r.json()["feedback"]["rating"] == "up"
        assert consequence.resolve(gid, eid) == 1.0

    def test_thumbs_down_records_reward_0(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        eid = w.start_episode(gid)
        # Feedback grounds only the completed run that produced the answer.
        w.end_episode(eid, "the memo", "success")
        w.set_goal_status(gid, "done", result="the memo")
        r = _rate(gid, {"rating": "down"})
        assert r.status_code == 200
        assert consequence.resolve(gid, eid) == 0.0

    def test_feedback_persists_and_reads_back(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        w.start_episode(gid)
        w.set_goal_status(gid, "done", result="the memo")
        _rate(gid, {"rating": "up"})
        got = client.get(f"/api/v1/goals/{gid}/feedback").json()
        assert got["feedback"]["rating"] == "up"

    def test_bad_rating_is_422(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("x", "")
        r = _rate(gid, {"rating": "meh"})
        assert r.status_code == 422

    def test_feedback_on_missing_goal_is_404(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        _world(tmp_path, monkeypatch)
        r = _rate(999999, {"rating": "up"})
        assert r.status_code == 404

    def test_no_grounding_when_consequence_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "0")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        eid = w.start_episode(gid)
        # Feedback grounds only the completed run that produced the answer.
        w.end_episode(eid, "the memo", "success")
        w.set_goal_status(gid, "done", result="the memo")
        r = _rate(gid, {"rating": "up"})
        assert r.status_code == 200                      # feedback still persists...
        assert consequence.resolve(gid, eid) is None     # ...but nothing is grounded


class TestDeliverableEditGrounding:
    def test_verbatim_keep_grounds_high_edit_replaces_result(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        eid = w.start_episode(gid)
        w.set_goal_status(gid, "done", result="the agent's draft")
        # a near-verbatim keep -> high similarity -> strong positive
        r = client.post(f"/api/v1/goals/{gid}/deliverable/edit",
                        json={"text": "the agent's draft.", "expected_updated_at": w.get_goal(gid).updated_at, "operation_id": "local-learning-edit-1"})
        assert r.status_code == 200 and r.json()["similarity"] > 0.9
        assert consequence.resolve(gid, eid) > 0.9
        assert w.get_goal(gid).result == "the agent's draft."   # the edit is canonical now

    def test_heavy_rewrite_grounds_low(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        eid = w.start_episode(gid)
        w.set_goal_status(gid, "done", result="aaaaaaaaaaaaaaaaaaaa")
        r = client.post(f"/api/v1/goals/{gid}/deliverable/edit",
                        json={"text": "completely different text zzzzzzzz", "expected_updated_at": w.get_goal(gid).updated_at, "operation_id": "local-learning-edit-1"})
        assert r.status_code == 200 and r.json()["similarity"] < 0.5
        assert consequence.resolve(gid, eid) < 0.5

    def test_edit_missing_goal_is_404(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        _world(tmp_path, monkeypatch)
        assert client.post("/api/v1/goals/999/deliverable/edit",
                           json={"text": "x", "expected_updated_at": 1.0, "operation_id": "local-learning-edit-missing"}).status_code == 404

    def test_edit_with_no_draft_saves_but_grounds_nothing(self, tmp_path, monkeypatch):
        # No agent draft to grade against -> save the human's text but ground
        # nothing (grounding a 0.0 would punish the agent for text it never wrote).
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Draft the memo", "")
        eid = w.start_episode(gid)
        w.set_goal_status(gid, "done", result="")   # the agent produced nothing
        r = client.post(f"/api/v1/goals/{gid}/deliverable/edit",
                        json={"text": "a human-written memo", "expected_updated_at": w.get_goal(gid).updated_at, "operation_id": "local-learning-edit-1"})
        assert r.status_code == 200 and r.json()["similarity"] is None
        assert w.get_goal(gid).result == "a human-written memo"   # still saved
        assert consequence.resolve(gid, eid) is None               # ...but not grounded

    def test_large_edit_similarity_uses_bounded_sample(self, monkeypatch):
        from maverick_dashboard import api

        calls = []

        class SpyMatcher:
            def __init__(self, _junk, original, revised):
                calls.append((len(original), len(revised)))

            def ratio(self):
                return 0.5

        monkeypatch.setattr(api.difflib, "SequenceMatcher", SpyMatcher)
        similarity = api._deliverable_edit_similarity("a" * 200_000, "b" * 200_000)

        assert similarity == 0.5
        assert calls == [(api._DELIVERABLE_EDIT_SIMILARITY_SAMPLE_CHARS,
                          api._DELIVERABLE_EDIT_SIMILARITY_SAMPLE_CHARS)]


class TestSystemOfRecordLoop:
    """Register a business key during a run, then have a system of record report
    the real outcome using only that key -- the marquee grounded signal."""

    def test_link_then_outcome_by_key_grounds(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        consequence = _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("Bill the client", "")
        eid = w.start_episode(gid)
        # the run links the invoice it created
        r = client.post("/api/v1/outcomes/link",
                        json={"goal_id": gid, "episode_id": eid, "key": "invoice:INV-9"})
        assert r.status_code == 204
        # weeks later, Stripe's webhook reports payment with only the invoice id
        r = client.post("/api/v1/outcomes/by-key",
                        json={"key": "invoice:INV-9", "value": 1.0, "kind": "paid"})
        assert r.status_code == 200 and r.json()["matched"] is True
        assert consequence.resolve(gid, eid) == 1.0

    def test_outcome_by_key_unmatched(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
        _isolate(tmp_path, monkeypatch)
        _world(tmp_path, monkeypatch)
        r = client.post("/api/v1/outcomes/by-key",
                        json={"key": "invoice:NOPE", "value": 1.0})
        assert r.status_code == 200 and r.json()["matched"] is False

    def test_link_missing_episode_is_404(self, tmp_path, monkeypatch):
        _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        gid = w.create_goal("x", "")
        r = client.post("/api/v1/outcomes/link",
                        json={"goal_id": gid, "episode_id": 424242, "key": "k"})
        assert r.status_code == 404


class TestTriggerOutcomeAttribution:
    def test_outcomes_endpoint_counts_by_status(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "1")
        _isolate(tmp_path, monkeypatch)
        w = _world(tmp_path, monkeypatch)
        # two goals spawned by the same event trigger: one done, one failed
        g1 = w.create_goal("from trigger", "")
        w.record_goal_origin(g1, "event", "nightly")
        w.set_goal_status(g1, "done", result="ok")
        g2 = w.create_goal("from trigger", "")
        w.record_goal_origin(g2, "event", "nightly")
        w.set_goal_status(g2, "blocked", result="boom")
        # register the trigger so it's owner-visible
        from maverick_dashboard import event_triggers_store
        monkeypatch.setattr(event_triggers_store, "_path",
                            lambda: tmp_path / "triggers.toml")
        event_triggers_store.set_trigger("nightly", "tmpl", "http_json",
                                         config={"url": "https://ex.com/x"})
        r = client.get("/api/v1/event-triggers/outcomes")
        assert r.status_code == 200
        counts = r.json()["outcomes"]["nightly"]
        assert counts.get("done") == 1
        assert counts.get("blocked") == 1
