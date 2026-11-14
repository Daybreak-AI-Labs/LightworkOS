"""Tests for training data ingest and its schema (maverick.training)."""
from __future__ import annotations

# ---------- Training schema + ingest ----------

class TestTrainingSchema:
    def test_klear_format_shape(self):
        from maverick.training.schema import (
            TrainingStep,
            TrainingTrajectory,
            to_klear_jsonl,
        )
        traj = TrainingTrajectory(
            trajectory_id="abc-1",
            task_brief_hash="abc",
            model_id="claude-opus-4-7",
            outcome="success",
            terminal_reward=1.0,
            verifier_confidence=0.9,
            disagreement_entropy=0.7,
            steps=[
                TrainingStep(
                    step_index=0, role="orchestrator",
                    action_type="think", action_name="",
                    observation_hash="h0",
                    promise_label=0.5, progress_label=0.0,
                ),
                TrainingStep(
                    step_index=1, role="researcher",
                    action_type="tool_call", action_name="read_file",
                    observation_hash="h1",
                    promise_label=0.7, progress_label=0.1,
                ),
            ],
        )
        out = to_klear_jsonl(traj)
        assert out["id"] == "abc-1"
        assert out["outcome"] == "success"
        assert len(out["messages"]) == 2
        assert out["messages"][1]["name"] == "read_file"
        assert len(out["rewards"]) == 2
        assert out["meta"]["verifier_confidence"] == 0.9


class TestIngest:
    def test_build_trajectory_labels_steps(self):
        from maverick.training.ingest import build_trajectory
        record = {
            "task_brief_hash": "abc",
            "ts": 1717000000,
            "model_id": "claude-opus-4-7",
            "outcome": "success",
            "reward": 1.0,
            "verifier_confidence": 0.9,
            "disagreement_entropy": 0.7,
        }
        events = [
            {"agent": "orchestrator-0-abc", "kind": "plan",
             "content": "plan the work", "ts": 1717000001},
            {"agent": "researcher-1-xyz", "kind": "observation",
             "content": "tool=read_file -> done", "ts": 1717000002},
            {"agent": "orchestrator-0-abc", "kind": "finding",
             "content": "the answer", "ts": 1717000003},
        ]
        traj = build_trajectory(record, events)
        assert len(traj.steps) == 3
        # First (plan) labeled by heuristic with neutral promise.
        # Second (tool success) labeled positive.
        assert traj.steps[1].action_type == "tool_call"
        assert traj.steps[1].action_name == "read_file"
        assert traj.steps[1].promise_label is not None
        # Third (final) labeled strongly positive.
        assert traj.steps[2].action_type == "final"
        assert traj.steps[2].promise_label >= 0.9

    def test_build_trajectory_sets_task_family(self):
        """DPO pairs only form WITHIN a task_family; ingest must set it from the
        task_brief_hash (repeated attempts at one task share that hash). It used
        to be left None, so build_preference_pairs skipped every row -> 0 pairs.
        """
        from maverick.training.ingest import build_trajectory
        traj = build_trajectory({"task_brief_hash": "abc", "ts": 1}, [])
        assert traj.task_family == "abc"

    def test_ingested_rows_pair_when_rewards_differ(self):
        """End-to-end: two attempts at the SAME task with a reward gap produce a
        DPO pair once task_family is populated (regression for 0-pairs bug)."""
        from maverick.training.ingest import build_trajectory
        from maverick.training.rlaif import build_preference_pairs
        from maverick.training.schema import to_klear_jsonl
        good = to_klear_jsonl(build_trajectory(
            {"task_brief_hash": "fam", "ts": 1, "outcome": "success",
             "reward": 1.0, "verifier_confidence": 0.95}, []))
        weak = to_klear_jsonl(build_trajectory(
            {"task_brief_hash": "fam", "ts": 2, "outcome": "success",
             "reward": 0.6, "verifier_confidence": 0.6}, []))
        pairs = build_preference_pairs([good, weak], min_margin=0.25)
        assert len(pairs) == 1
        assert pairs[0]["task_family"] == "fam"
        assert pairs[0]["chosen_reward"] > pairs[0]["rejected_reward"]

    def test_rejected_drafts_become_low_reward_pair_members(self):
        """A rejected pre-revision draft ingests as a low-reward row in the SAME
        task_family as the accepted run, so DPO pairs the two (chosen=accepted
        ~1.0, rejected=draft confidence). Drafts without text are skipped."""
        from maverick.training.ingest import (
            build_rejected_trajectories,
            rejected_trajectory_id,
        )
        rec = {
            "task_brief_hash": "fam", "ts": 7, "reward": 1.0,
            "rejected_attempts": [
                {"text": "weak draft", "confidence": 0.6, "critique": "x"},
                {"confidence": 0.5},  # no text -> skipped (nothing for DPO sidecar)
            ],
        }
        rejects = build_rejected_trajectories(rec)
        assert len(rejects) == 1
        r = rejects[0]
        assert r.task_family == "fam"           # same family as the accepted run
        assert r.terminal_reward == 0.6          # un-clamped low reward
        assert r.trajectory_id == rejected_trajectory_id(rec, 0)

    def test_rejected_draft_forms_a_dpo_pair_end_to_end(self):
        from maverick.training.ingest import (
            build_rejected_trajectories,
            build_trajectory,
        )
        from maverick.training.rlaif import build_preference_pairs
        from maverick.training.schema import to_klear_jsonl
        rec = {
            "task_brief_hash": "fam", "ts": 7, "outcome": "success", "reward": 1.0,
            "verifier_confidence": 0.92,
            "rejected_attempts": [{"text": "weak", "confidence": 0.5}],
        }
        rows = [to_klear_jsonl(build_trajectory(rec, []))]
        rows += [to_klear_jsonl(t) for t in build_rejected_trajectories(rec)]
        pairs = build_preference_pairs(rows, min_margin=0.25)
        assert len(pairs) == 1
        assert pairs[0]["chosen_reward"] == 1.0 and pairs[0]["rejected_reward"] == 0.5

    def test_candidate_trajectories_scored_by_objective_tests(self):
        """Best-of-N candidates ingest as rows rewarded by their OBJECTIVE test
        score (not the LLM verifier), all in the same task_family. Text-less
        candidates are skipped."""
        from maverick.training.ingest import (
            build_candidate_trajectories,
            candidate_trajectory_id,
        )
        rec = {
            "task_brief_hash": "fam", "ts": 7, "reward": 1.0,
            "scored_candidates": [
                {"text": "diff pass", "score": 1.0, "all_pass": True},
                {"text": "diff fail", "score": 0.0, "all_pass": False},
                {"score": 0.5},  # no text -> skipped (no patch for the sidecar)
            ],
        }
        cands = build_candidate_trajectories(rec)
        assert len(cands) == 2
        assert [c.terminal_reward for c in cands] == [1.0, 0.0]
        assert all(c.task_family == "fam" for c in cands)
        assert cands[0].trajectory_id == candidate_trajectory_id(rec, 0)
        assert cands[0].outcome == "candidate"

    def test_bestofn_candidates_form_a_dpo_pair_end_to_end(self):
        from maverick.training.ingest import build_candidate_trajectories
        from maverick.training.rlaif import build_preference_pairs
        from maverick.training.schema import to_klear_jsonl
        rec = {
            "task_brief_hash": "fam", "ts": 7,
            "scored_candidates": [
                {"text": "the patch that passes tests", "score": 1.0, "all_pass": True},
                {"text": "the patch that fails tests", "score": 0.0, "all_pass": False},
            ],
        }
        rows = [to_klear_jsonl(t) for t in build_candidate_trajectories(rec)]
        pairs = build_preference_pairs(rows, min_margin=0.5)
        assert len(pairs) == 1
        assert pairs[0]["chosen_reward"] == 1.0 and pairs[0]["rejected_reward"] == 0.0
        assert pairs[0]["margin"] == 1.0

    def test_load_donations_empty_dir(self, tmp_path):
        from maverick.training.ingest import load_donations
        out = list(load_donations(tmp_path))
        assert out == []

    def test_load_donations_reads_json(self, tmp_path):
        import json

        from maverick.training.ingest import load_donations
        (tmp_path / "a.json").write_text(json.dumps({"x": 1, "source_ownership": "unowned"}))
        (tmp_path / "b.json").write_text(json.dumps({"x": 2, "source_ownership": "unowned"}))
        records = list(load_donations(tmp_path))
        assert len(records) == 2
        assert {r["x"] for r in records} == {1, 2}

    def test_load_donations_skips_bad_json(self, tmp_path):
        from maverick.training.ingest import load_donations
        (tmp_path / "bad.json").write_text("not valid json")
        (tmp_path / "good.json").write_text('{"x": 1, "source_ownership": "unowned"}')
        records = list(load_donations(tmp_path))
        assert records == [{"x": 1, "source_ownership": "unowned"}]

    def test_fetch_steps_raises_instead_of_returning_a_truncated_trajectory(self, monkeypatch):
        # A DB error on the second page returned the first page as if it were
        # the whole trajectory, which was then trained on as complete.
        from types import SimpleNamespace

        import pytest
        from maverick import memory_ownership, pilot_learning
        from maverick.training.ingest import fetch_steps_for_goal

        monkeypatch.setattr(pilot_learning, "excluded", lambda goal_id: False)
        monkeypatch.setattr(memory_ownership, "source_allowed", lambda *a, **k: True)

        class World:
            def goal_events(self, goal_id, since_id=0, limit=500):
                if since_id:
                    raise OSError("database is locked")
                return [SimpleNamespace(id=i + 1, agent="a", kind="plan", content="x", ts=0.0)
                        for i in range(limit)]

        with pytest.raises(RuntimeError, match="truncated"):
            fetch_steps_for_goal(World(), 7)

    def test_klear_rows_skips_only_the_donation_whose_events_fail(self, tmp_path, monkeypatch):
        import json

        from maverick.training import ingest

        for gid in (1, 2):
            (tmp_path / f"{gid}.json").write_text(json.dumps({
                "goal_id": gid, "source_ownership": "unowned", "task_brief_hash": f"h{gid}",
                "ts": gid, "model_id": "m", "outcome": "success", "reward": 1.0}))
        monkeypatch.setattr(ingest, "load_donations",
                            lambda outbox, world=None: iter(
                                json.loads(p.read_text()) for p in sorted(outbox.glob("*.json"))))

        def fetch(world, gid):
            if gid == 1:
                raise RuntimeError("goal_events failed")
            return []

        monkeypatch.setattr(ingest, "fetch_steps_for_goal", fetch)
        rows = list(ingest.klear_rows(tmp_path, world=object()))
        assert len(rows) == 1
