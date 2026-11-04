"""Atomic answer/evidence regression cases; execution coordinated after implementation."""
import hashlib

import pytest
from maverick.attachment_submissions import SubmissionConflict
from maverick.attachments import Stored
from maverick.chat_threads import ChatThreads, question_version
from maverick.world_model import WorldModel


@pytest.fixture
def prepared(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        goal_id = world.create_goal("Review the supplied evidence", owner="user:alice")
        question_id = world.ask("Which signed evidence should I use?", goal_id=goal_id)
        world.set_goal_status(goal_id, "blocked")
        q = world.open_questions(goal_id=goal_id)[0]
        data = b"Evidence contents"
        path = tmp_path / "evidence.txt"
        path.write_bytes(data)
        record = Stored("evidence.txt", "text/plain", len(data), hashlib.sha256(data).hexdigest(), path)
        yield world, goal_id, question_id, question_version(q.id, q.asked_at, q.question), record


def answer(prepared, publish, **overrides):
    world, goal, question, version, record = prepared
    values = dict(expected_question=version, operation_id="answer-operation-one", actor="user:alice",
                  request_hash="a" * 64, records=[record], publish=publish,
                  require_admission=lambda: None, require_authority=lambda: None)
    values.update(overrides)
    return ChatThreads(world).answer_with_evidence(goal, question, "Use the selected evidence.", **values)


def test_files_are_admitted_before_answer_and_restart_and_replay_is_once(prepared):
    world, goal, _, _, record = prepared
    published = []
    def publish(value):
        assert world.get_goal(goal).status == "blocked"
        assert world.open_questions(goal_id=goal)
        published.append(value)
        return value
    result = answer(prepared, publish)
    assert result["admitted"] and not result["replayed"]
    assert not world.open_questions(goal_id=goal)
    assert world.get_goal(goal).status == "pending"
    assert world.list_attachments(goal)[0].sha256 == record.sha256
    repeated = answer(prepared, publish)
    assert repeated["replayed"] and repeated["attachment_ids"] == result["attachment_ids"]
    assert len(published) == 1


def test_other_answer_wins_without_publishing_or_misbinding_files(prepared):
    world, goal, question, _, _ = prepared
    world.answer(question, "Other answer")
    def publish(value):
        raise AssertionError("A refused answer must never publish a file")
    with pytest.raises(SubmissionConflict):
        answer(prepared, publish)
    assert world.list_attachments(goal) == []
    assert world.get_goal(goal).status == "blocked"


def test_failed_batch_rolls_back_question_attachment_metadata_and_restart(prepared):
    world, goal, _, _, record = prepared
    second = Stored("second.txt", record.mime, record.size_bytes, record.sha256, record.path)
    def publish(value):
        if value.filename == "second.txt":
            raise OSError("simulated disk interruption")
        return value
    with pytest.raises(OSError):
        answer(prepared, publish, records=[record, second])
    assert world.open_questions(goal_id=goal)
    assert world.list_attachments(goal) == []
    assert world.get_goal(goal).status == "blocked"


def test_stale_question_and_revoked_authority_refuse_before_file_publication(prepared):
    def publish(value):
        raise AssertionError("No publication permitted")
    with pytest.raises(SubmissionConflict):
        answer(prepared, publish, expected_question="b" * 64)
    def denied():
        raise PermissionError("Authority revoked")
    with pytest.raises(PermissionError):
        answer(prepared, publish, require_authority=denied)
