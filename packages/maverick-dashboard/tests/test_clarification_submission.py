"""Multipart answer admission through native routes; providers never invoked."""
import pytest
from fastapi.testclient import TestClient
from maverick import attachments
from maverick.world_model import WorldModel
from maverick_dashboard import api, draft_api
from maverick_dashboard import app as dashboard
from maverick_dashboard import clarification_submission as submissions


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(attachments, "DEFAULT_ROOT", tmp_path / "attachments")
    monkeypatch.setattr(attachments, "s3_mirror_enabled", lambda: False)
    monkeypatch.setattr(submissions, "require_permission", lambda *args: None)
    monkeypatch.setattr(submissions, "caller_principal", lambda *args: None)
    monkeypatch.setattr(draft_api, "context_for", lambda *args: "test-context")
    monkeypatch.setattr(api, "_require_goal_restart_admission", lambda *args: None)
    with WorldModel(tmp_path / "world.db") as world:
        monkeypatch.setattr(api, "_world", lambda: world)
        monkeypatch.setattr(dashboard, "_world", lambda: world)
        goal_id = world.create_goal("Use the selected evidence")
        question_id = world.ask("Which evidence should I use?", goal_id=goal_id)
        world.set_goal_status(goal_id, "blocked")
        runs = []
        def dispatch(request, bg, goal_id, **kwargs):
            assert not world.open_questions(goal_id=goal_id)
            rows = world.list_attachments(goal_id)
            assert rows and all(attachments.read_bytes(row.path) for row in rows)
            runs.append(goal_id)
        monkeypatch.setattr(api, "_dispatch_requeued_goal", dispatch)
        from maverick.chat_threads import question_version
        q = world.open_questions(goal_id=goal_id)[0]
        version = question_version(q.id, q.asked_at, q.question)
        client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
        yield client, world, goal_id, question_id, runs, version


def send(environment, *, name="evidence.pdf", data=b"%PDF-1.4\n%%EOF", mime="application/pdf", **overrides):
    client, _, goal, question, _, version = environment
    fields = {"question_id":question, "expected_question":version, "answer":"Use this evidence.",
              "operation_id":"answer-operation-one", "expected_context":"test-context"}
    fields.update(overrides)
    return client.post(f"/api/v1/goals/{goal}/answer-with-files", data=fields,
                       files={"files":(name,data,mime)})


def test_pdf_is_readable_before_one_restart_and_exact_replay_is_one_receipt(environment):
    _, world, goal, _, runs, _ = environment
    first = send(environment)
    assert first.status_code == 200 and first.json()["received"]
    repeated = send(environment)
    assert repeated.status_code == 200 and repeated.json()["replayed"]
    assert runs == [goal] and len(world.list_attachments(goal)) == 1


def test_malformed_upload_leaves_question_open_and_does_not_restart(environment):
    _, world, goal, _, runs, _ = environment
    response = send(environment, name="blocked.exe", data=b"MZ blocked", mime="application/x-msdownload")
    assert response.status_code == 400
    assert world.open_questions(goal_id=goal) and not world.list_attachments(goal) and not runs


def test_concurrent_answer_never_publishes_selected_files(environment, monkeypatch):
    _, world, goal, question, runs, _ = environment
    original = submissions._prepare
    def prepare(*args):
        world.answer(question, "Another answer won")
        return original(*args)
    monkeypatch.setattr(submissions, "_prepare", prepare)
    response = send(environment)
    assert response.status_code == 409 and not runs and not world.list_attachments(goal)
    assert not [path for path in attachments.DEFAULT_ROOT.glob("**/*") if path.is_file()]


def test_workspace_change_refuses_before_admission(environment):
    _, world, goal, _, runs, _ = environment
    response = send(environment, expected_context="earlier-workspace")
    assert response.status_code == 409 and response.json()["detail"]["code"] == "context_changed"
    assert world.open_questions(goal_id=goal) and not runs


def test_clarification_prepares_document_without_mirroring_before_admission(tmp_path, monkeypatch):
    import hashlib

    data = b"{\\rtf1 example evidence}"
    staged = tmp_path / "staged-upload"
    staged.write_bytes(data)
    record = attachments.Stored("evidence.rtf", "application/rtf", len(data), hashlib.sha256(data).hexdigest(), staged)
    monkeypatch.setattr(attachments, "s3_mirror_enabled", lambda: True)
    monkeypatch.setattr(attachments, "_s3_mirror", lambda *args: pytest.fail("staging must not mirror files"))
    monkeypatch.setattr(attachments, "_extract_document", lambda path: "example evidence")
    result = submissions._prepare([record], 7, tmp_path / "prepared")
    assert [item.filename for item in result] == ["evidence.rtf", "evidence.rtf.extracted.txt"]
    assert submissions._read_staged(result[1]) == b"example evidence"
