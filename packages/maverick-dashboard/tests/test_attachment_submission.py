"""Actual chat/REST admission and interrupted-upload recovery, no paid work."""
from __future__ import annotations

import asyncio
import io
import re
from html import unescape

import pytest
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient
from maverick import attachments
from maverick.attachment_submissions import SubmissionStore
from maverick.world_model import WorldModel
from maverick_dashboard import app as dashboard
from maverick_dashboard import attachment_submission as submissions
from starlette.datastructures import Headers


@pytest.fixture
def environment(monkeypatch, tmp_path):
    from maverick_dashboard import api

    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)
    monkeypatch.setattr(attachments, "DEFAULT_ROOT", tmp_path / "attachments")
    monkeypatch.setattr(attachments, "_transcribe_media", lambda path: None)
    monkeypatch.setattr(attachments, "_extract_document", lambda path: None)
    runs = []

    async def run(goal_id, **kwargs):
        receipt = SubmissionStore(world).for_goal(goal_id)
        runs.append((goal_id, receipt, attachments.content_blocks_for_goal(world, goal_id)))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world, runs
    world.close()


def test_invalid_second_file_creates_no_goal_or_committed_batch(environment):
    client, world, runs = environment
    result = client.post("/chat/send", data={"title": "Read files"}, files=[
        ("files", ("good.txt", b"good", "text/plain")),
        ("files", ("bad.exe", b"MZ executable", "application/x-msdownload")),
    ], follow_redirects=False)
    assert result.status_code == 400
    assert not world.list_goals() and not runs
    assert not list(attachments.DEFAULT_ROOT.glob("*/*"))


def test_same_submission_key_replays_one_goal_attachment_and_run(environment):
    client, world, runs = environment
    def send():
        return client.post("/chat/send", data={"title": "Read files", "submission_key": "retry-token"},
                           files={"files": ("good.txt", b"good", "text/plain")}, follow_redirects=False)
    first, retry = send(), send()
    assert first.status_code == retry.status_code == 303
    assert first.headers["location"] == retry.headers["location"]
    assert len(world.list_goals()) == len(runs) == 1
    assert len(world.list_attachments(runs[0][0])) == 1
    conversation = world.get_or_create_conversation("web", f"local/{runs[0][0]}")
    assert len(world.recent_turns(conversation.id)) == 1
    mismatch = client.post("/chat/send", data={"title": "Different instruction", "submission_key": "retry-token"}, follow_redirects=False)
    assert mismatch.status_code == 409 and len(world.list_goals()) == 1


def test_no_file_preparation_is_not_an_answer_on_page_or_refreshed_panel(environment):
    client, world, runs = environment
    response = client.post("/chat/send", data={"title": "Draft a plan"}, follow_redirects=False)
    assert response.status_code == 303 and len(runs) == 1
    goal_id, receipt, _ = runs[0]
    assert receipt["detail"]["coverage"] == []
    assert not world.get_goal(goal_id).result

    page = client.get(f"/chat/goal/{goal_id}")
    assert page.status_code == 200
    assert 'id="submission-status"' not in page.text
    assert re.search(r'id="result-section"[^>]*display: none', page.text)

    # Older builds stored this preparation notice as goals.result. The live
    # answer-panel refresh must apply the same suppression as the full page.
    world.set_goal_status(goal_id, "pending", result=receipt["detail"]["message"])
    legacy_page = client.get(f"/chat/goal/{goal_id}")
    panel = client.get(f"/chat/goal/{goal_id}/answer-panel")
    assert legacy_page.status_code == panel.status_code == 200
    assert re.search(r'id="result-section"[^>]*display: none', legacy_page.text)
    assert re.search(r'id="result-section"[^>]*display: none', panel.text)

    world.set_goal_status(goal_id, "pending", result="Here is the plan.")
    answer_panel = client.get(f"/chat/goal/{goal_id}/answer-panel")
    assert re.search(r'id="result-section"[^>]*display: block', answer_panel.text)
    assert "Here is the plan." in answer_panel.text


def test_missing_companion_is_explicit_before_runner_and_in_model_context(environment):
    client, world, runs = environment
    response = client.post("/chat/send", data={"title": "Read recording"},
                           files={"files": ("recording.wav", b"RIFF fixture", "audio/wav")}, follow_redirects=False)
    assert response.status_code == 303
    goal_id, receipt, blocks = runs[0]
    assert receipt["state"] == "dispatching"
    assert receipt["detail"]["coverage"][0]["status"] == "unavailable"
    assert "has not been read" in receipt["detail"]["message"]
    assert any("Do not imply that its contents were read" in block.get("text", "") for block in blocks)
    page = client.get(f"/chat/goal/{goal_id}")
    status_panel = re.search(r'<section[^>]*id="submission-status"[^>]*>(.*?)</section>', page.text, re.DOTALL)
    assert status_panel is not None
    # Translation spans and bidi-isolated parameters preserve the readable text.
    visible = unescape(re.sub(r"<[^>]+>", "", status_panel.group(1))).lower()
    assert "recording.wav" in visible and "could not be read (unavailable)" in visible
    assert world.get_goal(goal_id).status == "pending"
    assert not world.get_goal(goal_id).result
    assert re.search(r'id="result-section"[^>]*display: none', page.text)
    # Existing installs may already have stored the preparation message in
    # goals.result. Keep it in the status panel, never in the answer panel.
    world.set_goal_status(goal_id, "pending", result=receipt["detail"]["message"])
    legacy_page = client.get(f"/chat/goal/{goal_id}")
    assert re.search(r'id="result-section"[^>]*display: none', legacy_page.text)


def test_storage_failure_is_recoverable_draft_and_retry_deduplicates(environment, monkeypatch):
    client, world, runs = environment
    publish = submissions.publish_batch
    monkeypatch.setattr(submissions, "publish_batch", lambda *args: (_ for _ in ()).throw(OSError("disk failed")))
    args = {"title": "Read files", "submission_key": "interrupted"}
    first = client.post("/chat/send", data=args, files={"files": ("good.txt", b"good", "text/plain")}, follow_redirects=False)
    assert first.status_code == 409 and not runs
    goal = world.list_goals()[0]
    assert goal.status == "draft"
    page = client.get(f"/chat/goal/{goal.id}")
    assert "Submission saved as a draft" in page.text and "Retry preparation" in page.text
    retry_missing = client.post(f"/chat/goal/{goal.id}/recover-submission", follow_redirects=False)
    assert retry_missing.status_code == 409 and not runs
    monkeypatch.setattr(submissions, "publish_batch", publish)
    retry = client.post("/chat/send", data=args, files={"files": ("good.txt", b"good", "text/plain")}, follow_redirects=False)
    assert retry.status_code == 303 and len(world.list_goals()) == 1 and len(runs) == 1


def test_rest_retry_deduplicates_identical_attachment(environment):
    client, world, _ = environment
    goal = world.create_goal("Files")
    first = client.post(f"/api/v1/goals/{goal}/attachments", files={"file": ("good.txt", b"good", "text/plain")})
    retry = client.post(f"/api/v1/goals/{goal}/attachments", files={"file": ("good.txt", b"good", "text/plain")})
    assert first.status_code == retry.status_code == 201
    assert first.json()["id"] == retry.json()["id"]
    assert len(world.list_attachments(goal)) == 1


def test_admitted_submission_recovers_after_background_was_never_started(environment):
    client, world, runs = environment
    upload = UploadFile(file=io.BytesIO(b"good"), filename="x.txt", headers=Headers({"content-type": "text/plain"}))
    receipt = asyncio.run(submissions.submit(world, [upload], token="lost-response", owner="", title="Retry", description="Retry"))
    upload.file.close()
    assert receipt["state"] == "admitted" and world.get_goal(receipt["goal_id"]).status == "draft"
    recovered = client.post(f"/chat/goal/{receipt['goal_id']}/recover-submission", follow_redirects=False)
    assert recovered.status_code == 303 and len(runs) == 1
    duplicate = client.post(f"/chat/goal/{receipt['goal_id']}/recover-submission", follow_redirects=False)
    assert duplicate.status_code == 409 and len(runs) == 1


def test_changed_admitted_file_blocks_preparation_and_remains_a_draft(environment):
    _, world, runs = environment
    upload = UploadFile(file=io.BytesIO(b"good"), filename="x.txt", headers=Headers({"content-type": "text/plain"}))
    receipt = asyncio.run(submissions.submit(world, [upload], token="changed-file", owner="", title="Retry", description="Retry"))
    upload.file.close()
    source = world.list_attachments(receipt["goal_id"])[0]
    from pathlib import Path
    Path(source.path).write_bytes(b"changed after admission")
    assert not submissions.prepare(world, receipt)
    assert world.get_goal(receipt["goal_id"]).status == "draft" and not runs
    assert "missing or changed" in SubmissionStore(world).for_goal(receipt["goal_id"])["detail"]["message"]


def test_partial_publication_never_commits_partial_metadata_or_starts_work(environment, monkeypatch):
    client, world, runs = environment
    publish = attachments._publish_attachment
    def fail_second(path, data, digest):
        if path.name.endswith("second.txt"):
            raise OSError("second file storage failed")
        return publish(path, data, digest)
    monkeypatch.setattr(attachments, "_publish_attachment", fail_second)
    response = client.post("/chat/send", data={"title": "Batch", "submission_key": "batch-failure"}, files=[
        ("files", ("first.txt", b"first", "text/plain")),
        ("files", ("second.txt", b"second", "text/plain")),
    ], follow_redirects=False)
    assert response.status_code == 409 and not runs
    goal = world.list_goals()[0]
    assert goal.status == "draft" and world.list_attachments(goal.id) == []
    receipt = SubmissionStore(world).for_goal(goal.id)
    assert [item["filename"] for item in receipt["detail"]["manifest"]] == ["first.txt", "second.txt"]
    assert all(not path.is_dir() for path in submissions.data_dir("attachment-staging").glob("batch-*"))


def test_upload_reads_are_bounded_without_content_length(monkeypatch):
    monkeypatch.setattr(attachments, "MAX_FILE_BYTES", 7)

    class Upload:
        filename, content_type = "x.txt", "text/plain"
        def __init__(self):
            self.read_sizes = []
        async def read(self, size):
            self.read_sizes.append(size)
            return b"x" * size  # never-ending stream, no trusted Content-Length

    upload = Upload()
    async def attempt():
        async with submissions.stage_uploads([upload]):
            pytest.fail("oversized stream admitted")
    with pytest.raises(HTTPException, match="size"):
        asyncio.run(attempt())
    assert upload.read_sizes == [8]


def test_interruption_cleans_stage_and_retry_creates_one_goal(environment):
    _, world, _ = environment
    stages = []

    class Interrupted:
        filename, content_type = "x.txt", "text/plain"
        async def read(self, size):
            stages.extend(submissions.data_dir("attachment-staging").glob("batch-*"))
            raise ConnectionResetError("client disconnected")

    async def attempt(files):
        return await submissions.submit(world, files, token="disconnected", owner="", title="Retry", description="Retry")
    with pytest.raises(ConnectionResetError):
        asyncio.run(attempt([Interrupted()]))
    assert stages and all(not path.exists() for path in stages)
    assert world.list_goals() == []
    upload = UploadFile(file=io.BytesIO(b"good"), filename="x.txt", headers=Headers({"content-type": "text/plain"}))
    receipt = asyncio.run(attempt([upload]))
    assert receipt["state"] == "admitted" and len(world.list_goals()) == 1
    upload.file.close()
