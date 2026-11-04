"""Actual local files, sealed originals and stopped-task recovery authority."""
from __future__ import annotations

import asyncio
import os

import pytest
from maverick import config
from maverick import task_file_recovery as recovery
from maverick.crypto_at_rest import EncryptionUnavailable
from maverick.paths import tenant_scope
from maverick.sandbox.local import LocalBackend
from maverick.tools.fs import write_text_contained
from maverick.world_model import WorldModel

OWNER = "user:file-owner"


@pytest.fixture
def files(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    home = tmp_path / "private"
    home.mkdir()
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "1")
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL_STRICT", "1")
    root = tmp_path / "task"
    root.mkdir()
    (root / "draft.txt").write_text("original customer draft\n")
    with tenant_scope(tenant="file-workspace"):
        world = WorldModel(home / "world.db")
        goal = world.create_goal("Synthetic file task", owner=OWNER)
        sandbox = LocalBackend(root)
        yield world, goal, sandbox
    config.reset_config_cache()


def recorded(files):
    world, goal, sandbox = files
    with recovery.run_scope(world, goal, sandbox):
        recovery.begin_capture(world, goal)
        write_text_contained(sandbox, sandbox.workdir / "draft.txt", "revised by task\n")
        write_text_contained(sandbox, sandbox.workdir / "new.txt", "new task file\n")
    world.set_goal_status(goal, status="done", result="Synthetic task complete")
    return recovery.preview(world, goal, OWNER)


def restore(files, review, request_id="reviewed-request-1"):
    world, goal, _ = files
    return recovery.revert(world, goal, OWNER, version=review["version"], request_id=request_id, confirm=True)


def test_real_original_preview_drift_refusal_new_review_restore_and_lost_reply(files):
    world, goal, sandbox = files
    review = recorded(files)
    from maverick.workspace_journal import journal_root
    assert not list(journal_root().rglob("*.pre")), "Protected capture must not duplicate private originals into the legacy plaintext journal"
    assert [row["path"] for row in review["files"]] == ["draft.txt", "new.txt"]
    assert "original customer draft" in review["files"][0]["diff"]
    assert str(sandbox.workdir) not in str(review)
    (sandbox.workdir / "draft.txt").write_text("edited after review")
    with pytest.raises(recovery.RecoveryConflict, match="changed after review"):
        restore(files, review)
    assert (sandbox.workdir / "draft.txt").read_text() == "edited after review"
    latest = recovery.preview(world, goal, OWNER)
    receipt = restore(files, latest)
    assert receipt["state"] == "complete" and receipt["files"] == 2
    assert (sandbox.workdir / "draft.txt").read_text() == "original customer draft\n"
    assert not (sandbox.workdir / "new.txt").exists()
    assert restore(files, latest) == receipt
    assert "original customer draft" not in (recovery._directory(recovery._key(world, goal)) / "manifest.sealed").read_text(errors="ignore")


def test_foreign_owner_running_and_second_task_in_same_folder_refused(files):
    world, goal, sandbox = files
    recorded(files)
    with pytest.raises(PermissionError):
        recovery.preview(world, goal, "user:foreign")
    world.set_goal_status(goal, status="running")
    with pytest.raises(recovery.RecoveryConflict, match="Stop the task"):
        recovery.preview(world, goal, OWNER)
    world.set_goal_status(goal, status="done")
    other = world.create_goal("Other active task", owner=OWNER)
    with recovery.run_scope(world, other, sandbox):
        with pytest.raises(recovery.RecoveryConflict, match="still running"):
            recovery.preview(world, goal, OWNER)
    from types import SimpleNamespace
    with recovery.run_scope(world, other, SimpleNamespace(workdir=sandbox.workdir)):
        with pytest.raises(recovery.RecoveryConflict, match="still running"):
            recovery.preview(world, goal, OWNER)


def test_same_thread_async_run_lease_is_not_reentrant(files):
    world, goal, sandbox = files
    async def attempt():
        await asyncio.sleep(0)
        with pytest.raises(recovery.RecoveryConflict):
            with recovery.run_scope(world, goal, sandbox):
                pytest.fail("A second coroutine entered the active task")
    async def exercise():
        with recovery.run_scope(world, goal, sandbox):
            await asyncio.create_task(attempt())
    asyncio.run(exercise())


def test_interruption_retries_exact_intent_without_overwriting_newer_change(files, monkeypatch):
    world, goal, sandbox = files
    review = recorded(files)
    apply = recovery._apply
    calls = []
    def interrupted(root, relative, raw, identity=None):
        calls.append(relative)
        if len(calls) == 2:
            raise OSError("synthetic interruption")
        apply(root, relative, raw, identity)
    monkeypatch.setattr(recovery, "_apply", interrupted)
    with pytest.raises(OSError):
        restore(files, review)
    with pytest.raises(recovery.RecoveryConflict, match="interrupted"):
        with recovery.run_scope(world, goal, sandbox):
            pytest.fail("Restart raced unfinished recovery")
    (sandbox.workdir / "new.txt").write_text("manual correction")
    with pytest.raises(recovery.RecoveryConflict, match="changed during interrupted"):
        restore(files, review)
    (sandbox.workdir / "new.txt").write_text("new task file\n")
    monkeypatch.setattr(recovery, "_apply", apply)
    assert restore(files, review)["state"] == "complete"


def test_missing_or_corrupt_original_and_hardlink_refused(files):
    world, goal, sandbox = files
    review = recorded(files)
    key = recovery._key(world, goal)
    record = recovery._load(key)
    blob = recovery._directory(key) / record["files"]["draft.txt"]["blob"]
    original = blob.read_bytes()
    blob.write_bytes(b"invalid ciphertext")
    with pytest.raises(EncryptionUnavailable):
        restore(files, review)
    assert (sandbox.workdir / "draft.txt").read_text() == "revised by task\n"
    blob.write_bytes(original)
    os.link(sandbox.workdir / "draft.txt", sandbox.workdir / "alias.txt")
    with pytest.raises(recovery.RecoveryConflict, match="single-link"):
        recovery.preview(world, goal, OWNER)


def test_a_later_file_changed_between_restore_steps_is_not_overwritten(files, monkeypatch):
    _, _, sandbox = files
    review = recorded(files)
    apply = recovery._apply
    def change_later_file(root, relative, raw, identity=None):
        apply(root, relative, raw, identity)
        if relative == "draft.txt":
            (sandbox.workdir / "new.txt").write_text("new outside correction")
    monkeypatch.setattr(recovery, "_apply", change_later_file)
    with pytest.raises(recovery.RecoveryConflict, match="changed after recovery started"):
        restore(files, review)
    assert (sandbox.workdir / "new.txt").read_text() == "new outside correction"


def test_pending_job_and_replaced_root_refuse_recovery(files):
    from maverick.job_queue import JobQueue
    world, goal, sandbox = files
    review = recorded(files)
    queue = JobQueue()
    job = queue.enqueue("run_goal", {"goal_id": goal})
    with pytest.raises(recovery.RecoveryConflict, match="pending or running"):
        restore(files, review)
    queue.complete(job)
    original = sandbox.workdir.with_name("original-folder")
    sandbox.workdir.rename(original)
    sandbox.workdir.mkdir()
    with pytest.raises(recovery.RecoveryConflict, match="folder was replaced"):
        restore(files, review)


def test_preflight_keeps_pinned_root_identity_for_actual_reads(files):
    world, goal, sandbox = files
    recorded(files)
    root_identity = recovery._load(recovery._key(world, goal))["root_identity"]
    sandbox.workdir.rename(sandbox.workdir.with_name("prior-root"))
    sandbox.workdir.mkdir()
    (sandbox.workdir / "draft.txt").write_text("replacement")
    with pytest.raises(recovery.RecoveryConflict, match="folder was replaced"):
        recovery._read(sandbox.workdir, "draft.txt", root_identity)


def test_disabled_capture_does_not_promote_legacy_journal(files, monkeypatch):
    world, goal, sandbox = files
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "0")
    with recovery.run_scope(world, goal, sandbox):
        recovery.begin_capture(world, goal)
        write_text_contained(sandbox, sandbox.workdir / "draft.txt", "not captured")
    world.set_goal_status(goal, status="done")
    with pytest.raises(recovery.RecoveryConflict, match="No protected"):
        recovery.preview(world, goal, OWNER)


def test_task_lease_excludes_a_second_actual_process(files):
    import subprocess
    import sys
    world, goal, _ = files
    key = recovery._key(world, goal)
    script = "import sys\nfrom maverick.task_file_recovery import _lease,RecoveryConflict\ntry:\n with _lease(sys.argv[1]): pass\nexcept RecoveryConflict: sys.exit(3)\n"
    with recovery._lease(key):
        child = subprocess.run([sys.executable, "-c", script, key], capture_output=True, text=True, timeout=15)
    assert child.returncode == 3, child.stderr
    child = subprocess.run([sys.executable, "-c", script, key], capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr


@pytest.mark.asyncio
async def test_actual_orchestrator_file_tool_captures_for_named_owner(files, fake_llm, make_llm_response):
    from maverick.budget import Budget
    from maverick.llm import ToolCall
    from maverick.orchestrator import run_goal
    world, goal, sandbox = files
    fake_llm.scripted = [
        make_llm_response(tool_calls=[ToolCall(id="write-1", name="write_file", input={"path": "draft.txt", "content": "actual tool revision"})]),
        make_llm_response(text="FINAL: Synthetic local draft updated"),
        make_llm_response(text='{"confidence":0.95,"accepts":true,"critique":"ok","issues":[]}'),
        make_llm_response(text="FINAL: no skill"),
    ]
    result = await run_goal(fake_llm, world, Budget(max_dollars=1), goal, sandbox=sandbox, user_id="file-owner", max_depth=1)
    assert "DONE" in result
    assert (sandbox.workdir / "draft.txt").read_text() == "actual tool revision"
    reviewed = recovery.preview(world, goal, OWNER)
    assert reviewed["files"][0]["path"] == "draft.txt"
    assert restore(files, reviewed)["state"] == "complete"
    assert (sandbox.workdir / "draft.txt").read_text() == "original customer draft\n"


def test_new_run_bounds_original_storage_and_preserves_prior_receipt(files):
    world, goal, sandbox = files
    first = recorded(files)
    receipt = restore(files, first)
    directory = recovery._directory(recovery._key(world, goal))
    old_blobs = set(directory.glob("*-*.sealed"))
    with recovery.run_scope(world, goal, sandbox):
        recovery.begin_capture(world, goal)
        write_text_contained(sandbox, sandbox.workdir / "draft.txt", "second run revision")
    world.set_goal_status(goal, "done")
    assert all(not path.exists() for path in old_blobs)
    assert len(list(directory.glob("*-*.sealed"))) == 1
    assert restore(files, first) == receipt
    assert (sandbox.workdir / "draft.txt").read_text() == "second run revision"
