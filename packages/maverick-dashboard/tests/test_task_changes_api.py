"""'What changed during this task': before/now for the task's own files only.

The journal's records are editable files, so these tests forge records that
point outside the task's work folder -- by ``..``, absolute names, a foreign
folder, a link on the way or at the end, a hard link, or a linked saved copy --
and check none of that content ever reaches the response.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config, workspace_journal
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.paths import tenant_scope
from maverick.sandbox.local import LocalBackend
from maverick.tools.fs import write_text_contained
from maverick.world_model import WorldModel
from maverick_dashboard import page_assets, rbac
from maverick_dashboard import task_changes_api as changes_api
from maverick_dashboard import task_file_recovery_api as recovery_api

OUTSIDE_TEXT = "Private words kept outside the work folder"
TENANT = "file-workspace"


@pytest.fixture
def env(tmp_path, monkeypatch):
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "private"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(OUTSIDE_TEXT)
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[sandbox]\nworkdir = "{work.as_posix()}"\n')
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_WORKSPACE_JOURNAL", "1")
    config.reset_config_cache()
    workspace_journal._reset_for_tests()
    rbac.set_role("user:owner", "operator")
    rbac.set_role("user:foreign", "admin")
    rbac.set_role("user:viewer", "viewer")
    from maverick_dashboard import app as dashboard
    world = WorldModel(tmp_path / "world.db")
    goal = world.create_goal("Synthetic task changes", owner="user:owner")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    application = FastAPI()

    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", TENANT)):
            return await call_next(request)

    application.include_router(recovery_api.router)
    application.include_router(changes_api.router)
    application.include_router(page_assets.router)
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield SimpleNamespace(client=client, goal=goal, work=work, outside=outside, home=home, cfg=cfg,
                              url=f"/api/v1/task-files/{goal}/changes")
    config.reset_config_cache()
    workspace_journal._reset_for_tests()


def _task_writes(env, writes):
    """Write files through the real file tool inside this task's context."""
    sandbox = LocalBackend(env.work)
    with tenant_scope(tenant=TENANT):
        tokens = set_goal_context(goal_id=env.goal)
        try:
            for name, text in writes:
                write_text_contained(sandbox, sandbox.workdir.resolve() / name, text)
        finally:
            reset_goal_context(tokens)


def _forge(env, seq, **record):
    """Hand-write a journal record, as someone with file access could."""
    with tenant_scope(tenant=TENANT):
        folder = workspace_journal.goal_dir(env.goal)
    folder.mkdir(parents=True, exist_ok=True)
    row = {"seq": seq, "ts": 1, "path": "x.txt", "workdir": str(env.work.resolve()), "existed": False,
           "pre_bytes": 0, "pre_sha256": "", "blob": False, "skipped_reason": ""}
    row.update(record)
    (folder / f"{seq:06d}.json").write_text(json.dumps(row))
    return folder


def test_before_and_now_for_files_the_task_changed(env):
    (env.work / "notes.txt").write_text("first line\nsecond line\nthird line\n")
    (env.work / "logo.bin").write_bytes(b"\x00\x01\x02")
    _task_writes(env, [("notes.txt", "first line\nchanged line\nthird line\n"), ("new.txt", "brand new\n")])
    # The file tool writes text; make a binary change the same journaled way.
    with tenant_scope(tenant=TENANT):
        tokens = set_goal_context(goal_id=env.goal)
        try:
            workspace_journal.record_pre_image(env.work.resolve(), env.work.resolve() / "logo.bin")
        finally:
            reset_goal_context(tokens)
    (env.work / "logo.bin").write_bytes(b"\x00\x09\x02")

    response = env.client.get(env.url)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    data = response.json()
    assert data["available"] is True and data["left_out"] == 0
    rows = {row["name"]: row for row in data["files"]}
    assert set(rows) == {"notes.txt", "new.txt", "logo.bin"}
    notes = rows["notes.txt"]
    assert notes["change"] == "edited"
    assert {"kind": "remove", "text": "second line"} in notes["lines"]
    assert {"kind": "add", "text": "changed line"} in notes["lines"]
    assert rows["new.txt"]["change"] == "created"
    assert rows["new.txt"]["lines"] == [{"kind": "gap", "text": ""}, {"kind": "add", "text": "brand new"}]
    assert rows["logo.bin"] == {"name": "logo.bin", "change": "binary", "lines": [], "shortened": False}
    assert str(env.work) not in response.text and str(env.home) not in response.text


def test_forged_records_never_expose_files_outside_the_work_folder(env):
    (env.work / "sub").mkdir()
    os.link(env.outside / "secret.txt", env.work / "hard.txt")
    _forge(env, 1, path="../outside/secret.txt")
    _forge(env, 2, path="sub/../../outside/secret.txt")
    _forge(env, 3, path=str(env.outside / "secret.txt"))
    _forge(env, 4, path="secret.txt", workdir=str(env.outside))
    _forge(env, 7, path="hard.txt")
    _forge(env, 8, path="C:/Windows/win.ini")

    response = env.client.get(env.url)
    assert response.status_code == 200, response.text
    assert OUTSIDE_TEXT not in response.text
    assert response.json()["left_out"] == 6
    assert response.json()["files"] == []


def _symlink(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        if os.name == "nt" and exc.winerror == 1314:
            pytest.skip("Windows host does not grant symbolic-link creation privileges")
        raise


def test_symbolic_links_never_expose_outside_files_or_saved_copies(env):
    _symlink(env.work / "link.txt", env.outside / "secret.txt")
    _symlink(env.work / "linked-dir", env.outside, directory=True)
    _forge(env, 5, path="link.txt")
    _forge(env, 6, path="linked-dir/secret.txt")
    # A saved "earlier copy" that is really a link to a file outside.
    (env.work / "real.txt").write_text("now")
    folder = _forge(env, 9, path="real.txt", existed=True, blob=True)
    _symlink(folder / "000009.pre", env.outside / "secret.txt")

    response = env.client.get(env.url)
    assert response.status_code == 200, response.text
    assert OUTSIDE_TEXT not in response.text
    data = response.json()
    assert data["left_out"] == 2
    assert data["files"] == [{"name": "real.txt", "change": "not_saved", "lines": [], "shortened": False}]


def test_broad_or_remote_work_folders_are_refused(env):
    _task_writes(env, [("a.txt", "one\n")])
    env.cfg.write_text(f'[sandbox]\nworkdir = "{env.home.as_posix()}"\n')
    config.reset_config_cache()
    data = env.client.get(env.url).json()
    assert data["available"] is False and "too broad" in data["message"] and data["files"] == []
    env.cfg.write_text(f'[sandbox]\nworkdir = "{Path(env.work.anchor).as_posix()}"\n')
    config.reset_config_cache()
    assert "too broad" in env.client.get(env.url).json()["message"]
    env.cfg.write_text(f'[sandbox]\nbackend = "ssh"\nworkdir = "{env.work.as_posix()}"\n')
    config.reset_config_cache()
    assert "another computer" in env.client.get(env.url).json()["message"]
    env.cfg.write_text(f'[sandbox]\nworkdir = "{env.work.as_posix()}"\n')
    config.reset_config_cache()
    # A history folder shared by every workspace is not shown for one of them.
    shared = env.home.parent / "shared-history"
    env.cfg.write_text(f'[sandbox]\nworkdir = "{env.work.as_posix()}"\n[workspace]\njournal_dir = "{shared.as_posix()}"\n')
    config.reset_config_cache()
    data = env.client.get(env.url).json()
    assert data["available"] is False and "shared between workspaces" in data["message"]


def test_linked_journal_folder_is_refused(env):
    _task_writes(env, [("a.txt", "one\n")])
    with tenant_scope(tenant=TENANT):
        folder = workspace_journal.goal_dir(env.goal)
    moved = folder.with_name("elsewhere")
    folder.rename(moved)
    _symlink(folder, moved, directory=True)
    data = env.client.get(env.url).json()
    assert data["available"] is False and "can't be read safely" in data["message"]


def test_owner_permission_and_workspace_scoping(env):
    _task_writes(env, [("a.txt", "one\n")])
    assert env.client.get(env.url, headers={"X-Test-User": "foreign"}).status_code == 404
    assert env.client.get(env.url, headers={"X-Test-User": "viewer"}).status_code == 403
    other = env.client.get(env.url, headers={"X-Test-Tenant": "another-workspace"})
    assert other.status_code == 200 and other.json()["files"] == []
    assert env.client.get("/api/v1/task-files/999999/changes").status_code == 404
    mine = env.client.get(env.url).json()
    assert [row["name"] for row in mine["files"]] == ["a.txt"]


def test_no_history_says_so_and_page_offers_the_view_plainly(env):
    from test_support.plain_language import developer_terms, visible_text

    data = env.client.get(env.url).json()
    assert {key: data[key] for key in ("available", "files", "left_out", "more", "incomplete")} == {
        "available": True, "files": [], "left_out": 0, "more": 0, "incomplete": False}
    page = env.client.get(f"/chat/goal/{env.goal}/files")
    assert page.status_code == 200
    assert "What changed during this task" in page.text and 'id="tc-show"' in page.text
    assert "in-between versions can't be compared" in visible_text(page.text)
    assert "/static/lightwork-task-changes.js" in page.text
    assert developer_terms(page.text) == []
    script = env.client.get("/static/lightwork-task-changes.js")
    assert script.status_code == 200 and "task-changes" in script.text


def test_file_and_line_bounds(env, monkeypatch):
    monkeypatch.setattr(changes_api, "MAX_FILES", 2)
    monkeypatch.setattr(changes_api, "MAX_LINES_PER_FILE", 3)
    (env.work / "big.txt").write_text("x" * (changes_api.MAX_FILE_BYTES + 10))
    _task_writes(env, [("a.txt", "1\n2\n3\n4\n5\n"), ("b.txt", "b\n"), ("c.txt", "c\n")])
    data = env.client.get(env.url).json()
    assert len(data["files"]) == 2 and data["more"] == 1
    assert data["files"][0]["shortened"] is True and len(data["files"][0]["lines"]) == 3
    monkeypatch.setattr(changes_api, "MAX_FILES", 100)
    _task_writes(env, [("big.txt", "small now\n")])
    rows = {row["name"]: row for row in env.client.get(env.url).json()["files"]}
    assert rows["big.txt"]["change"] == "too_large" and rows["big.txt"]["lines"] == []
    monkeypatch.setattr(changes_api, "MAX_TEXT_LINES", 4)
    rows = {row["name"]: row for row in env.client.get(env.url).json()["files"]}
    assert rows["a.txt"]["change"] == "too_large" and rows["b.txt"]["change"] == "created"
