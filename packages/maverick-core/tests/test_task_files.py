"""Files a task saves are offered on its page exactly as the task left them.

Seen live: asked for totals.csv, the agent wrote it and linked
``sandbox:/…/totals.csv``; the link rendered as plain text and nothing could
serve the file. The workspace is shared by every task, so a download is bound
to the bytes this task recorded, never to whatever the folder holds now.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from maverick import task_files
from maverick.tools.fs import deliver_file, write_file
from maverick.tools.str_edit import str_replace_editor
from maverick.world_model import WorldModel


@pytest.fixture
def task(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("Make totals.csv", "")
    other = world.create_goal("Another person's task", "")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    yield world, gid, other, SimpleNamespace(workdir=workspace), workspace
    world.close()


def test_a_saved_file_is_listed_and_served_as_saved(task):
    world, gid, other, sandbox, workspace = task
    body = "region,total\nNorth,100\nSouth,200\nEast,300\n"
    assert write_file(sandbox, goal_id=gid, world=world).fn(
        {"path": "out/totals.csv", "content": body}).startswith("wrote")
    (listed,) = task_files.files_for(world, gid)
    assert (listed.number, listed.name, listed.path, listed.size) == (1, "totals.csv", "out/totals.csv", len(body))
    found, data = task_files.read_for_download(world, gid, 1)
    assert data == body.encode() and found.name == "totals.csv"
    assert task_files.files_for(world, other) == []
    with pytest.raises(task_files.TaskFileUnavailable, match="no such file"):
        task_files.read_for_download(world, other, 1)


def test_a_file_changed_or_removed_since_is_not_served(task):
    world, gid, _other, sandbox, workspace = task
    write_file(sandbox, goal_id=gid, world=world).fn({"path": "totals.csv", "content": "a,b\n"})
    (workspace / "totals.csv").write_text("someone else's numbers\n")
    with pytest.raises(task_files.TaskFileUnavailable, match="changed after the task saved it"):
        task_files.read_for_download(world, gid, 1)
    (workspace / "totals.csv").unlink()
    with pytest.raises(task_files.TaskFileUnavailable, match="no longer in the work folder"):
        task_files.read_for_download(world, gid, 1)


def test_a_symlink_swapped_in_cannot_reach_outside_the_workspace(task, tmp_path):
    world, gid, _other, sandbox, workspace = task
    write_file(sandbox, goal_id=gid, world=world).fn({"path": "report.txt", "content": "ok\n"})
    secret = tmp_path / "secret.txt"
    secret.write_text("ok\n")  # same bytes, so only containment can refuse it
    (workspace / "report.txt").unlink()
    os.symlink(secret, workspace / "report.txt")
    with pytest.raises(task_files.TaskFileUnavailable, match="can't be opened safely"):
        task_files.read_for_download(world, gid, 1)


def test_an_edit_updates_what_the_page_serves(task):
    world, gid, _other, sandbox, workspace = task
    write_file(sandbox, goal_id=gid, world=world).fn({"path": "plan.md", "content": "Draft\n"})
    out = str_replace_editor(sandbox, goal_id=gid, world=world).fn(
        {"command": "str_replace", "path": "plan.md", "old_str": "Draft", "new_str": "Final"})
    assert out.startswith("edited"), out
    (listed,) = task_files.files_for(world, gid)  # one entry per path
    assert task_files.read_for_download(world, gid, listed.number)[1] == b"Final\n"


def test_a_file_a_command_made_is_offered_with_deliver_file(task):
    world, gid, _other, sandbox, workspace = task
    (workspace / "chart.png").write_bytes(b"\x89PNG fake")
    tool = deliver_file(sandbox, gid, world)
    assert "is now a download on the task's page" in tool.fn({"path": "chart.png"})
    assert [f.name for f in task_files.files_for(world, gid)] == ["chart.png"]
    (workspace / "folder").mkdir()
    assert tool.fn({"path": "folder"}).startswith("ERROR")
    assert tool.fn({"path": "../outside.txt"}).startswith("ERROR")
    assert deliver_file(sandbox, None, world).fn({"path": "chart.png"}).startswith("ERROR")


def test_an_answer_link_matches_only_this_tasks_files(task):
    world, gid, _other, sandbox, workspace = task
    write_file(sandbox, goal_id=gid, world=world).fn({"path": "totals.csv", "content": "x\n"})
    files = task_files.files_for(world, gid)
    absolute = f"sandbox:{workspace.resolve()}/totals.csv"
    for link in (absolute, "sandbox:totals.csv", "sandbox:/workspace/totals.csv", "totals.csv"):
        assert task_files.sandbox_link_number(files, link) == 1, link
    assert task_files.sandbox_link_number(files, "sandbox:/etc/passwd") is None
    assert task_files.sandbox_link_number(files, "sandbox:other.csv") is None


def test_records_are_found_past_the_first_page_of_events(task):
    world, gid, _other, sandbox, workspace = task
    for n in range(620):
        world.append_event(gid, "orchestrator", "observation", f"step {n}")
    write_file(sandbox, goal_id=gid, world=world).fn({"path": "late.txt", "content": "late\n"})
    assert [f.name for f in task_files.files_for(world, gid)] == ["late.txt"]


def test_without_a_world_nothing_is_recorded(task):
    world, gid, _other, sandbox, workspace = task
    assert write_file(sandbox, goal_id=gid).fn({"path": "a.txt", "content": "a"}).startswith("wrote")
    assert task_files.files_for(world, gid) == []


def test_a_markdown_draft_of_a_document_is_not_offered_unless_delivered(task):
    # Live: asked for an updated NDA as a Word file, the agent wrote its
    # Markdown draft and then the .docx; both were offered, the draft first.
    world, gid, _other, sandbox, workspace = task
    write = write_file(sandbox, goal_id=gid, world=world)
    assert write.fn({"path": "nda.md", "content": "# NDA\n\nTerm: 3 years.\n"}).startswith("wrote")
    assert write.fn({"path": "nda.docx", "content": "# NDA\n\nTerm: 3 years.\n"}).startswith("wrote a Word")
    assert write.fn({"path": "notes/nda.md", "content": "other folder\n"}).startswith("wrote")
    assert write.fn({"path": "summary.md", "content": "no document of this name\n"}).startswith("wrote")
    listed = task_files.files_for(world, gid)
    assert [(f.number, f.path) for f in listed] == [(1, "nda.docx"), (2, "notes/nda.md"), (3, "summary.md")]
    assert task_files.read_for_download(world, gid, 1)[0].name == "nda.docx"
    # Handed over on purpose, the draft is offered too.
    deliver_file(sandbox, gid, world).fn({"path": "nda.md"})
    assert [f.path for f in task_files.files_for(world, gid)] == ["nda.md", "nda.docx", "notes/nda.md", "summary.md"]
