"""Each chat conversation works in its own folder (maverick.task_workspace)."""
from __future__ import annotations

import pytest


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from maverick import config
    from maverick.world_model import WorldModel

    shared = tmp_path / "workspace"
    shared.mkdir()
    cfg = tmp_path / "config.toml"

    def configure(extra: str = "", backend: str = "local") -> None:
        cfg.write_text(f'[sandbox]\nbackend = "{backend}"\nworkdir = "{shared}"\n{extra}', encoding="utf-8")
        config.reset_config_cache()

    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    configure()
    world = WorldModel(path=tmp_path / "world.db")
    yield world, shared, configure
    config.reset_config_cache()


def _chat_goal(world, title="Summarize the sales file", *, conversation=None, **kw):
    goal_id = world.create_goal(title, "", **kw)
    if conversation is None:
        conversation = world.get_or_create_conversation("web", f"local/{goal_id}").id
    world.append_turn(conversation, "user", title, goal_id=goal_id)
    return world.get_goal(goal_id), conversation


def test_a_chat_conversation_gets_its_own_folder_and_follow_ups_share_it(setup):
    from maverick import task_workspace

    world, shared, _ = setup
    first, conversation = _chat_goal(world)
    folder = task_workspace.folder_for(world, first)
    assert folder == shared / "tasks" / f"conversation-{conversation}"
    assert folder.is_dir()
    follow_up, _ = _chat_goal(world, "Now chart it", conversation=conversation)
    assert task_workspace.folder_for(world, follow_up) == folder
    other, _ = _chat_goal(world, "Draft a job post")
    assert task_workspace.folder_for(world, other) != folder


def test_a_channel_conversation_without_a_recorded_turn_uses_the_runner_conversation(setup):
    from maverick import task_workspace

    world, shared, _ = setup
    goal = world.get_goal(world.create_goal("From Telegram", ""))
    assert task_workspace.folder_for(world, goal) is None  # no conversation: shared workspace
    assert task_workspace.folder_for(world, goal, 42) == shared / "tasks" / "conversation-42"


@pytest.mark.parametrize("kind", ["specialist", "sample", "flow_run", "schedule", "trigger", "codebase_feature"])
def test_specialists_samples_and_automations_keep_the_shared_workspace(setup, kind):
    import sqlite3
    import time

    from maverick import sample_outcomes, task_workspace

    world, _, _ = setup
    goal, _ = _chat_goal(world, domain="finance" if kind == "specialist" else "")
    if kind == "sample":
        sample_outcomes.mark_goal_as_sample(world, goal.id, sample_outcomes.DEFAULT_DEPARTMENT)
    elif kind != "specialist":
        with sqlite3.connect(world.path) as db:
            db.execute("INSERT INTO goal_origins(goal_id,kind,ref,created_at) VALUES(?,?,?,?)",
                       (goal.id, kind, "ref", time.time()))
    assert task_workspace.folder_for(world, world.get_goal(goal.id)) is None


def test_the_setting_coding_mode_and_remote_backends_turn_it_off(setup, monkeypatch):
    from maverick import task_workspace

    world, _, configure = setup
    goal, _ = _chat_goal(world)
    configure("task_folders = false\n")
    assert task_workspace.folder_for(world, goal) is None
    configure(backend="ssh")
    assert task_workspace.folder_for(world, goal) is None
    configure()
    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    assert task_workspace.folder_for(world, goal) is None
    monkeypatch.delenv("MAVERICK_CODING_MODE")
    assert task_workspace.folder_for(world, goal) is not None


def _task_sandbox(world, shared):
    from maverick import task_workspace
    from maverick.sandbox import LocalBackend

    goal, _ = _chat_goal(world)
    folder = task_workspace.folder_for(world, goal)
    sandbox = LocalBackend(workdir=folder)
    task_workspace.use(sandbox, folder)
    return sandbox, folder


def test_a_shared_file_is_copied_in_on_first_read_and_the_original_is_kept(setup):
    from maverick.tools.fs import list_dir, read_file, write_file

    world, shared, _ = setup
    (shared / "prices.csv").write_text("item,price\ntea,3\n", encoding="utf-8")
    (shared / "old-report.md").write_text("from an earlier task", encoding="utf-8")
    sandbox, folder = _task_sandbox(world, shared)

    listing = list_dir(sandbox).fn({"path": "."})
    assert "Files in the shared workspace" in listing
    assert "- prices.csv" in listing and "tasks" not in listing.split("\n")

    assert "tea,3" in read_file(sandbox).fn({"path": "prices.csv"})
    assert (folder / "prices.csv").read_text(encoding="utf-8") == "item,price\ntea,3\n"
    write_file(sandbox).fn({"path": "prices.csv", "content": "item,price\ntea,4\n"})
    assert (shared / "prices.csv").read_text(encoding="utf-8") == "item,price\ntea,3\n"
    assert not (folder / "old-report.md").exists()  # only what is opened comes in


def test_other_conversations_folders_are_not_reachable_through_the_shared_workspace(setup):
    from maverick.tools.fs import list_dir, read_file

    world, shared, _ = setup
    other = shared / "tasks" / "conversation-999"
    other.mkdir(parents=True)
    (other / "secret.txt").write_text("another conversation's file", encoding="utf-8")
    sandbox, _ = _task_sandbox(world, shared)
    assert "not found" in read_file(sandbox).fn({"path": "tasks/conversation-999/secret.txt"})
    assert "not found" in list_dir(sandbox).fn({"path": "tasks"})


def test_a_shared_subfolder_is_listed_and_its_files_come_in(setup):
    from maverick.tools.fs import list_dir, read_file

    world, shared, _ = setup
    (shared / "data").mkdir()
    (shared / "data" / "q1.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    sandbox, folder = _task_sandbox(world, shared)
    assert "- q1.csv" in list_dir(sandbox).fn({"path": "data"})
    assert "1,2" in read_file(sandbox).fn({"path": "data/q1.csv"})
    assert (folder / "data" / "q1.csv").is_file()


def test_a_link_in_the_shared_workspace_is_not_followed(setup, tmp_path):
    from maverick.tools.fs import read_file

    world, shared, _ = setup
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    (shared / "link.txt").symlink_to(outside)
    sandbox, folder = _task_sandbox(world, shared)
    assert "private" not in read_file(sandbox).fn({"path": "link.txt"})
    assert not (folder / "link.txt").exists()


def test_the_runner_runs_a_chat_task_in_its_folder(setup, monkeypatch):
    from maverick import orchestrator, runner
    from maverick import sandbox as sandbox_mod
    from maverick.sandbox import LocalBackend

    world, shared, _ = setup
    goal, conversation = _chat_goal(world)
    seen = {}

    def build(workdir=None):
        seen["workdir"] = workdir
        return LocalBackend(workdir=workdir or shared)

    def run(llm, world_, budget, goal_id, *, sandbox, **kw):
        seen["sandbox"] = sandbox
        world_.set_goal_status(goal_id, "done", result="ok")
        return "ok"

    monkeypatch.setattr(sandbox_mod, "build_sandbox", build)
    monkeypatch.setattr("maverick.llm.LLM", lambda: object())
    monkeypatch.setattr(orchestrator, "run_goal_sync", run)
    assert runner.run_goal_in_thread(goal.id, db_path=world.path) == "done"
    folder = shared / "tasks" / f"conversation-{conversation}"
    assert seen["workdir"] == folder
    assert seen["sandbox"].shared_workdir == shared


def test_the_first_workspace_uses_plain_conversation_folders_and_others_get_their_own(setup):
    from maverick import task_workspace
    from maverick.paths import reset_tenant, set_tenant

    world, shared, _ = setup
    goal, conversation = _chat_goal(world)

    def folder_in(tenant):
        token = set_tenant(tenant)
        try:
            return task_workspace._folder_name(conversation)
        finally:
            reset_tenant(token)

    assert folder_in("local") == folder_in(None) == task_workspace.Path("tasks", f"conversation-{conversation}")
    other = folder_in("acme")
    assert other.parts[0] == "tasks" and other.parts[-1] == f"conversation-{conversation}" and len(other.parts) == 3
