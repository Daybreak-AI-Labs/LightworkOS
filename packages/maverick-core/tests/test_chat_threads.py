"""Durable chat membership, process-safe admission and real restart history."""
from __future__ import annotations

import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick.attachment_submissions import SubmissionConflict
from maverick.chat_threads import ChatThreads
from maverick.world_model import WorldModel

from test_support.chat_threads_native import _create, _process_reply


@pytest.fixture(params=["sqlite", "postgres"])
def worlds(request, tmp_path):
    if request.param == "postgres":
        from maverick.world_model_backends.postgres import PostgresWorldModel

        dsn = request.getfixturevalue("postgres_test_dsn")
        def factory():
            return PostgresWorldModel(dsn=dsn)
    else:
        def factory():
            return WorldModel(tmp_path / "chat.db")
    with factory() as world:
        yield factory, world


def test_atomic_admission_across_independent_connections(worlds):
    factory, world = worlds
    root = _create(world)["goal_id"]
    world.set_goal_status(root, "done")
    barrier = Barrier(3)

    def reply(index):
        with factory() as other:
            barrier.wait(timeout=30)
            try:
                return _create(other, root=root, token=f"reply-{index}")["goal_id"]
            except SubmissionConflict:
                return None

    with ThreadPoolExecutor(max_workers=3) as executor:
        children = list(executor.map(reply, range(3)))
    assert sum(child is not None for child in children) == 1
    assert len(world.list_goals()) == 2
    binding = ChatThreads(world).binding(root)
    assert len(world.recent_turns(binding.conversation_id)) == 2
    assert ChatThreads(world).latest(root) == next(child for child in children if child is not None)


def test_resume_and_new_turn_share_the_same_fence(worlds):
    factory, world = worlds
    root = _create(world)["goal_id"]
    world.set_goal_status(root, "cancelled")
    barrier = Barrier(2)

    def attempt(operation):
        with factory() as other:
            barrier.wait(timeout=30)
            try:
                if operation == "resume":
                    ChatThreads(other).resume(root)
                else:
                    _create(other, root=root, token="new-turn")
                return True
            except SubmissionConflict:
                return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        admitted = list(executor.map(attempt, ["resume", "reply"]))
    assert sum(admitted) == 1
    if admitted[0]:
        assert world.get_goal(root).status == "pending" and len(world.list_goals()) == 1
    else:
        assert world.get_goal(root).status == "cancelled" and len(world.list_goals()) == 2


def test_restart_binding_requires_canonical_user_turn_and_owner(worlds):
    _, world = worlds
    root = _create(world)["goal_id"]
    binding = ChatThreads(world).binding(root)
    for owner in ["user:alice", "user:bob"]:
        child = world.create_goal("workflow child", parent_id=root, owner=owner)
        world.set_goal_status(child, "blocked")
        assert ChatThreads(world).resume(child) is None
        world.append_turn(binding.conversation_id, "assistant", "not a user turn", goal_id=child)
        assert ChatThreads(world).binding(child) is None
        if owner == "user:bob":
            world.append_turn(binding.conversation_id, "user", "foreign owner", goal_id=child)
            assert ChatThreads(world).binding(child) is None
    assert ChatThreads(world).latest(root) == root
    world.set_goal_status(root, "done")
    with pytest.raises(SubmissionConflict, match="owner and tenant"):
        _create(world, root=root, token="foreign", owner="user:bob")


def test_failed_binding_write_rolls_back_every_admission_row(worlds, monkeypatch):
    _, world = worlds
    record = ChatThreads.record

    def failure(*args, **kwargs):
        record(*args, **kwargs)
        raise OSError("durability failure")

    monkeypatch.setattr(ChatThreads, "record", failure)
    with pytest.raises(OSError, match="durability failure"):
        _create(world)
    assert not world.list_goals() and not world.list_conversations()
    assert not world.query("SELECT * FROM attachment_submissions")


def test_legacy_chat_bindings_survive_without_submission_receipts(worlds):
    _, world = worlds
    root = world.create_goal("Legacy report", owner="user:alice")
    child = world.create_goal("Legacy revision", owner="user:alice", parent_id=root)
    conversation = world.get_or_create_conversation("web", f"user:alice/{root}")
    world.append_turn(conversation.id, "user", "Original constraint", goal_id=root)
    world.append_turn(conversation.id, "user", "Revise that", goal_id=child)
    world.set_goal_status(root, "done")
    world.set_goal_status(child, "blocked")
    assert ChatThreads(world).latest(root) == child
    assert ChatThreads(world).resume(child) == conversation.id
    assert world.get_goal(child).status == "pending"


def test_native_chat_operations_keep_tenant_scope(postgres_test_dsn):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        with tenant_scope(tenant="chat-a"):
            root_a = _create(world)["goal_id"]
            world.set_goal_status(root_a, "done")
            stored = ChatThreads(world)
            binding_a = stored.binding(root_a)
        with tenant_scope(tenant="chat-b"):
            root_b = _create(world)["goal_id"]
            assert root_b != root_a
            assert ChatThreads(world).binding(root_a) is None
            with pytest.raises(SubmissionConflict, match="unavailable in this tenant"):
                ChatThreads(world).resume(root_a)
            assert ChatThreads(world).binding(root_b).conversation_id != binding_a.conversation_id
            with pytest.raises(SubmissionConflict, match="owner and tenant"):
                _create(world, root=root_a, token="foreign-root")
            with pytest.raises(SubmissionConflict, match="tenant context changed"):
                stored.latest(root_a)
        with tenant_scope(tenant="chat-a"):
            assert world.get_goal(root_a).status == "done"
            assert len(world.list_goals()) == 1


def test_first_chat_conversion_and_ordinary_goal_resume_share_fence(worlds):
    factory, world = worlds
    root = world.create_goal("Ordinary API task", owner="user:alice")
    world.set_goal_status(root, "cancelled")
    assert ChatThreads(world).binding(root) is None
    barrier = Barrier(2)

    def attempt(operation):
        with factory() as other:
            barrier.wait(timeout=30)
            try:
                if operation == "resume":
                    ChatThreads(other).resume(root)
                else:
                    _create(other, root=root, token="first-chat-turn")
                return True
            except SubmissionConflict:
                return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        admitted = list(executor.map(attempt, ["resume", "first-reply"]))
    assert sum(admitted) == 1
    if admitted[0]:
        assert not world.list_conversations()
        assert world.get_goal(root).status == "pending" and len(world.list_goals()) == 1
    else:
        assert world.get_goal(root).status == "cancelled" and len(world.list_goals()) == 2


def test_legacy_missing_root_turn_still_protects_and_reopens_existing_child(worlds):
    _, world = worlds
    root = world.create_goal("Legacy root with interrupted history", owner="user:alice")
    child = world.create_goal("Legacy follow-up", owner="user:alice", parent_id=root)
    conversation = world.get_or_create_conversation("web", f"user:alice/{root}")
    world.append_turn(conversation.id, "user", "Existing actual follow-up", goal_id=child)
    world.set_goal_status(root, "done")
    assert ChatThreads(world).latest(root) == child
    with pytest.raises(SubmissionConflict, match="still working"):
        _create(world, root=root, token="stale-root")
    assert len(world.list_goals()) == 2


def test_first_reply_to_ordinary_task_preserves_its_existing_answer(worlds):
    _, world = worlds
    root = world.create_goal("Original request", description="Original constraints", owner="user:alice")
    world.set_goal_status(root, "done", result="Unique original answer ABC731")
    child = _create(world, root=root, token="first-reply")["goal_id"]
    binding = ChatThreads(world).binding(child)
    turns = world.recent_turns(binding.conversation_id)
    assert [(t.role, t.goal_id) for t in turns] == [("user", root), ("assistant", root), ("user", child)]
    assert turns[0].content == "Original request\n\nOriginal constraints"
    assert turns[1].content == "Unique original answer ABC731"
    _create(world, root=root, token="first-reply")
    assert len(world.recent_turns(binding.conversation_id)) == 3


def test_failed_final_question_admission_does_not_consume_answer(worlds):
    _, world = worlds
    root = _create(world)["goal_id"]
    world.set_goal_status(root, "blocked")
    question = world.ask("Final clarification?", goal_id=root)

    def refused():
        raise RuntimeError("admission unavailable")

    with pytest.raises(RuntimeError, match="admission unavailable"):
        ChatThreads(world).answer(root, question, "Confirmed", require_admission=refused)
    assert [q.id for q in world.open_questions(root)] == [question]
    assert world.get_goal(root).status == "blocked"
    result = ChatThreads(world).answer(root, question, "Confirmed", require_admission=lambda: None)
    assert result.admitted and result.conversation_id == ChatThreads(world).binding(root).conversation_id
    assert not world.open_questions(root) and world.get_goal(root).status == "pending"


def test_parallel_question_answers_restart_once_across_connections(worlds):
    factory, world = worlds
    root = _create(world)["goal_id"]
    world.set_goal_status(root, "blocked")
    questions = [world.ask(f"Clarification {index}?", goal_id=root) for index in range(2)]
    barrier = Barrier(2)

    def answer(question):
        with factory() as other:
            barrier.wait(timeout=30)
            return ChatThreads(other).answer(root, question, "Confirmed", require_admission=lambda: None)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(answer, questions))
    assert sum(result.admitted for result in results) == 1
    assert not world.open_questions(root) and world.get_goal(root).status == "pending"


def test_independent_processes_admit_only_one_followup(tmp_path):
    path = tmp_path / "process-chat.db"
    with WorldModel(path) as world:
        root = _create(world)["goal_id"]
        world.set_goal_status(root, "done")
    ctx = multiprocessing.get_context("spawn")
    barrier, output = ctx.Barrier(2), ctx.Queue()
    processes = [ctx.Process(target=_process_reply, args=(path, root, index, barrier, output)) for index in range(2)]
    try:
        for process in processes:
            process.start()
        results = [output.get(timeout=45) for _ in processes]
        for process in processes:
            process.join(timeout=15)
            assert process.exitcode == 0
        assert sorted(state for state, _ in results) == ["admitted", "refused"]
        with WorldModel(path) as world:
            assert len(world.list_goals()) == 2
            assert len(ChatThreads(world).members(ChatThreads(world).binding(root))) == 2
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=10)
        output.close()


@pytest.mark.asyncio
async def test_resumed_orchestrator_reads_history_and_appends_to_same_chat(tmp_path, fake_llm, make_llm_response):
    from maverick.budget import Budget
    from maverick.orchestrator import run_goal
    from maverick.sandbox import LocalBackend

    with WorldModel(tmp_path / "orchestrator-chat.db") as world:
        root = _create(world)["goal_id"]
        binding = ChatThreads(world).binding(root)
        world.append_turn(binding.conversation_id, "assistant", "Original assistant report", goal_id=root)
        world.set_goal_status(root, "done")
        child = _create(world, root=root, token="revise")["goal_id"]
        world.set_goal_status(child, "blocked")
        conversation_id = ChatThreads(world).resume(child)
        fake_llm.scripted = [
            make_llm_response(text="FINAL: Updated assistant report"),
            make_llm_response(text='{"confidence":0.95,"accepts":true,"critique":"ok","issues":[]}'),
        ]
        await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1), goal_id=child,
                       conversation_id=conversation_id, sandbox=LocalBackend(workdir=tmp_path), max_depth=1)
        assert world.get_goal(child).status == "done"
        assert "BUDGET-ALPHA-731" in str(fake_llm.calls)
        assert "Original assistant report" in str(fake_llm.calls)
        turns = world.recent_turns(binding.conversation_id)
        assert [(t.role, t.goal_id) for t in turns] == [
            ("user", root), ("assistant", root), ("user", child), ("assistant", child)]
        assert "Updated assistant report" in turns[-1].content


def test_history_pages_relative_to_selected_turn_without_future_displacement(worlds):
    _, world = worlds
    root = _create(world)["goal_id"]
    world.set_goal_status(root, "done")
    conversation = ChatThreads(world).binding(root).conversation_id
    selected = None
    for index in range(220):
        goal = _create(world, root=root, token=f"history-{index}")["goal_id"]
        world.append_turn(conversation, "assistant", f"Answer {index}", goal_id=goal)
        world.set_goal_status(goal, "done")
        if index == 8:
            selected = goal
    early, more = ChatThreads(world).history(selected, limit=50)
    assert early and not more
    assert all(turn.goal_id < selected for turn in early)
    cursor, collected = None, []
    while True:
        page, more = ChatThreads(world).history(goal, before_id=cursor, limit=50)
        collected.extend(turn.id for turn in page)
        if not more:
            break
        cursor = page[0].id
    assert len(collected) > 200
    assert len(collected) == len(set(collected))


def test_members_are_the_roots_own_children_and_the_owner_index_is_not_scanned(worlds, monkeypatch):
    # Members of a thread are the root and its children for that owner only.
    # On SQLite the members query must reach them through the id and parent
    # indexes, not by scanning every goal the owner has.
    from maverick.chat_threads import ChatThreads as Threads

    factory, world = worlds
    root = _create(world)["goal_id"]
    world.set_goal_status(root, "done")
    reply = _create(world, root=root, token="reply")["goal_id"]
    binding = Threads(world).binding(root)
    intruder = world.create_goal("another owner's note", parent_id=root, owner="user:bob")
    world.append_turn(binding.conversation_id, "user", "hello", goal_id=intruder)
    assert [tuple(row[:1]) for row in Threads(world).members(binding)] == [(reply,), (root,)]
    assert Threads(world).latest(root) == reply

    if not isinstance(world, WorldModel):
        return
    seen = []
    original = Threads._rows

    def spy(self, sql, values=(), **kwargs):
        if "FROM goals g WHERE (g.id=?" in sql and "g.owner" in sql:
            seen.append((sql, values))
        return original(self, sql, values, **kwargs)

    monkeypatch.setattr(Threads, "_rows", spy)
    Threads(world).members(binding)
    sql, values = seen[0]
    plan = " ".join(str(row[-1]) for row in world.query("EXPLAIN QUERY PLAN " + sql, values))
    assert "idx_goals_owner" not in plan
