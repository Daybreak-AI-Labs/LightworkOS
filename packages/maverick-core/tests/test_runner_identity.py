from __future__ import annotations


def test_run_goal_in_thread_propagates_execution_identity(monkeypatch, tmp_path):
    """HTTP adapters can pass an authenticated user through the runner."""
    from maverick import budget as budget_mod
    from maverick import llm as llm_mod
    from maverick import orchestrator, runner, world_model
    from maverick import sandbox as sandbox_mod

    captured: dict = {}

    db = tmp_path / "world.db"
    world = world_model.WorldModel(db)
    goal_id = world.create_goal("fixture task", owner="user:alice",
                                    execution_principal="user:alice")

    def fake_run_goal_sync(*args, **kwargs):
        args[1].set_goal_status(args[3], "done")
        captured.update(kwargs)
        return "DONE."

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: world_model.WorldModel(db))
    world.close()
    monkeypatch.setattr(llm_mod, "LLM", lambda: object())
    monkeypatch.setattr(sandbox_mod, "build_sandbox", lambda: object())
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kwargs: budget_mod.Budget())
    monkeypatch.setattr(orchestrator, "run_goal_sync", fake_run_goal_sync)

    assert runner.run_goal_in_thread(
        goal_id, max_depth=2, channel="api", user_id="alice", conversation_id=9,
        allowed_suites=frozenset({"finance"}),
    ) == "done"
    assert captured["channel"] == "api"
    assert captured["user_id"] == "alice"
    assert captured["conversation_id"] == 9
    assert captured["allowed_suites"] == frozenset({"finance"})
    assert captured["resume"] is True


def test_run_goal_in_thread_can_schedule_by_caller_principal(monkeypatch, tmp_path):
    """Fleet runs keep agent audit identity but share the caller's fair lane."""
    from maverick import budget as budget_mod
    from maverick import llm as llm_mod
    from maverick import orchestrator, runner, world_model
    from maverick import sandbox as sandbox_mod

    captured: dict = {}
    lanes: list[str | None] = []

    db = tmp_path / "world.db"
    world = world_model.WorldModel(db)
    goal_id = world.create_goal("fixture task", owner="user:alice",
                                    execution_principal="user:agent:acme.coder")

    class FakeSemaphore:
        def acquire(self, timeout=None):
            return True

        def release(self):
            pass

    def fake_run_goal_sync(*args, **kwargs):
        args[1].set_goal_status(args[3], "done")
        captured.update(kwargs)
        return "DONE."

    def fake_principal_semaphore(principal):
        lanes.append(principal)
        return FakeSemaphore()

    monkeypatch.setattr(runner, "_principal_semaphore", fake_principal_semaphore)
    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: world_model.WorldModel(db))
    world.close()
    monkeypatch.setattr(llm_mod, "LLM", lambda: object())
    monkeypatch.setattr(sandbox_mod, "build_sandbox", lambda: object())
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kwargs: budget_mod.Budget())
    monkeypatch.setattr(orchestrator, "run_goal_sync", fake_run_goal_sync)

    assert runner.run_goal_in_thread(
        goal_id,
        max_depth=2,
        channel="fleet",
        user_id="agent:acme.coder",
        concurrency_principal="user:alice",
    ) == "done"
    assert lanes == ["user:alice"]
    assert captured["channel"] == "fleet"
    assert captured["user_id"] == "agent:acme.coder"


def test_runner_refuses_mismatched_principal_before_setup_or_trace(
    monkeypatch,
    tmp_path,
):
    from maverick import llm as llm_mod
    from maverick import runner, trace_pin, world_model
    from maverick import sandbox as sandbox_mod

    world = world_model.WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal(
        "delegated work",
        owner="user:human-owner",
        execution_principal="agent:assigned",
    )
    called: list[str] = []

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: world)
    monkeypatch.setattr(world_model, "close_world_if_owned", lambda _world: None)
    monkeypatch.setattr(llm_mod, "LLM", lambda: called.append("llm"))
    monkeypatch.setattr(
        sandbox_mod,
        "build_sandbox",
        lambda: called.append("sandbox"),
    )
    monkeypatch.setattr(
        trace_pin,
        "pin_trace",
        lambda *_a, **_k: called.append("trace"),
    )

    assert runner.run_goal_in_thread(goal_id, user_id="attacker") == "blocked"
    assert called == []
    assert world.get_goal(goal_id).status == "pending"
    assert world.get_goal(goal_id).owner == "user:human-owner"
    assert world.get_goal(goal_id).execution_principal == "agent:assigned"
    assert world.goal_events(goal_id) == []
