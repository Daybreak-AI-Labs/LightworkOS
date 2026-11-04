"""With [autonomy] confirm_plan on, a person confirms the plan before a
task's first action that could reach outside Lightwork."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest


@pytest.fixture
def plan_on(tmp_path, monkeypatch):
    from maverick import agent, config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
    (tmp_path / "config.toml").write_text("[autonomy]\nconfirm_plan = true\n", encoding="utf-8")
    config.reset_config_cache()
    agent._PLAN_DECISIONS.clear()
    yield tmp_path
    agent._PLAN_DECISIONS.clear()
    config.reset_config_cache()


def _agent(goal_id=7, episode_id=1):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard

    board = Blackboard()
    board.post("orchestrator", "plan", "role=orchestrator depth=0 brief=Match invoices to purchase orders")
    board.post("worker-1", "plan", "role=worker depth=1 brief=Email the supplier about the missing receipt")
    tools = SimpleNamespace(all=lambda: [SimpleNamespace(name=n) for n in ("read_file", "send_email", "http_fetch",
                                                                           "write_file", "crm_update_contact")])
    fake = SimpleNamespace(name="worker-1", tools=tools,
                           ctx=SimpleNamespace(goal_id=goal_id, episode_id=episode_id, blackboard=board,
                                               budget=SimpleNamespace(max_dollars=2.5)))
    fake._plan_summary = lambda name, args: Agent._plan_summary(fake, name, args)
    return fake


def _deny(fake, name, args):
    from maverick.agent import Agent

    return asyncio.run(Agent._plan_denial(fake, name, args))


def _decide(monkeypatch, granted):
    from maverick.safety import consent

    asked = []
    monkeypatch.setattr(consent, "require_consent", lambda action, **kw: asked.append((action, kw))
                        or SimpleNamespace(granted=granted))
    return asked


def test_the_plan_is_shown_once_before_the_first_outside_action(plan_on, monkeypatch):
    asked = _decide(monkeypatch, True)
    fake = _agent()
    assert _deny(fake, "read_file", {"path": "invoices.csv"}) is None and asked == []  # reading needs no plan review
    assert _deny(fake, "send_email", {"to": "supplier@example.com"}) is None
    assert _deny(fake, "send_payment", {"amount": 120}) is None  # the run's plan is already confirmed
    assert len(asked) == 1
    action, how = asked[0]
    assert action == "confirm_plan" and how["provenance"] == "plan" and how["allow_auto_approve"] is False
    detail = how["detail"]
    assert "1. Match invoices to purchase orders; 2. Email the supplier about the missing receipt" in detail
    assert "First action: send an email to supplier@example.com" in detail
    assert "Spending cap for this task: $2.50" in detail
    # A new run of the task asks again.
    assert _deny(_agent(episode_id=2), "send_email", {}) is None and len(asked) == 2


def test_the_card_lists_the_plan_steps_and_the_outside_actions_in_plain_words(plan_on, monkeypatch):
    from maverick.approval_cards import validate_approval_card

    asked = _decide(monkeypatch, True)
    _deny(_agent(goal_id=11), "send_email", {"to": "supplier@example.com", "body": "Hello"})
    card = validate_approval_card(asked[0][1]["approval_card"])
    assert card["action"] == "Check the plan before this task acts"
    assert card["parameters"]["summary"] == [
        "Step 1: Match invoices to purchase orders",
        "Step 2: Email the supplier about the missing receipt",
        "First outside action: send an email to supplier@example.com",
    ]
    effects = card["consequences"]["known_effects"]
    # Every other outside action the agent can take, in plain words; reading
    # inside Lightwork is not listed.
    assert ("Later in this task it can also: change files in the workspace, open web pages or call outside "
            "services, change records in connected systems.") in effects
    assert any("If you reject, nothing runs" in e for e in effects)
    assert any("$2.50" in e and "a cap, not an estimate" in e for e in effects)
    assert card["target"]["label"] == "Task 11"
    assert card["consequences"]["unresolved_assumptions"] == []


def test_a_task_without_a_written_plan_says_so_on_the_card(plan_on, monkeypatch):
    from maverick.agent import Agent
    from maverick.approval_cards import validate_approval_card
    from maverick.blackboard import Blackboard

    asked = _decide(monkeypatch, True)
    fake = _agent(goal_id=12)
    fake.ctx.blackboard = Blackboard()
    fake.tools = None
    asyncio.run(Agent._plan_denial(fake, "shell", {"cmd": "ls"}))
    card = validate_approval_card(asked[0][1]["approval_card"])
    assert card["parameters"]["summary"] == ["First outside action: run a command"]
    assert card["consequences"]["unresolved_assumptions"] == ["The task wrote no plan before this first action."]


def test_other_actions_are_grouped_in_plain_words_and_the_rest_counted():
    from maverick.plan_review import outside_actions

    tools = ["read_file", "shell", "python_exec", "kv_memory", "slack_post", "find_controls", "view_video",
             "clipboard", "arxiv", "semantic_scholar", "str_replace_editor"]
    assert outside_actions(tools, "send_email") == [
        "send messages or email", "change files in the workspace", "run commands or programs",
        "save notes to its memory", "use 5 other tools it has been given"]
    assert outside_actions(["arxiv", "clipboard_copy"], "shell") == ["use 2 other tools: arxiv, clipboard copy"]
    assert outside_actions([f"tool_{i}" for i in range(3253)], "shell")[-1] == "use 3,253 other tools it has been given"


def test_a_step_says_the_goal_once():
    from maverick.agent import _plan_facts
    from maverick.blackboard import Blackboard

    board = Blackboard()
    board.post("orchestrator", "plan", "role=orchestrator depth=0 brief=Top-level goal: Archive the drafts\n"
               "Description: Archive the drafts\nPrior conversation: none")
    fake = SimpleNamespace(tools=None, ctx=SimpleNamespace(blackboard=board, budget=None))
    assert _plan_facts(fake)[0] == ["Archive the drafts"]


def test_a_rejected_plan_runs_nothing_and_is_not_asked_again(plan_on, monkeypatch):
    asked = _decide(monkeypatch, False)
    fake = _agent(goal_id=8)
    refusal = _deny(fake, "send_email", {"to": "supplier@example.com"})
    assert refusal and "nothing ran" in refusal and "Do not take any action" in refusal
    assert _deny(fake, "http_fetch", {"url": "https://example.com"}) == refusal
    assert len(asked) == 1


def test_off_by_default(tmp_path, monkeypatch):
    from maverick import agent, config

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    agent._PLAN_DECISIONS.clear()
    asked = _decide(monkeypatch, False)
    try:
        assert _deny(_agent(goal_id=9), "send_email", {}) is None and asked == []
    finally:
        config.reset_config_cache()


def test_agents_asking_at_once_raise_one_prompt_and_share_its_answer(plan_on, monkeypatch):
    import threading
    import time

    from maverick.safety import consent

    asked = []

    def slow_consent(action, **kw):
        asked.append(action)
        time.sleep(0.4)  # the person is still reading the card
        return SimpleNamespace(granted=True)
    monkeypatch.setattr(consent, "require_consent", slow_consent)
    results, start = [], threading.Barrier(4)

    def first_action(index):
        start.wait()
        results.append(_deny(_agent(goal_id=21), "send_email", {"to": f"agent{index}@example.com"}))
    threads = [threading.Thread(target=first_action, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert results == [None] * 4
    assert len(asked) == 1  # one plan decision per task run, however many agents act first


def test_a_refused_prompt_is_shared_by_the_agents_that_waited_for_it(plan_on, monkeypatch):
    import threading
    import time

    from maverick.safety import consent

    asked = []

    def slow_refusal(action, **kw):
        asked.append(action)
        time.sleep(0.3)
        return SimpleNamespace(granted=False)
    monkeypatch.setattr(consent, "require_consent", slow_refusal)
    results, start = [], threading.Barrier(3)

    def first_action():
        start.wait()
        results.append(_deny(_agent(goal_id=22), "send_email", {}))
    threads = [threading.Thread(target=first_action) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(asked) == 1 and len(results) == 3
    assert all(r and "nothing ran" in r for r in results)


def test_an_agent_waiting_on_another_agents_prompt_checks_less_and_less_often(plan_on, monkeypatch):
    from maverick import agent

    key, waits = ("", False, 23, 1), []

    async def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 8:  # the person decides while this agent waits
            agent._PLAN_DECISIONS[key] = True
    monkeypatch.setattr(agent, "asyncio", SimpleNamespace(sleep=sleep))
    agent._PLAN_ASKING.add(key)
    try:
        assert _deny(_agent(goal_id=23), "send_email", {}) is None
    finally:
        agent._PLAN_ASKING.discard(key)
    assert waits == [0.05, 0.1, 0.2, 0.4, 0.8, 1.0, 1.0, 1.0]


def test_a_decision_never_carries_over_to_another_workspace_or_practice(plan_on, monkeypatch):
    # Goal and episode ids count up per database: goal 31 in one workspace is
    # an unrelated task from goal 31 in another, or in the practice workspace.
    from maverick import practice
    from maverick.paths import tenant_scope

    asked = _decide(monkeypatch, True)
    with tenant_scope(tenant="acme"):
        assert _deny(_agent(goal_id=31), "send_email", {}) is None
        assert _deny(_agent(goal_id=31), "send_email", {}) is None
    assert len(asked) == 1  # the same run in the same workspace is asked once
    with tenant_scope(tenant="globex"):
        _deny(_agent(goal_id=31), "send_email", {})
    with tenant_scope(tenant="acme"), practice.scope():
        _deny(_agent(goal_id=31), "send_email", {})
    assert len(asked) == 3


def test_runs_without_a_goal_do_not_share_one_cached_decision(plan_on, monkeypatch):
    from maverick.safety import consent

    answers = iter([False, True])
    asked = []
    monkeypatch.setattr(consent, "require_consent", lambda action, **kw: asked.append(action)
                        or SimpleNamespace(granted=next(answers)))
    refused = _agent(goal_id=0, episode_id=0)
    assert "nothing ran" in _deny(refused, "send_email", {})
    # An unrelated goal-less run asks for itself instead of inheriting the refusal...
    other = _agent(goal_id=0, episode_id=0)
    assert _deny(other, "send_email", {}) is None
    assert len(asked) == 2
    # ...while the agents of one run still share their run's answer.
    assert "nothing ran" in _deny(refused, "http_fetch", {})
    assert _deny(other, "http_fetch", {}) is None
    assert len(asked) == 2
