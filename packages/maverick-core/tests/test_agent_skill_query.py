"""The root agent matches skills against the person's task, not its brief.

The root brief is the task plus standing text: the decision rules, approved
instruction changes, facts and "decompose, spawn workers". Matching skills
against all of it recalled compliance skills into every task (on one
installation ``ai-act-conformity-check`` reached 79 of about 92 mostly
one-line tasks), and "Reply with only the number 4." got governance skills
instead of the learned skill that matched it.
"""
from __future__ import annotations

from types import SimpleNamespace

TASK = "Reply with only the number 4."


def _skill(directory, name, trigger, summary):
    (directory / f"{name}.md").write_text(
        f"---\nname: {name}\ntriggers:\n  - {trigger}\n---\n\n# What this does\n\n{summary}\n",
        encoding="utf-8")


def _agent(depth, brief, goal):
    from maverick.agent import Agent

    agent = Agent.__new__(Agent)
    agent.depth, agent.brief = depth, brief
    agent.ctx = SimpleNamespace(world=SimpleNamespace(get_goal=lambda _gid: goal), goal_id=4)
    return agent


def test_the_root_agent_recalls_the_skill_for_the_task_not_for_the_standing_rules(tmp_path, monkeypatch):
    from maverick import decision_requests, skills
    from maverick.agent import apply_skill_overlays

    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "0")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # The deterministic word-matching path (embeddings vary by installation;
    # live, they matched the same compliance skills).
    monkeypatch.setattr("maverick.skill.embeddings.relevant_skills_embed", lambda *_a, **_k: None)
    store = tmp_path / "skills"
    store.mkdir()
    monkeypatch.setattr(skills, "skills_dir", lambda: store)
    _skill(store, "number-only-reply", "reply with only the number", "Answer with the bare number.")
    _skill(store, "governance-review", "data erasure and retention",
           "Review security, retention, spending and governance decisions before acting.")
    brief = (f"Top-level goal: {TASK}\nDescription: \n\n{decision_requests.rules_text()}\n\n"
             "Decompose into sub-tasks, spawn workers (parallel where possible), synthesize "
             "their findings, verify, and respond with FINAL:.")
    # The assembled brief alone matches the governance skill too.
    assert "governance-review" in [s.name for s in skills.relevant_skills(brief, skills.available_skills())]

    root = _agent(0, brief, SimpleNamespace(title=TASK, description=""))
    assert root._skill_query() == TASK
    _prompt, recalled = apply_skill_overlays("Base", brief=root._skill_query(), use_skills=True)
    assert [s.name for s in recalled] == ["number-only-reply"]


def test_a_sub_agent_and_a_missing_record_keep_the_brief():
    worker = _agent(1, "Check the supplier statement", SimpleNamespace(title=TASK, description=""))
    assert worker._skill_query() == "Check the supplier statement"
    root = _agent(0, "the brief", None)          # record unreadable
    assert root._skill_query() == "the brief"
