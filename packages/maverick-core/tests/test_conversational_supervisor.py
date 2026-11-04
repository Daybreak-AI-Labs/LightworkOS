"""Conversational supervisor — grammar, cheap reads, fail-closed mutations."""
from __future__ import annotations

import pytest
from maverick.conversational_supervisor import (
    HELP_TEXT,
    MAX_GOAL_REF_DIGITS,
    MUTATING_INTENTS,
    Supervisor,
    parse_utterance,
    resolve_goal_ref,
)
from maverick.quotas import UsageLedger
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    yield w
    w.close()


@pytest.fixture
def ledger(tmp_path):
    return UsageLedger(path=tmp_path / "usage" / "ledger.json")


def make_supervisor(world, ledger, **kw):
    kw.setdefault("clock", lambda: 1_750_000_000.0)  # deterministic "today"
    return Supervisor(world, ledger, **kw)


TODAY = "2025-06-15"  # UTC day of the fixed clock above


# ----- grammar -----

@pytest.mark.parametrize("utterance,intent", [
    ("what's running?", "status"),
    ("  What IS   Running ", "status"),
    ("status report", "status"),
    ("how much have we spent today?", "spend"),
    ("what's the spend today", "spend"),
    ("what failed?", "failures"),
    ("summarize overnight failures", "failures"),
])
def test_parse_read_intents(utterance, intent):
    parsed = parse_utterance(utterance)
    assert parsed is not None
    assert parsed[0] == intent
    assert parsed[0] not in MUTATING_INTENTS


@pytest.mark.parametrize("utterance,intent,slots", [
    ("pause goal five", "pause", {"goal": "five"}),
    ("PAUSE GOAL 5.", "pause", {"goal": "5"}),
    ("resume goal 12", "resume", {"goal": "12"}),
    ("cancel goal two", "cancel", {"goal": "two"}),
    ("prioritize goal 3", "prioritize", {"goal": "3"}),
    ("prioritize the deploy goal", "prioritize", {"title": "deploy"}),
])
def test_parse_mutating_intents(utterance, intent, slots):
    parsed = parse_utterance(utterance)
    assert parsed == (intent, slots)
    assert intent in MUTATING_INTENTS


def test_parse_no_match_and_empty():
    assert parse_utterance("make me a sandwich") is None
    assert parse_utterance("") is None
    assert parse_utterance("   ") is None


def test_parse_rejects_duplicate_slot_grammar():
    with pytest.raises(ValueError):
        parse_utterance("anything", grammar=[("x", "{a} and {a}")])


@pytest.mark.parametrize("ref,expected", [
    ("5", 5), ("#5", 5), (" five ", 5), ("twelve", 12), ("Twenty", 20),
    ("the deploy one", None), ("", None),
])
def test_resolve_goal_ref(ref, expected):
    assert resolve_goal_ref(ref) == expected


# ----- read intents answer from world + ledger -----

def test_status_empty_world(world, ledger):
    sup = make_supervisor(world, ledger)
    assert sup.handle("what's running?") == "Nothing is running and nothing is queued."


def test_status_reports_active_and_queued(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")
    world.create_goal("write the docs")  # stays pending
    out = make_supervisor(world, ledger).handle("what's running?")
    assert f"goal {gid} 'deploy the api'" in out
    assert "1 queued" in out


def test_spend_empty_ledger(world, ledger):
    out = make_supervisor(world, ledger).handle("how much have we spent today?")
    assert out == "No spend recorded today."


def test_spend_sums_today_across_principals(world, ledger):
    ledger.record("alice", 1.25, 100, 200, day=TODAY)
    ledger.record("bob", 0.75, 10, 20, day=TODAY)
    ledger.record("alice", 99.0, 1, 1, day="2025-06-14")  # yesterday: excluded
    out = make_supervisor(world, ledger).handle("how much have we spent today?")
    assert "$2.00" in out
    assert "330 tokens" in out


def test_failures_empty(world, ledger):
    assert "No failures" in make_supervisor(world, ledger).handle("what failed?")


def test_failures_lists_blocked_goals(world, ledger):
    gid = world.create_goal("scrape the site")
    world.set_goal_status(gid, "blocked", result="boom")
    out = make_supervisor(world, ledger).handle("what failed?")
    assert f"goal {gid} 'scrape the site'" in out


# ----- mutating intents: strict fail-closed confirm gate -----

def test_pause_without_confirm_seam_refuses(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")
    out = make_supervisor(world, ledger).handle(f"pause goal {gid}")
    assert "Nothing changed" in out
    assert world.get_goal(gid).status == "active"


@pytest.mark.parametrize("verdict", ["yes", "true", 1, "True", None, object()])
def test_pause_with_non_boolean_confirm_refuses(world, ledger, verdict):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")
    sup = make_supervisor(world, ledger, confirm=lambda _desc: verdict)
    out = sup.handle(f"pause goal {gid}")
    assert "Not confirmed" in out
    assert world.get_goal(gid).status == "active"


def test_confirm_seam_raising_fails_closed(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")

    def confirm(_desc):
        raise RuntimeError("channel down")

    out = make_supervisor(world, ledger, confirm=confirm).handle(f"pause goal {gid}")
    assert "Nothing changed" in out
    assert world.get_goal(gid).status == "active"


def test_pause_confirmed_blocks_goal_and_logs_event(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")
    asked = []

    def confirm(desc):
        asked.append(desc)
        return True

    out = make_supervisor(world, ledger, confirm=confirm).handle("pause goal one")
    assert "Paused goal 1" in out
    assert world.get_goal(gid).status == "blocked"
    events = world.goal_events(gid)
    assert any(e.kind == "supervision" and "paused" in e.content for e in events)
    assert asked and "pause goal 1" in asked[0]


def test_resume_confirmed_only_from_blocked(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "blocked")
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    assert "Resumed" in sup.handle(f"resume goal {gid}")
    assert world.get_goal(gid).status == "pending"
    # Resuming a non-blocked goal is refused honestly.
    out = sup.handle(f"resume goal {gid}")
    assert "not paused/blocked" in out
    assert world.get_goal(gid).status == "pending"


def test_cancel_confirmed(world, ledger):
    gid = world.create_goal("deploy the api")
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    assert "Cancelled" in sup.handle(f"cancel goal {gid}")
    assert world.get_goal(gid).status == "cancelled"


def test_prioritize_records_fact_not_fake_column(world, ledger):
    gid = world.create_goal("deploy the api")
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle(f"prioritize goal {gid}")
    assert "priority=high" in out
    assert world.get_fact(f"goal:{gid}:priority") == "high"


def test_prioritize_refuses_a_concurrent_fact_change(world, ledger, monkeypatch):
    from maverick.fact_revision import FactConflict

    gid = world.create_goal("priority race")
    sup = make_supervisor(world, ledger, confirm=lambda _description: True)
    monkeypatch.setattr(world, "upsert_fact", lambda *_args, **_kwargs: (_ for _ in ()).throw(FactConflict("changed")))
    out = sup.handle(f"prioritize goal {gid}")
    assert "changed" in out and "nothing was changed" in out


def test_prioritize_by_title_unique_match(world, ledger):
    gid = world.create_goal("deploy the api")
    world.create_goal("write the docs")
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle("prioritize the deploy goal")
    assert f"Prioritized goal {gid}" in out
    assert world.get_fact(f"goal:{gid}:priority") == "high"


def test_prioritize_by_title_ambiguous_refuses(world, ledger):
    world.create_goal("deploy the api")
    world.create_goal("deploy the docs site")
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle("prioritize the deploy goal")
    assert "More than one goal matches" in out
    assert "Nothing changed" in out
    assert world.get_facts() == {}


def test_unknown_goal_id_is_honest(world, ledger):
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle("pause goal 99")
    assert "no goal 99" in out


def test_unreadable_goal_ref_is_honest(world, ledger):
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle("pause goal banana")
    assert "couldn't read a goal number" in out


def test_overlong_numeric_goal_ref_is_honest(world, ledger):
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle("pause goal " + "9" * (MAX_GOAL_REF_DIGITS + 1))
    assert "couldn't read a goal number" in out


def test_extremely_long_numeric_goal_ref_does_not_raise(world, ledger):
    sup = make_supervisor(world, ledger, confirm=lambda _d: True)
    out = sup.handle("pause goal " + "9" * 5000)
    assert "couldn't read a goal number" in out


# ----- LLM fallback: helps with reads, never mutates -----

def test_unknown_without_llm_gives_help(world, ledger):
    assert make_supervisor(world, ledger).handle("whatcha up to") == HELP_TEXT


def test_llm_fallback_answers_read_intent(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")
    sup = make_supervisor(world, ledger, llm=lambda _u: "what's running")
    out = sup.handle("whatcha up to")
    assert "interpreted as" in out
    assert "deploy the api" in out


def test_llm_fallback_never_mutates(world, ledger):
    gid = world.create_goal("deploy the api")
    world.set_goal_status(gid, "active")
    # Even with a confirm seam that says yes, a paraphrase-derived mutation
    # must not execute.
    sup = make_supervisor(
        world, ledger,
        llm=lambda _u: f"cancel goal {gid}",
        confirm=lambda _d: True,
    )
    out = sup.handle("nuke that deploy thing")
    assert "don't act on guesses" in out
    assert world.get_goal(gid).status == "active"


def test_llm_failure_gives_honest_help(world, ledger):
    def boom(_u):
        raise RuntimeError("provider down")

    assert make_supervisor(world, ledger, llm=boom).handle("hmm?") == HELP_TEXT


def test_llm_garbage_suggestion_gives_help(world, ledger):
    sup = make_supervisor(world, ledger, llm=lambda _u: "fly me to the moon")
    assert sup.handle("hmm?") == HELP_TEXT
    sup2 = make_supervisor(world, ledger, llm=lambda _u: 42)
    assert sup2.handle("hmm?") == HELP_TEXT
