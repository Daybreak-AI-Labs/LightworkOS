"""Suggested edits to policy documents, accepted or rejected by a person (NOT-4).

An AI assistant, an agent or a colleague proposes a change to one part of a
policy document. The proposal is kept as a suggestion (what it changes, who
or what proposed it and why) and never changes the document by itself.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_a_suggestion_is_stored_with_who_proposed_it_and_why_and_changes_nothing():
    from maverick import policy_suggestions as ps

    row = ps.propose("ai-policy", "customer-data", field="statement:no-export",
                     before="AI must not send customer data outside the EU.",
                     after="AI must not send customer data outside the EU or the UK.",
                     base_version=1, proposer="ai:policy-assistant", proposer_kind="ai",
                     reason="The UK adequacy decision is under review.", model="test-model")
    assert row["state"] == "open" and row["proposer_kind"] == "ai" and row["model"] == "test-model"
    assert row["reason"] == "The UK adequacy decision is under review."
    assert [r["id"] for r in ps.list_for("ai-policy", "customer-data")] == [row["id"]]
    assert ps.list_for("ai-policy", "other") == []
    # The diff names exactly what changes, word by word.
    changed = [(op["op"], op["text"]) for op in row["diff"] if op["op"] != "same"]
    assert changed == [("del", "EU."), ("ins", "EU or the UK.")]


def test_reads_never_create_the_store(home):
    from maverick import policy_suggestions as ps

    assert ps.list_for("ai-policy", "customer-data") == [] and ps.get(1) is None
    assert not list((home / "home").rglob("policy_suggestions.sqlite3"))


def test_a_suggestion_is_decided_once_with_the_deciders_reason():
    from maverick import policy_suggestions as ps

    row = ps.propose("ai-policy", "customer-data", field="description", before="a", after="b",
                     base_version=1, proposer="user:ana@corp.com", proposer_kind="person", reason="")
    done = ps.decide(row["id"], accepted=False, by="user:dana@corp.com", reason="Too broad.")
    assert done["state"] == "rejected" and done["decided_by"] == "user:dana@corp.com"
    assert done["decision_reason"] == "Too broad."
    assert ps.decide(row["id"], accepted=True, by="user:dana@corp.com") is None
    assert ps.list_for("ai-policy", "customer-data") == []
    assert [r["state"] for r in ps.list_for("ai-policy", "customer-data", states=("rejected",))] == ["rejected"]


def test_a_suggestion_is_refused_when_it_changes_nothing_or_names_no_part():
    from maverick import policy_suggestions as ps

    with pytest.raises(ps.SuggestionError, match="does not change"):
        ps.propose("ai-policy", "p", field="title", before="Same", after="Same", base_version=1,
                   proposer="user:a@b.c", proposer_kind="person", reason="")
    with pytest.raises(ps.SuggestionError, match="part"):
        ps.propose("ai-policy", "p", field="owner", before="a", after="b", base_version=1,
                   proposer="user:a@b.c", proposer_kind="person", reason="")
    with pytest.raises(ps.SuggestionError):
        ps.propose("ai-policy", "p", field="title", before="a", after="b", base_version=1,
                   proposer="user:a@b.c", proposer_kind="robot", reason="")


def test_the_settings_turn_suggestions_and_ai_suggestions_off(home):
    from maverick import config
    from maverick import policy_suggestions as ps

    assert ps.enabled() and ps.ai_enabled()
    (home / "config.toml").write_text("[collaboration]\nai_suggestions = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert ps.enabled() and not ps.ai_enabled()


def test_a_persons_suggestions_and_decision_notes_are_erased_on_request():
    from maverick import policy_suggestions as ps

    mine = ps.propose("ai-policy", "p", field="title", before="a", after="b", base_version=1,
                      proposer="user:ana@corp.com", proposer_kind="person", reason="My idea.")
    theirs = ps.propose("ai-policy", "p", field="description", before="a", after="c", base_version=1,
                        proposer="agent:reviewer", proposer_kind="agent", reason="")
    ps.decide(theirs["id"], accepted=False, by="user:ana@corp.com", reason="Ana's note.")
    assert ps.count_by("user:ana@corp.com") == 2
    assert ps.erase_person("user:ana@corp.com") == 2
    assert ps.get(mine["id"]) is None
    kept = ps.get(theirs["id"])
    assert kept["state"] == "rejected" and kept["decided_by"] == "" and kept["decision_reason"] == ""
    assert ps.count_by("user:ana@corp.com") == 0
