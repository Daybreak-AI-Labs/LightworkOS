"""Schema ratchet for complete GDPR goal-graph erasure coverage.

Post-delete subject matching cannot rediscover orphaned goal rows after the
conversation and turns are gone. Complete proof therefore depends on the
signed pre-delete receipt enumerating the exact goal closure and on the backend
counting every table in that closure. This test derives the graph from live
SQLite foreign keys so a newly added goal-linked table cannot silently fall
outside that contract.
"""

from __future__ import annotations

import sqlite3

import pytest
from maverick.erasure_receipts import (
    GOAL_LINKED_STORES,
    SOURCE_EPISODE_STORES,
)


def _goal_linked_tables(db_path) -> dict[str, list[str]]:
    con = sqlite3.connect(db_path)
    try:
        tables = [
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ]
        refs: dict[str, list[str]] = {}
        for table in tables:
            for row in con.execute(f"PRAGMA foreign_key_list({table})"):
                if row[2] == "goals":
                    refs.setdefault(table, []).append(row[3])
        return refs
    finally:
        con.close()


def _episode_linked_tables(db_path) -> set[str]:
    con = sqlite3.connect(db_path)
    try:
        tables = [
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            table
            for table in tables
            if any(
                row[1] == "source_episode_id"
                for row in con.execute(f"PRAGMA table_info({table})")
            )
        }
    finally:
        con.close()


@pytest.fixture()
def schema(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    from maverick import world_model

    db = tmp_path / "world.db"
    world_model.open_world(db).close()
    return db


def test_the_scan_finds_the_goal_graph(schema) -> None:
    refs = _goal_linked_tables(schema)
    assert len(refs) >= 12, sorted(refs)


def test_every_goal_linked_table_is_in_the_receipt_contract(schema) -> None:
    refs = set(_goal_linked_tables(schema))
    covered = set(GOAL_LINKED_STORES) - set(SOURCE_EPISODE_STORES)
    assert refs == covered, (
        "Every table referencing goals must be counted from the signed "
        "pre-delete receipt. "
        f"uncovered={sorted(refs - covered)}, stale={sorted(covered - refs)}"
    )


def test_every_episode_derived_store_is_in_the_receipt_contract(schema) -> None:
    refs = _episode_linked_tables(schema)
    covered = set(SOURCE_EPISODE_STORES.values())
    assert refs == covered, (
        "Every table carrying source_episode_id must be counted from exact "
        "episode ids in the signed pre-delete receipt. "
        f"uncovered={sorted(refs - covered)}, stale={sorted(covered - refs)}"
    )


def test_receipt_contract_has_no_duplicate_store_names() -> None:
    assert len(GOAL_LINKED_STORES) == len(set(GOAL_LINKED_STORES))


def test_verifier_documents_the_pre_delete_proof_boundary() -> None:
    from maverick import erasure_verify

    doc = (
        (erasure_verify.__doc__ or "")
        + (erasure_verify.verify_erasure.__doc__ or "")
    ).lower()
    assert "pre-delete" in doc
    assert "signed" in doc
    assert "indeterminate" in doc


def test_human_edit_receipts_are_counted_then_removed_with_exact_goal(tmp_path):
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "mutation-erasure.db")
    try:
        conversation = world.get_or_create_conversation("dashboard", "alice")
        goal = world.create_goal("private edit", owner="user:alice")
        other = world.create_goal("other work", owner="user:bob")
        world.append_turn(conversation.id, "user", "private", goal_id=goal)
        with world._writing() as con:
            for identifier in (goal, other):
                con.execute("INSERT INTO goal_mutation_receipts VALUES (?, 'edit', 'operation', 'owner', 'hash', '{}', 1)", (identifier,))
        assert world.count_erasure_receipt_store("goal_mutation_receipts", [conversation.id], [goal]) == 1
        world.erase_conversations([conversation.id])
        assert world.count_erasure_receipt_store("goal_mutation_receipts", [conversation.id], [goal]) == 0
        assert world.count_erasure_receipt_store("goal_mutation_receipts", [], [other]) == 1
    finally:
        world.close()


def test_approvals_parked_by_an_erased_goal_lose_their_content(tmp_path):
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "approval-erasure.db")
    try:
        conversation = world.get_or_create_conversation("dashboard", "alice")
        goal = world.create_goal("private", owner="user:alice")
        world.append_turn(conversation.id, "user", "private", goal_id=goal)
        mine = world.create_approval("email alice@example.com", scope="12 Elm St",
                                     detail="Alice Smith, 12 Elm St")
        other = world.create_approval("unrelated", detail="keep")
        with world._writing() as con:
            con.execute("UPDATE approvals SET goal_id = ? WHERE id = ?", (goal, mine))
            con.execute("INSERT INTO approval_signoffs VALUES (?, 'u:bob', 'approved', 1, 'for Alice')", (mine,))
        world.erase_conversations([conversation.id])
        erased = world.get_approval(mine)
        assert (erased.action, erased.scope, erased.detail) == ("[erased]", None, None)
        with world._writing() as con:
            assert con.execute("SELECT note FROM approval_signoffs").fetchone()[0] is None
        assert world.get_approval(other).detail == "keep"
    finally:
        world.close()
