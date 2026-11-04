"""Durable cross-cycle accounting for sealed Self-Harness queries."""
from __future__ import annotations

import multiprocessing
import os
import sqlite3
import time

import pytest
from maverick.self_harness_holdout import (
    AlphaBudget,
    HoldoutBudgetExhausted,
    HoldoutLedgerError,
    HoldoutLedgerTampered,
    HoldoutQuery,
    HoldoutQueryLedger,
    fingerprint_manifest,
)


def _query(digest: str, query_id: str, *, cycle: str = "cycle-1",
           signature: str = "missing citations", epoch: str = "judge-v1",
           view: str | None = None) -> HoldoutQuery:
    return HoldoutQuery(
        holdout_sha256=digest, query_id=query_id, cycle_id=cycle,
        signature=signature, evaluator_epoch=epoch, view_sha256=view,
        final_set_sha256=fingerprint_manifest({
            "holdout_sha256": digest, "query_id": query_id,
        }),
        protocol_sha256=fingerprint_manifest({"protocol": "holdout-test-v1"}),
    )


def test_runtime_never_recreates_a_missing_ledger(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger(path)
    digest = fingerprint_manifest({"cases": [{"goal": "g", "expected": "e"}]})

    with pytest.raises(HoldoutLedgerError, match="missing"):
        ledger.authorize(_query(digest, "q-1"), AlphaBudget())
    assert not path.exists()

    provisioned = HoldoutQueryLedger.provision(path)
    assert provisioned.verify().ledger_events == 0
    with pytest.raises(HoldoutLedgerError, match="already exists"):
        HoldoutQueryLedger.provision(path)

    deleted_path = tmp_path / "deleted.db"
    deleted = HoldoutQueryLedger.provision(deleted_path)
    deleted_path.unlink()
    with pytest.raises(HoldoutLedgerError, match="missing"):
        deleted.authorize(_query(digest, "q-after-delete"), AlphaBudget())
    assert not deleted_path.exists()


def test_budget_persists_across_cycles_signatures_and_evaluator_epochs(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path, now=lambda: 10.0)
    digest = fingerprint_manifest({"cases": ["sealed-a", "sealed-b"], "grader": "v1"})
    policy = AlphaBudget(family_alpha=0.03, query_alpha=0.01, max_queries=3)

    first = ledger.authorize(_query(digest, "q-1"), policy)
    rotated_view = fingerprint_manifest({"fold": ["sealed-b"]})
    second = HoldoutQueryLedger(path, now=lambda: 11.0).authorize(
        _query(digest, "q-2", cycle="cycle-2", signature="different weakness",
               epoch="judge-v2", view=rotated_view),
        policy,
    )
    third = HoldoutQueryLedger(path, now=lambda: 12.0).authorize(
        _query(digest, "q-3", cycle="cycle-3", signature="third weakness",
               epoch="judge-v3"),
        policy,
    )

    assert (first.ordinal, second.ordinal, third.ordinal) == (1, 2, 3)
    assert first.critical_z_two_sided > 2.5
    status = HoldoutQueryLedger(path).status(digest)
    assert status.queries == 3
    assert status.alpha_spent == pytest.approx(0.03)
    assert status.alpha_remaining == pytest.approx(0.0)
    with pytest.raises(HoldoutBudgetExhausted, match="query limit"):
        HoldoutQueryLedger(path).authorize(
            _query(digest, "q-4", cycle="cycle-4", signature="fourth weakness"),
            policy,
        )


def test_policy_cannot_be_loosened_after_first_query(tmp_path):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    digest = fingerprint_manifest([{"goal": "sealed", "expected": "answer"}])
    original = AlphaBudget(family_alpha=0.02, query_alpha=0.01, max_queries=2)
    ledger.authorize(_query(digest, "q-1"), original)

    with pytest.raises(HoldoutLedgerError, match="immutable"):
        ledger.authorize(
            _query(digest, "q-2"),
            AlphaBudget(family_alpha=0.03, query_alpha=0.01, max_queries=3),
        )
    assert ledger.status(digest).queries == 1


def test_duplicate_query_id_is_not_an_idempotent_second_exposure(tmp_path):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    digest = fingerprint_manifest(["sealed"])
    policy = AlphaBudget(family_alpha=0.02, query_alpha=0.01, max_queries=2)
    ledger.authorize(_query(digest, "same-id"), policy)

    with pytest.raises(HoldoutLedgerError, match="already been spent"):
        ledger.authorize(
            _query(digest, "same-id", cycle="retry", signature="retry"), policy)
    assert ledger.status(digest).queries == 1


def test_tampered_event_and_tail_truncation_fail_closed(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    digest = fingerprint_manifest(["sealed"])
    ledger.authorize(_query(digest, "q-1"), AlphaBudget())

    with sqlite3.connect(path) as conn:
        trigger_sql = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE name='holdout_events_no_update'",
        ).fetchone()[0]
        conn.execute("DROP TRIGGER holdout_events_no_update")
        conn.execute("UPDATE events SET payload = replace(payload, 'q-1', 'q-X') WHERE seq=2")
        conn.execute(trigger_sql)
    with pytest.raises(HoldoutLedgerTampered, match="hash chain"):
        ledger.verify()

    # Restore by reprovisioning a distinct test ledger, then delete only its tail.
    truncated_path = tmp_path / "truncated.db"
    truncated = HoldoutQueryLedger.provision(truncated_path)
    truncated.authorize(_query(digest, "q-2"), AlphaBudget())
    with sqlite3.connect(truncated_path) as conn:
        trigger_sql = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE name='holdout_events_no_delete'",
        ).fetchone()[0]
        conn.execute("DROP TRIGGER holdout_events_no_delete")
        conn.execute("DELETE FROM events WHERE seq=2")
        conn.execute(trigger_sql)
    with pytest.raises(HoldoutLedgerTampered, match="event count"):
        truncated.verify()


def test_schema_triggers_block_accidental_history_and_identity_mutation(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    digest = fingerprint_manifest(["sealed"])
    ledger.authorize(_query(digest, "q-1"), AlphaBudget())

    statements = (
        "UPDATE events SET payload=payload WHERE seq=1",
        "DELETE FROM events WHERE seq=1",
        "UPDATE meta SET value='2' WHERE key='schema_version'",
        "UPDATE meta SET key='other' WHERE key='event_count'",
        "DELETE FROM meta WHERE key='tip_sha256'",
        "INSERT INTO meta(key,value) VALUES ('other','x')",
    )
    for statement in statements:
        with sqlite3.connect(path) as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute(statement)
    assert ledger.verify().ledger_events == 2


def test_missing_or_rewritten_schema_trigger_fails_closed(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER holdout_events_no_update")
        conn.execute(
            "CREATE TRIGGER holdout_events_no_update BEFORE UPDATE ON events "
            "BEGIN SELECT 1; END")
    with pytest.raises(HoldoutLedgerTampered, match="schema object"):
        ledger.verify()


def test_persistent_sqlite_journal_mode_change_fails_closed(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    with pytest.raises(HoldoutLedgerError, match="journal mode changed"):
        ledger.verify()


def test_commit_is_read_back_before_a_permit_is_returned(tmp_path, monkeypatch):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    digest = fingerprint_manifest(["sealed"])
    original = ledger._read_state
    calls = 0

    def hide_committed_query(conn):
        nonlocal calls
        calls += 1
        state = original(conn)
        if calls == 2:
            state.query_ids.discard("q-readback")
        return state

    monkeypatch.setattr(ledger, "_read_state", hide_committed_query)
    with pytest.raises(HoldoutLedgerError, match="failed readback"):
        ledger.authorize(_query(digest, "q-readback"), AlphaBudget())

    # Commit ambiguity burns access rather than returning an unproven permit.
    assert HoldoutQueryLedger(path).status(digest).queries == 1


def test_leaf_symlink_and_hardlink_paths_are_rejected(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    link = tmp_path / "holdout-link.db"
    try:
        link.symlink_to(path)
    except OSError:
        pass  # Windows may require Developer Mode; hard-link coverage still runs.
    else:
        with pytest.raises(HoldoutLedgerError, match="regular file"):
            HoldoutQueryLedger(link).verify()

        real_parent = tmp_path / "real-parent"
        real_parent.mkdir()
        parent_ledger = HoldoutQueryLedger.provision(real_parent / "ledger.db")
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with pytest.raises(HoldoutLedgerError, match="parent"):
            HoldoutQueryLedger(linked_parent / parent_ledger.path.name).verify()

    hardlink = tmp_path / "holdout-hardlink.db"
    os.link(path, hardlink)
    with pytest.raises(HoldoutLedgerError, match="hard links"):
        ledger.verify()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_writeable_ledger_permissions_are_rejected(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    path.chmod(0o666)
    with pytest.raises(HoldoutLedgerError, match="external writes"):
        ledger.verify()


def test_path_replacement_during_sqlite_open_is_detected(tmp_path, monkeypatch):
    path = tmp_path / "holdout.db"
    replacement = tmp_path / "replacement.db"
    ledger = HoldoutQueryLedger.provision(path)
    HoldoutQueryLedger.provision(replacement)
    real_connect = sqlite3.connect
    swapped = False

    def replacing_connect(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            os.replace(replacement, path)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", replacing_connect)
    with pytest.raises(HoldoutLedgerError, match="replaced during access"):
        ledger.verify()


def test_relative_ledger_path_is_frozen_across_chdir(tmp_path, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    ledger = HoldoutQueryLedger.provision("holdout.db")
    monkeypatch.chdir(second)

    assert ledger.verify().ledger_events == 0
    assert ledger.path == first / "holdout.db"
    assert not (second / "holdout.db").exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows filenames cannot contain '?'")
def test_sqlite_uri_metacharacters_in_path_cannot_inject_options(tmp_path):
    path = tmp_path / "ledger?mode=memory#fragment.db"
    ledger = HoldoutQueryLedger.provision(path)
    digest = fingerprint_manifest(["sealed"])
    ledger.authorize(_query(digest, "q-uri"), AlphaBudget())
    assert path.is_file()
    assert ledger.status(digest).queries == 1


def test_corrupt_database_never_leaks_raw_sqlite_errors(tmp_path):
    path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(path)
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(HoldoutLedgerError):
        HoldoutQueryLedger(path).verify()


def test_sensitive_manifest_signature_cycle_and_epoch_are_not_persisted(tmp_path):
    path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(path)
    manifest = {"goal": "sensitive sealed goal", "expected": "private label"}
    digest = fingerprint_manifest(manifest)
    ledger.authorize(
        _query(digest, "safe-query-id", cycle="private-cycle-name",
               signature="customer-specific failure text", epoch="secret-judge-build"),
        AlphaBudget(),
    )
    raw = path.read_bytes()
    for secret in (
        b"sensitive sealed goal", b"private label", b"private-cycle-name",
        b"customer-specific failure text", b"secret-judge-build",
    ):
        assert secret not in raw


def test_cross_process_callers_cannot_overspend(tmp_path):
    path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(path)
    digest = fingerprint_manifest(["sealed-a", "sealed-b"])
    policy = AlphaBudget(family_alpha=0.04, query_alpha=0.01, max_queries=4)
    context = multiprocessing.get_context("spawn")
    # Submit the importable production method itself.  A helper defined in this
    # test module is not spawn-safe when another workspace package named
    # ``tests`` wins module resolution in a fresh Windows interpreter.
    with context.Pool(processes=10) as workers:
        pending = [
            workers.apply_async(
                HoldoutQueryLedger.authorize,
                (
                    HoldoutQueryLedger(path, timeout_seconds=20.0),
                    _query(
                        digest, f"query-{index}", cycle=f"cycle-{index}",
                        signature=f"signature-{index}", epoch=f"judge-{index}",
                    ),
                    policy,
                ),
            )
            for index in range(10)
        ]
        deadline = time.monotonic() + 60.0
        results = []
        for result in pending:
            try:
                result.get(timeout=max(0.1, deadline - time.monotonic()))
            except HoldoutBudgetExhausted:
                results.append("exhausted")
            except multiprocessing.TimeoutError:
                pytest.fail("holdout accounting worker deadlocked")
            else:
                results.append("ok")

    assert results.count("ok") == 4
    assert results.count("exhausted") == 6
    status = HoldoutQueryLedger(path).status(digest)
    assert status.queries == 4
    assert status.alpha_spent == pytest.approx(0.04)
    assert status.ledger_events == 5  # one immutable policy + four query events


@pytest.mark.parametrize(
    "kwargs",
    [
        {"family_alpha": float("nan")},
        {"query_alpha": 0.0},
        {"max_queries": 0},
        {"family_alpha": 0.01, "query_alpha": 0.01, "max_queries": 2},
    ],
)
def test_invalid_alpha_policies_are_rejected(kwargs):
    with pytest.raises(ValueError):
        AlphaBudget(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": True},
        {"timeout_seconds": 86_401},
        {"max_events": True},
        {"max_events": 0},
    ],
)
def test_invalid_sqlite_boundary_limits_are_rejected(tmp_path, kwargs):
    with pytest.raises(ValueError):
        HoldoutQueryLedger(tmp_path / "holdout.db", **kwargs)
