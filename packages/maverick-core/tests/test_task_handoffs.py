"""Selected-copy transfer, durable acceptance and source execution fences."""
import json
from types import SimpleNamespace

import pytest
from maverick import attachments, audit, config
from maverick.attachment_submissions import SubmissionConflict
from maverick.chat_threads import ChatThreads
from maverick.deliverable_bundles import BundleDenied, DeliverableBundles
from maverick.goal_mutations import GoalMutationConflict
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.task_execution_guard import TaskBusy, lease
from maverick.task_handoffs import TaskHandoffs, apply_ceiling, closure, lineage, require_open
from maverick.world_model import WorldModel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(attachments, "DEFAULT_ROOT", tmp_path / "attachments")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    with tenant_scope(tenant="tenant-a"), WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("Private work", "Unselected private instructions", owner="user:owner")
        world.set_goal_status(goal, "done", result="Unselected private result")
        chosen = world.add_artifact(goal, kind="table", title="Selected table", content="| Name | Amount |\n| --- | --- |\n| =UNTRUSTED() | 12 |")
        other = world.add_artifact(goal, kind="text", title="Private artifact", content="Never shared")
        grants = {"user:owner": True, "user:recipient": True, "user:other": True}
        def service(actor):
            return DeliverableBundles(world, actor=actor, eligible=lambda who, *_: grants.get(who, False))
        yield world, goal, chosen, other, grants, service
    config.reset_config_cache()


def share(setup, **changes):
    _world, goal, chosen, _other, _grants, service = setup
    choices = {"artifact_ids": [chosen], "attachment_ids": [], "include_result": False,
               "name": "For recipient review", "recipient": "user:recipient",
               "note": "Review the selected numbers.", "unresolved": "Verify factual accuracy.", "lifetime": 86400}
    choices.update(changes)
    owner = service("user:owner")
    preview = owner.prepare(goal, **choices)
    row = owner.create(goal, expected_review=preview["review_version"], operation_id="share-operation-one", **choices)
    return row, choices, preview



@pytest.fixture
def offered(setup):
    world, goal, _chosen, _other, grants, bundles = setup
    bundle, _, _ = share(setup)
    source = TaskHandoffs(bundles("user:owner"))
    choices = {"title": "Recipient next work", "instruction": "Continue only the selected analysis.",
               "commitments": "No known external commitments; verify the figures.", "max_dollars": 2.0}
    preview = source.prepare(bundle["id"], **choices)
    row = source.create(bundle["id"], **choices, expected_review=preview["review_version"], operation_id="offer-operation-one")
    return world, goal, grants, bundles, row, choices, preview


def accept(offered, **changes):
    _world, _goal, _grants, bundles, row, _, _ = offered
    args = {"action": "accept", "expected_revision": row["revision"], "operation_id": "accept-handoff-one"}
    args.update(changes)
    return TaskHandoffs(bundles("user:recipient")).respond(row["id"], **args)


def test_offer_preserves_owner_and_does_not_start_any_task(offered):
    world, goal, _, _, row, _, _ = offered
    assert world.get_goal(goal).owner == "user:owner"
    assert row["state"] == "offered" and closure(world, goal) is None
    assert world.query("SELECT COUNT(*) FROM goals")[0][0] == 1
    assert row["preview"]["items"][0]["title"] == "Selected table"
    assert "Unselected private instructions" not in json.dumps(row)


def test_accept_creates_one_unstarted_private_successor_with_selected_evidence(offered):
    world, goal, _, bundles, row, _, _ = offered
    accepted = accept(offered)
    successor_id = accepted["acceptance"]["successor_id"]
    successor = world.get_goal(successor_id)
    assert successor.owner == "user:recipient" and successor.parent_id is None and successor.status == "blocked"
    assert "Unselected private instructions" not in successor.description
    assert "Continue only the selected analysis." in successor.description
    assert world.get_goal(goal).owner == "user:owner"
    artifacts = world.artifacts_for_goal(successor_id)
    assert len(artifacts) == 1 and artifacts[0]["title"] == "Selected table"
    evidence = world.list_attachments(successor_id)
    assert len(evidence) == 1 and b"=UNTRUSTED" in attachments.read_bytes(evidence[0].path)
    assert lineage(world, successor_id)["original_author"] == "user:owner"
    assert accept(offered)["acceptance"]["successor_id"] == successor_id
    assert world.query("SELECT COUNT(*) FROM goals")[0][0] == 2
    assert "successor_id" not in TaskHandoffs(bundles("user:owner")).get(row["id"])["acceptance"]


def test_original_thread_cannot_resume_or_admit_another_followup(offered):
    world, goal, *_ = offered
    accept(offered)
    with pytest.raises(GoalMutationConflict, match="handed off"):
        require_open(world, goal)
    with pytest.raises(SubmissionConflict, match="handed off"):
        ChatThreads(world).resume(goal)
    threads = ChatThreads(world)
    with threads.store.transaction("test") as connection:
        with pytest.raises(SubmissionConflict, match="handed off"):
            threads.require_idle(connection, goal, "user:owner")


def test_active_execution_lease_refuses_transfer_even_with_terminal_status(offered):
    world, goal, *_ = offered
    with lease(world, goal):
        with pytest.raises(TaskBusy, match="still running"):
            accept(offered)
    assert closure(world, goal) is None
    assert accept(offered)["state"] == "accepted"


def test_unsettled_episode_refuses_transfer(offered):
    world, goal, *_ = offered
    world.start_episode(goal)
    with pytest.raises(TaskBusy, match="episode"):
        accept(offered)
    assert closure(world, goal) is None


def test_revoked_recipient_permission_refuses_without_closing_source(offered):
    world, goal, grants, *_ = offered
    grants["user:recipient"] = False
    with pytest.raises(BundleDenied):
        accept(offered)
    assert closure(world, goal) is None


def test_source_changes_refuse_old_offer(offered):
    world, goal, *_ = offered
    world.add_artifact(goal, kind="table", title="Selected table", content="Changed")
    with pytest.raises(RecordConflict, match="bundle changed"):
        accept(offered)
    assert closure(world, goal) is None


def test_offer_withdrawal_ends_future_access_not_original_ownership(offered):
    world, goal, _, bundles, row, _, _ = offered
    sender = TaskHandoffs(bundles("user:owner"))
    assert sender.respond(row["id"], action="withdraw", expected_revision=row["revision"], operation_id="withdraw-handoff-one")["state"] == "withdrawn"
    with pytest.raises(BundleDenied):
        TaskHandoffs(bundles("user:recipient")).get(row["id"])
    assert closure(world, goal) is None


def test_review_bundle_acceptance_never_transfers_responsibility(offered):
    world, goal, _, bundles, row, _, _ = offered
    bundle = bundles("user:recipient").get(row["preview"]["bundle_id"])
    bundles("user:recipient").respond(bundle["id"], action="accept", note="Reviewed only.", expected_revision=bundle["revision"], operation_id="bundle-review-one")
    assert world.query("SELECT COUNT(*) FROM goals")[0][0] == 1
    assert closure(world, goal) is None
    with pytest.raises(RecordConflict):
        accept(offered)


def test_world_receipt_survives_governed_publication_failure_without_second_successor(offered, monkeypatch):
    world, goal, _, bundles, row, _, _ = offered
    source = TaskHandoffs(bundles("user:recipient"))
    backend = source.store._backend()
    original = backend.update
    def interrupted(identifier, mutate, **kwargs):
        def mutate_then_interrupt(record):
            mutate(record)
            raise OSError("simulated governed publication failure")
        return original(identifier, mutate_then_interrupt, **kwargs)
    monkeypatch.setattr(backend, "update", interrupted)
    monkeypatch.setattr(source.store, "_backend", lambda: backend)
    with pytest.raises(OSError):
        source.respond(row["id"], action="accept", expected_revision=row["revision"], operation_id="accept-handoff-one")
    assert closure(world, goal) is not None
    monkeypatch.setattr(backend, "update", original)
    repeated = source.respond(row["id"], action="accept", expected_revision=row["revision"], operation_id="accept-handoff-one")
    assert repeated["state"] == "accepted" and world.query("SELECT COUNT(*) FROM goals")[0][0] == 2


def test_spending_ceiling_can_only_tighten_and_accounts_previous_runs(offered):
    world, *_ = offered
    successor = accept(offered)["acceptance"]["successor_id"]
    budget = SimpleNamespace(max_dollars=8.0)
    apply_ceiling(world, successor, budget)
    assert budget.max_dollars == 2.0
    episode = world.start_episode(successor)
    world.end_episode(episode, "Partial", "blocked", cost_dollars=0.75)
    apply_ceiling(world, successor, budget)
    assert budget.max_dollars == 1.25
    budget.max_dollars = 0.2
    apply_ceiling(world, successor, budget)
    assert budget.max_dollars == 0.2


def test_decline_exact_receipt_replay_exposes_no_offer_content(offered):
    _, _, _, bundles, row, _, _ = offered
    recipient = TaskHandoffs(bundles("user:recipient"))
    args = {"action": "decline", "expected_revision": row["revision"], "operation_id": "decline-handoff-one"}
    first = recipient.respond(row["id"], **args)
    assert first["content_withheld"] and first["state"] == "declined"
    assert "preview" not in recipient.respond(row["id"], **args)


def test_descendant_resume_inherits_remaining_handoff_ceiling(offered):
    world, *_ = offered
    successor = accept(offered)["acceptance"]["successor_id"]
    child = world.create_goal("Selected subtask", parent_id=successor, owner="user:recipient")
    episode = world.start_episode(child)
    world.end_episode(episode, "Partial", "blocked", cost_dollars=0.4)
    budget = SimpleNamespace(max_dollars=7.0)
    apply_ceiling(world, child, budget)
    assert budget.max_dollars == 1.6


def test_the_inbox_states_each_handoff_from_the_listed_record(offered, monkeypatch):
    # The inbox used get() per row: another store read and authorization each.
    _world, _goal, _grants, bundles, row, _, _ = offered
    recipient = TaskHandoffs(bundles("user:recipient"))
    assert [(item["id"], item["state"]) for item in recipient.inbox()] == [(row["id"], "offered")]
    accept(offered)
    reads = []
    real_get = recipient.store.get
    monkeypatch.setattr(recipient.store, "get", lambda identifier: reads.append(identifier) or real_get(identifier))
    assert [(item["id"], item["state"]) for item in recipient.inbox()] == [(row["id"], "accepted")]
    assert reads == []
