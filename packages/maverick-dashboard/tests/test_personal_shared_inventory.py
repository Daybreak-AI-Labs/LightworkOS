"""Real local copies remain visible without transferring source or successor ACLs."""
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import audit, config
from maverick.deliverable_bundles import DeliverableBundles
from maverick.paths import tenant_scope
from maverick.task_handoffs import TaskHandoffs
from maverick.world_model import WorldModel
from maverick_dashboard import deliverable_bundles_api, personal_shared_inventory, task_handoffs_api


@pytest.fixture
def copies(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    config.reset_config_cache()
    with tenant_scope(tenant="tenant-a"), WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("Private source", "Never expose these instructions", owner="user:owner")
        world.set_goal_status(goal, "done", result="Private unselected result")
        chosen = world.add_artifact(goal, kind="text", title="Selected evidence", content="Captured private bytes")
        allowed = {"user:owner": True, "user:recipient": True, "user:other": True}

        def bundles(actor):
            return DeliverableBundles(world, actor=actor, eligible=lambda who, *_: allowed.get(who, False))

        monkeypatch.setattr(deliverable_bundles_api, "service", lambda request: bundles(request.actor))
        monkeypatch.setattr(task_handoffs_api, "service", lambda request: TaskHandoffs(bundles(request.actor)))
        owner = bundles("user:owner")
        choices = {"artifact_ids": [chosen], "attachment_ids": [], "include_result": False,
                   "name": "Reviewable copy", "recipient": "user:recipient", "note": "Private review comment",
                   "unresolved": "Private caveat", "lifetime": 86400}
        preview = owner.prepare(goal, **choices)
        bundle = owner.create(goal, expected_review=preview["review_version"], operation_id="bundle-inventory-test", **choices)
        handoffs = TaskHandoffs(owner)
        offer = {"title": "Continue selected work", "instruction": "Private instruction for recipient",
                 "commitments": "Private commitment details", "max_dollars": 2.0}
        review = handoffs.prepare(bundle["id"], **offer)
        handoff = handoffs.create(bundle["id"], **offer, expected_review=review["review_version"], operation_id="handoff-inventory-test")
        yield SimpleNamespace(world=world, goal=goal, allowed=allowed, bundles=bundles, bundle=bundle, handoff=handoff)
    config.reset_config_cache()


def inventory(actor="user:owner"):
    return personal_shared_inventory.inventory(SimpleNamespace(actor=actor), actor)


def test_owned_local_copies_have_source_expiry_dependencies_and_controls(copies):
    bundle, handoff = inventory()
    assert bundle["visible_count"] == handoff["visible_count"] == 1
    item = bundle["items"][0]
    assert item["source_href"] == f"/chat/goal/{copies.goal}"
    assert item["access_expires_at"] == copies.bundle["expires_at"]
    assert "not deletion" in item["expiry"]
    assert item["href"] == "/deliverable-bundles?open=" + copies.bundle["id"]
    assert handoff["items"][0]["dependency_href"] == item["href"]
    assert handoff["items"][0]["href"] == "/task-handoffs?open=" + copies.handoff["id"]
    encoded = json.dumps([bundle, handoff])
    for withheld in ["Never expose", "Private unselected", "Captured private bytes", "Private review comment",
                     "Private caveat", "Private instruction", "Private commitment", "content_base64", "source_version"]:
        assert withheld not in encoded


@pytest.mark.parametrize("actor", ["user:recipient", "user:other"])
def test_received_or_unrelated_copies_are_not_claimed_as_owned_data(copies, actor):
    for store in inventory(actor):
        assert store["state"] == "current-authorized-only"
        assert store["visible_count"] == 0 and store["items"] == []
        assert "not counted" in store["coverage"]


def test_revoked_access_does_not_claim_retained_copy_was_deleted(copies):
    copies.bundles("user:owner").respond(copies.bundle["id"], action="revoke", note="",
                                         expected_revision=copies.bundle["revision"], operation_id="revoke-inventory-test")
    bundle, handoff = inventory()
    assert bundle["items"][0]["state"] == "revoked" and bundle["visible_count"] == 1
    assert handoff["visible_count"] == 1
    assert "previously downloaded" in bundle["items"][0]["expiry"]


def test_changed_source_does_not_rewrite_saved_copy_or_claim_currentness(copies):
    copies.world.set_goal_status(copies.goal, "done", result="Changed source")
    assert inventory()[0]["items"][0]["source_state"] == "Source changed or unavailable"


def test_accepted_successor_stays_private_to_recipient(copies):
    accepted = TaskHandoffs(copies.bundles("user:recipient")).respond(
        copies.handoff["id"], action="accept", expected_revision=copies.handoff["revision"], operation_id="accept-inventory-test")
    successor = accepted["acceptance"]["successor_id"]
    item = inventory()[1]["items"][0]
    assert item["state"] == "accepted"
    assert "successor_id" not in json.dumps(item)
    assert f"/chat/goal/{successor}" not in json.dumps(item)
    assert "cannot be recalled" in item["action"]


def test_current_membership_is_checked_again_after_inventory_was_previously_read(copies):
    assert inventory()[0]["visible_count"] == 1
    copies.allowed["user:owner"] = False
    assert all(store["items"] == [] for store in inventory())


def test_disabled_or_failed_native_inventory_is_unavailable_not_empty(copies, monkeypatch):
    def disabled(_request):
        raise HTTPException(403, "Feature disabled")

    monkeypatch.setattr(deliverable_bundles_api, "service", disabled)
    result = inventory()[0]
    assert result["state"] == "unavailable"
    assert "items" not in result and "visible_count" not in result
    assert "no zero count" in result["action"]


def test_window_is_explicitly_bounded_and_never_a_total_retained_count(copies, monkeypatch):
    monkeypatch.setattr(personal_shared_inventory, "LIMIT", 0)
    for store in inventory():
        assert store["partial"] is True
        assert store["visible_count"] == 0
        assert "count" not in store
