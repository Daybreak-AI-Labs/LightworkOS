"""Native handoff services shared by typed, reviewed product operations."""
import pytest
from fastapi import HTTPException
from maverick import attachments, audit, config
from maverick.deliverable_bundles import DeliverableBundles
from maverick.paths import tenant_scope
from maverick.task_handoffs import TaskHandoffs
from maverick.world_model import WorldModel
from maverick_dashboard import product_operations_handoffs as actions


@pytest.fixture
def ready(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setattr(attachments, "DEFAULT_ROOT", tmp_path / "attachments")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(actions.auth, "require_permission", lambda *args: None)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    actor = ["user:owner"]
    with tenant_scope(tenant="workspace"), WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("Original", "Private", owner="user:owner")
        world.set_goal_status(goal, "done", result="Only selected result")
        def service(_request):
            return TaskHandoffs(DeliverableBundles(world, actor=actor[0], eligible=lambda *args: True))
        monkeypatch.setattr(actions, "service", service)
        bundles = service(None).bundles
        choices = {"artifact_ids": [], "attachment_ids": [], "include_result": True, "name": "Selected",
                   "recipient": "user:recipient", "note": "Review", "unresolved": "", "lifetime": 86400}
        preview = bundles.prepare(goal, **choices)
        row = bundles.create(goal, **choices, expected_review=preview["review_version"], operation_id="bundle-operation-one")
        yield world, actor, row, service
    config.reset_config_cache()


def test_offer_then_accept_uses_native_receipt_and_explicit_start(ready):
    world, actor, bundle, service = ready
    selection = {"kind": "bundle", "id": bundle["id"]}
    args = {"title": "Next task", "instruction": "Continue selected work", "commitments": "None known", "max_dollars": 1.5}
    snapshot = actions.offer_snapshot(None, selection)
    assert {field["name"] for field in snapshot.fields} == set(args)
    preview = actions.offer_preview(None, selection, args)
    offered = actions.offer_execute(None, selection, args, preview.native, "offer-operation-one")
    assert offered.status == "confirmed" and world.query("SELECT COUNT(*) FROM goals")[0][0] == 1
    handoff = {"kind": "handoff", "id": offered.details["handoff_id"]}
    actor[0] = "user:recipient"
    reviewed = actions.response_preview(None, handoff, {"action": "accept"})
    accepted = actions.response_execute(None, handoff, {"action": "accept"}, reviewed.native, "accept-operation-one")
    replay = actions.response_recover(None, handoff, {"action": "accept"}, reviewed.native, "accept-operation-one")
    assert accepted.details["state"] == "accepted" and replay.status == "replayed"
    assert world.query("SELECT COUNT(*) FROM goals")[0][0] == 2
    successor = service(None).get(handoff["id"])["acceptance"]["successor_id"]
    assert world.get_goal(successor).status == "blocked"
    assert accepted.details["open"]["href"] == f"/chat/goal/{successor}"
    actor[0] = "user:owner"
    assert actions.offer_snapshot(None, selection).blocked
    assert actions.offer_recover(None, selection, args, preview.native, "offer-operation-one").status == "replayed"


def test_recipient_review_rights_do_not_enable_offer(ready):
    _, actor, bundle, _ = ready
    actor[0] = "user:recipient"
    with pytest.raises(HTTPException) as caught:
        actions.offer_snapshot(None, {"kind": "bundle", "id": bundle["id"]})
    assert caught.value.status_code == 404


def test_declined_receipt_can_recover_without_reexposing_content(ready):
    _, actor, bundle, _ = ready
    selected = {"kind": "bundle", "id": bundle["id"]}
    args = {"title": "Next", "instruction": "Continue", "commitments": "None known", "max_dollars": 1.0}
    native = actions.offer_preview(None, selected, args).native
    offered = actions.offer_execute(None, selected, args, native, "offer-operation-one")
    actor[0] = "user:recipient"
    handoff = {"kind": "handoff", "id": offered.details["handoff_id"]}
    native = actions.response_preview(None, handoff, {"action": "decline"}).native
    actions.response_execute(None, handoff, {"action": "decline"}, native, "decline-operation-one")
    assert actions.response_snapshot(None, handoff).details == {"state": "declined"}
    assert actions.response_recover(None, handoff, {"action": "decline"}, native, "decline-operation-one").status == "replayed"
