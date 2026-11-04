"""Real local project records: independent source ACL, CAS, freshness and planning."""
from __future__ import annotations

import uuid

import pytest
from maverick import audit, config
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.project_reviews import ProjectReviewDenied, ProjectReviews
from maverick.project_workspaces import ProjectWorkspaces
from maverick.world_model import WorldModel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    with tenant_scope(tenant="tenant-a"), WorldModel(tmp_path / "world.db") as world:
        project = world.create_project("Outcome project", owner="user:owner")
        goal = world.create_goal("Private result", "Private conversation", owner="user:owner", project_id=project)
        world.set_goal_status(goal, "done", result="Sensitive original result")
        grants = dict.fromkeys(("user:owner", "user:reviewer", "user:third"), True)
        def service(actor="user:owner"):
            def eligible(principal, *_args):
                return grants.get(principal, False)
            reviews = ProjectReviews(world, principal=actor, eligible=eligible)
            return ProjectWorkspaces(world, principal=actor, eligible=eligible, reviews=reviews)
        yield world, project, goal, grants, service
    config.reset_config_cache()


def change(service, project, action, payload, **overrides):
    request = {"expected_revision": service.get(project)["revision"], "operation_id": uuid.uuid4().hex}
    request.update(overrides)
    return service.change(project, action, payload, **request)["workspace"]


def details(outcome="Explicit outcome"):
    return {"outcome": outcome, "criteria": ["Current evidence reviewed"], "labels": ["Customer"], "default_view": "board"}


def milestone(goal, **overrides):
    return {"id": uuid.uuid4().hex, "title": "Evidence ready", "due": "2026-12-01", "goals": [goal], "reviews": [], **overrides}


def packet(setup):
    _, project, goal, _, service = setup
    owner = service().reviews
    team = owner.set_member(project, member="user:reviewer", allowed=True, expected_revision=0, request_id="grant-reviewer")
    preview = owner.prepare(project, goal)
    return owner.send(project, goal_id=goal, reviewer="user:reviewer", note="Check this result", due_at=owner.packets.authoritative_time() + 3600,
                      source_version=preview["source_version"], expected_team_revision=team["revision"], request_id="send-review-packet")


def test_review_membership_is_not_workspace_or_live_task_access(setup):
    _, project, goal, _, service = setup
    packet(setup)
    with pytest.raises(ProjectReviewDenied):
        service("user:reviewer").get(project)
    owner = service()
    change(owner, project, "details", details())
    change(owner, project, "milestone", milestone(goal))
    current = owner.preview_source(project, "result", str(goal))
    change(owner, project, "context", {"kind": "result", "source_id": str(goal), "version": current["version"]})
    change(owner, project, "member", {"member": "user:reviewer", "allowed": True})
    shared = service("user:reviewer").get(project)
    assert shared["outcome"] == "Explicit outcome"
    assert shared["milestones"][0]["state"] == "restricted"
    assert shared["milestones"][0]["sources"] == []
    assert shared["context"][0]["title"] == "Restricted source"
    assert "Sensitive" not in str(shared) and "Private result" not in str(shared)
    assert not shared["can_edit"] and shared["editor"] is None
    with pytest.raises(ProjectReviewDenied):
        service("user:reviewer").preview_source(project, "result", str(goal))
    with pytest.raises(ProjectReviewDenied):
        service("user:reviewer").change(project, "details", details("attack"), expected_revision=shared["revision"], operation_id=uuid.uuid4().hex)


def test_context_source_is_revalidated_on_open_and_on_refresh(setup):
    world, project, goal, _, service = setup
    owner = service()
    selected = owner.preview_source(project, "result", str(goal))
    workspace = change(owner, project, "context", {"kind": "result", "source_id": str(goal), "version": selected["version"]})
    reference = workspace["context"][0]["reference"]
    assert owner.open_source(project, reference)["content"] == "Sensitive original result"
    world.set_goal_status(goal, "done", result="Changed saved result")
    assert owner.get(project)["context"][0]["fresh"] is False
    with pytest.raises(RecordConflict):
        owner.open_source(project, reference)
    with pytest.raises(RecordConflict):
        change(owner, project, "context", {"kind": "result", "source_id": str(goal), "version": selected["version"]})
    fresh = owner.preview_source(project, "result", str(goal))
    change(owner, project, "context", {"kind": "result", "source_id": str(goal), "version": fresh["version"]})
    assert owner.open_source(project, reference)["content"] == "Changed saved result"


def test_cas_receipts_preserve_newer_updates_and_reject_changed_retry(setup):
    _, project, _, _, service = setup
    owner = service()
    operation = uuid.uuid4().hex
    change(owner, project, "details", details(), expected_revision=0, operation_id=operation)
    latest = change(owner, project, "details", details("Later outcome"))
    result = owner.change(project, "details", details(), expected_revision=0, operation_id=operation)
    assert result["status"] == "replayed" and result["workspace"]["revision"] == latest["revision"]
    assert result["workspace"]["outcome"] == "Later outcome"
    with pytest.raises(RecordConflict):
        change(owner, project, "details", details("Forged retry"), expected_revision=0, operation_id=operation)
    with pytest.raises(RecordConflict):
        change(owner, project, "details", details("Lost update"), expected_revision=1)


def test_milestone_work_done_is_not_acceptance_and_reordering_does_not_modify_tasks(setup):
    world, project, goal, _, service = setup
    owner = service()
    first, second = milestone(goal), milestone(goal, title="Delivery")
    state = change(owner, project, "milestone", first)
    assert state["milestones"][0]["state"] == "work complete" and state["latest_accepted"] is None
    change(owner, project, "milestone", second)
    change(owner, project, "dependency", {"id": second["id"], "prerequisite": first["id"], "required": True})
    before = world.get_goal(goal)
    state = change(owner, project, "reorder", {"id": second["id"], "direction": "up"})
    after = world.get_goal(goal)
    assert [row["id"] for row in state["milestones"]] == [second["id"], first["id"]]
    assert state["milestones"][0]["depends_on"] == [first["id"]]
    assert (before.parent_id, before.updated_at, before.status) == (after.parent_id, after.updated_at, after.status)
    with pytest.raises(ValueError, match="cycle"):
        change(owner, project, "dependency", {"id": first["id"], "prerequisite": second["id"], "required": True})


def test_accepted_deliverable_uses_current_independent_review_and_source_version(setup):
    world, project, goal, _, service = setup
    review = packet(setup)
    owner = service()
    change(owner, project, "milestone", milestone(goal, reviews=[review["id"]]))
    assert owner.get(project)["latest_accepted"] is None
    service("user:reviewer").reviews.respond(review["id"], action="approve", note="Evidence checked",
        expected_revision=review["revision"], source_version=review["source_version"], request_id="independent-accept")
    state = owner.get(project)
    assert state["milestones"][0]["state"] == "accepted" and state["latest_accepted"]["id"] == review["id"]
    world.set_goal_status(goal, "done", result="Subsequent changed result")
    state = owner.get(project)
    assert state["latest_accepted"] is None and state["milestones"][0]["state"] == "waiting for review"


def test_revocation_and_tenant_switch_remove_all_shared_projection_access(setup):
    _, project, _, grants, service = setup
    owner = service()
    change(owner, project, "member", {"member": "user:reviewer", "allowed": True})
    reviewer = service("user:reviewer")
    assert len(reviewer.list()) == 1
    grants["user:reviewer"] = False
    assert reviewer.list() == []
    with pytest.raises(ProjectReviewDenied):
        reviewer.get(project)
    grants["user:reviewer"] = True
    change(owner, project, "member", {"member": "user:reviewer", "allowed": False})
    assert reviewer.list() == []
    with tenant_scope(tenant="tenant-b"), pytest.raises(ProjectReviewDenied):
        owner.get(project)


def test_reusable_defaults_do_not_copy_members_sources_dates_or_dependencies(setup):
    world, project, goal, _, service = setup
    owner = service()
    change(owner, project, "details", details())
    change(owner, project, "milestone", milestone(goal))
    change(owner, project, "member", {"member": "user:third", "allowed": True})
    operation = uuid.uuid4().hex
    revision = owner.get(project)["revision"]
    change(owner, project, "save_defaults", {"defaults_revision": 0}, operation_id=operation)
    assert owner.receipt(project, operation, "save_defaults", {"defaults_revision": 0}, revision)
    defaults = owner.personal_defaults()
    assert defaults["structure"]["milestones"] == [{"title": "Evidence ready"}]
    assert service("user:third").personal_defaults()["structure"] is None
    other = world.create_project("Another owned project", owner="user:owner")
    state = change(owner, other, "apply_defaults", {"defaults_revision": defaults["revision"]})
    row = state["editor"]["milestones"][0]
    assert row["goals"] == row["reviews"] == row["depends_on"] == [] and row["due"] == ""
    assert state["members"] == state["context"] == []
    with pytest.raises(ValueError, match="without milestones"):
        change(owner, other, "apply_defaults", {"defaults_revision": defaults["revision"]})
    with pytest.raises(RecordConflict):
        owner.receipt(other, operation, "save_defaults", {"defaults_revision": 0}, revision)


def test_unrelated_task_cannot_be_linked_or_disclosed(setup):
    world, project, _, _, service = setup
    other = world.create_goal("Another person's task", "secret", owner="user:third", project_id=project)
    with pytest.raises(ProjectReviewDenied):
        change(service(), project, "milestone", milestone(other))
    assert not any(row["id"] == other for row in service().choices(project)["goals"])


def test_owned_defaults_erasure_keeps_revision_barrier_and_never_touches_shared_planning(setup):
    from maverick.project_workspaces import erase_owned_defaults, owned_defaults_inventory
    _, project, _, _, service = setup
    owner = service()
    change(owner, project, "details", details())
    change(owner, project, "save_defaults", {"defaults_revision": 0})
    record = owned_defaults_inventory("user:owner")[0]
    request = {"record_id": record["id"], "expected_revision": record["revision"],
               "operation_id": "reviewed-private-erasure", "actor": "user:owner"}
    with pytest.raises(ProjectReviewDenied):
        erase_owned_defaults("user:third", **request)
    result = erase_owned_defaults("user:owner", **request)
    assert result["revision"] > record["revision"] and owned_defaults_inventory("user:owner") == []
    assert owner.personal_defaults()["structure"] is None
    assert owner.get(project)["outcome"] == "Explicit outcome"
    assert erase_owned_defaults("user:owner", **request)["status"] == "replayed"
    with pytest.raises(RecordConflict):
        change(owner, project, "save_defaults", {"defaults_revision": record["revision"]})
