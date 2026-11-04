"""Local governed project review authority; no provider or task execution."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from maverick import audit, config
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.project_reviews import ProjectReviewDenied, ProjectReviews
from maverick.world_model import WorldModel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    with tenant_scope(tenant="tenant-a"), WorldModel(tmp_path / "world.db") as world:
        project = world.create_project("Customer review", owner="user:owner")
        goal = world.create_goal("Selected result", "", owner="user:owner", project_id=project)
        world.set_goal_status(
            goal, "done", result="Captured result containing evidence and uncertainty."
        )
        grants = {"user:owner": True, "user:reviewer": True, "user:third": True}

        def service(actor):
            return ProjectReviews(
                world,
                principal=actor,
                eligible=lambda principal, *_args: grants.get(principal, False),
            )

        owner = service("user:owner")
        team = owner.set_member(
            project,
            member="user:reviewer",
            allowed=True,
            expected_revision=0,
            request_id="grant-reviewer",
        )
        yield world, project, goal, grants, service, team
    config.reset_config_cache()


def send(setup, **changes):
    _, project, goal, _, service, team = setup
    owner = service("user:owner")
    preview = owner.prepare(project, goal)
    payload = {
        "goal_id": goal,
        "reviewer": "user:reviewer",
        "note": "Please review this captured result.",
        "due_at": owner.packets.authoritative_time() + 3600,
        "source_version": preview["source_version"],
        "expected_team_revision": team["revision"],
        "request_id": "send-packet-one",
    }
    payload.update(changes)
    return owner.send(project, **payload), payload


def test_inherited_specialist_requires_its_suite_for_project_review(setup, tmp_path, monkeypatch):
    from maverick.project_workspaces import ProjectWorkspaces

    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    world = setup[0]
    project = world.create_project("Restricted fork", owner="user:owner", domain="client_fork")
    goal = world.create_goal("Restricted result", owner="user:owner", project_id=project,
                             domain="client_fork")
    world.set_goal_status(goal, "done", result="Private result")
    def eligible(principal, suite, permission, member):
        return suite in {None, "finance"}
    reviews = ProjectReviews(world, principal="user:owner", eligible=eligible)
    workspace = ProjectWorkspaces(world, principal="user:owner", eligible=eligible)
    with pytest.raises(ProjectReviewDenied):
        reviews.team(project)
    with pytest.raises(ProjectReviewDenied):
        reviews.prepare(project, goal)
    with pytest.raises(ProjectReviewDenied):
        workspace.get(project)


def respond(service, packet, **changes):
    payload = {
        "action": "approve",
        "note": "Reviewed the stated evidence and limitations.",
        "expected_revision": packet["revision"],
        "source_version": packet["source_version"],
        "request_id": "response-one",
    }
    payload.update(changes)
    return service.respond(packet["id"], **payload)


def test_capacity_keeps_revocation_bounded_idempotent_and_authoritative(setup):
    from maverick.project_reviews import _seal

    _, project, _, _, service, team = setup
    packet, _ = send(setup)
    owner = service("user:owner")

    def accumulated(record):
        # Valid repeated-grant history at the production ordinary-operation cap.
        record["operations"].update({f"grant-{n:04d}": "a" * 64 for n in range(1999)})
        record["history"] *= 2000
        _seal(record)

    full = owner.teams.update(team["id"], accumulated, expected_revision=team["revision"],
                              action="capacity_fixture", actor="user:owner")
    request = dict(member="user:reviewer", allowed=False,
                   expected_revision=full["revision"], request_id="revoke-at-capacity")
    revoked = owner.set_member(project, **request)
    assert revoked["members"] == []
    assert len(revoked["history"]) == 2001
    assert owner.set_member(project, **request)["revision"] == revoked["revision"]
    with pytest.raises(ProjectReviewDenied):
        service("user:reviewer").get(packet["id"])
    # Arbitrary repeated removals cannot grow the reserved terminal capacity.
    unchanged = owner.set_member(project, **{**request, "expected_revision": revoked["revision"],
                                              "request_id": "already-removed-person"})
    assert unchanged["revision"] == revoked["revision"]
    with pytest.raises(ValueError, match="history reached"):
        owner.set_member(project, member="user:third", allowed=True,
                         expected_revision=revoked["revision"], request_id="grant-after-capacity")


@pytest.mark.parametrize("action,actor,status", [
    ("cancel", "user:owner", "cancelled"),
    ("approve", "user:reviewer", "approved"),
    ("request_changes", "user:reviewer", "changes_requested"),
])
def test_discussion_capacity_reserves_one_terminal_response(setup, action, actor, status):
    from maverick.project_reviews import _seal

    _, _, _, _, service, _ = setup
    packet, _ = send(setup)
    owner = service("user:owner")
    packet = respond(owner, packet, action="comment", request_id="first-comment")

    def accumulated(record):
        record["history"].extend([record["history"][-1].copy() for _ in range(498)])
        _seal(record)

    full = owner.packets.update(packet["id"], accumulated, expected_revision=packet["revision"],
                                action="capacity_fixture", actor="user:owner")
    with pytest.raises(ValueError, match="history reached"):
        respond(owner, full, action="comment", request_id="excess-comment")
    closed = respond(service(actor), full, action=action, request_id="terminal-at-capacity")
    assert closed["status"] == status and len(closed["history"]) == 501
    assert respond(service(actor), full, action=action, request_id="terminal-at-capacity")["revision"] == closed["revision"]
    with pytest.raises(RecordConflict):
        respond(service(actor), closed, action=action, request_id="another-terminal-attempt")


def test_packet_is_exact_immutable_review_and_never_live_goal_signoff(setup):
    world, project, goal, _, service, _ = setup
    packet, payload = send(setup)
    before = world.get_goal(goal)
    approved = respond(service("user:reviewer"), packet)
    assert approved["status"] == "approved"
    assert approved["snapshot"] == packet["snapshot"]
    assert approved["live_goal_signoff"] is False
    assert world.get_goal(goal) == before
    assert world.signoff_for(goal) is None
    assert service("user:owner").send(project, **payload)["id"] == packet["id"]
    assert respond(service("user:reviewer"), packet)["revision"] == approved["revision"]
    with pytest.raises(RecordConflict):
        respond(service("user:reviewer"), packet, note="Different request content")


@pytest.mark.parametrize("change", ["result", "status", "title", "unfile"])
def test_changed_source_keeps_original_packet_but_refuses_new_decision(setup, change):
    world, _, goal, _, service, _ = setup
    packet, _ = send(setup)
    if change == "result":
        world.set_goal_status(goal, "done", result="A new result")
    elif change == "status":
        world.set_goal_status(goal, "active")
    elif change == "title":
        world.set_goal_title(goal, "New title")
    else:
        world.set_goal_project(goal, None)
    loaded = service("user:reviewer").get(packet["id"])
    assert loaded["stale"] is True
    assert loaded["snapshot"] == packet["snapshot"]
    with pytest.raises(RecordConflict, match="Source task changed"):
        respond(service("user:reviewer"), packet)
    commented = respond(
        service("user:reviewer"), packet, action="comment", note="Please send a current result."
    )
    assert commented["status"] == "pending" and commented["stale"]


def test_revocation_hides_packet_counts_and_content_immediately_but_preserves_owner_history(setup):
    _, project, _, _, service, team = setup
    packet, _ = send(setup)
    owner, reviewer = service("user:owner"), service("user:reviewer")
    assert len(reviewer.inbox()) == 1
    owner.set_member(
        project,
        member="user:reviewer",
        allowed=False,
        expected_revision=team["revision"],
        request_id="revoke-reviewer",
    )
    assert reviewer.inbox() == []
    with pytest.raises(ProjectReviewDenied):
        reviewer.get(packet["id"])
    with pytest.raises(ProjectReviewDenied):
        respond(reviewer, packet)
    assert owner.get(packet["id"])["history"][0]["action"] == "sent"
    assert respond(owner, packet, action="cancel")["status"] == "cancelled"


@pytest.mark.parametrize("change", ["unassigned", "role", "tenant"])
def test_current_access_is_checked_before_packet_counts_or_content(setup, change):
    _, _, _, grants, service, _ = setup
    packet, _ = send(setup)
    reviewer = service("user:third" if change == "unassigned" else "user:reviewer")
    if change == "role":
        grants["user:reviewer"] = False
    if change == "tenant":
        with tenant_scope(tenant="tenant-b"), pytest.raises(ProjectReviewDenied):
            reviewer.inbox()
    else:
        assert reviewer.inbox() == []
        with pytest.raises(ProjectReviewDenied):
            reviewer.get(packet["id"])


def test_owner_cannot_self_approve_or_share_unfiled_foreign_or_changed_result(setup):
    world, project, goal, _, service, _ = setup
    packet, _ = send(setup)
    with pytest.raises(ProjectReviewDenied):
        respond(service("user:owner"), packet)
    with pytest.raises(ProjectReviewDenied):
        send(setup, reviewer="user:owner", request_id="self-packet")
    foreign = world.create_goal(
        "Private foreign result", "", owner="user:third", project_id=project
    )
    world.set_goal_status(foreign, "done", result="Private")
    with pytest.raises(ProjectReviewDenied):
        service("user:owner").prepare(project, foreign)
    with pytest.raises(RecordConflict):
        send(setup, source_version="0" * 64, request_id="changed-packet")
    assert world.get_goal(goal).result == packet["snapshot"]["result"]


def test_revocation_and_response_use_one_local_project_critical_section(setup, monkeypatch):
    _, project, _, _, service, team = setup
    packet, _ = send(setup)
    entered, release = Event(), Event()
    owner, reviewer = service("user:owner"), service("user:reviewer")
    original = owner.teams.update

    def hold(*args, **kwargs):
        result = original(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(owner.teams, "update", hold)

    def revoke():
        with tenant_scope(tenant="tenant-a"):
            return owner.set_member(
                project,
                member="user:reviewer",
                allowed=False,
                expected_revision=team["revision"],
                request_id="concurrent-revoke",
            )

    def approve():
        with tenant_scope(tenant="tenant-a"):
            with pytest.raises(ProjectReviewDenied):
                respond(reviewer, packet)

    with ThreadPoolExecutor(max_workers=2) as pool:
        revoke_future = pool.submit(revoke)
        assert entered.wait(5)
        approve_future = pool.submit(approve)
        release.set()
        revoke_future.result(timeout=5)
        approve_future.result(timeout=5)
    assert owner.get(packet["id"])["status"] == "pending"


def test_postgres_fence_rejects_changed_membership_version(setup):
    _, _, _, _, service, team = setup
    owner = service("user:owner")
    authority = owner._team(team["id"])
    fence = owner._fence(authority, "postgres")
    fence.validate(authority, 0)
    changed = {**authority, "revision": authority["revision"] + 1}
    with pytest.raises(RecordConflict):
        fence.validate(changed, 0)


def test_review_revision_is_one_private_unstarted_draft_with_exact_comments(setup):
    world, _, goal, _, service, _ = setup
    packet, _ = send(setup)
    requested = respond(service("user:reviewer"), packet, action="request_changes", note="Correct the assumptions and retain the evidence.")
    owner = service("user:owner")
    request = {"expected_revision": requested["revision"], "source_version": requested["source_version"], "request_id": "prepare-revision"}
    first = owner.revision_draft(packet["id"], **request)
    second = owner.revision_draft(packet["id"], **{**request, "request_id": "another-browser-click"})
    assert first["goal_id"] == second["goal_id"] and first["started"] is False
    draft = world.get_goal(first["goal_id"])
    assert draft.owner == "user:owner" and draft.status == "draft"
    assert packet["id"] in draft.description and "Correct the assumptions" in draft.description
    assert world.signoff_for(draft.id) is None
    assert world.get_goal(goal).status == "done"
    with pytest.raises(ProjectReviewDenied):
        service("user:reviewer").revision_draft(packet["id"], **request)


def test_resubmission_has_new_approval_identity_and_exact_predecessor(setup):
    world, project, goal, _, service, team = setup
    packet, _ = send(setup)
    respond(service("user:reviewer"), packet, action="request_changes")
    world.set_goal_status(goal, "done", result="Changed result after feedback")
    owner = service("user:owner")
    prepared = owner.prepare(project, goal)
    request = {"goal_id": goal, "reviewer": "user:reviewer", "note": "Review the correction",
               "due_at": owner.packets.authoritative_time() + 3600, "source_version": prepared["source_version"],
               "expected_team_revision": team["revision"], "request_id": "resubmission-two",
               "previous_packet_id": packet["id"], "change_summary": "Corrected the assumptions"}
    fresh = owner.send(project, **request)
    assert owner.send(project, **request)["id"] == fresh["id"]
    assert fresh["id"] != packet["id"] and fresh["status"] == "pending"
    assert fresh["previous_source_version"] == packet["source_version"]
    assert fresh["snapshot"]["result"] == "Changed result after feedback"
    assert world.signoff_for(goal) is None
