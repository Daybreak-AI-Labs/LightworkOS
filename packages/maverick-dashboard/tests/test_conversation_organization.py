"""Organization changes private presentation, never durable chat authority."""
import hashlib

import pytest
from fastapi import HTTPException, Response
from maverick import audit, config
from maverick.attachment_submissions import SubmissionStore
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import conversation_organization as organization
from starlette.requests import Request


@pytest.fixture
def thread(tmp_path, monkeypatch):
    from maverick_dashboard import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(organization, "require_permission", lambda *args: None)
    monkeypatch.setattr(organization, "assert_goal_access", lambda *args: None)
    monkeypatch.setattr(organization, "domain_suites_allowed", lambda *args: True)
    monkeypatch.setattr(organization, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(organization, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(app, "_require_same_origin", lambda request: None)
    with tenant_scope(tenant="organization-test"), WorldModel(tmp_path / "world.db") as world:
        monkeypatch.setattr(app, "_world", lambda: world)
        store = SubmissionStore(world)
        root = store.create(token="root-request", fingerprint=hashlib.sha256(b"root").hexdigest(), owner="user:alice", title="Original request", description="", manifest=[], chat_text="Find the old ledger")
        world.set_goal_status(root["goal_id"], "done", result="Saved answer")
        child = store.create(token="next-request", fingerprint=hashlib.sha256(b"next").hexdigest(), owner="user:alice", title="Next turn", description="", manifest=[], chat_text="Continue with the receipts", parent_id=root["goal_id"], chat_root_id=root["goal_id"])
        yield world, root["goal_id"], child["goal_id"]
    config.reset_config_cache()


def request():
    return Request({"type": "http", "method": "PUT", "path": "/", "headers": [(b"x-lightwork-conversation-context", b"a" * 64)]})


def change(revision, operation="operation-one", **values):
    return organization.OrganizationIn(expected_revision=revision, operation_id=operation, title=values.get("title", "Month end"), pinned=values.get("pinned", True), archived=values.get("archived", True))


def test_rename_pin_archive_apply_to_all_turns_without_changing_task_records(thread):
    world, root, child = thread
    original = world.get_goal(root)
    saved = organization.save_organization(request(), child, change(0))
    assert saved["root_id"] == root
    assert organization.organization(request(), world, root)["title"] == "Month end"
    assert organization.organization(request(), world, child)["archived"] is True
    assert world.get_goal(root) == original
    restored = organization.save_organization(request(), root, change(saved["revision"], "undo-operation", title="", pinned=False, archived=False))
    assert restored["title"] == "" and not restored["archived"]
    assert world.get_goal(root).owner == "user:alice"


def test_stale_window_refuses_and_exact_response_loss_replay_is_one_revision(thread):
    _, root, _ = thread
    saved = organization.save_organization(request(), root, change(0))
    assert organization.save_organization(request(), root, change(0))["revision"] == saved["revision"]
    with pytest.raises(HTTPException) as rejected:
        organization.save_organization(request(), root, change(0, "other-window", title="Stale overwrite"))
    assert rejected.value.status_code == 409


def test_history_search_finds_old_message_content_and_archived_restore_view(thread):
    _, root, child = thread
    organization.save_organization(request(), root, change(0))
    hidden = organization.conversations(request(), Response(), q="ledger", before_id=None, view="active")
    assert hidden["items"] == []
    found = organization.conversations(request(), Response(), q="ledger", before_id=None, view="archived")
    assert found["items"][0]["root_id"] == root
    assert found["items"][0]["matched_goal_id"] == root
    assert found["items"][0]["display_title"] == "Month end"


def test_even_admin_content_access_cannot_relabel_another_owners_thread(thread, monkeypatch):
    world, root, _ = thread
    monkeypatch.setattr(organization, "caller_principal", lambda request: "user:administrator")
    with pytest.raises(HTTPException) as denied:
        organization.organization(request(), world, root)
    assert denied.value.status_code == 403


def test_content_only_match_beyond_recent_25_is_found_without_other_owner(thread):
    world, root, _ = thread
    store = SubmissionStore(world)
    for number in range(26):
        store.create(token=f"later-{number}", fingerprint=hashlib.sha256(f"later-{number}".encode()).hexdigest(),
                     owner="user:alice", title=f"Later chat {number}", description="", manifest=[], chat_text="Current discussion")
    store.create(token="foreign", fingerprint=hashlib.sha256(b"foreign").hexdigest(), owner="user:bob",
                 title="Other owner", description="", manifest=[], chat_text="Find the old ledger")
    found = organization.conversations(request(), Response(), q="ledger", before_id=None, view="all")
    assert [row["root_id"] for row in found["items"]] == [root]
    assert found["items"][0]["matched_goal_id"] == root


def _counting(monkeypatch, world):
    seen = {"reads": [], "access": [], "suites": []}
    real = world.get_goal
    monkeypatch.setattr(world, "get_goal", lambda goal_id: seen["reads"].append(goal_id) or real(goal_id))
    monkeypatch.setattr(organization, "assert_goal_access", lambda request, goal: seen["access"].append(goal.id))
    monkeypatch.setattr(organization, "domain_suites_allowed", lambda request, domain: seen["suites"].append(domain) or True)
    return seen


def test_a_root_conversation_is_read_and_checked_once(thread, monkeypatch):
    world, root, child = thread
    seen = _counting(monkeypatch, world)
    assert organization.organization(request(), world, root)["root_id"] == root
    assert seen["reads"] == [root] and seen["access"] == [root] and len(seen["suites"]) == 1
    loaded = world.get_goals([root])[root]
    seen["reads"].clear(), seen["access"].clear(), seen["suites"].clear()
    assert organization.organization(request(), world, root, goal=loaded)["root_id"] == root
    assert seen["reads"] == [], "the sidebar's batch read is used"
    assert seen["access"] == [root] and len(seen["suites"]) == 1, "and still checked"


def test_a_later_turn_still_reads_and_checks_its_root(thread, monkeypatch):
    world, root, child = thread
    seen = _counting(monkeypatch, world)
    assert organization.organization(request(), world, child)["root_id"] == root
    assert seen["reads"] == [child, root] and seen["access"] == [child, root] and len(seen["suites"]) == 2


def test_a_goal_handed_in_for_another_id_is_not_trusted(thread, monkeypatch):
    world, root, child = thread
    other = SubmissionStore(world).create(
        token="other-request", fingerprint=hashlib.sha256(b"other").hexdigest(), owner="user:alice",
        title="Another conversation", description="", manifest=[], chat_text="Something else")["goal_id"]
    wrong = world.get_goals([other])[other]
    seen = _counting(monkeypatch, world)
    assert organization.organization(request(), world, root, goal=wrong)["root_id"] == root
    assert seen["reads"] == [root] and seen["access"] == [root]


def test_a_root_owned_by_someone_else_still_refuses(thread, monkeypatch):
    world, root, child = thread
    monkeypatch.setattr(organization, "caller_principal", lambda request: "user:mallory")
    loaded = world.get_goals([root])[root]
    with pytest.raises(HTTPException) as refused:
        organization.organization(request(), world, root, goal=loaded)
    assert refused.value.status_code == 403
