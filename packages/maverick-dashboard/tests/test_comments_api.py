"""Comment threads and @mentions on tasks, runs, approvals and policies (NOT-4).

Only people who can open the item read its thread or are offered as a
mention; the server refuses any other mention, and a mention reaches the
person through their own personal notifications with why, what and where.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
ANA = "user:ana@corp.com"
DANA = "user:dana@corp.com"
LEE = "user:lee@corp.com"
VIC = "user:vic@corp.com"
ROLES = {ANA: "operator", DANA: "admin", LEE: "admin", VIC: "viewer"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    (tmp_path / "config.toml").write_text("[features]\npersonal_preferences = true\n", encoding="utf-8")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard import api, rbac
    api._world_cache.clear()
    monkeypatch.setattr(rbac, "list_users", lambda: dict(ROLES))
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN), world
    world.close()
    api._world_cache.clear()
    config.reset_config_cache()


def _as(monkeypatch, principal):
    from maverick_dashboard import api, auth

    role = ROLES[principal]
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: ROLES.get(p))
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p, **kw: ROLES.get(p))
    monkeypatch.setattr(api, "_supervisor", lambda request: principal)
    monkeypatch.setattr(auth, "has_permission",
                        lambda request, perm, **kw: perm in __import__("maverick_dashboard.rbac", fromlist=["x"]).permissions_for(role))
    monkeypatch.setattr(auth, "has_global_permission",
                        lambda request, perm, **kw: perm in __import__("maverick_dashboard.rbac", fromlist=["x"]).permissions_for(role))


def test_a_policy_thread_offers_only_people_who_manage_it_and_refuses_others(env, monkeypatch):
    client, _world = env
    _as(monkeypatch, DANA)
    thread = client.get("/api/v1/comments", params={"kind": "policy", "id": "tools"}).json()
    assert thread["comments"] == [] and thread["can_comment"] is True
    # People who may change tool permissions (operate), never yourself or a viewer.
    assert [p["principal"] for p in thread["people"]] == [ANA, LEE]
    refused = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools",
                                                    "body": "@Vic please look", "mentions": [VIC]})
    assert refused.status_code == 422
    assert "only people who can open this item" in refused.json()["detail"]
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools",
                                                   "body": "@Lee should web fetch stay blocked?", "mentions": [LEE]})
    assert posted.status_code == 201, posted.text
    body = posted.json()
    assert body["posted"]["mine"] is True and body["posted"]["mentions"] == ["lee@corp.com"]
    assert [c["body"] for c in body["comments"]] == ["@Lee should web fetch stay blocked?"]


def test_a_mention_reaches_the_person_with_why_what_and_where(env, monkeypatch):
    client, _world = env
    _as(monkeypatch, DANA)
    comment_id = client.post("/api/v1/comments", json={"kind": "policy", "id": "spending-limits",
                                                       "body": "@Lee can we lower this?", "mentions": [LEE]}).json()["posted"]["id"]
    from maverick_dashboard.comments_api import mention_sources

    sources = mention_sources(LEE)
    assert len(sources) == 1
    source = sources[0]
    assert source["ref"] == f"comment:{comment_id}" and source["category"] == "mention"
    assert source["href"] == f"/spending-limits#comment-{comment_id}"
    assert source["reason"] == "dana@corp.com mentioned you in a comment"
    assert source["action"] == "Read the comment and reply"
    assert "lower this" not in str(source)  # the alert never carries the comment text
    # Someone who can no longer open the item no longer sees the mention.
    ROLES[LEE] = "viewer"
    try:
        assert mention_sources(LEE) == []
    finally:
        ROLES[LEE] = "admin"


def test_a_task_thread_is_private_to_who_can_open_the_task(env, monkeypatch):
    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    _as(monkeypatch, ANA)
    thread = client.get("/api/v1/comments", params={"kind": "task", "id": str(goal_id)}).json()
    assert thread["people"] == []  # nobody else can open this task, so nobody else is offered
    assert client.post("/api/v1/comments", json={"kind": "task", "id": str(goal_id),
                                                 "body": "Note to self", "mentions": []}).status_code == 201
    assert client.post("/api/v1/comments", json={"kind": "task", "id": str(goal_id), "body": "@Lee",
                                                 "mentions": [LEE]}).status_code == 422
    _as(monkeypatch, LEE)
    assert client.get("/api/v1/comments", params={"kind": "task", "id": str(goal_id)}).status_code == 404


def test_only_the_author_deletes_and_unknown_items_have_no_thread(env, monkeypatch):
    client, _world = env
    _as(monkeypatch, DANA)
    comment = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "First"}).json()["posted"]
    _as(monkeypatch, LEE)
    assert client.delete(f"/api/v1/comments/{comment['id']}").status_code == 403
    _as(monkeypatch, DANA)
    assert client.delete(f"/api/v1/comments/{comment['id']}").json()["comments"] == []
    assert client.get("/api/v1/comments", params={"kind": "policy", "id": "nope"}).status_code == 404
    assert client.get("/api/v1/comments", params={"kind": "folder", "id": "1"}).status_code == 404


def test_turning_comments_off_says_so(env, monkeypatch, tmp_path):
    from maverick import config

    client, _world = env
    _as(monkeypatch, DANA)
    (tmp_path / "config.toml").write_text("[collaboration]\ncomments = false\n", encoding="utf-8")
    config.reset_config_cache()
    refused = client.get("/api/v1/comments", params={"kind": "policy", "id": "tools"})
    assert refused.status_code == 403
    assert refused.headers["X-Lightwork-Reason"] == "feature-off"


def _lee_reads_anas_task(world, monkeypatch):
    from maverick_dashboard import content_access

    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [{"requester": LEE}])
    monkeypatch.setattr(content_access, "_grant_current", lambda grant, **kw: True)
    return goal_id


def test_a_reader_the_company_directory_turned_off_is_not_offered_or_mentionable(env, monkeypatch):
    # Lee holds a reviewed read grant for Ana's task, but company sign-in
    # (SCIM) turned Lee off: Lee can no longer sign in to read a mention.
    from maverick_dashboard import scim_groups

    client, world = env
    goal_id = _lee_reads_anas_task(world, monkeypatch)
    _as(monkeypatch, ANA)
    params = {"kind": "task", "id": str(goal_id)}
    assert [p["principal"] for p in client.get("/api/v1/comments", params=params).json()["people"]] == [LEE]
    monkeypatch.setattr(scim_groups, "active_check", lambda: lambda principal: False if principal == LEE else None)
    assert client.get("/api/v1/comments", params=params).json()["people"] == []
    assert client.post("/api/v1/comments", json={**params, "body": "@Lee", "mentions": [LEE]}).status_code == 422
    assert client.post("/api/v1/comments", json={**params, "body": "Note", "mentions": []}).status_code == 201


def test_an_unreadable_company_directory_offers_nobody_and_holds_mentions(env, monkeypatch):
    from maverick_dashboard import scim_groups

    client, world = env
    goal_id = _lee_reads_anas_task(world, monkeypatch)
    _as(monkeypatch, ANA)

    def unreadable():
        raise OSError("directory unreadable")

    monkeypatch.setattr(scim_groups, "active_check", unreadable)
    params = {"kind": "task", "id": str(goal_id)}
    thread = client.get("/api/v1/comments", params=params)
    assert thread.status_code == 200 and thread.json()["people"] == []
    assert client.post("/api/v1/comments", json={**params, "body": "@Lee", "mentions": [LEE]}).status_code == 503
    assert client.post("/api/v1/comments", json={**params, "body": "Note", "mentions": []}).status_code == 201


def test_an_unreadable_company_directory_holds_a_mention_on_any_thread_with_the_same_answer(env, monkeypatch):
    # On an approval or policy thread the readers themselves come from the
    # directory, so an unreadable one is a 503, not "not allowed".
    from maverick_dashboard import scim_groups

    client, world = env
    _as(monkeypatch, DANA)

    def unreadable():
        raise OSError("directory unreadable")

    monkeypatch.setattr(scim_groups, "active_check", unreadable)
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@Ana",
                                                   "mentions": [ANA]})
    assert posted.status_code == 503


def test_a_thread_with_nobody_else_to_offer_does_not_read_the_directory(env, monkeypatch):
    from maverick_dashboard import scim_groups

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    _as(monkeypatch, ANA)
    reads = []
    real = scim_groups.active_check
    monkeypatch.setattr(scim_groups, "active_check", lambda: reads.append(1) or real())
    assert client.get("/api/v1/comments", params={"kind": "task", "id": str(goal_id)}).json()["people"] == []
    assert reads == []


def test_a_mention_nobody_could_accept_is_refused_while_the_directory_is_unreadable(env, monkeypatch):
    # Someone who cannot open the item, or yourself, is refused whatever the
    # directory says: a 422 now, not a 503 that fails again after a retry.
    from maverick_dashboard import scim_groups

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    _as(monkeypatch, ANA)

    def unreadable():
        raise OSError("directory unreadable")

    monkeypatch.setattr(scim_groups, "active_check", unreadable)
    task = {"kind": "task", "id": str(goal_id)}
    assert client.post("/api/v1/comments", json={**task, "body": "@Lee", "mentions": [LEE]}).status_code == 422
    assert client.post("/api/v1/comments", json={**task, "body": "@Ana", "mentions": [ANA]}).status_code == 422
    _as(monkeypatch, DANA)
    policy = {"kind": "policy", "id": "tools"}
    assert client.post("/api/v1/comments", json={**policy, "body": "@Dana", "mentions": [DANA]}).status_code == 422


def test_a_mention_is_decided_by_one_fresh_read_of_the_directory(env, monkeypatch):
    # The directory read that lists the policy's readers fails; the one that
    # checks the mention a moment later succeeds. The mention is decided by
    # that read: Lee manages tool permissions, so it is posted.
    from maverick_dashboard import scim_groups

    client, _world = env
    _as(monkeypatch, DANA)
    real, failures = scim_groups.active_check, [1]

    def flaky():
        if failures:
            failures.pop()
            raise OSError("directory briefly unreadable")
        return real()

    monkeypatch.setattr(scim_groups, "active_check", flaky)
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@Lee",
                                                   "mentions": [LEE]})
    assert posted.status_code == 201, posted.text
    assert failures == []


def test_an_unreadable_role_list_holds_a_mention_instead_of_refusing_it(env, monkeypatch):
    from maverick_dashboard import rbac

    client, _world = env
    _as(monkeypatch, DANA)

    def unreadable():
        raise OSError("role list unreadable")

    monkeypatch.setattr(rbac, "list_users", unreadable)
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@Lee",
                                                   "mentions": [LEE]})
    assert posted.status_code == 503
    assert "can't be checked right now" in posted.json()["detail"]


def _current_grant(owner, requester, kind, resource_id, revision=None):
    import time

    from maverick_dashboard import content_access

    grant = {"id": f"car-{requester}-{kind}-{resource_id}", "purpose": "Payroll audit",
             "tenant": content_access.tenant(), "owner": owner, "requester": requester, "resource_kind": kind,
             "resource_id": str(resource_id), "status": "approved", "expires_at": time.time() + 3600,
             "reviewed_by": DANA}
    if revision is not None:
        grant["resource_revision"] = revision
    return grant


def _directory_unreadable(monkeypatch):
    """Make the company directory unreadable; returns a function that restores it."""
    from maverick_dashboard import scim_groups

    real = scim_groups.active_check, scim_groups.active_for_principal

    def unreadable(*args):
        raise OSError("directory unreadable")

    monkeypatch.setattr(scim_groups, "active_check", unreadable)
    monkeypatch.setattr(scim_groups, "active_for_principal", unreadable)

    def restore():
        monkeypatch.setattr(scim_groups, "active_check", real[0])
        monkeypatch.setattr(scim_groups, "active_for_principal", real[1])
    return restore


def test_a_mention_of_a_reader_by_grant_is_held_while_the_directory_is_unreadable(env, monkeypatch):
    # Lee reads Ana's task through a reviewed grant. Whether that grant is
    # still current depends on the directory, so while it cannot be read the
    # mention is held (503), not refused as "not allowed".
    from maverick_dashboard import content_access

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [_current_grant(ANA, LEE, "goal", goal_id)])
    _as(monkeypatch, ANA)
    task = {"kind": "task", "id": str(goal_id), "body": "@Lee"}
    assert client.post("/api/v1/comments", json={**task, "mentions": [VIC]}).status_code == 422
    restore = _directory_unreadable(monkeypatch)
    assert client.post("/api/v1/comments", json={**task, "mentions": [LEE]}).status_code == 503
    # Vic holds no grant: refused without reading the directory.
    assert client.post("/api/v1/comments", json={**task, "mentions": [VIC]}).status_code == 422
    restore()
    assert client.post("/api/v1/comments", json={**task, "mentions": [LEE]}).status_code == 201


def test_an_approval_thread_mentions_only_its_readers_and_holds_one_it_cannot_confirm(env, monkeypatch):
    from maverick_dashboard import content_access

    client, world = env
    approval_id = world.create_approval("Pay invoice", requested_by=ANA)
    approval = world.get_approval(approval_id)
    revision = content_access.approval_resource(approval, world)["resource_revision"]
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list",
                        lambda: [_current_grant(ANA, LEE, "approval", approval_id, revision)])
    _as(monkeypatch, ANA)
    card = {"kind": "approval", "id": str(approval_id), "body": "@Lee"}
    assert client.post("/api/v1/comments", json={**card, "mentions": [VIC]}).status_code == 422
    assert client.post("/api/v1/comments", json={**card, "mentions": [LEE]}).status_code == 201
    _directory_unreadable(monkeypatch)
    assert client.post("/api/v1/comments", json={**card, "mentions": [LEE]}).status_code == 503
    assert client.post("/api/v1/comments", json={**card, "mentions": [VIC]}).status_code == 422


def test_a_policy_mention_is_checked_for_the_person_named_not_against_a_capped_list(env, monkeypatch):
    # The mention list shows at most 200 people; a mention of someone past
    # them who holds the permission is still accepted.
    from maverick_dashboard import auth, rbac

    client, _world = env
    roles = {**ROLES, **{f"user:op{index:03}@corp.com": "operator" for index in range(250)}}
    monkeypatch.setattr(rbac, "list_users", lambda: dict(roles))
    _as(monkeypatch, DANA)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p, **kw: roles.get(p))
    last = "user:op249@corp.com"
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@op249",
                                                   "mentions": [last]})
    assert posted.status_code == 201, posted.text
    # ...and it reaches them.
    from maverick_dashboard.comments_api import mention_sources

    assert [source["label"] for source in mention_sources(last)] == ["Mentioned you"]
    # Someone the list could never show (not on the roster, never signed in)
    # is refused, although the default role would cover them.
    unknown = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@x",
                                                    "mentions": ["user:nobody-ever@evil.example"]})
    assert unknown.status_code == 422


def test_a_role_from_an_unreadable_group_mapping_holds_a_mention_instead_of_refusing_it(env, monkeypatch):
    # Lee has signed in before and holds operator through a company-directory
    # group. While the group mapping cannot be read, sign-in treats Lee as a
    # viewer (the safe answer for access), but a mention is held, not refused.
    from maverick_dashboard import auth, rbac, scim_groups, subject_directory

    client, _world = env
    roles = {key: value for key, value in ROLES.items() if key != LEE}
    monkeypatch.setattr(rbac, "list_users", lambda: dict(roles))
    real_role = auth.global_role_for_principal
    _as(monkeypatch, DANA)
    monkeypatch.setattr(auth, "global_role_for_principal", real_role)
    monkeypatch.setattr(rbac, "get_stored_role", lambda p: roles.get(p))
    subject_directory.record_login(LEE.removeprefix("user:"), [LEE.removeprefix("user:")])
    monkeypatch.setattr(scim_groups, "_ci_mapping", lambda key: {"ops": "operator"})
    monkeypatch.setattr(scim_groups, "group_names_for_principal",
                        lambda p: frozenset({"ops"}) if p == LEE else frozenset())
    mention = {"kind": "policy", "id": "tools", "body": "@Lee", "mentions": [LEE]}
    assert client.post("/api/v1/comments", json=mention).status_code == 201

    def unreadable(key):
        raise OSError("group mapping unreadable")

    monkeypatch.setattr(scim_groups, "_ci_mapping", unreadable)
    assert scim_groups.role_for_principal(LEE) == "viewer"
    assert client.post("/api/v1/comments", json=mention).status_code == 503


def test_posting_a_mention_reads_the_directory_once_for_the_check(env, monkeypatch):
    # One read lists the policy's people, one decides the mention; the
    # posted thread reuses the first instead of reading again.
    from maverick_dashboard import scim_groups

    client, _world = env
    _as(monkeypatch, DANA)
    reads, real = [], scim_groups.active_check
    monkeypatch.setattr(scim_groups, "active_check", lambda: reads.append(1) or real())
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@Lee",
                                                   "mentions": [LEE]})
    assert posted.status_code == 201 and len(reads) == 2


def test_a_grant_holder_who_can_no_longer_open_the_task_is_not_offered_mentioned_or_told(env, monkeypatch):
    # Vic still holds a reviewed grant for Ana's task but is now a viewer: a
    # grant opens another person's task only to a global administrator. Vic
    # is not offered, cannot be mentioned, and an earlier mention does not
    # reach Vic with the task's title.
    from maverick import comments
    from maverick_dashboard import content_access
    from maverick_dashboard.comments_api import mention_sources

    client, world = env
    goal_id = world.create_goal("Secret layoff plan for Q3", owner=ANA)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [_current_grant(ANA, VIC, "goal", goal_id),
                                                               _current_grant(ANA, LEE, "goal", goal_id)])
    _as(monkeypatch, ANA)
    task = {"kind": "task", "id": str(goal_id)}
    assert [p["principal"] for p in client.get("/api/v1/comments", params=task).json()["people"]] == [LEE]
    assert client.post("/api/v1/comments", json={**task, "body": "@Vic", "mentions": [VIC]}).status_code == 422
    comments.add("task", str(goal_id), author=ANA, body="@Vic @Lee", mentions=[VIC, LEE])
    assert mention_sources(VIC) == []
    assert [source["title"] for source in mention_sources(LEE)] == ["Task: Secret layoff plan for Q3"]


def test_a_mention_of_someone_who_cannot_open_the_item_is_refused_beside_one_that_cannot_be_confirmed(env, monkeypatch):
    from maverick_dashboard import content_access

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [_current_grant(ANA, LEE, "goal", goal_id)])
    _as(monkeypatch, ANA)
    _directory_unreadable(monkeypatch)
    posted = client.post("/api/v1/comments", json={"kind": "task", "id": str(goal_id), "body": "@Lee @Vic",
                                                   "mentions": [LEE, VIC]})
    assert posted.status_code == 422


def test_mentioning_an_approvals_owner_does_not_wait_on_the_grant_store(env, monkeypatch):
    # Lee opens Ana's request through a grant; the grant store then fails.
    # Ana's own access needs no grant, so mentioning Ana is still checked.
    from maverick_dashboard import content_access

    client, world = env
    approval_id = world.create_approval("Pay invoice", requested_by=ANA)
    revision = content_access.approval_resource(world.get_approval(approval_id), world)["resource_revision"]
    reads = []

    def grants():
        reads.append(1)
        if len(reads) > 1:
            raise OSError("grant store unreadable")
        return [_current_grant(ANA, LEE, "approval", approval_id, revision)]

    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", grants)
    _as(monkeypatch, LEE)
    posted = client.post("/api/v1/comments", json={"kind": "approval", "id": str(approval_id), "body": "@Ana",
                                                   "mentions": [ANA]})
    assert posted.status_code == 201, posted.text


def test_a_policy_mention_of_someone_without_the_role_is_refused_while_the_directory_is_unreadable(env, monkeypatch):
    client, _world = env
    _as(monkeypatch, DANA)
    _directory_unreadable(monkeypatch)
    posted = client.post("/api/v1/comments", json={"kind": "policy", "id": "tools", "body": "@Vic",
                                                   "mentions": [VIC]})
    assert posted.status_code == 422


def _grant_store_unreadable(monkeypatch):
    from maverick_dashboard import content_access

    def unreadable():
        raise OSError("grant store unreadable")

    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", unreadable)


def test_someone_who_could_never_open_the_item_is_refused_while_the_grant_store_is_unreadable(env, monkeypatch):
    # Vic is a viewer: a grant opens another person's task only to a global
    # administrator, and an approval only to someone who may operate. That
    # is decided without the grant store.
    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    approval_id = world.create_approval("Pay invoice", requested_by=ANA)
    _as(monkeypatch, ANA)
    _grant_store_unreadable(monkeypatch)
    for kind, object_id in (("task", goal_id), ("approval", approval_id)):
        posted = client.post("/api/v1/comments", json={"kind": kind, "id": str(object_id), "body": "@Vic",
                                                       "mentions": [VIC]})
        assert posted.status_code == 422, (kind, posted.text)
    lee = client.post("/api/v1/comments", json={"kind": "task", "id": str(goal_id), "body": "@Lee",
                                                "mentions": [LEE]})
    assert lee.status_code == 503


def test_an_owner_whose_role_no_longer_lets_them_view_is_not_offered_or_told(env, monkeypatch):
    # The task page and its thread need the view permission; an owner whose
    # role grants nothing is refused there, so is not told about the task.
    from maverick import comments
    from maverick_dashboard import auth, rbac
    from maverick_dashboard.comments_api import mention_sources

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=VIC)
    comments.add("task", str(goal_id), author=ANA, body="@Vic", mentions=[VIC])
    assert len(mention_sources(VIC)) == 1
    roles = {**ROLES, VIC: "retired-custom-role"}
    monkeypatch.setattr(rbac, "list_users", lambda: dict(roles))
    monkeypatch.setattr(auth, "role_for_principal", lambda p, **kw: roles.get(p))
    assert mention_sources(VIC) == []
    from maverick_dashboard.comments_api import _goal_readers

    assert VIC not in _goal_readers(world.get_goal(goal_id))


def test_a_refusal_from_a_readable_rule_decides_whatever_the_directory_says(env, monkeypatch):
    # Dana is an administrator with no grant for Ana's task or request: the
    # readable grant store already refuses her, so an unreadable directory
    # does not turn that into "try again".
    from maverick_dashboard import content_access

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    approval_id = world.create_approval("Pay invoice", requested_by=ANA)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", list)
    _as(monkeypatch, ANA)
    _directory_unreadable(monkeypatch)
    for kind, object_id in (("task", goal_id), ("approval", approval_id)):
        posted = client.post("/api/v1/comments", json={"kind": kind, "id": str(object_id), "body": "@Dana",
                                                       "mentions": [DANA]})
        assert posted.status_code == 422, (kind, posted.text)


@pytest.mark.parametrize("reader,role,grant,domain_ok,expected", [
    (ANA, "nothing", False, True, False),     # owner whose role grants nothing (the page needs view)
    (ANA, "operator", False, True, True),     # owner
    (ANA, "operator", False, False, False),   # owner outside the task's department
    (LEE, "admin", True, True, True),         # global administrator with a current grant
    (LEE, "admin", False, True, False),       # global administrator without one
    (VIC, "viewer", True, True, False),       # a grant without administrator rights
    (LEE, "admin", True, False, False),       # grant, but outside the department
])
def test_who_is_told_about_a_task_matches_who_the_task_page_lets_in(env, monkeypatch, reader, role, grant,
                                                                    domain_ok, expected):
    # auth.goal_readable_by (mentions and notifications) and auth.can_access_goal
    # (the page) must give the same answer.
    from maverick import domain as domain_mod
    from maverick_dashboard import auth, content_access, rbac, suite_grants
    from starlette.requests import Request

    client, world = env
    goal_id = world.create_goal("Reconcile vendor spend", owner=ANA)
    goal = world.get_goal(goal_id)
    goal.domain = "finance-pack"
    monkeypatch.setattr(domain_mod, "suites_for_domain", lambda d: ["finance"])
    monkeypatch.setattr(suite_grants, "granted_suites", lambda p: None if domain_ok else frozenset({"legal"}))
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda p: False)
    roles = {**ROLES, reader: role}
    monkeypatch.setattr(rbac, "list_users", lambda: dict(roles))
    monkeypatch.setattr(auth, "role_for_principal", lambda p, **kw: roles.get(p))
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p, **kw: roles.get(p))
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: reader)
    monkeypatch.setattr(auth, "has_global_permission",
                        lambda request, perm, **kw: perm in rbac.permissions_for(roles.get(reader)))
    monkeypatch.setattr(auth, "has_permission",
                        lambda request, perm, **kw: perm in rbac.permissions_for(roles.get(reader)))
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list",
                        lambda: [_current_grant(ANA, reader, "goal", goal_id)] if grant else [])
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    # The page: the view permission, then the task's own rules.
    page = auth.has_permission(request, "view") and auth.can_access_goal(request, goal)
    assert page is expected
    assert auth.goal_readable_by(reader, goal) is page


def _copy_of(world, monkeypatch, sources):
    """Ana's task, a copied conversation of ``sources`` (Ana's tasks), checked
    by the real copied-source walk."""
    from maverick import chat_message_actions

    goal_id = world.create_goal("Copy of the vendor review", owner=ANA)
    source_ids = [world.create_goal(title, owner=ANA, domain=domain) for title, domain in sources]
    monkeypatch.setattr(chat_message_actions, "_alternative",
                        lambda world, goal: {"source_goal_ids": source_ids} if goal == goal_id else None)
    return goal_id, source_ids


def test_a_copied_source_that_refuses_decides_while_the_grant_store_is_unreadable(env, monkeypatch):
    # Ana's task copies a conversation from the legal department. Lee works
    # in finance only, so that source refuses him outright; that decides even
    # though his grant for the task itself cannot be read.
    from maverick import domain as domain_mod
    from maverick_dashboard import suite_grants

    client, world = env
    goal_id, _ = _copy_of(world, monkeypatch, [("Legal review", "legal-pack")])
    monkeypatch.setattr(domain_mod, "suites_for_domain", lambda d: ["legal"] if d == "legal-pack" else [])
    monkeypatch.setattr(suite_grants, "granted_suites",
                        lambda p: frozenset({"finance", "legal"} if p == ANA else {"finance"}))
    _as(monkeypatch, ANA)
    _grant_store_unreadable(monkeypatch)
    posted = client.post("/api/v1/comments", json={"kind": "task", "id": str(goal_id), "body": "@Lee",
                                                   "mentions": [LEE]})
    assert posted.status_code == 422, posted.text


@pytest.mark.parametrize("order", ["legal first", "finance first"])
def test_a_copied_source_that_cannot_be_read_does_not_hide_a_later_one_that_refuses(env, monkeypatch, order):
    # Two copied sources: one cannot be checked (its knowledge connector is
    # down), the other is from the legal department, which refuses Lee. The
    # refusal decides, in whichever order the walk visits them.
    from maverick import domain as domain_mod
    from maverick import knowledge_task_context
    from maverick_dashboard import auth, strict_reads, suite_grants

    client, world = env
    sources = [("Legal review", "legal-pack"), ("Finance review", "finance-pack")]
    if order == "finance first":
        sources.reverse()
    goal_id, ids = _copy_of(world, monkeypatch, sources)
    legal, finance = ids if order == "legal first" else ids[::-1]
    monkeypatch.setattr(domain_mod, "suites_for_domain",
                        lambda d: {"legal-pack": ["legal"], "finance-pack": ["finance"]}.get(d, []))
    monkeypatch.setattr(suite_grants, "granted_suites", lambda p: frozenset({"finance"}))

    def require_read(goal, actor, **kw):
        if goal.id == finance:
            raise RuntimeError("knowledge connector unreachable")

    monkeypatch.setattr(knowledge_task_context, "require_read", require_read)
    # Lee holds grants for the task and both sources: only the department
    # and the outage decide.
    from maverick_dashboard import content_access

    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list",
                        lambda: [_current_grant(ANA, LEE, "goal", goal) for goal in (goal_id, legal, finance)])
    _as(monkeypatch, ANA)
    roles = dict(ROLES)
    monkeypatch.setattr(auth, "role_for_principal", lambda p, **kw: roles.get(p))
    with strict_reads.strict():
        assert auth.goal_readable_by(LEE, world.get_goal(goal_id), grants={LEE}) is False


def test_a_copied_source_that_cannot_be_read_does_not_turn_an_unreadable_grant_into_a_refusal(env, monkeypatch):
    # Lee's grant for the task cannot be read, and the copied source's
    # connector is down (which the copy check reports as an unavailable
    # source). Neither is a refusal, so a strict check raises.
    from maverick import knowledge_task_context
    from maverick.knowledge_task_context import SourceContextUnavailable
    from maverick_dashboard import auth, content_access, strict_reads

    client, world = env
    goal_id, (source_id,) = _copy_of(world, monkeypatch, [("Finance review", "")])

    reads = []

    def require_read(goal, actor, **kw):
        reads.append(goal.id)
        raise SourceContextUnavailable("The knowledge connector could not be reached.")

    monkeypatch.setattr(knowledge_task_context, "require_read", require_read)
    # Lee may read the source itself; only the task's grant read fails.
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list", lambda: [_current_grant(ANA, LEE, "goal", source_id)])
    _as(monkeypatch, ANA)
    goal = world.get_goal(goal_id)
    with strict_reads.strict(), pytest.raises(OSError):
        auth.goal_readable_by(LEE, goal, grants=OSError("grant store unreadable"))
    assert reads == [source_id]  # the source was walked and reported unavailable
    assert auth.goal_readable_by(LEE, goal, grants=OSError("grant store unreadable")) is False
    # With the task's own grant readable, the unavailable source alone is a refusal.
    with strict_reads.strict():
        assert auth.goal_readable_by(LEE, goal, grants={LEE}) is False


@pytest.mark.parametrize("order", ["unavailable first", "outage first"])
def test_an_outage_in_one_copied_source_is_not_read_as_a_refusal_in_another(env, monkeypatch, order):
    # One source reports itself unavailable (which may be a refusal), another
    # cannot be read at all. The person cannot be confirmed either way, in
    # whichever order the walk visits the two.
    from maverick import knowledge_task_context
    from maverick.knowledge_task_context import SourceContextUnavailable
    from maverick_dashboard import auth, content_access, strict_reads

    client, world = env
    goal_id, ids = _copy_of(world, monkeypatch, [("A", ""), ("B", "")])
    unavailable, down = ids if order == "outage first" else ids[::-1]

    def require_read(goal, actor, **kw):
        if goal.id == unavailable:
            raise SourceContextUnavailable("This source is unavailable.")
        if goal.id == down:
            raise RuntimeError("store down")

    monkeypatch.setattr(knowledge_task_context, "require_read", require_read)
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list",
                        lambda: [_current_grant(ANA, LEE, "goal", goal) for goal in (goal_id, *ids)])
    _as(monkeypatch, ANA)
    with strict_reads.strict(), pytest.raises(RuntimeError):
        auth.goal_readable_by(LEE, world.get_goal(goal_id), grants={LEE})


def test_a_nested_copied_source_that_refuses_decides_past_a_parent_that_cannot_be_read(env, monkeypatch):
    # The task copies A, and A is itself a copy of B. A cannot be read (its
    # connector is down); B is from the legal department, which refuses Lee.
    from maverick import chat_message_actions, knowledge_task_context
    from maverick import domain as domain_mod
    from maverick_dashboard import auth, content_access, strict_reads, suite_grants

    client, world = env
    goal_id, (parent,) = _copy_of(world, monkeypatch, [("A", "finance-pack")])
    nested = world.create_goal("B", owner=ANA, domain="legal-pack")

    class Store:
        def __init__(self, world):
            pass

        def for_goal(self, identity):
            if identity == parent:
                return {"detail": {"kind": chat_message_actions.KINDS[0],
                                   "alternative": {"source_goal_ids": [nested]}}}
            return None

    def require_read(goal, actor, **kw):
        if goal.id == parent:
            raise RuntimeError("connector unreachable")

    monkeypatch.setattr(chat_message_actions, "SubmissionStore", Store)
    monkeypatch.setattr(knowledge_task_context, "require_read", require_read)
    monkeypatch.setattr(domain_mod, "suites_for_domain",
                        lambda d: {"legal-pack": ["legal"], "finance-pack": ["finance"]}.get(d, []))
    monkeypatch.setattr(suite_grants, "granted_suites", lambda p: frozenset({"finance"}))
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list",
                        lambda: [_current_grant(ANA, LEE, "goal", goal) for goal in (goal_id, parent, nested)])
    _as(monkeypatch, ANA)
    with strict_reads.strict():
        assert auth.goal_readable_by(LEE, world.get_goal(goal_id), grants={LEE}) is False


def test_a_nested_copied_source_that_refuses_decides_past_a_parent_that_cannot_be_loaded(env, monkeypatch):
    # As above, but loading A itself fails: B is still walked and refuses.
    from maverick import chat_message_actions, knowledge_task_context
    from maverick import domain as domain_mod
    from maverick_dashboard import auth, content_access, strict_reads, suite_grants

    client, world = env
    goal_id, (parent,) = _copy_of(world, monkeypatch, [("A", "finance-pack")])
    nested = world.create_goal("B", owner=ANA, domain="legal-pack")

    class Store:
        def __init__(self, world):
            pass

        def for_goal(self, identity):
            if identity == parent:
                return {"detail": {"kind": chat_message_actions.KINDS[0],
                                   "alternative": {"source_goal_ids": [nested]}}}
            return None

    real_get_goal = world.get_goal

    def get_goal(identity):
        if identity == parent:
            raise OSError("world unreadable for A")
        return real_get_goal(identity)

    monkeypatch.setattr(chat_message_actions, "SubmissionStore", Store)
    monkeypatch.setattr(knowledge_task_context, "require_read", lambda goal, actor, **kw: None)
    monkeypatch.setattr(domain_mod, "suites_for_domain",
                        lambda d: {"legal-pack": ["legal"], "finance-pack": ["finance"]}.get(d, []))
    monkeypatch.setattr(suite_grants, "granted_suites", lambda p: frozenset({"finance"}))
    monkeypatch.setattr(content_access, "enabled", lambda: True)
    monkeypatch.setattr(content_access.STORE, "list",
                        lambda: [_current_grant(ANA, LEE, "goal", goal) for goal in (goal_id, parent, nested)])
    _as(monkeypatch, ANA)
    goal = world.get_goal(goal_id)
    monkeypatch.setattr(world, "get_goal", get_goal)
    from maverick_dashboard import _shared

    monkeypatch.setattr(_shared, "_world", lambda: world)
    with strict_reads.strict():
        assert auth.goal_readable_by(LEE, goal, grants={LEE}) is False
