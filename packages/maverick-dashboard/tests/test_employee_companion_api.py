"""Companion HTTP boundaries with real, temporary policy/history and task stores.

Identity headers are a test-only authentication seam. The router's permission,
current membership, same-origin, context, and policy checks remain real. The
small app deliberately omits the production lifespan and its background jobs.
"""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Event

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.world_model import WorldModel
from maverick_dashboard import employee_companion_api as companion

BASE = "/api/v1/employee-companion"
CONTEXT = "X-Lightwork-Companion-Context"
ALICE = "user:alice"
BOB = "user:bob"
ADMIN = "user:administrator"


def _ok(response):
    assert response.status_code == 200, response.text
    return response.json()


def _headers(actor=ALICE, tenant="acme", *, context=None):
    headers = {"X-Test-Principal": actor, "X-Test-Tenant": tenant}
    if context is not None:
        headers[CONTEXT] = context
    return headers


def _policy_body(owner=ALICE, revision=0, **changes):
    return {
        "owner": owner,
        "expected_revision": revision,
        "enabled": True,
        "allowed_sources": ["own_tasks"],
        "allowed_tools": ["task_status"],
        "retention_days": 7,
        **changes,
    }


def _request_id():
    return f"{int(time.time() * 1000)}.{uuid.uuid4().hex}"


@dataclass
class Environment:
    client: TestClient
    worlds: dict[str, WorldModel]
    features: dict
    memberships: dict[str, dict[str, str]]
    active: dict[str, bool]
    suites: dict[str, frozenset[str] | None]

    def view(self, actor=ALICE, tenant="acme"):
        return _ok(self.client.get(BASE, headers=_headers(actor, tenant)))

    def admin(self, tenant="acme"):
        return _ok(self.client.get(BASE + "/admin", headers=_headers(ADMIN, tenant)))

    def policy(self, owner=ALICE, tenant="acme", **changes):
        revision = self.view(owner, tenant)["policy"]["revision"]
        context = self.admin(tenant)["context"]
        return _ok(self.client.put(
            BASE + "/admin/policy",
            headers=_headers(ADMIN, tenant, context=context),
            json=_policy_body(owner, revision, **changes),
        ))["policy"]

    def message(self, message="what is running?", *, actor=ALICE, tenant="acme", view=None):
        snapshot = self.view(actor, tenant) if view is None else view
        return self.client.post(
            BASE + "/messages",
            headers=_headers(actor, tenant, context=snapshot["context"]),
            json={"message": message, "expected_revision": snapshot["policy"]["revision"]},
        )

    def conversation(self, message="Help me draft a plan", *, actor=ALICE, tenant="acme",
                     view=None, request_id=None, **changes):
        snapshot = self.view(actor, tenant) if view is None else view
        return self.client.post(
            BASE + "/messages",
            headers=_headers(actor, tenant, context=snapshot["context"]),
            json={
                "mode": "conversation", "message": message,
                "request_id": request_id or _request_id(),
                "expected_revision": snapshot["policy"]["revision"],
                "expected_history_generation": snapshot["history_generation"],
                **changes,
            },
        )

    def request_status(self, request_id, *, actor=ALICE, tenant="acme"):
        return _ok(self.client.get(
            BASE + f"/requests/{request_id}", headers=_headers(actor, tenant),
        ))


@dataclass
class DraftGeneration:
    """A synchronous provider stand-in which honors the physical dispatch guard."""

    calls: list[dict] = field(default_factory=list)
    dispatched: list[dict] = field(default_factory=list)
    reply: str = "A private draft to review."
    before_dispatch: object = None
    after_dispatch: object = None

    def generate(self, *, actor, tenant, route, message, history, tasks, dispatch_guard):
        call = {
            "actor": actor, "tenant": tenant, "route": route,
            "message": message, "history": history, "tasks": tasks,
        }
        self.calls.append(call)
        if self.before_dispatch is not None:
            self.before_dispatch()
        dispatch_guard()
        self.dispatched.append(call)
        if self.after_dispatch is not None:
            self.after_dispatch()
        return self.reply


@pytest.fixture
def draft_generation(environment, monkeypatch):
    model = companion.companion_model
    draft = DraftGeneration()
    monkeypatch.setattr(model, "prepare_route", lambda: model.CompanionModelRoute(
        model="mock:companion-test-route", provider="mock", fingerprint="a" * 64,
        tenant=current_tenant_id_strict(),
    ))
    monkeypatch.setattr(model, "validate_route", lambda _route: None)
    monkeypatch.setattr(model, "generate_draft", draft.generate)
    return draft


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from maverick import crypto_at_rest, providers, runner
    from maverick.llm import LLM
    from maverick.tools import ToolRegistry
    from maverick_dashboard import app as dashboard

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "test-at-rest.key")

    features = {"employee_companions": True}
    memberships = {
        "acme": {ALICE: "operator", BOB: "viewer", ADMIN: "admin"},
        "globex": {ALICE: "operator", "user:globex-only": "viewer", ADMIN: "admin"},
    }
    active = {}
    suites = {}
    monkeypatch.setattr(companion.config, "get_features", lambda: dict(features))
    monkeypatch.setattr(
        companion.auth, "caller_principal",
        lambda request: request.headers.get("X-Test-Principal") or None,
    )
    monkeypatch.setattr(companion.auth, "anonymous_local_access_allowed", lambda: True)
    monkeypatch.setattr(companion.auth, "is_dashboard_admin", lambda principal: principal == ADMIN)
    # Preserve the legacy authenticated default; absence from the live tenant
    # roster must still be denied by the additional companion membership gate.
    monkeypatch.setattr(companion.auth, "global_role_for_principal", lambda _principal: "operator")
    monkeypatch.setattr(
        companion.rbac, "get_tenant_role",
        lambda tenant, principal: memberships.get(tenant, {}).get(principal),
    )
    monkeypatch.setattr(
        companion.rbac, "list_tenant_roles",
        lambda tenant: dict(memberships.get(tenant, {})),
    )
    monkeypatch.setattr(
        companion.scim_groups, "active_for_principal", lambda principal: active.get(principal, True),
    )
    monkeypatch.setattr(companion, "granted_suites", lambda principal: suites.get(principal))

    worlds = {}
    for tenant in memberships:
        with tenant_scope(tenant=tenant):
            worlds[tenant] = WorldModel(tmp_path / f"{tenant}-world.db")
    monkeypatch.setattr(dashboard, "_world", lambda: worlds[current_tenant_id_strict()])
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda *_args, **_kwargs: None)

    def forbidden(*_args, **_kwargs):
        pytest.fail("The bounded companion must not invoke a provider, model, runner, or tool")

    monkeypatch.setattr(providers, "get_provider_client", forbidden)
    monkeypatch.setattr(LLM, "complete", forbidden)
    monkeypatch.setattr(LLM, "complete_async", forbidden)
    monkeypatch.setattr(ToolRegistry, "run", forbidden)
    monkeypatch.setattr(runner, "run_goal_in_thread", forbidden)
    monkeypatch.setattr(runner, "run_goal_in_background", forbidden)
    monkeypatch.setattr(runner, "run_goal_in_background_async", forbidden)

    app = FastAPI()

    @app.middleware("http")
    async def selected_workspace(request, call_next):
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "acme")):
            return await call_next(request)

    app.include_router(companion.router)
    from maverick_dashboard import product_operations

    app.include_router(product_operations.router)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield Environment(client, worlds, features, memberships, active, suites)
    for world in worlds.values():
        world.close()


def test_missing_feature_flag_disables_reads_and_messages(environment, monkeypatch):
    environment.policy()
    environment.features.clear()

    def no_sources(*_args, **_kwargs):
        pytest.fail("A disabled companion must not fetch task sources")

    monkeypatch.setattr(companion, "_tasks", no_sources)
    view = environment.view()
    assert view["available"] is False
    assert view["tasks"] == []
    assert environment.message(view=view).status_code == 403
    assert environment.admin()["available"] is False


def test_employee_policy_starts_disabled_and_bounded(environment):
    view = environment.view()
    policy = view["policy"]
    assert view["available"] is False
    assert view["tasks"] == view["history"] == []
    assert policy["revision"] == 0
    assert policy["enabled"] is False
    assert policy["allowed_sources"] == policy["allowed_tools"] == []
    assert policy["memory_enabled"] is False
    assert policy["admin_content_access"] is False
    assert policy["action_mode"] == "read_only"
    assert policy["approvals"] == "writes_blocked"
    assert policy["retention_days"] == 0
    assert environment.message(view=view).status_code == 403


@pytest.mark.parametrize("actor", ["", "service:worker", "user:unassigned"])
def test_named_explicit_member_required_even_with_default_operator(environment, actor):
    response = environment.client.get(BASE, headers=_headers(actor))
    assert response.status_code == 403


def test_config_admin_still_needs_explicit_workspace_membership(environment):
    del environment.memberships["acme"][ADMIN]
    assert environment.client.get(BASE, headers=_headers(ADMIN)).status_code == 403
    assert environment.client.get(BASE + "/admin", headers=_headers(ADMIN)).status_code == 403


@pytest.mark.parametrize("actor", [ALICE, BOB])
def test_policy_administration_requires_admin_permission(environment, actor):
    context = environment.view(actor)["context"]
    assert environment.client.get(BASE + "/admin", headers=_headers(actor)).status_code == 403
    response = environment.client.put(
        BASE + "/admin/policy", headers=_headers(actor, context=context), json=_policy_body(),
    )
    assert response.status_code == 403
    assert environment.view()["policy"]["revision"] == 0


def test_admin_cannot_target_other_tenant_or_inactive_employee(environment):
    context = environment.admin()["context"]
    environment.active[BOB] = False
    for owner in ("user:globex-only", BOB, "user:unassigned"):
        response = environment.client.put(
            BASE + "/admin/policy", headers=_headers(ADMIN, context=context),
            json=_policy_body(owner=owner),
        )
        assert response.status_code == 404, response.text
    assert environment.admin()["policies"] == []
    assert {employee["principal"] for employee in environment.admin()["employees"]} == {ALICE, ADMIN}


def test_owner_only_tasks_and_history_even_for_configuration_admin(environment):
    world = environment.worlds["acme"]
    alice_goal = world.create_goal("Alice private task title", owner=ALICE)
    bob_goal = world.create_goal("Bob private task title", owner=BOB)
    admin_goal = world.create_goal("Administrator own task", owner=ADMIN)
    world.create_goal("Legacy ownerless task")
    for actor in (ALICE, BOB, ADMIN):
        environment.policy(actor)
        assert environment.message(f"Private conversation belonging to {actor}", actor=actor).status_code == 200

    for actor, expected_goal in ((ALICE, alice_goal), (BOB, bob_goal), (ADMIN, admin_goal)):
        view = environment.view(actor)
        assert [task["goal_id"] for task in view["tasks"]] == [expected_goal]
        assert [turn["content"] for turn in view["history"] if turn["role"] == "user"] == [
            f"Private conversation belonging to {actor}",
        ]
        # Query parameters cannot select a different employee's personal view.
        forged = _ok(environment.client.get(
            BASE + "?owner=user:alice", headers=_headers(actor),
        ))
        assert forged["history"] == view["history"]
        assert [task["goal_id"] for task in forged["tasks"]] == [expected_goal]


def test_same_employee_isolated_between_tenants(environment):
    environment.worlds["acme"].create_goal("Acme private task", owner=ALICE)
    environment.worlds["globex"].create_goal("Globex private task", owner=ALICE)
    environment.policy(tenant="acme")
    environment.policy(tenant="globex", retention_days=1)
    assert environment.message("Acme-only private conversation", tenant="acme").status_code == 200

    acme = environment.view(tenant="acme")
    globex = environment.view(tenant="globex")
    assert acme["context"] != globex["context"]
    assert [task["title"] for task in acme["tasks"]] == ["Acme private task"]
    assert [task["title"] for task in globex["tasks"]] == ["Globex private task"]
    assert globex["history"] == []
    assert globex["policy"]["retention_days"] == 1
    assert acme["policy"]["retention_days"] == 7
    assert all(event["action"] != "reply" for event in environment.admin("globex")["events"])


def test_current_department_and_project_scope_applies_to_admin_owned_tasks(environment, monkeypatch):
    world = environment.worlds["acme"]
    environment.policy(ADMIN)
    environment.suites[ADMIN] = frozenset({"finance"})
    own_project = world.create_project("Own project", owner=ADMIN)
    foreign_project = world.create_project("Employee private project", owner=ALICE)
    missing_project = world.create_project("Unavailable project", owner=ADMIN)
    allowed = world.create_goal("Finance task", owner=ADMIN, domain="finance_fpa", project_id=own_project)
    world.create_goal("No legal access", owner=ADMIN, domain="legal_contract_review")
    world.create_goal("Foreign project", owner=ADMIN, domain="finance_fpa", project_id=foreign_project)
    world.create_goal("Missing project", owner=ADMIN, domain="finance_fpa", project_id=missing_project)
    world.create_goal("Unavailable finance specialist", owner=ADMIN, domain="finance_planning")
    original_get_project = world.get_project
    monkeypatch.setattr(
        world, "get_project",
        lambda project_id: None if project_id == missing_project else original_get_project(project_id),
    )
    assert [task["goal_id"] for task in environment.view(ADMIN)["tasks"]] == [allowed]


def test_policy_compare_and_swap_and_stale_message_fail_closed(environment, monkeypatch):
    first = environment.policy()
    stale = environment.view()
    current = environment.policy(retention_days=1)
    assert current["revision"] == first["revision"] + 1
    context = environment.admin()["context"]
    response = environment.client.put(
        BASE + "/admin/policy", headers=_headers(ADMIN, context=context),
        json=_policy_body(revision=first["revision"], enabled=False),
    )
    assert response.status_code == 409
    assert environment.view()["policy"] == current

    def no_sources(*_args, **_kwargs):
        pytest.fail("A stale policy revision must be rejected before reading sources")

    monkeypatch.setattr(companion, "_tasks", no_sources)
    assert environment.message(view=stale).status_code == 409
    assert all(event["action"] != "reply" for event in environment.admin()["events"])


@pytest.mark.parametrize("actor,tenant", [(BOB, "acme"), (ALICE, "globex")])
def test_stale_account_or_workspace_context_rejected_for_reads_and_writes(environment, actor, tenant):
    environment.policy()
    environment.policy(actor, tenant)
    original = environment.view()
    wrong_context = _headers(actor, tenant, context=original["context"])
    assert environment.client.get(BASE, headers=wrong_context).status_code == 409
    assert environment.client.post(
        BASE + "/messages", headers=wrong_context,
        json={"message": "Private stale-tab message", "expected_revision": 1},
    ).status_code == 409
    assert environment.client.request("DELETE", BASE + "/history", headers=wrong_context,
                                      json={"expected_revision": environment.view()["history_revision"]}).status_code == 409
    assert environment.view(actor, tenant)["history"] == []
    assert all(event["action"] != "reply" for event in environment.admin(tenant)["events"])


@pytest.mark.parametrize("operation", ["message", "clear", "policy"])
def test_writes_require_context_from_current_get(environment, operation):
    environment.policy()
    if operation == "message":
        response = environment.client.post(
            BASE + "/messages", headers=_headers(),
            json={"message": "what is running?", "expected_revision": 1},
        )
    elif operation == "clear":
        response = environment.client.request("DELETE", BASE + "/history", headers=_headers(),
                                              json={"expected_revision": environment.view()["history_revision"]})
    else:
        response = environment.client.put(
            BASE + "/admin/policy", headers=_headers(ADMIN), json=_policy_body(revision=1),
        )
    assert response.status_code == 409


@pytest.mark.parametrize("operation", ["message", "clear", "policy"])
def test_foreign_origin_blocked_even_with_valid_context(environment, operation):
    environment.policy()
    actor = ADMIN if operation == "policy" else ALICE
    headers = _headers(actor, context=environment.view(actor)["context"])
    headers["Origin"] = "https://untrusted.example"
    if operation == "message":
        response = environment.client.post(
            BASE + "/messages", headers=headers,
            json={"message": "what is running?", "expected_revision": 1},
        )
    elif operation == "clear":
        response = environment.client.request("DELETE", BASE + "/history", headers=headers,
                                              json={"expected_revision": environment.view()["history_revision"]})
    else:
        response = environment.client.put(
            BASE + "/admin/policy", headers=headers, json=_policy_body(revision=1),
        )
    assert response.status_code == 403


@pytest.mark.parametrize("extra", [
    {"owner": BOB}, {"tenant": "globex"}, {"tools": ["shell"]},
    {"memory_enabled": True}, {"expected_revision": True}, {"message": 123},
])
def test_message_payload_rejects_authority_spoofing_and_coercion(environment, extra):
    environment.policy()
    view = environment.view()
    response = environment.client.post(
        BASE + "/messages", headers=_headers(context=view["context"]),
        json={"message": "what is running?", "expected_revision": 1, **extra},
    )
    assert response.status_code == 422
    assert environment.view()["history"] == []


@pytest.mark.parametrize("changes", [
    {"allowed_sources": ["all_documents"]}, {"allowed_tools": ["shell"]},
    {"memory_enabled": True}, {"admin_content_access": True},
    {"approvals": "automatic"}, {"action_mode": "write"},
    {"tenant": "globex"}, {"retention_days": 365}, {"retention_days": True},
    {"enabled": "true"}, {"expected_revision": True},
])
def test_policy_payload_cannot_expand_supported_capabilities(environment, changes):
    context = environment.admin()["context"]
    response = environment.client.put(
        BASE + "/admin/policy", headers=_headers(ADMIN, context=context),
        json=_policy_body(**changes),
    )
    assert response.status_code == 422
    assert environment.view()["policy"]["revision"] == 0


@pytest.mark.parametrize("revocation", ["membership", "offboarding", "policy", "sources", "tools"])
def test_current_revocation_prevents_source_fetch(environment, monkeypatch, revocation):
    environment.policy()
    previous = environment.view()
    if revocation == "membership":
        del environment.memberships["acme"][ALICE]
    elif revocation == "offboarding":
        environment.active[ALICE] = False
    else:
        change = {"enabled": False} if revocation == "policy" else {f"allowed_{revocation}": []}
        environment.policy(**change)

    def no_sources(*_args, **_kwargs):
        pytest.fail("Revoked authority must be denied before fetching any task source")

    monkeypatch.setattr(companion, "_tasks", no_sources)
    expected = 403 if revocation in {"membership", "offboarding"} else 409
    assert environment.message(view=previous).status_code == expected
    if expected == 409:
        now = environment.view()
        assert now["available"] is False
        assert now["tasks"] == []
        assert environment.message(view=now).status_code == 403


def test_department_revocation_hides_current_sources_and_historical_links(environment):
    world = environment.worlds["acme"]
    world.create_goal("Previously allowed confidential finance title", owner=ALICE, domain="finance_fpa")
    environment.policy()
    environment.suites[ALICE] = frozenset({"finance"})
    first = _ok(environment.message())
    assert len(first["message"]["sources"]) == 1
    environment.suites[ALICE] = frozenset()
    second = _ok(environment.message())
    assert second["message"]["sources"] == []
    assert "Previously allowed confidential finance title" not in str(second)
    assert all(turn.get("sources", []) == [] for turn in second["history"])


def test_department_revoke_waits_for_authority_bound_read(environment, monkeypatch):
    from maverick import authority_effects, suite_grants

    monkeypatch.setattr(suite_grants, "_audit_grant_change", lambda *_args: None)
    suite_grants.set_suites(ALICE, ["finance"], actor=ADMIN)
    original_fence = authority_effects.authority_effect_fence
    original_write = suite_grants._write
    revoke_reached_fence = Event()
    read_in_progress = Event()

    @contextmanager
    def observed_fence():
        revoke_reached_fence.set()
        with original_fence():
            yield

    def guarded_write(data):
        assert not read_in_progress.is_set(), "Department revoke passed an active authority fence"
        original_write(data)

    monkeypatch.setattr(authority_effects, "authority_effect_fence", observed_fence)
    monkeypatch.setattr(suite_grants, "_write", guarded_write)
    with ThreadPoolExecutor(max_workers=1) as worker:
        with original_fence():
            read_in_progress.set()
            future = worker.submit(suite_grants.set_suites, ALICE, [], actor=ADMIN)
            try:
                assert revoke_reached_fence.wait(timeout=5), "Revoke did not use the authority fence"
                assert not future.done()
                assert suite_grants.get_grant(ALICE) == frozenset({"finance"})
            finally:
                read_in_progress.clear()
        future.result(timeout=5)
    assert suite_grants.get_grant(ALICE) == frozenset()


def test_active_durable_work_does_not_block_replies_or_mutate_work(environment):
    world = environment.worlds["acme"]
    goal = world.create_goal("Already running task", owner=ALICE)
    world.set_goal_status(goal, "active")
    environment.policy()
    for text in ("what is running?", "what needs attention?", f"cancel goal {goal}"):
        reply = _ok(environment.message(text))
        assert reply["message"]["trace"]["decision"] == "allowed"
        assert world.get_goal(goal).status == "active"
    assert len(world.list_goals(owner=ALICE)) == 1
    assert len(environment.view()["history"]) == 6


def test_admin_metadata_never_contains_private_conversation_or_task_titles(environment, monkeypatch):
    from maverick import crypto_at_rest

    world = environment.worlds["acme"]
    world.create_goal("Private merger plan title", owner=ALICE)
    environment.policy()
    private_text = "Private health and family discussion"
    assert environment.message(private_text).status_code == 200
    assert environment.message().status_code == 200

    def no_decryption(*_args, **_kwargs):
        pytest.fail("Administrative metadata must not decrypt employee conversations")

    monkeypatch.setattr(crypto_at_rest, "unseal_bound", no_decryption)
    admin = environment.admin()
    assert private_text not in str(admin)
    assert "Private merger plan title" not in str(admin)
    assert "history" not in admin
    assert any(event["action"] == "reply" for event in admin["events"])
    forbidden_fields = {"message", "response", "content", "history", "source_refs", "sources"}
    assert all(not forbidden_fields.intersection(event) for event in admin["events"])
    assert all(policy["admin_content_access"] is False for policy in admin["policies"])


def test_clear_only_removes_callers_history_and_works_when_feature_is_off(environment):
    for actor in (ALICE, BOB):
        environment.policy(actor)
        assert environment.message(f"Private text for {actor}", actor=actor).status_code == 200
    view = environment.view()
    environment.features.clear()
    response = environment.client.request(
        "DELETE", BASE + "/history?owner=user:bob", headers=_headers(context=view["context"]),
        json={"expected_revision": view["history_revision"]},
    )
    assert _ok(response)["history"] == []
    assert environment.view()["history"] == []
    assert len(environment.view(BOB)["history"]) == 2


def test_zero_retention_returns_reply_without_saving_private_text(environment):
    environment.policy(retention_days=0)
    reply = _ok(environment.message("Do not retain this private text"))
    assert reply["message"]["content"]
    assert reply["history"] == []
    assert environment.view()["history"] == []
    assert "Do not retain this private text" not in str(environment.admin())


def test_required_state_and_audit_publication_failure_returns_no_answer(environment, monkeypatch):
    from maverick import employee_companion

    environment.policy()
    view = environment.view()
    events = environment.admin()["events"]

    def cannot_publish(*_args, **_kwargs):
        raise OSError("Synthetic companion authority publication failure")

    monkeypatch.setattr(employee_companion.file_lock, "atomic_write_text", cannot_publish)
    response = environment.message("Never publish this private text", view=view)
    assert response.status_code == 503
    assert "message" not in response.json()
    assert "Never publish this private text" not in response.text
    assert environment.view()["history"] == []
    assert environment.admin()["events"] == events


def test_personal_and_administrative_responses_are_not_cacheable(environment):
    for suffix, actor in (("", ALICE), ("/admin", ADMIN)):
        response = environment.client.get(BASE + suffix, headers=_headers(actor))
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "private, no-store"


def test_conversation_without_sources_uses_only_employee_prompt_and_history(
    environment, draft_generation, monkeypatch,
):
    environment.worlds["acme"].create_goal("Do not include this task", owner=ALICE)
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])

    def no_sources(*_args, **_kwargs):
        pytest.fail("Prompt-only conversation must not read task sources")

    monkeypatch.setattr(companion, "_tasks", no_sources)
    view = environment.view()
    assert view["conversation_available"] is True
    assert view["status_available"] is False
    assert view["tasks"] == []
    first = _ok(environment.conversation("Private first prompt", view=view))
    assert first["message"]["content"] == draft_generation.reply
    assert first["message"]["sources"] == []
    assert draft_generation.calls[0]["message"] == "Private first prompt"
    assert draft_generation.calls[0]["history"] == []
    assert draft_generation.calls[0]["tasks"] == []
    _ok(environment.conversation("Continue my draft"))
    second = draft_generation.calls[1]
    assert second["actor"] == ALICE
    assert second["tenant"] == "acme"
    assert "Private first prompt" in str(second["history"])
    assert "Do not include this task" not in str(second)
    assert len(draft_generation.dispatched) == 2


@pytest.mark.parametrize("actor", [ALICE, ADMIN])
def test_conversation_sources_respect_owner_tenant_department_and_project(
    environment, draft_generation, actor,
):
    world = environment.worlds["acme"]
    project = world.create_project("Owned finance project", owner=actor)
    foreign_project = world.create_project("Foreign project", owner=BOB)
    allowed = world.create_goal("Allowed task context", owner=actor, domain="finance_fpa", project_id=project)
    world.create_goal("Other employee secret", owner=BOB, domain="finance_fpa")
    world.create_goal("Other department secret", owner=actor, domain="legal_contract_review")
    world.create_goal("Other project secret", owner=actor, domain="finance_fpa", project_id=foreign_project)
    environment.worlds["globex"].create_goal("Other tenant secret", owner=actor, domain="finance_fpa")
    environment.suites[actor] = frozenset({"finance"})
    environment.policy(actor, allowed_tools=["draft_reply", "task_status"])

    reply = _ok(environment.conversation(actor=actor))
    sent = draft_generation.dispatched[0]
    assert sent["actor"] == actor
    assert sent["tenant"] == "acme"
    assert [task["goal_id"] for task in sent["tasks"]] == [allowed]
    assert [task["goal_id"] for task in reply["message"]["sources"]] == [allowed]
    for secret in ("Other employee secret", "Other department secret", "Other project secret", "Other tenant secret"):
        assert secret not in str(sent)
        assert secret not in str(reply)


def test_model_history_never_crosses_employee_or_tenant_boundaries(environment, draft_generation):
    conversations = (
        (ALICE, "acme", "Alice Acme private conversation"),
        (BOB, "acme", "Bob Acme private conversation"),
        (ALICE, "globex", "Alice Globex private conversation"),
        (ADMIN, "acme", "Administrator personal conversation"),
    )
    for actor, tenant, text in conversations:
        environment.policy(actor, tenant, allowed_sources=[], allowed_tools=["draft_reply"])
        _ok(environment.conversation(text, actor=actor, tenant=tenant))
        call = draft_generation.calls[-1]
        assert call["actor"] == actor
        assert call["tenant"] == tenant
        assert call["history"] == []
        assert call["message"] == text
    for actor, tenant, own_text in conversations:
        _ok(environment.conversation("Continue my personal draft", actor=actor, tenant=tenant))
        history = str(draft_generation.calls[-1]["history"])
        assert own_text in history
        for _, _, other_text in conversations:
            if other_text != own_text:
                assert other_text not in history


@pytest.mark.parametrize("revocation", ["membership", "offboarding", "policy", "department"])
@pytest.mark.parametrize("phase", ["before_dispatch", "after_dispatch"])
def test_conversation_revalidates_authority_at_dispatch_and_before_publication(
    environment, draft_generation, revocation, phase,
):
    from maverick.employee_companion import EmployeeCompanionStore

    environment.worlds["acme"].create_goal("Sensitive finance task", owner=ALICE, domain="finance_fpa")
    environment.suites[ALICE] = frozenset({"finance"})
    policy = environment.policy(allowed_tools=["draft_reply"])
    view = environment.view()
    request_id = _request_id()

    def revoke():
        if revocation == "membership":
            del environment.memberships["acme"][ALICE]
        elif revocation == "offboarding":
            environment.active[ALICE] = False
        elif revocation == "department":
            environment.suites[ALICE] = frozenset()
        else:
            EmployeeCompanionStore().update_policy(
                ALICE, actor=ADMIN, expected_revision=policy["revision"], enabled=False,
                allowed_sources=policy["allowed_sources"], allowed_tools=policy["allowed_tools"],
                retention_days=policy["retention_days"],
            )

    setattr(draft_generation, phase, revoke)
    response = environment.conversation("Do not publish after revocation", view=view, request_id=request_id)
    assert response.status_code in (403, 409), response.text
    assert draft_generation.reply not in response.text
    assert "Do not publish after revocation" not in response.text
    expected_dispatches = 0 if phase == "before_dispatch" else 1
    assert len(draft_generation.dispatched) == expected_dispatches
    with tenant_scope(tenant="acme"):
        store = EmployeeCompanionStore()
        assert store.history(ALICE) == []
        assert store.turn_status(ALICE, request_id)["state"] != "completed"


@pytest.mark.parametrize("phase", ["before_dispatch", "after_dispatch"])
def test_session_revocation_during_conversation_invalidates_admitted_reply(
    environment, draft_generation, phase,
):
    from maverick.employee_companion import EmployeeCompanionStore
    from maverick_dashboard import session_revocation

    subject = ALICE.removeprefix("user:")
    session_revocation.revoke_principal(subject, at=1000.0)
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    view = environment.view()
    request_id = _request_id()

    def revoke_existing_session():
        # Two credential invalidations must not be confused with the epoch
        # captured when this request was admitted. No credential is created.
        session_revocation.revoke_principal(subject, at=2000.0)
        session_revocation.revoke_principal(subject, at=3000.0)

    setattr(draft_generation, phase, revoke_existing_session)
    response = environment.conversation("Never publish this revoked-session reply", view=view, request_id=request_id)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "companion_context_changed"
    assert draft_generation.reply not in response.text
    assert session_revocation.revocation_epoch(subject) == 3000.0
    assert len(draft_generation.dispatched) == (0 if phase == "before_dispatch" else 1)
    with tenant_scope(tenant="acme"):
        store = EmployeeCompanionStore()
        assert store.history(ALICE) == []
        assert store.turn_status(ALICE, request_id)["state"] != "completed"


@pytest.mark.parametrize("phase", ["before_dispatch", "after_dispatch"])
def test_workspace_switch_away_and_back_invalidates_admitted_generation(
    environment, draft_generation, phase,
):
    from maverick.employee_companion import EmployeeCompanionStore
    from maverick_dashboard import workspace_tenants

    workspace_tenants.set_selection(ALICE, "acme")
    admitted_binding = workspace_tenants.get_selection_binding(ALICE)
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    view = environment.view()
    request_id = _request_id()

    def switch_away_and_back():
        # The final tenant and request context still say Acme; only the
        # monotonic selection generation reveals the intervening switches.
        workspace_tenants.set_selection(ALICE, "globex")
        workspace_tenants.set_selection(ALICE, "acme")

    setattr(draft_generation, phase, switch_away_and_back)
    response = environment.conversation("Reply admitted before workspace switch", view=view, request_id=request_id)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "companion_context_changed"
    assert draft_generation.reply not in response.text
    selected_tenant, current_generation = workspace_tenants.get_selection_binding(ALICE)
    assert selected_tenant == admitted_binding[0] == "acme"
    assert current_generation == admitted_binding[1] + 2
    assert len(draft_generation.dispatched) == (0 if phase == "before_dispatch" else 1)
    with tenant_scope(tenant="acme"):
        store = EmployeeCompanionStore()
        assert store.history(ALICE) == []
        assert store.turn_status(ALICE, request_id)["state"] != "completed"


@pytest.mark.parametrize("phase", ["before_dispatch", "after_dispatch"])
def test_other_employee_credential_changes_do_not_invalidate_own_conversation(
    environment, draft_generation, phase,
):
    from maverick_dashboard import session_revocation, workspace_tenants

    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    workspace_tenants.set_selection(BOB, "acme")

    def change_other_employee_credentials():
        session_revocation.revoke_principal(BOB.removeprefix("user:"), at=1000.0)
        workspace_tenants.set_selection(BOB, None)
        workspace_tenants.set_selection(BOB, "acme")

    setattr(draft_generation, phase, change_other_employee_credentials)
    reply = _ok(environment.conversation("Alice's own draft can finish"))
    assert reply["message"]["content"] == draft_generation.reply
    assert len(draft_generation.dispatched) == 1
    assert reply["request"]["state"] == "completed"


def test_clearing_history_while_generation_waits_discards_late_answer(
    environment, draft_generation,
):
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    view = environment.view()
    request_id = _request_id()
    model_started = Event()
    release_model = Event()

    def wait_for_clear():
        model_started.set()
        assert release_model.wait(timeout=10), "Test did not release the mocked model"

    draft_generation.after_dispatch = wait_for_clear
    with ThreadPoolExecutor(max_workers=2) as workers:
        conversation = workers.submit(
            environment.conversation, "This pending text must not reappear", view=view, request_id=request_id,
        )
        try:
            assert model_started.wait(timeout=5)
            current = environment.view()
            clear = workers.submit(
                environment.client.request, "DELETE", BASE + "/history",
                headers=_headers(context=view["context"]),
                json={"expected_revision": current["history_revision"]},
            )
            assert _ok(clear.result(timeout=5))["history"] == []
        finally:
            release_model.set()
        response = conversation.result(timeout=5)
    assert response.status_code == 409
    assert draft_generation.reply not in response.text
    latest = environment.view()
    assert latest["history"] == []
    assert latest["history_generation"] > view["history_generation"]
    assert latest["active_turn"] is None
    assert environment.request_status(request_id)["request"]["state"] == "cancelled"


def test_duplicate_pending_and_completed_requests_never_generate_twice(
    environment, draft_generation,
):
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    view = environment.view()
    request_id = _request_id()
    model_started = Event()
    release_model = Event()

    def wait_for_duplicate():
        model_started.set()
        assert release_model.wait(timeout=10), "Test did not release the mocked model"

    draft_generation.after_dispatch = wait_for_duplicate
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(
            environment.conversation, "Draft once", view=view, request_id=request_id,
        )
        try:
            assert model_started.wait(timeout=5)
            duplicate = workers.submit(
                environment.conversation, "Draft once", view=view, request_id=request_id,
            )
            pending = _ok(duplicate.result(timeout=5))
            assert pending["request"]["state"] == "pending"
            assert "message" not in pending
            assert len(draft_generation.dispatched) == 1
        finally:
            release_model.set()
        assert _ok(first.result(timeout=5))["message"]["content"] == draft_generation.reply
    completed = _ok(environment.conversation("Draft once", view=view, request_id=request_id))
    assert completed["request"]["state"] == "completed"
    assert "message" not in completed
    assert len(draft_generation.calls) == len(draft_generation.dispatched) == 1
    assert len(environment.view()["history"]) == 2
    changed_payload = environment.conversation("Different text using the same ID", view=view, request_id=request_id)
    assert changed_payload.status_code == 409
    assert len(draft_generation.calls) == 1


def test_request_metadata_is_owner_and_tenant_scoped_without_private_content(
    environment, draft_generation,
):
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    request_id = _request_id()
    private_message = "Employee-only medical conversation"
    _ok(environment.conversation(private_message, request_id=request_id))

    owner = environment.request_status(request_id)
    assert owner["request"]["state"] == "completed"
    assert private_message not in str(owner["request"])
    assert draft_generation.reply not in str(owner["request"])
    assert not {"token", "fingerprint", "message", "response", "history"}.intersection(owner["request"])
    for actor, tenant in ((BOB, "acme"), (ADMIN, "acme"), (ALICE, "globex")):
        foreign = environment.request_status(request_id, actor=actor, tenant=tenant)
        assert foreign["request"]["state"] == "not_started"
        assert foreign["history"] == []
        assert private_message not in str(foreign)
        assert draft_generation.reply not in str(foreign)
    admin = environment.admin()
    assert private_message not in str(admin)
    assert draft_generation.reply not in str(admin)
    assert any(event["action"] == "draft_reply" for event in admin["events"])
    assert all(
        not {"message", "response", "history", "token", "fingerprint"}.intersection(event)
        for event in admin["events"]
    )


def test_provider_failure_is_generic_and_consumes_request_without_retry(
    environment, draft_generation,
):
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    view = environment.view()
    request_id = _request_id()
    exception_detail = "Provider rejected credential SECRET and private prompt bytes"

    def fail_provider():
        raise RuntimeError(exception_detail)

    draft_generation.after_dispatch = fail_provider
    response = environment.conversation("Sensitive prompt", view=view, request_id=request_id)
    assert response.status_code == 503
    assert exception_detail not in response.text
    assert "Sensitive prompt" not in response.text
    status = environment.request_status(request_id)
    assert status["request"]["state"] == "failed"
    assert status["history"] == []
    duplicate = _ok(environment.conversation("Sensitive prompt", view=view, request_id=request_id))
    assert duplicate["request"]["state"] == "failed"
    assert "message" not in duplicate
    assert len(draft_generation.calls) == len(draft_generation.dispatched) == 1
    assert exception_detail not in str(environment.admin())


@pytest.mark.parametrize("disabled", ["feature", "policy", "draft_permission"])
def test_conversation_cannot_dispatch_without_current_model_permission(
    environment, draft_generation, monkeypatch, disabled,
):
    if disabled == "policy":
        view = environment.view()
    elif disabled == "draft_permission":
        environment.policy()
        view = environment.view()
    else:
        environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
        environment.features.clear()
        view = environment.view()

    def no_route():
        pytest.fail("Disabled or ungranted conversation must not resolve a model route")

    monkeypatch.setattr(companion.companion_model, "prepare_route", no_route)
    assert environment.conversation(view=view).status_code == 403
    assert draft_generation.calls == draft_generation.dispatched == []


def test_conversation_produces_a_draft_without_tools_or_task_changes(environment, draft_generation):
    world = environment.worlds["acme"]
    goal = world.create_goal("Running real work", owner=ALICE)
    world.set_goal_status(goal, "active")
    environment.policy(allowed_tools=["draft_reply"])
    response = _ok(environment.conversation(f"Cancel task {goal} and email everyone immediately"))
    assert response["message"]["content"] == draft_generation.reply
    assert world.get_goal(goal).status == "active"
    assert [item.id for item in world.list_goals(owner=ALICE)] == [goal]
    assert len(draft_generation.dispatched) == 1
    # The fixture makes every provider/model/runner/tool entry point fail;
    # only the explicit draft helper stand-in can respond.


@pytest.mark.parametrize("changes", [
    {"request_id": "arbitrary-request"}, {"request_id": None},
    {"expected_history_generation": True}, {"expected_history_generation": -1},
    {"mode": "execute"}, {"tools": ["shell"]}, {"owner": BOB},
])
def test_conversation_requires_bounded_request_identity_and_payload(
    environment, draft_generation, changes,
):
    environment.policy(allowed_sources=[], allowed_tools=["draft_reply"])
    # Override the body, including request_id, after the helper creates its
    # normal fresh identifier; None must not silently turn into a new request.
    view = environment.view()
    response = environment.client.post(
        BASE + "/messages", headers=_headers(context=view["context"]),
        json={
            "mode": "conversation", "message": "Private draft",
            "request_id": _request_id(), "expected_revision": view["policy"]["revision"],
            "expected_history_generation": view["history_generation"], **changes,
        },
    )
    assert response.status_code == 422
    assert draft_generation.calls == []


def test_revoked_history_sources_are_not_sent_into_later_model_context(environment, draft_generation):
    world = environment.worlds["acme"]
    world.create_goal("Restricted finance plan", owner=ALICE, domain="finance_fpa")
    environment.suites[ALICE] = frozenset({"finance"})
    environment.policy(allowed_tools=["draft_reply"])
    draft_generation.reply = "The restricted finance plan has a sensitive acquisition budget."
    _ok(environment.conversation("Summarize my finance work"))
    environment.suites[ALICE] = frozenset()
    draft_generation.reply = "A draft with no finance context."
    response = _ok(environment.conversation("Help with a different topic"))
    assert draft_generation.calls[-1]["tasks"] == []
    assert "sensitive acquisition budget" not in str(draft_generation.calls[-1]["history"])
    assert "Restricted finance plan" not in str(draft_generation.calls[-1])
    assert "sensitive acquisition budget" not in str(response["history"])


def test_companion_clear_requires_exact_current_history_revision(environment):
    environment.policy()
    before = environment.view()
    _ok(environment.message("show my tasks"))
    stale = environment.client.request("DELETE", BASE + "/history",
        headers=_headers(context=before["context"]),
        json={"expected_revision": before["history_revision"]})
    assert stale.status_code == 409
    current = environment.view()
    assert current["history"] and current["history_revision"] != before["history_revision"]
    cleared = environment.client.request("DELETE", BASE + "/history",
        headers=_headers(context=current["context"]),
        json={"expected_revision": current["history_revision"]})
    assert _ok(cleared)["history"] == []


def test_copilot_reviews_and_clears_only_owned_current_companion_history(environment, monkeypatch):
    from maverick.governed_operations import digest
    from maverick_dashboard import product_operations as operations

    monkeypatch.setattr(operations, "_gate", lambda _request: None)
    monkeypatch.setattr(operations, "enabled_families", lambda: {"preferences"})
    monkeypatch.setattr(operations, "_context", lambda request: digest([
        request.headers.get("X-Test-Principal"), request.headers.get("X-Test-Tenant")]))
    environment.policy()
    _ok(environment.message("show my tasks"))
    headers = _headers()
    base = "/api/v1/copilot/product-operations"
    catalog = _ok(environment.client.post(base + "/catalog", headers=headers,
                                          json={"page": "/companion", "selection": {}}))
    actions = {row["id"]: row for row in catalog["operations"]}
    assert actions["companion.status"]["available"]
    assert actions["companion.clear_history"]["available"]
    assert actions["companion.clear_history"]["details"]["saved_exchanges"] == 1
    assert "show my tasks" not in str(catalog)
    review_body = {"page": "/companion", "selection": {}, "operation": "companion.clear_history",
                   "context": catalog["context"], "revision": actions["companion.clear_history"]["revision"],
                   "arguments": {}}
    prepared = _ok(environment.client.post(base + "/prepare", headers=headers, json=review_body))
    assert environment.view()["history"]
    _ok(environment.message("what needs attention"))
    assert environment.client.post(base + "/execute", headers=headers,
        json={"token": prepared["token"], "confirmed": True}).status_code == 409
    assert len(environment.view()["history"]) == 4
    current = _ok(environment.client.post(base + "/catalog", headers=headers,
                                         json={"page": "/companion", "selection": {}}))
    review_body.update(context=current["context"], revision=next(row["revision"] for row in current["operations"]
                                                                if row["id"] == "companion.clear_history"))
    prepared = _ok(environment.client.post(base + "/prepare", headers=headers, json=review_body))
    assert environment.client.post(base + "/execute", headers=headers,
        json={"token": prepared["token"], "confirmed": False}).status_code == 400
    payload = {"token": prepared["token"], "confirmed": True}
    completed = _ok(environment.client.post(base + "/execute", headers=headers, json=payload))
    assert completed["status"] == "confirmed"
    assert environment.view()["history"] == []
    replay = _ok(environment.client.post(base + "/execute", headers=headers, json=payload))
    assert replay["status"] == "replayed"
    assert "show my tasks" not in str(completed)
    environment.memberships["acme"][ALICE] = None
    assert environment.client.post(base + "/execute", headers=headers, json=payload).status_code == 403


def _conversation_copilot(environment, monkeypatch):
    from maverick.governed_operations import digest
    from maverick_dashboard import product_operations as operations
    from maverick_dashboard import product_operations_companion_conversation as controls

    monkeypatch.setattr(operations, "_gate", lambda _request: None)
    monkeypatch.setattr(operations, "enabled_families", lambda: {"preferences"})
    monkeypatch.setattr(operations, "_context", lambda request: digest([
        request.headers.get("X-Test-Principal"), request.headers.get("X-Test-Tenant")]))
    monkeypatch.setattr(operations, "adapters", lambda: {entry.id: entry for entry in controls.entries()})
    monkeypatch.setattr(companion.companion_model, "draft_limits", lambda: {
        "max_dollars": 0.25, "max_input_tokens": 16000, "max_output_tokens": 2000,
        "max_wall_seconds": 90, "max_tool_calls": 0})
    base = "/api/v1/copilot/product-operations"
    selection = {"kind": "own_companion"}

    def prepare(operation="companion.draft", message="Please draft my private update"):
        catalog = _ok(environment.client.post(base + "/catalog", headers=_headers(),
            json={"page": "/companion", "selection": selection}))
        item = next(row for row in catalog["operations"] if row["id"] == operation)
        return environment.client.post(base + "/prepare", headers=_headers(), json={
            "page": "/companion", "selection": selection, "operation": operation,
            "context": catalog["context"], "revision": item["revision"],
            "arguments": {"message": message} if operation == "companion.draft" else {}})

    return base, prepare


def test_copilot_conversation_runs_native_once_and_recovers_exact_retained_reply(environment, draft_generation, monkeypatch):
    environment.policy(allowed_tools=["task_status", "draft_reply"])
    world = environment.worlds["acme"]
    goal = world.create_goal("Alice's reviewable work", owner=ALICE)
    world.create_goal("Bob's secret work", owner=BOB)
    base, prepare = _conversation_copilot(environment, monkeypatch)
    read = _ok(prepare("companion.work"))
    assert read["read_only"] and "Alice's reviewable work" in str(read)
    assert "Bob's secret work" not in str(read) and draft_generation.calls == []
    review = _ok(prepare())
    assert "Maximum AI spend" in str(review) and "$0.25" in str(review)
    assert draft_generation.calls == []
    payload = {"token": review["token"], "confirmed": True}
    assert environment.client.post(base + "/execute", headers=_headers(),
        json={**payload, "confirmed": False}).status_code == 400
    original_generate = draft_generation.generate

    def outside_fence(**arguments):
        # Another thread must obtain the authority fence while generation runs.
        from maverick.authority_effects import authority_effect_fence

        def acquire():
            with authority_effect_fence():
                return True
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(acquire).result(timeout=3)
        return original_generate(**arguments)
    monkeypatch.setattr(companion.companion_model, "generate_draft", outside_fence)
    accepted = _ok(environment.client.post(base + "/execute", headers=_headers(), json=payload))
    assert accepted["status"] == "queued"
    assert len(draft_generation.dispatched) == 1
    assert [row["goal_id"] for row in draft_generation.dispatched[0]["tasks"]] == [goal]
    recovered = _ok(environment.client.post(base + "/execute", headers=_headers(), json=payload))
    assert recovered["status"] == "replayed" and recovered["details"]["draft_to_review"] == draft_generation.reply
    assert len(draft_generation.calls) == 1
    request_id = recovered["details"]["open_reply"]["href"].split("?reply=")[1]
    assert environment.request_status(request_id)["retained_reply"]["content"] == draft_generation.reply
    for actor, tenant in ((BOB, "acme"), (ADMIN, "acme"), (ALICE, "globex")):
        assert environment.request_status(request_id, actor=actor, tenant=tenant)["retained_reply"] is None
        assert environment.client.post(base + "/execute", headers=_headers(actor, tenant), json=payload).status_code == 409
    current = environment.view()
    _ok(environment.client.request("DELETE", BASE + "/history", headers=_headers(context=current["context"]),
        json={"expected_revision": current["history_revision"]}))
    withheld = _ok(environment.client.post(base + "/execute", headers=_headers(), json=payload))
    assert withheld["status"] == "unconfirmed" and draft_generation.reply not in str(withheld)
    assert environment.request_status(request_id)["retained_reply"] is None
    assert len(draft_generation.calls) == 1


@pytest.mark.parametrize("changed", ["policy", "task", "route", "allowance", "membership"])
def test_copilot_conversation_refuses_changed_review_before_provider(environment, draft_generation, monkeypatch, changed):
    environment.policy(allowed_tools=["task_status", "draft_reply"])
    base, prepare = _conversation_copilot(environment, monkeypatch)
    reviewed = _ok(prepare())
    if changed == "policy":
        environment.policy(allowed_tools=["task_status"])
    elif changed == "task":
        environment.worlds["acme"].create_goal("Work created after review", owner=ALICE)
    elif changed == "route":
        monkeypatch.setattr(companion.companion_model, "prepare_route", lambda: companion.companion_model.CompanionModelRoute(
            model="mock:companion-test-route", provider="mock", fingerprint="b" * 64, tenant=current_tenant_id_strict()))
    elif changed == "allowance":
        monkeypatch.setattr(companion.companion_model, "draft_limits", lambda: {"max_dollars": 0.5})
    else:
        environment.memberships["acme"][ALICE] = None
    response = environment.client.post(base + "/execute", headers=_headers(),
        json={"token": reviewed["token"], "confirmed": True})
    assert response.status_code == (403 if changed == "membership" else 409)
    assert draft_generation.calls == []


def test_copilot_conversation_unsaved_answers_handoff_and_physical_revocation(environment, draft_generation, monkeypatch):
    environment.policy(allowed_tools=["task_status", "draft_reply"], retention_days=0)
    base, prepare = _conversation_copilot(environment, monkeypatch)
    refused = prepare()
    assert refused.status_code == 409 and "Ask companion" in refused.text
    environment.policy(allowed_tools=["task_status", "draft_reply"], retention_days=7)
    reviewed = _ok(prepare())

    def revoke():
        environment.active[ALICE] = False
    draft_generation.before_dispatch = revoke
    accepted = _ok(environment.client.post(base + "/execute", headers=_headers(),
        json={"token": reviewed["token"], "confirmed": True}))
    assert accepted["status"] == "queued" and draft_generation.dispatched == []
    environment.active[ALICE] = True
    stopped = _ok(environment.client.post(base + "/execute", headers=_headers(),
        json={"token": reviewed["token"], "confirmed": True}))
    assert stopped["status"] == "unconfirmed" and len(draft_generation.calls) == 1


def test_copilot_admin_policy_uses_native_revision_and_current_membership(environment, monkeypatch):
    from maverick.governed_operations import digest
    from maverick_dashboard import product_operations as operations

    monkeypatch.setattr(operations, "_gate", lambda _request: None)
    monkeypatch.setattr(operations, "enabled_families", lambda: {"preferences"})
    monkeypatch.setattr(operations, "_context", lambda request: digest([
        request.headers.get("X-Test-Principal"), request.headers.get("X-Test-Tenant")]))
    base, headers = "/api/v1/copilot/product-operations", _headers(ADMIN)
    selection = {"kind": "companion_employee", "id": ALICE}
    options = {"enabled": True, "own_tasks": True, "task_status": True,
               "draft_reply": False, "retention_days": "7"}

    def review():
        catalog = _ok(environment.client.post(base + "/catalog", headers=headers,
            json={"page": "/companion/admin", "selection": selection}))
        action = next(row for row in catalog["operations"] if row["id"] == "companion.admin.policy")
        return _ok(environment.client.post(base + "/prepare", headers=headers,
            json={"page": "/companion/admin", "selection": selection, "operation": action["id"],
                  "context": catalog["context"], "revision": action["revision"], "arguments": options}))

    prepared = review()
    payload = {"token": prepared["token"], "confirmed": True}
    assert _ok(environment.client.post(base + "/execute", headers=headers, json=payload))["status"] == "confirmed"
    assert environment.view()["policy"]["revision"] == 1
    assert _ok(environment.client.post(base + "/execute", headers=headers, json=payload))["status"] == "unconfirmed"
    assert environment.view()["policy"]["revision"] == 1
    assert environment.client.post(base + "/execute", headers=_headers(BOB), json=payload).status_code == 403
    assert environment.client.post(base + "/execute", headers=_headers(ADMIN, "globex"), json=payload).status_code in {404, 409}

    prepared = review()
    environment.policy(enabled=False, allowed_sources=[], allowed_tools=[])
    changed = _ok(environment.client.post(base + "/execute", headers=headers,
        json={"token": prepared["token"], "confirmed": True}))
    assert changed["status"] == "unconfirmed"
    assert environment.view()["policy"]["enabled"] is False
    assert environment.view()["policy"]["revision"] == 2
    prepared = review()
    environment.active[ALICE] = False
    assert environment.client.post(base + "/execute", headers=headers,
        json={"token": prepared["token"], "confirmed": True}).status_code == 404
    environment.active[ALICE] = True
    environment.memberships["acme"][ADMIN] = None
    assert environment.client.post(base + "/execute", headers=headers,
        json={"token": prepared["token"], "confirmed": True}).status_code == 403


def test_copilot_admin_metadata_and_lost_policy_response_do_not_read_or_repeat_content(environment, monkeypatch):
    from fastapi import HTTPException
    from maverick.governed_operations import digest
    from maverick_dashboard import product_operations as operations

    monkeypatch.setattr(operations, "_gate", lambda _request: None)
    monkeypatch.setattr(operations, "enabled_families", lambda: {"preferences"})
    monkeypatch.setattr(operations, "_context", lambda request: digest([
        request.headers.get("X-Test-Principal"), request.headers.get("X-Test-Tenant")]))
    environment.policy()
    _ok(environment.message("Private companion question kept out of Copilot"))
    base, headers = "/api/v1/copilot/product-operations", _headers(ADMIN)
    selection = {"kind": "companion_employee", "id": ALICE}
    catalog = _ok(environment.client.post(base + "/catalog", headers=headers,
        json={"page": "/companion/admin", "selection": selection}))
    actions = {row["id"]: row for row in catalog["operations"]}
    read = _ok(environment.client.post(base + "/prepare", headers=headers,
        json={"page": "/companion/admin", "selection": selection, "operation": "companion.admin.read",
              "context": catalog["context"], "revision": actions["companion.admin.read"]["revision"], "arguments": {}}))
    assert "Task question answered" in str(read)
    assert "Private companion question" not in str(catalog) + str(read)
    assert read["read_only"] is True
    options = {"enabled": False, "own_tasks": False, "task_status": False,
               "draft_reply": False, "retention_days": "0"}
    prepared = _ok(environment.client.post(base + "/prepare", headers=headers,
        json={"page": "/companion/admin", "selection": selection, "operation": "companion.admin.policy",
              "context": catalog["context"], "revision": actions["companion.admin.policy"]["revision"], "arguments": options}))
    calls, original = [], companion.administration_update

    def lost_response(*args, **kwargs):
        calls.append(True)
        original(*args, **kwargs)
        raise HTTPException(503, "Synthetic lost response after native save")

    monkeypatch.setattr(companion, "administration_update", lost_response)
    payload = {"token": prepared["token"], "confirmed": True}
    outcome = _ok(environment.client.post(base + "/execute", headers=headers, json=payload))
    assert outcome["status"] == "unconfirmed" and outcome["details"]["companion"] == "Disabled"
    assert environment.view()["policy"]["revision"] == 2
    assert environment.view()["history"] == []
    assert _ok(environment.client.post(base + "/execute", headers=headers, json=payload))["status"] == "unconfirmed"
    assert calls == [True]


def test_non_ascii_context_header_is_refused_like_any_other_wrong_one(environment):
    from fastapi import HTTPException
    from starlette.requests import Request

    environment.policy()
    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    for value in ("0" * 64, b"caf\xe9"):
        refused = environment.client.get(BASE, headers=_headers(context=value))
        assert refused.status_code == 409, (value, refused.status_code, refused.text)
    reviewed = environment.view()["context"]
    request = Request({"type": "http", "method": "POST", "path": BASE + "/messages", "state": {},
                       "headers": [(b"x-test-principal", ALICE.encode()), (CONTEXT.lower().encode(), b"caf\xe9")]})
    with tenant_scope(tenant="acme"), pytest.raises(HTTPException) as refused:
        companion._authority(request, reviewed_context=reviewed)
    assert refused.value.status_code == 409
