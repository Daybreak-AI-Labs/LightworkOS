"""One owned native dispatch, its private UI/API record and Copilot recovery."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from maverick import config, instruction_capture
from maverick.agent import Agent
from maverick.budget import Budget
from maverick.llm import LLM, LLMResponse
from maverick.paths import tenant_scope
from maverick.tenant.registry import create_tenant, get_tenant
from maverick_dashboard import rbac, workspace_tenants
from maverick_dashboard.learning_ops_api import _world

from test_support.action_episode_api import OWNER, TENANT
from test_support.action_episode_api import harness as harness

BASE = "/api/v1/learning/instructions"
COPILOT = "/api/v1/copilot/product-operations"


def test_native_record_review_source_withdrawal_and_copilot(harness, tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text('[features]\ncopilot_operations = true\n[copilot]\noperation_families = ["learning"]\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    config.reset_config_cache()
    if get_tenant(TENANT) is None:
        create_tenant(TENANT)
    for actor in (OWNER, "user:admin"):
        rbac.set_role(actor, "admin" if actor == "user:admin" else "operator", actor="user:admin")
        rbac.set_tenant_role(TENANT, actor, "operator", actor="user:admin")
        workspace_tenants.set_selection(actor, TENANT)
    with tenant_scope(tenant=TENANT):
        world = _world()
        task = world.create_goal("Prepare an order summary", "Private task body must not be captured", owner=OWNER)
        shared = world.create_goal("Permitted shared lesson source", "Unowned local source", owner="")
        private = world.create_goal("Other person's private lesson source", "Not readable to Alice", owner="user:admin")
        bindings = instruction_capture._source_bindings(world, task, {shared}, OWNER)
        assert {row["owner"] for row in bindings} == {OWNER, ""}
        import pytest
        with pytest.raises(ValueError):
            instruction_capture._source_bindings(world, task, {private}, OWNER)
        world.set_goal_status(task, "active")
        completed_ids = []
        for index in range(100):
            finished = world.create_goal("Finished order " + str(index), "Completed history", owner=OWNER)
            world.set_goal_status(finished, "done")
            completed_ids.append(finished)
    options = harness.client.get(BASE)
    assert options.status_code == 200, options.text
    offered = {row["value"] for row in options.json()["tasks"]}
    assert task in offered and not offered.intersection(completed_ids)
    context = options.json()["context"]
    assert options.json()["enabled"] is False
    assert harness.client.post(BASE + "/setup", json={"context": context, "confirm": True, "previous": False, "enabled": True}).status_code == 403
    admin_context = harness.client.get(BASE, headers={"Authorization": "Bearer admin"}).json()["context"]
    setting = harness.client.post(BASE + "/setup", headers={"Authorization": "Bearer admin"},
        json={"context": admin_context, "confirm": True, "previous": False, "enabled": True})
    assert setting.status_code == 200, setting.text
    page = harness.client.get("/learning/instructions")
    assert page.status_code == 200, page.text
    catalog = harness.client.post(COPILOT + "/catalog", json={"page": "/learning/instructions", "selection": {}}).json()
    operation = next(row for row in catalog["operations"] if row["id"] == "learning.instructions_start")
    prepared = harness.client.post(COPILOT + "/prepare", json={"page": "/learning/instructions", "selection": {},
        "context": catalog["context"], "operation": operation["id"], "revision": operation["revision"], "arguments": {"task": task}})
    assert prepared.status_code == 200, prepared.text
    result = harness.client.post(COPILOT + "/execute", json={"token": prepared.json()["token"], "confirmed": True})
    assert result.status_code == 200, result.text
    repeat = harness.client.post(COPILOT + "/execute", json={"token": prepared.json()["token"], "confirmed": True})
    assert repeat.status_code == 200 and repeat.json()["status"] == "replayed", repeat.text
    identity = harness.client.get(BASE).json()["records"][0]["id"]
    calls = []

    class Provider:
        async def complete_async(self, **kwargs):
            calls.append(kwargs)
            return LLMResponse("Actual local provider result", None, [], "end_turn")

    llm = LLM(model="ollama:synthetic-instruction-model")
    monkeypatch.setattr(llm, "_get_client", lambda _provider: Provider())
    with tenant_scope(tenant=TENANT):
        agent = Agent.__new__(Agent)
        agent.ctx = SimpleNamespace(world=world, goal_id=task, llm=llm, budget=Budget(max_wall_seconds=30), max_depth=2, use_skills=False)
        agent.role, agent.depth, agent.brief, agent.model, agent._domain_persona = "writer", 0, "Summarize this order", llm.model, None
        system = agent._build_system()
        response = asyncio.run(agent._complete_guarded(system=system, messages=[{"role": "user", "content": "Private order message"}], budget=agent.ctx.budget))
        assert response.text == "Actual local provider result"
    checked = harness.client.get(BASE + "/" + identity)
    assert checked.status_code == 200 and checked.json()["captured"], checked.text
    assert checked.json()["instructions"] == calls[0]["system"] == system
    assert "Private order message" not in checked.text and "Private task body" not in checked.text
    downloaded = harness.client.get(BASE + "/" + identity + "/download")
    assert downloaded.content == system.encode("utf-8") and "no-store" in downloaded.headers["cache-control"]
    denied = harness.client.get(BASE + "/" + identity, headers={"Authorization": "Bearer admin"})
    assert denied.status_code == 409 and system not in denied.text
    with tenant_scope(tenant=TENANT):
        from maverick.pilot_learning import protect
        protect(task, pilot_id="instruction-source-withdrawal", plan_version="1", input_version="1", actor=OWNER)
    assert harness.client.get(BASE + "/" + identity).status_code == 409
    assert harness.client.get(BASE + "/" + identity + "/download").status_code == 409
    withdrawal = harness.client.post(BASE + "/" + identity + "/withdraw", json={"context": context, "confirm": True, "revision": checked.json()["revision"]})
    assert withdrawal.status_code == 200, withdrawal.text
    with tenant_scope(tenant=TENANT):
        assert instruction_capture.records().get(identity)["instructions"] == ""
    assert len(calls) == 1
    with tenant_scope(tenant=TENANT):
        next_task = world.create_goal("Check an authorized instruction", "No message capture", owner=OWNER)
    next_request = harness.client.post(BASE, json={"context": context, "confirm": True, "task": next_task, "operation": "a" * 32})
    assert next_request.status_code == 200, next_request.text
    with tenant_scope(tenant=TENANT):
        agent.ctx.goal_id, agent.ctx.budget = next_task, Budget(max_wall_seconds=60)
        secret_system = system + "\nAccess credential: sk-" + "A" * 64
        result = asyncio.run(agent._complete_guarded(system=secret_system, messages=[], budget=agent.ctx.budget))
        assert result.text == "Actual local provider result"
        saved = instruction_capture.records().get("ISC-" + "a" * 32)
        assert saved["state"] == "withheld" and saved["instructions"] == "" and "secrets" in saved["reason"]
        # A consumed capture must not open governed storage on later calls.
        with monkeypatch.context() as late:
            late.setattr(instruction_capture, "records", lambda: (_ for _ in ()).throw(AssertionError("No authorized capture remains")))
            assert asyncio.run(agent._complete_guarded(system=system, messages=[], budget=agent.ctx.budget)).text == "Actual local provider result"
    assert len(calls) == 3
    with tenant_scope(tenant=TENANT):
        recovery_task = world.create_goal("Recover a recording receipt", "No message capture", owner=OWNER)
    recovery = harness.client.post(BASE, json={"context": context, "confirm": True, "task": recovery_task, "operation": "b" * 32})
    assert recovery.status_code == 200, recovery.text
    with tenant_scope(tenant=TENANT):
        saved_store = instruction_capture.records()
        original_update = saved_store.update

        def unavailable(identity, mutate, **kwargs):
            if kwargs.get("action") == "instructions.capture.completed":
                raise RuntimeError("Synthetic unavailable instruction receipt")
            return original_update(identity, mutate, **kwargs)

        with monkeypatch.context() as fault:
            fault.setattr(instruction_capture, "records", lambda: saved_store)
            fault.setattr(saved_store, "update", unavailable)
            agent.ctx.goal_id, agent.ctx.budget = recovery_task, Budget(max_wall_seconds=60)
            assert asyncio.run(agent._complete_guarded(system=system, messages=[], budget=agent.ctx.budget)).text == "Actual local provider result"
    pending = harness.client.get(BASE + "/ISC-" + "b" * 32)
    assert pending.status_code == 200 and pending.json()["result_pending"] and "instructions" not in pending.json()
    resolved = harness.client.post(BASE + "/ISC-" + "b" * 32 + "/finish", json={"context": context, "confirm": True, "revision": pending.json()["revision"]})
    assert resolved.status_code == 200 and "resolved as withheld" in resolved.text, resolved.text
    assert len(calls) == 4
    with tenant_scope(tenant=TENANT):
        delegated = world.create_goal("Task delegated to another account", "No message capture", owner=OWNER)
    delegated_capture = harness.client.post(BASE, json={"context": context, "confirm": True, "task": delegated, "operation": "c" * 32})
    assert delegated_capture.status_code == 200, delegated_capture.text
    from maverick import experience_preferences
    with tenant_scope(tenant=TENANT), monkeypatch.context() as delegated_preferences:
        delegated_preferences.setattr(experience_preferences, "prompt", lambda principal, **kwargs: "\nPrivate response preferences for " + principal)
        agent.ctx.goal_id, agent.ctx.budget = delegated, Budget(max_wall_seconds=60)
        agent.ctx.user_id, agent.ctx.channel = "bob", "dashboard"
        delegated_system = agent._build_system()
        assert "Private response preferences for user:bob" in delegated_system
        assert agent._instruction_preferences_owner == "user:bob"
        assert asyncio.run(agent._complete_guarded(system=delegated_system, messages=[], budget=agent.ctx.budget)).text == "Actual local provider result"
        withheld = instruction_capture.records().get("ISC-" + "c" * 32)
        assert withheld["state"] == "withheld" and withheld["instructions"] == "" and "another account" in withheld["reason"]
    assert len(calls) == 5
