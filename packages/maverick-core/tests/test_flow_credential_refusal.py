"""Flow expressions cannot turn deployment credentials into business parameters."""
from __future__ import annotations

import copy
import importlib

import pytest
from maverick import connections, secret_provider, tools
from maverick.flow import Flow, FlowNode, store
from maverick.flow.execution import default_action_runner
from maverick.flow.runner import FlowCredentialRefused, render, run_flow
from maverick.paths import tenant_scope

EXPRESSIONS = [
    "{{secret('LIGHTWORK_LOCAL_SECRET_FIXTURE')}}",
    "{{secret(name)}}",
    "{{secret(concat('LIGHTWORK_LOCAL_', 'SECRET_FIXTURE'))}}",
    "{{upper(secret(name))}}",
    "before {{concat('prefix', lower(secret(name)))}} after",
    "{{default(secret(name), 'fallback')}}",
    "{{secret()}}",
    "{{secret ('LIGHTWORK_LOCAL_SECRET_FIXTURE')}}",
]


@pytest.fixture(autouse=True)
def no_deployment_secret_lookup(monkeypatch):
    monkeypatch.setenv("LIGHTWORK_LOCAL_SECRET_FIXTURE", "synthetic-credential-only")
    monkeypatch.setattr(secret_provider, "get_secret", lambda *a: pytest.fail("deployment provider reached"))


@pytest.mark.parametrize("expression", EXPRESSIONS)
def test_every_secret_call_form_refuses_at_shared_render_boundary(expression):
    with pytest.raises(FlowCredentialRefused, match="Connections") as failure:
        render(expression, {"name": "LIGHTWORK_LOCAL_SECRET_FIXTURE"}, allow_secrets=True)
    assert "synthetic-credential-only" not in str(failure.value)


def action_flow(value):
    return Flow(id="credential-review", name="Review", start="prefix", nodes={
        "prefix": FlowNode(id="prefix", kind="action", tool="fixture_read", next="legacy", params={"q": "safe"}),
        "legacy": FlowNode(id="legacy", kind="action", tool="fixture_read", params={"q": value}, retries=3),
    })


@pytest.mark.parametrize("value", [*EXPRESSIONS, {"nested": ["{{secret(name)}}"]}])
def test_whole_graph_refusal_precedes_even_harmless_prefix(value):
    seen = []
    flow = action_flow(value)
    before = copy.deepcopy(flow.to_dict())
    result = run_flow(flow, agent_fn=lambda *a: seen.append("agent"),
                      action_fn=lambda *a: (seen.append("action"), 1.0), data={"name": "LIGHTWORK_LOCAL_SECRET_FIXTURE"})
    assert result.status == "failed" and "Connections" in result.error
    assert seen == [] and flow.to_dict() == before
    assert "synthetic-credential-only" not in str(result)


@pytest.mark.parametrize("kind", ["foreach", "while", "scope", "parallel", "subflow", "resume"])
def test_nested_graph_and_persisted_resume_do_not_bypass_preflight(kind):
    child = action_flow("{{secret(name)}}")
    if kind == "resume":
        root = child
        resume = {"node_id": "prefix", "data": {"name": "LIGHTWORK_LOCAL_SECRET_FIXTURE"}, "rerun": True}
    else:
        nested = FlowNode(id="nested", kind=kind, body=child if kind in {"foreach", "while", "scope"} else None,
                          branches=[child] if kind == "parallel" else [], flow_ref="saved-child" if kind == "subflow" else "")
        root = Flow(id="root", name="Root", start="first", nodes={
            "first": FlowNode(id="first", kind="action", tool="fixture_read", next="nested"), "nested": nested})
        resume = None
    called = []
    result = run_flow(root, agent_fn=lambda *a: pytest.fail("agent"),
        action_fn=lambda *a: (called.append(True), 1.0), resume=resume,
        resolve_flow=lambda name: child if name == "saved-child" else None)
    assert result.status == "failed" and "Connections" in result.error and called == []


def test_data_alias_cannot_deliver_unresolved_secret_expression_to_action():
    flow = action_flow("{{value}}")
    flow.start = "legacy"
    called = []
    result = run_flow(flow, data={"value": "{{secret('LIGHTWORK_LOCAL_SECRET_FIXTURE')}}"},
        agent_fn=lambda *a: pytest.fail("agent"), action_fn=lambda *a: (called.append(True), 1.0))
    assert result.status == "failed" and "Connections" in result.error and called == []


def test_plain_data_transforms_and_literal_examples_keep_their_contract():
    assert render("{{concat(upper(name), '-', add(2,3))}}", {"name": "example"}, allow_secrets=True) == "EXAMPLE-5"
    assert render("{{concat('secret(name)', '-example')}}", {}, allow_secrets=True) == "secret(name)-example"
    assert render("{{secret('key')}}", {}) == "{{secret('key')}}"  # Inert prose, never a secret lookup.


def test_reviewed_saved_subflow_copy_cannot_change_between_review_and_dispatch():
    safe = action_flow("ordinary-data")
    unsafe = action_flow("{{secret(name)}}")
    calls, lookups = [], []
    def resolve(name):
        lookups.append(name)
        return safe if len(lookups) == 1 else unsafe
    parent = Flow(id="parent", name="Parent", start="child", nodes={
        "child": FlowNode(id="child", kind="subflow", flow_ref="saved")})
    result = run_flow(parent, resolve_flow=resolve, agent_fn=lambda *a: pytest.fail("agent"),
        action_fn=lambda node, params, data: (calls.append(dict(params)), 1.0))
    assert result.status == "completed" and lookups == ["saved"]
    assert calls == [{"q": "safe"}, {"q": "ordinary-data"}]


@pytest.mark.parametrize("scoped", [False, True])
def test_unavailable_saved_subflow_is_a_failed_run_without_unchecked_prefix(scoped):
    parent = Flow(id="parent", name="Parent", start="prefix", nodes={
        "prefix": FlowNode(id="prefix", kind="action", tool="web_search", next="child"),
        "child": FlowNode(id="child", kind="subflow", flow_ref="saved")})
    if scoped:
        child = Flow(id="nested-scope", name="Nested", start="child", nodes={"child": parent.nodes["child"]})
        parent.nodes["child"] = FlowNode(id="child", kind="scope", body=child, on_error="recover")
        parent.nodes["recover"] = FlowNode(id="recover", kind="action", tool="web_search")
    def unavailable(name):
        raise OSError("saved source unavailable")
    called = []
    result = run_flow(parent, resolve_flow=unavailable, agent_fn=lambda *a: pytest.fail("agent"),
        action_fn=lambda *a: (called.append(True), 1.0))
    assert result.status == "failed" and "saved source unavailable" in result.error and called == []


def test_unknown_wrapper_is_conservatively_flagged_for_review_not_evaluated():
    expression = "{{unknown(secret('LIGHTWORK_LOCAL_SECRET_FIXTURE'))}}"
    assert render(expression, {}, allow_secrets=True) == expression
    called = []
    result = run_flow(action_flow(expression), agent_fn=lambda *a: pytest.fail("agent"),
        action_fn=lambda *a: (called.append(True), 1.0))
    assert result.status == "failed" and "Connections" in result.error and called == []


def test_durable_legacy_snapshot_resume_refuses_without_replaying_history():
    from maverick.flow import execution
    flow = action_flow("{{secret('LIGHTWORK_LOCAL_SECRET_FIXTURE')}}")
    for node in flow.nodes.values():
        node.tool = "web_search"
    flow.nodes["prefix"].next = "wait"
    flow.nodes["wait"] = FlowNode(id="wait", kind="delay", seconds=1, next="legacy")
    saved = store.save_flow(flow)
    digest, version, children = store.snapshot_flow_bundle(saved)
    old = store.FlowRun(run_id="legacy-secret-pause", flow_id=saved.id, status="paused_delay",
        cursor="wait", data={"completed_prefix": "retained"}, definition_digest=digest,
        definition_version=version, definition_revision=saved.revision, subflow_digests=children)
    store.save_run(old)
    called = []
    result = execution.execute(saved, resume_run_id=old.run_id,
        agent_runner=lambda *a: pytest.fail("agent"), action_runner=lambda *a: (called.append(True), 1.0))
    assert result.status == "failed" and "Connections" in result.error and called == []
    assert result.data == {"completed_prefix": "retained"}
    assert store.load_flow(saved.id).nodes["legacy"].params == flow.nodes["legacy"].params


def test_dry_run_refuses_vault_expression_without_saving_resolved_value(
        tmp_path, monkeypatch):
    from maverick.flow import execution

    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    flow = action_flow("{{secret('LIGHTWORK_LOCAL_SECRET_FIXTURE')}}")
    for node in flow.nodes.values():
        node.tool = "web_search"
    ag, act = execution.sandbox_runners()

    run = execution.execute(flow, agent_runner=ag, action_runner=act,
                            record_outcomes=False)
    saved = store.load_run(run.run_id)

    assert saved.status == "failed" and "Connections" in saved.error
    assert saved.data == {} and saved.input_data == {}
    assert "synthetic-credential-only" not in str(saved)


def test_legacy_definition_remains_readable_without_migrating_credentials():
    flow = action_flow("{{secret('LIGHTWORK_LOCAL_SECRET_FIXTURE')}}")
    for node in flow.nodes.values():
        node.tool = "web_search"
    saved = store.save_flow(flow)
    loaded = store.load_flow(saved.id)
    assert loaded.nodes["legacy"].params == flow.nodes["legacy"].params


def test_native_action_resolves_exact_account_inside_authorized_connector(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    owner = "user:flow-account@example.test"
    calls = []
    risk = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk, "_load_overrides", lambda: {"fixture_account_read": "low"})
    with tenant_scope(tenant="credential-team"):
        saved = connections.set_connection("reviewed-account", connector="fixture_account_read", owner=owner,
            base_url="https://api.example.test", token="synthetic-owned-account")
        def connector(params):
            record = connections.resolve_named(params["account"], expected_revision=params["revision"],
                connector="fixture_account_read", origin="https://api.example.test")
            assert record["token"] == "synthetic-owned-account"
            calls.append(dict(params))
            return "ok"
        def registry(*a, **kwargs):
            result = tools.ToolRegistry(principal=kwargs.get("user_id"))
            result.register(tools.Tool(name="fixture_account_read", description="Local account binding fixture",
                input_schema={"type": "object", "properties": {}}, fn=connector))
            return result
        monkeypatch.setattr(tools, "base_registry", registry)
        params = {"account": "reviewed-account", "revision": saved["revision"]}
        flow = Flow(id="bound", name="Bound", owner=owner, start="read", nodes={
            "read": FlowNode(id="read", kind="action", tool="fixture_account_read", params=params)})
        native = default_action_runner(None, user_id=owner)
        result = run_flow(flow, agent_fn=lambda *a: pytest.fail("agent"),
                         action_fn=lambda node, arguments, data: native(node.tool, arguments, data))
        assert result.status == "completed" and calls == [params], result.error
        assert "synthetic-owned-account" not in str(result) and "synthetic-owned-account" not in str(calls)
        connections.set_connection("reviewed-account", connector="fixture_account_read", owner=owner,
            token="rotated", expected_revision=saved["revision"])
        refused = native("fixture_account_read", params, {})
        assert refused[1] == 0.0 and calls == [params]
