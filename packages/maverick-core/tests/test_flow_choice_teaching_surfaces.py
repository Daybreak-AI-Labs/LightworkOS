"""Teaching drafts use real choice artifacts and native signed HTTP teachers.

The shared teacher fixture stubs OIDC token verification; capture, authenticated
approval attestations, native calls, signing, encryption and lineage are real.
These are draft/authority tests, not teaching-runtime completion tests.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import time
from pathlib import Path

import pytest
from maverick import audit
from maverick.flow import Flow, FlowNode, action_recipe, execution, recipe_flow, store
from maverick.flow.action_choice import synthesize_choice
from maverick.flow.recipe_lineage import RecipeLineageService, learn_choice_from_verified_bundles
from maverick.governed_operations import ServiceContext
from maverick.paths import tenant_scope

from test_support.action_episode_api import OWNER, TENANT, _base, _resume

_spec = importlib.util.spec_from_file_location(
    "choice_teaching_surface_teachers", Path(__file__).with_name("test_flow_recipe_choices_cli.py"))
_teachers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_teachers)
harness = _teachers.harness
signed_teachers = _teachers.signed_teachers

BASE = "/api/v1/flows/recipe-lineage"
MARKER = {"schema": "lightwork.action-choice-teaching.v1"}


def _artifact():
    return synthesize_choice(_teachers.examples(), allowed_tools=_teachers.ALLOWED,
                             domain=_teachers.domain(), max_operations=1, operators=["lt", "le", "not"])


def _assert_teaching(value):
    assert value["recipe_teaching"] == MARKER
    parsed = Flow.from_dict(value)
    assert parsed.to_dict() == value
    assert parsed.recipe_teaching == MARKER
    assert parsed.nodes["teaching_review"].kind == "approval"
    assert parsed.nodes["teaching_review"].choices == ["route:0", "route:1"]
    assert parsed.nodes["teaching_review"].next == "teaching_choice"
    assert parsed.nodes["teaching_choice"].kind == "switch"
    recipe_flow.validate_flow(parsed)
    assert sum(node.kind == "action" for node in parsed.nodes.values()) == 3
    assert sum(node.kind == "approval" for node in parsed.nodes.values()) == 4


@pytest.mark.parametrize("teaching", [False, True])
def test_raw_draft_explicit_teaching_marker_roundtrips_without_granting_lineage(tmp_path, teaching):
    artifact = _artifact()
    source = _teachers.write(tmp_path, "artifact.json", artifact)
    target = tmp_path / "draft.json"
    flags = ["--teach-choices"] if teaching else []
    result = _teachers.invoke("draft", "--artifact", source, "--flow-id", "teaching-inspection",
                              "--name", "Teaching inspection", "--output", target, *flags)
    assert result.exit_code == 0, result.output
    draft = json.loads(target.read_bytes())
    assert draft["learned_recipe"] == artifact and "recipe_lineage" not in draft
    assert "Not saved, published or executed" in result.output
    if teaching:
        _assert_teaching(draft)
        assert "governed lineage" in result.output and "no execution authority" in result.output
    else:
        assert "recipe_teaching" not in draft and "teaching_review" not in Flow.from_dict(draft).nodes
    before = target.read_bytes()
    repeat = _teachers.invoke("draft", "--artifact", source, "--flow-id", "teaching-inspection",
                              "--name", "Teaching inspection", "--output", target, *flags)
    assert repeat.exit_code != 0 and target.read_bytes() == before


def test_teaching_flag_rejects_straight_line_artifact_without_writing_output(tmp_path):
    artifact = action_recipe.synthesize(_teachers.examples()[:2], allowed_tools=_teachers.ALLOWED)
    source = _teachers.write(tmp_path, "straight.json", artifact)
    target = tmp_path / "none.json"
    result = _teachers.invoke("draft", "--artifact", source, "--flow-id", "wrong-mode",
                              "--name", "Wrong mode", "--teach-choices", "--output", target)
    assert result.exit_code != 0 and not target.exists()


def test_raw_teaching_marker_cannot_save_without_governed_reference(harness):
    risk = importlib.import_module("maverick.safety.tool_risk")
    harness.monkeypatch.setattr(risk, "_load_overrides", lambda: dict.fromkeys(_teachers.ALLOWED, "high"))
    harness.flags.update(action_recipes=True, action_recipe_transforms=True, action_recipe_choices=True,
                         action_recipe_teaching=True, action_recipe_lineage=True, require_action_recipe_lineage=False)
    flow = recipe_flow.make_flow(_artifact(), flow_id="unadmitted-teaching", name="Unadmitted teaching", teaching=True)
    flow.owner = OWNER
    with tenant_scope(tenant=TENANT):
        with pytest.raises(ValueError, match="teaching requires admitted signed evidence"):
            store.save_flow(flow)
        assert store.load_flow(flow.id) is None


@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", [], {}])
def test_governed_draft_library_teaching_option_rejects_non_booleans(value):
    service = RecipeLineageService(lambda *args: pytest.fail("invalid option must precede authority lookup"))
    ctx = ServiceContext(tenant=TENANT, actor=OWNER, resource_owner=OWNER, human=True,
                         credential_authority="surface-test", credential_ref="none")
    with pytest.raises(ValueError, match="teaching must be a boolean"):
        service.draft(ctx, "LRA-" + "0" * 32, flow_id="draft", name="Draft", teaching=value)


@pytest.mark.parametrize("patch", [
    {"teaching": None}, {"teaching": 0}, {"teaching": 1}, {"teaching": "true"},
    {"teaching": "false"}, {"teaching": []}, {"teaching": {}},
    {"teaching": True, "owner": "user:admin"}, {"teaching": True, "tenant": "foreign"},
    {"teaching": True, "human": True}, {"teaching": True, "actor": OWNER},
])
def test_teaching_draft_http_rejects_coercion_and_body_authority(harness, patch):
    response = harness.client.post(BASE + "/LRA-" + "0" * 32 + "/draft",
                                   json={"flow_id": "strict-draft", "name": "Strict", **patch})
    assert response.status_code == 422, response.text


@pytest.fixture
def signed_package(signed_teachers):
    trust = json.loads(signed_teachers["trust"].read_bytes())
    package = learn_choice_from_verified_bundles(
        signed_teachers["all"][:4], trust=trust, expected_tenant=TENANT, now=time.time(),
        allowed_tools=_teachers.ALLOWED, domain=_teachers.domain(), max_operations=1,
        operators=["lt", "le", "not"],
    )
    return package, signed_teachers


def test_verified_cli_and_http_teaching_drafts_keep_inspection_and_admission_distinct(signed_package, harness, tmp_path):
    package, sources = signed_package
    source = _teachers.write(tmp_path, "package.json", package)
    for teaching in (False, True):
        target = tmp_path / f"inspection-{teaching}.json"
        flags = ["--teach-choices"] if teaching else []
        result = _teachers.invoke("draft-verified", "--package", source, "--trust", sources["trust"],
                                  "--tenant", TENANT, "--flow-id", "inspection", "--name", "Inspection",
                                  "--output", target, *flags)
        assert result.exit_code == 0, result.output
        draft = json.loads(target.read_bytes())
        assert "recipe_lineage" not in draft
        assert "Unadmitted inspection draft" in result.output and "live status not checked" in result.output
        if teaching:
            _assert_teaching(draft)
        else:
            assert "recipe_teaching" not in draft
    admitted = harness.client.post(BASE, json={"package": package})
    assert admitted.status_code == 200, admitted.text
    path = BASE + "/" + admitted.json()["id"] + "/draft"
    for teaching in (None, False, True):
        body = {"flow_id": "governed-teaching", "name": "Governed teaching"}
        if teaching is not None:
            body["teaching"] = teaching
        response = harness.client.post(path, json=body)
        assert response.status_code == 200, response.text
        draft = response.json()
        assert draft["recipe_lineage"] == admitted.json()["reference"] and draft["owner"] == OWNER
        assert draft["learned_recipe"] == package["artifact"]
        if teaching:
            _assert_teaching(draft)
        else:
            assert "recipe_teaching" not in draft
        assert response.headers["cache-control"] == "no-store"
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("governed-teaching") is None


def test_teaching_http_keeps_current_owner_and_permission_checks(signed_package, harness):
    from maverick_dashboard import rbac

    package, _ = signed_package
    admitted = harness.client.post(BASE, json={"package": package})
    assert admitted.status_code == 200, admitted.text
    path = BASE + "/" + admitted.json()["id"] + "/draft"
    body = {"flow_id": "teaching-target", "name": "Teaching target", "teaching": True}
    foreign = harness.client.post(path, json=body, headers={"Authorization": "Bearer bob"})
    assert foreign.status_code == 403, foreign.text
    with harness.monkeypatch.context() as scoped:
        scoped.setattr(rbac, "default_role", lambda: "viewer")
        response = harness.client.post(path, json=body)
        assert response.status_code == 403, response.text
    with tenant_scope(tenant=TENANT):
        target = Flow(id="teaching-target", name="Other owner's target", owner="user:bob",
                      start="review", nodes={"review": FlowNode(id="review", kind="approval", prompt="Review")})
        store.save_flow(target)
    response = harness.client.post(path, json=body)
    assert response.status_code == 403, response.text
    source_id = package["bundles"][0]["body"]["source"]["flow_id"]
    with tenant_scope(tenant=TENANT):
        source = store.load_flow(source_id)
        source.owner = "user:bob"
        store.save_flow(source)
    response = harness.client.post(path, json={**body, "flow_id": "fresh-target"})
    assert response.status_code == 403, response.text


@pytest.mark.parametrize("receipt", [False, 1])
def test_teaching_draft_withholds_pending_admission_without_replaying_teachers(signed_package, harness, receipt):
    from maverick import tools

    package, _ = signed_package
    harness.monkeypatch.setattr(tools, "base_registry", lambda *a, **kw: pytest.fail("draft cannot dispatch tools"))
    original = audit.record
    harness.monkeypatch.setattr(audit, "record", lambda *a, **kw: receipt)
    admitted = harness.client.post(BASE, json={"package": package})
    assert admitted.status_code == 503, admitted.text
    identity = admitted.json()["id"]
    assert "reference" not in admitted.json() and "package" not in admitted.json()
    body = {"flow_id": "pending-teaching", "name": "Pending teaching", "teaching": True}
    response = harness.client.post(BASE + "/" + identity + "/draft", json=body)
    assert response.status_code == 503, response.text
    assert "learned_recipe" not in response.text and "recipe_teaching" not in response.text
    harness.monkeypatch.setattr(audit, "record", original)
    recovered = harness.client.post(BASE + "/" + identity + "/draft", json=body)
    assert recovered.status_code == 200, recovered.text
    _assert_teaching(recovered.json())


def test_http_teaching_enrollment_uses_all_tools_two_steps_and_only_the_initial_pause(signed_package, harness):
    from maverick.flow.action_episodes import TEACHING_FAMILY
    from maverick_dashboard import rbac

    package, _ = signed_package
    harness.flags.update(action_recipes=True, action_recipe_transforms=True, action_recipe_choices=True,
                         action_recipe_lineage=True, action_recipe_teaching=True)
    admitted = harness.client.post(BASE, json={"package": package})
    assert admitted.status_code == 200, admitted.text
    response = harness.client.post(BASE + "/" + admitted.json()["id"] + "/draft",
                                   json={"flow_id": "enrolled-teaching", "name": "Teaching", "teaching": True})
    assert response.status_code == 200, response.text
    flow = Flow.from_dict(response.json())
    inputs = {"amount": 1, "limit": 5, "legacy_ok": False}
    with tenant_scope(tenant=TENANT):
        flow = store.save_flow(flow)
        run = execution.execute(flow, owner=OWNER, data={"input": inputs}, action_runner=harness.native,
                                agent_runner=lambda *a, **kw: pytest.fail("agent work"))
    assert run.status == "paused_approval" and run.cursor == "approval_0", run.error
    path = _base(run)
    prepared = harness.client.get(path + "/enrollment")
    assert prepared.status_code == 200, prepared.text
    info = prepared.json()
    assert info["allowed_tools"] == sorted(_teachers.ALLOWED) and info["planned_steps"] == 2
    assert info["status"] == "initial_approval" and len(info["expected_pause_binding"]) == 64
    assert info["capture_family"] == TEACHING_FAMILY
    assert info["retention"]["human_continuation_choice_required"] is True
    assert info["retention"]["agreement_only_runs_are_training_evidence"] is False
    assert prepared.headers["cache-control"] == "no-store"
    assert "legacy_ok" not in prepared.text and "native-fresh-" not in prepared.text
    assert harness.client.get(path + "/enrollment", headers={"Authorization": "Bearer bob"}).status_code == 404
    with harness.monkeypatch.context() as scoped:
        scoped.setattr(rbac, "default_role", lambda: "viewer")
        assert harness.client.get(path + "/enrollment").status_code == 403
    for disabled in (False, 1, "true"):
        harness.flags["action_recipe_teaching"] = disabled
        assert harness.client.get(path + "/enrollment").status_code == 403
    harness.flags["action_recipe_teaching"] = True

    # A fabricated completed alternate terminal cannot evade the initial-pause
    # check merely because the eventual selected plan would contain two steps.
    with tenant_scope(tenant=TENANT):
        original = store.load_run(run.run_id)
        tampered = copy.deepcopy(original)
        tampered.nodes["action_1_1"] = {"status": "done"}
        store.save_run(tampered)
    assert harness.client.get(path + "/enrollment").status_code == 409
    with tenant_scope(tenant=TENANT):
        store.save_run(original)
    info = harness.client.get(path + "/enrollment").json()
    declared = _teachers.domain()
    body = {"expected_pause_binding": info["expected_pause_binding"], "allowed_tools": info["allowed_tools"],
            "input_schema": declared["inputs"],
            "tool_data_schemas": {_teachers.PREFIX: declared["prefix"], **declared["branches"]},
            "retain_until": time.time() + 1800}
    stale = harness.client.post(path, json={**body, "expected_pause_binding": "0" * 64})
    assert stale.status_code == 409, stale.text
    missing = copy.deepcopy(body)
    missing["allowed_tools"].remove(_teachers.REVIEW)
    missing["tool_data_schemas"].pop(_teachers.REVIEW)
    assert harness.client.post(path, json=missing).status_code == 400
    enrolled = harness.client.post(path, json=body)
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["planned_steps"] == 2 and enrolled.json()["binding"]["family"] == TEACHING_FAMILY
    paused = _resume(harness, flow, run)
    assert paused.status == "paused_approval" and paused.cursor == "teaching_review", paused.error
    assert harness.client.get(path + "/enrollment").status_code == 409
    view_path = "/api/v1/flows/runs/" + run.run_id
    shown = harness.client.get(view_path)
    assert shown.status_code == 200, shown.text
    question = paused.data["_recipe_teaching_question"]
    assert shown.json()["teaching_review"]["status"] == "current"
    assert shown.json()["teaching_review"]["question"]["options"] == question["options"]
    assert all(option["arguments"]["case_id"] == paused.data["_recipe_step_0"]["case_id"]
               for option in question["options"])
    assert harness.client.get(view_path, headers={"Authorization": "Bearer bob"}).status_code in {403, 404}
