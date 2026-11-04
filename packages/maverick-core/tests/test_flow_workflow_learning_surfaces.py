"""Workflow learning surfaces use actual signed native capture and synthesis.

OIDC signature verification is stubbed by the shared API fixture. Current roles,
workspace/ownership, native tools/approval attestations, encrypted capture,
review, signing and governed stores remain real. No provider or external calls.
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import time

import pytest
from click.testing import CliRunner
from maverick import audit
from maverick.cli import main
from maverick.flow import store
from maverick.paths import tenant_scope

from test_support.action_episode_api import (
    CREATE,
    LOOKUP,
    OWNER,
    PRIVATE_REF,
    RATIONALE,
    TENANT,
    _awaiting_review,
    _base,
    _object,
    _review,
    _string,
)
from test_support.action_episode_api import harness as harness

BASE = "/api/v1/flows/recipe-lineage"
LEARN = BASE + "/learn-workflow-verified"


def _domain():
    return {"inputs": _object(ref=_string()), "tools": {
        LOOKUP: {"arguments": _object(query=_string()), "result": _object(customer_id=_string())},
        CREATE: {"arguments": _object(customer_id=_string()), "result": _object(order_id=_string())},
    }}


@pytest.fixture
def enabled(harness):
    harness.flags.update(action_workflow_learning=True, action_recipes=True, action_recipe_transforms=True,
                         action_recipe_lineage=True, require_action_recipe_lineage=False,
                         action_evidence_issuer="workflow-surface-native", action_evidence_revoked_keys=[])
    return harness


def _signed_case(enabled, index):
    source, run, row = _awaiting_review(enabled, index=index, flow_id=f"workflow-source-{index}")
    response = enabled.client.post(_base(run) + "/review", json=_review(row))
    assert response.status_code == 200, response.text
    row = response.json()
    response = enabled.client.post(_base(run) + "/training-grant", json={
        "expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
        "use_until": row["retain_until"] - 1, "retain_derived_copies": True,
        "rationale": "Permit bounded workflow learning from the reviewed execution.",
    })
    assert response.status_code == 200, response.text
    row = response.json()
    response = enabled.client.post(_base(run) + "/signed-export", json={
        "expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
        "expected_grant_sha256": row["grant_sha256"],
    })
    assert response.status_code == 200, response.text
    return (source, run), response.json()


@pytest.fixture
def signed_workflow(enabled):
    cases = [_signed_case(enabled, index) for index in range(2)]
    sources, bundles = [case[0] for case in cases], [case[1] for case in cases]
    return {"bundles": bundles, "sources": sources,
            "request": {"bundles": bundles, "allowed_tools": [LOOKUP, CREATE], "domain": _domain()}}


def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _invoke(command, *options):
    return CliRunner().invoke(main, ["flow", "recipe", command, *map(str, options)])


def _cli_options(tmp_path, sources):
    from maverick.flow.action_provenance import local_trust

    with tenant_scope(tenant=TENANT):
        trust = local_trust(TENANT)
    return ["--bundles", _write(tmp_path, "bundles.json", sources["bundles"]),
            "--trust", _write(tmp_path, "trust.json", trust), "--tenant", TENANT,
            "--domain", _write(tmp_path, "domain.json", _domain()),
            "--allow-tool", LOOKUP, "--allow-tool", CREATE]


def test_signed_native_cli_workflow_package_draft_and_fresh_process(enabled, signed_workflow, tmp_path):
    from maverick.flow.recipe_lineage import validate_package

    options = _cli_options(tmp_path, signed_workflow)
    output = tmp_path / "workflow.json"
    result = _invoke("learn-workflow-verified", *options, "--output", output)
    assert result.exit_code == 0, result.output
    assert "Not governed-admitted" in result.output and "live status not checked" in result.output
    assert "up to 8 actions" in result.output
    before = output.read_bytes()
    package = json.loads(before)
    assert package["artifact"]["schema"] == "lightwork.workflow-transducer.v1"
    validate_package(package, trust=json.loads((tmp_path / "trust.json").read_bytes()),
                     expected_tenant=TENANT, now=time.time())
    again = _invoke("learn-workflow-verified", *options, "--output", output)
    assert again.exit_code != 0 and "already exists" in again.output and output.read_bytes() == before
    inspection = tmp_path / "inspection.json"
    drafted = _invoke("draft-verified", "--package", output, "--trust", tmp_path / "trust.json",
                      "--tenant", TENANT, "--flow-id", "workflow-inspection", "--name", "Inspection",
                      "--output", inspection)
    assert drafted.exit_code == 0, drafted.output
    assert "recipe_lineage" not in json.loads(inspection.read_bytes())
    forbidden = _invoke("draft-verified", "--package", output, "--trust", tmp_path / "trust.json",
                        "--tenant", TENANT, "--flow-id", "not-choice-teaching", "--name", "Not teaching",
                        "--teach-choices", "--output", tmp_path / "teaching.json")
    assert forbidden.exit_code != 0 and not (tmp_path / "teaching.json").exists()
    raw = _write(tmp_path, "artifact.json", package["artifact"])
    raw_teaching = _invoke("draft", "--artifact", raw, "--flow-id", "raw-teaching", "--name", "No",
                           "--teach-choices", "--output", tmp_path / "raw-teaching.json")
    assert raw_teaching.exit_code != 0 and not (tmp_path / "raw-teaching.json").exists()
    _source, extra = _signed_case(enabled, 2)
    added = _write(tmp_path, "added.json", [extra])
    refined = tmp_path / "refined.json"
    refinement = _invoke("refine-verified", "--package", output, "--bundles", added,
                         "--trust", tmp_path / "trust.json", "--tenant", TENANT, "--output", refined)
    assert refinement.exit_code == 0, refinement.output
    updated = json.loads(refined.read_bytes())
    assert len(updated["manifest"]) == 3 and updated["artifact"]["episode_count"] == 3
    assert output.read_bytes() == before and updated["package_sha256"] != package["package_sha256"]
    validate_package(updated, trust=json.loads((tmp_path / "trust.json").read_bytes()),
                     expected_tenant=TENANT, now=time.time())
    fresh = tmp_path / "fresh-process.json"
    process = subprocess.run([sys.executable, "-m", "maverick.cli", "--db", str(tmp_path / "subprocess.db"),
                              "flow", "recipe", "learn-workflow-verified", *map(str, options),
                              "--output", str(fresh)], capture_output=True, text=True, timeout=60, check=False)
    assert process.returncode == 0, process.stderr
    assert json.loads(fresh.read_bytes())["package_sha256"] == package["package_sha256"]
    assert len(enabled.calls) == 6


def test_http_learns_admits_and_drafts_from_current_signed_native_sources(enabled, signed_workflow):
    response = enabled.client.post(LEARN, json=signed_workflow["request"])
    assert response.status_code == 200, response.text
    meta = response.json()
    assert meta["status"] == "admitted" and meta["current_eligibility"] == "accepted"
    assert "package" not in meta and PRIVATE_REF not in response.text and RATIONALE not in response.text
    assert response.headers["cache-control"] == "no-store"
    detail = enabled.client.get(BASE + "/" + meta["id"] + "/detail")
    assert detail.status_code == 200, detail.text
    artifact = detail.json()["package"]["artifact"]
    assert artifact["schema"] == "lightwork.workflow-transducer.v1"
    draft = enabled.client.post(BASE + "/" + meta["id"] + "/draft",
                                json={"flow_id": "learned-workflow", "name": "Reviewed workflow"})
    assert draft.status_code == 200, draft.text
    assert draft.json()["learned_recipe"] == artifact and draft.json()["recipe_lineage"] == meta["reference"]
    teaching = enabled.client.post(BASE + "/" + meta["id"] + "/draft",
                                   json={"flow_id": "invalid-teaching", "name": "No", "teaching": True})
    assert teaching.status_code == 400, teaching.text
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("learned-workflow") is None
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("receipt", [False, 1])
def test_http_pending_workflow_learning_withholds_content_and_recovers_without_calls(enabled, signed_workflow, receipt):
    original = audit.record
    enabled.monkeypatch.setattr(audit, "record", lambda *a, **kw: receipt)
    response = enabled.client.post(LEARN, json=signed_workflow["request"])
    assert response.status_code == 503, response.text
    row = response.json()
    assert row["status"] == "audit_pending" and "package" not in row and "reference" not in row
    assert PRIVATE_REF not in response.text and RATIONALE not in response.text
    held = enabled.client.get(BASE + "/" + row["id"] + "/detail")
    assert held.status_code == 503 and "package" not in held.json()
    enabled.monkeypatch.setattr(audit, "record", original)
    recovered = enabled.client.post(LEARN, json=signed_workflow["request"])
    assert recovered.status_code == 200 and recovered.json()["id"] == row["id"], recovered.text
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("mode", ["foreign_owner", "withdrawn", "role", "tampered", "foreign_tenant", "foreign_caller"])
def test_http_rejects_stale_or_foreign_source_before_synthesis(enabled, signed_workflow, mode):
    from maverick.flow import recipe_lineage
    from maverick_dashboard import rbac

    request = copy.deepcopy(signed_workflow["request"])
    if mode == "foreign_owner":
        source = signed_workflow["sources"][0][0]
        with tenant_scope(tenant=TENANT):
            current = store.load_flow(source.id)
            current.owner = "user:bob"
            store.save_flow(current)
    elif mode == "withdrawn":
        run = signed_workflow["sources"][0][1]
        current = enabled.client.get(_base(run)).json()
        withdrawn = enabled.client.post(_base(run) + "/withdraw", json={
            "expected_revision": current["revision"], "expected_episode_sha256": current["episode_sha256"],
            "expected_review_sha256": current["review_sha256"], "withdraw": True, "rationale": "Withdraw reuse.",
        })
        assert withdrawn.status_code == 200, withdrawn.text
    elif mode == "role":
        enabled.monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
    elif mode == "tampered":
        request["bundles"][0]["body"]["episode"]["inputs"]["ref"] = "forged-private-reference"
    elif mode == "foreign_tenant":
        enabled.monkeypatch.setenv("MAVERICK_TENANT", "foreign-workflow-tenant")
    enabled.monkeypatch.setattr(recipe_lineage, "learn_transducer_from_verified_bundles",
                                lambda *a, **kw: pytest.fail("unauthorized expensive synthesis"))
    headers = {"Authorization": "Bearer bob"} if mode == "foreign_caller" else {}
    response = enabled.client.post(LEARN, json=request, headers=headers)
    assert response.status_code in {400, 403, 409}, response.text
    assert PRIVATE_REF not in response.text and "forged-private-reference" not in response.text
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("mode", ["role", "flag"])
def test_http_rechecks_authority_and_flag_after_actual_synthesis(enabled, signed_workflow, mode):
    from maverick.flow import recipe_lineage
    from maverick_dashboard import rbac

    original = recipe_lineage.learn_transducer_from_verified_bundles

    def learn_then_revoke(*args, **kwargs):
        package = original(*args, **kwargs)
        if mode == "role":
            enabled.monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
        else:
            enabled.flags["action_workflow_learning"] = False
        return package

    enabled.monkeypatch.setattr(recipe_lineage, "learn_transducer_from_verified_bundles", learn_then_revoke)
    response = enabled.client.post(LEARN, json=signed_workflow["request"])
    assert response.status_code == 403, response.text
    assert PRIVATE_REF not in response.text and RATIONALE not in response.text
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("key", ["action_workflow_learning", "action_recipes",
                                  "action_recipe_transforms", "action_recipe_lineage"])
@pytest.mark.parametrize("value", [False, 1, "true"])
def test_http_requires_all_literal_feature_flags_before_reading_body(enabled, key, value):
    enabled.flags[key] = value
    response = enabled.client.post(LEARN, content=b"not JSON", headers={"Content-Type": "application/json"})
    assert response.status_code == 403, response.text
    assert not enabled.calls


@pytest.mark.parametrize("patch", [
    {"actor": OWNER}, {"tenant": TENANT}, {"owner": OWNER}, {"human": True}, {"trust": {}},
    {"max_operations": True}, {"max_operations": 3}, {"max_steps": "8"}, {"max_steps": 9}, {"max_steps": 0},
    {"bundles": [{}]}, {"bundles": [{}] * 33}, {"allowed_tools": []}, {"domain": []},
])
def test_http_strict_bounded_body_does_not_accept_authority_or_coercions(enabled, patch):
    payload = {"bundles": [{}, {}], "allowed_tools": [LOOKUP, CREATE], "domain": _domain(), **patch}
    response = enabled.client.post(LEARN, json=payload)
    assert response.status_code == 422, response.text
    assert not enabled.calls


@pytest.mark.parametrize("body", [b'{"domain": {}, "domain": {}}', b'{"domain": NaN}', b'[[[['])
def test_http_rejects_duplicate_nonfinite_or_malformed_json(enabled, body):
    response = enabled.client.post(LEARN, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 422, response.text
    assert not enabled.calls


@pytest.mark.parametrize("streamed", [False, True])
def test_http_bounds_request_bytes_before_synthesis(enabled, streamed):
    body = b" " * (2 * 1024 * 1024 + 1)
    response = enabled.client.post(LEARN, content=iter([body]) if streamed else body,
                                    headers={"Content-Type": "application/json"})
    assert response.status_code == 413, response.text
    assert not enabled.calls


@pytest.mark.parametrize("option", [["--max-operations", "0"], ["--max-operations", "3"],
                                     ["--max-steps", "0"], ["--max-steps", "9"]])
def test_workflow_cli_rejects_out_of_bounds_options_without_output(tmp_path, option):
    empty = _write(tmp_path, "empty.json", {})
    output = tmp_path / "refused.json"
    result = _invoke("learn-workflow-verified", "--bundles", empty, "--trust", empty, "--tenant", TENANT,
                     "--allow-tool", LOOKUP, "--domain", empty, "--output", output, *option)
    assert result.exit_code != 0 and not output.exists()
