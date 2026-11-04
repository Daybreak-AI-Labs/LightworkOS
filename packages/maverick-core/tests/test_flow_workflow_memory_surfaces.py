"""Memory learning uses native signed sources and existing authenticated surfaces.

Shared API fixture stubs OIDC verification only. Native dispatch, encrypted
capture, reviews, grants, signatures and governed admission remain real. These
simple sources qualify the surfaces; accumulator semantics have separate tests.
"""
from __future__ import annotations

import copy
import json
import time

import pytest
from click.testing import CliRunner
from maverick import audit
from maverick.cli import main
from maverick.flow import recipe_lineage, store
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
LEARN = BASE + "/learn-memory-verified"


def _domain():
    return {"inputs": _object(ref=_string()), "tools": {
        LOOKUP: {"arguments": _object(query=_string()), "result": _object(customer_id=_string())},
        CREATE: {"arguments": _object(customer_id=_string()), "result": _object(order_id=_string())},
    }}


@pytest.fixture
def enabled(harness):
    harness.flags.update(action_workflow_memory_learning=True, action_workflow_learning=True,
        action_recipes=True, action_recipe_transforms=True, action_recipe_lineage=True,
        action_evidence_issuer="memory-surface-native", action_evidence_revoked_keys=[])
    return harness


def _signed(enabled, index):
    source, run, row = _awaiting_review(enabled, index=index, flow_id=f"memory-source-{index}")
    reviewed = enabled.client.post(_base(run) + "/review", json=_review(row))
    assert reviewed.status_code == 200, reviewed.text
    row = reviewed.json()
    granted = enabled.client.post(_base(run) + "/training-grant", json={
        "expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
        "use_until": row["retain_until"] - 1, "retain_derived_copies": True,
        "rationale": "Permit learning from this reviewed native execution.",
    })
    assert granted.status_code == 200, granted.text
    row = granted.json()
    exported = enabled.client.post(_base(run) + "/signed-export", json={
        "expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
        "expected_grant_sha256": row["grant_sha256"],
    })
    assert exported.status_code == 200, exported.text
    return (source, run), exported.json()


@pytest.fixture
def signed(enabled):
    pairs = [_signed(enabled, index) for index in range(2)]
    bundles = [pair[1] for pair in pairs]
    return {"sources": [pair[0] for pair in pairs], "bundles": bundles,
            "request": {"bundles": bundles, "allowed_tools": [LOOKUP, CREATE], "domain": _domain()}}


def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _invoke(command, *options):
    return CliRunner().invoke(main, ["flow", "recipe", command, *map(str, options)])


def test_cli_memory_package_is_unadmitted_and_existing_refine_draft_dispatch(enabled, signed, tmp_path):
    from maverick.flow.action_provenance import local_trust

    with tenant_scope(tenant=TENANT):
        trust = local_trust(TENANT)
    options = ["--bundles", _write(tmp_path, "bundles.json", signed["bundles"]),
        "--trust", _write(tmp_path, "trust.json", trust), "--tenant", TENANT,
        "--domain", _write(tmp_path, "domain.json", _domain()), "--allow-tool", LOOKUP, "--allow-tool", CREATE]
    output = tmp_path / "memory.json"
    result = _invoke("learn-memory-verified", *options, "--output", output)
    assert result.exit_code == 0, result.output
    assert "Not governed-admitted" in result.output and "live status not checked" in result.output
    before = output.read_bytes()
    package = json.loads(before)
    assert package["artifact"]["schema"] == "lightwork.workflow-memory.v1"
    recipe_lineage.validate_package(package, trust=trust, expected_tenant=TENANT, now=time.time())
    duplicate = _invoke("learn-memory-verified", *options, "--output", output)
    assert duplicate.exit_code != 0 and output.read_bytes() == before
    draft = tmp_path / "draft.json"
    result = _invoke("draft-verified", "--package", output, "--trust", tmp_path / "trust.json", "--tenant", TENANT,
        "--flow-id", "memory-inspection", "--name", "Memory inspection", "--output", draft)
    assert result.exit_code == 0, result.output
    assert "recipe_lineage" not in json.loads(draft.read_bytes())
    _, added = _signed(enabled, 2)
    refined = tmp_path / "refined.json"
    result = _invoke("refine-verified", "--package", output, "--bundles", _write(tmp_path, "added.json", [added]),
        "--trust", tmp_path / "trust.json", "--tenant", TENANT, "--output", refined)
    assert result.exit_code == 0, result.output
    updated = json.loads(refined.read_bytes())
    assert updated["artifact"]["schema"] == package["artifact"]["schema"] and len(updated["manifest"]) == 3
    assert output.read_bytes() == before and len(enabled.calls) == 6


def test_http_memory_learning_admits_current_signed_sources_and_returns_no_raw_examples(enabled, signed):
    response = enabled.client.post(LEARN, json=signed["request"])
    assert response.status_code == 200, response.text
    metadata = response.json()
    assert metadata["status"] == "admitted" and metadata["current_eligibility"] == "accepted"
    assert response.headers["cache-control"] == "no-store"
    assert "package" not in metadata and PRIVATE_REF not in response.text and RATIONALE not in response.text
    detail = enabled.client.get(BASE + "/" + metadata["id"] + "/detail")
    assert detail.status_code == 200, detail.text
    assert detail.json()["package"]["artifact"]["schema"] == "lightwork.workflow-memory.v1"
    draft = enabled.client.post(BASE + "/" + metadata["id"] + "/draft",
        json={"flow_id": "memory-unsaved", "name": "Memory draft"})
    assert draft.status_code == 200 and draft.json()["recipe_lineage"] == metadata["reference"], draft.text
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("memory-unsaved") is None
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("acknowledgement", [False, 1])
def test_memory_pending_receipt_withholds_content_and_retry_reuses_admission(enabled, signed, acknowledgement):
    original = audit.record
    enabled.monkeypatch.setattr(audit, "record", lambda *a, **kw: acknowledgement)
    response = enabled.client.post(LEARN, json=signed["request"])
    assert response.status_code == 503, response.text
    metadata = response.json()
    assert metadata["status"] == "audit_pending" and "reference" not in metadata and "package" not in metadata
    assert PRIVATE_REF not in response.text and RATIONALE not in response.text
    enabled.monkeypatch.setattr(audit, "record", original)
    recovered = enabled.client.post(LEARN, json=signed["request"])
    assert recovered.status_code == 200 and recovered.json()["id"] == metadata["id"], recovered.text
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("flag", ["action_workflow_memory_learning", "action_workflow_learning",
    "action_recipes", "action_recipe_transforms", "action_recipe_lineage"])
@pytest.mark.parametrize("value", [False, "true", 1])
def test_memory_all_dependencies_are_strict_before_synthesis(enabled, flag, value):
    enabled.flags[flag] = value
    response = enabled.client.post(LEARN, json={})
    assert response.status_code == 403, response.text
    assert not enabled.calls


def test_memory_flag_withdrawn_after_synthesis_cannot_admit(enabled, signed, monkeypatch):
    original = recipe_lineage.learn_memory_from_verified_bundles

    def withdraw(*args, **kwargs):
        package = original(*args, **kwargs)
        enabled.flags["action_workflow_memory_learning"] = False
        return package

    monkeypatch.setattr(recipe_lineage, "learn_memory_from_verified_bundles", withdraw)
    monkeypatch.setattr(recipe_lineage.RecipeLineageService, "admit", lambda *a, **kw: pytest.fail("must not admit"))
    response = enabled.client.post(LEARN, json=signed["request"])
    assert response.status_code == 403, response.text
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("mode", ["foreign_owner", "withdrawn", "role", "tampered", "foreign_tenant"])
def test_memory_authority_and_live_sources_checked_before_synthesis(enabled, signed, monkeypatch, mode):
    from maverick_dashboard import rbac

    body = copy.deepcopy(signed["request"])
    source, run = signed["sources"][0]
    if mode == "foreign_owner":
        with tenant_scope(tenant=TENANT):
            current = store.load_flow(source.id)
            current.owner = "other-user"
            store.save_flow(current)
    elif mode == "withdrawn":
        row = enabled.client.get(_base(run)).json()
        response = enabled.client.post(_base(run) + "/withdraw", json={"expected_revision": row["revision"],
            "expected_episode_sha256": row["episode_sha256"], "expected_review_sha256": row["review_sha256"],
            "withdraw": True, "rationale": "Withdraw reuse."})
        assert response.status_code == 200, response.text
    elif mode == "role":
        monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
    elif mode == "foreign_tenant":
        monkeypatch.setenv("MAVERICK_TENANT", "foreign-memory-tenant")
    else:
        body["bundles"][0]["body"]["episode"]["inputs"]["ref"] = "tampered"
    monkeypatch.setattr(recipe_lineage, "learn_memory_from_verified_bundles",
        lambda *a, **kw: pytest.fail("invalid source must be rejected before learning"))
    response = enabled.client.post(LEARN, json=body)
    assert response.status_code in {400, 403, 404, 409}, response.text
    assert len(enabled.calls) == 4


@pytest.mark.parametrize("patch", [{"actor": OWNER}, {"owner": OWNER}, {"tenant": TENANT}, {"trust": {}},
    {"max_operations": True}, {"max_operations": 3}, {"max_steps": 9}, {"max_steps": "8"},
    {"bundles": [{}]}, {"bundles": [{}] * 33}, {"allowed_tools": []}, {"domain": []}])
def test_memory_strict_request_rejects_authority_injection_and_coercions(enabled, patch):
    body = {"bundles": [{}, {}], "allowed_tools": [LOOKUP, CREATE], "domain": _domain(), **patch}
    response = enabled.client.post(LEARN, json=body)
    assert response.status_code == 422, response.text
    assert not enabled.calls


@pytest.mark.parametrize("body", [b'{"domain":{},"domain":{}}', b'{"domain":NaN}', b'[[[['])
def test_memory_rejects_duplicate_nonfinite_and_malformed_json(enabled, body):
    response = enabled.client.post(LEARN, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 422 and not enabled.calls


@pytest.mark.parametrize("streamed", [False, True])
def test_memory_request_size_is_bounded_before_synthesis(enabled, streamed):
    body = b" " * (2 * 1024 * 1024 + 1)
    response = enabled.client.post(LEARN, content=iter([body]) if streamed else body,
        headers={"Content-Type": "application/json"})
    assert response.status_code == 413 and not enabled.calls


@pytest.mark.parametrize("option", [["--max-operations", "0"], ["--max-operations", "3"],
    ["--max-steps", "0"], ["--max-steps", "9"], ["--operators", "add,,sub"]])
def test_memory_cli_rejects_invalid_options_without_output(tmp_path, option):
    empty, output = _write(tmp_path, "empty.json", {}), tmp_path / "not-created.json"
    result = _invoke("learn-memory-verified", "--bundles", empty, "--trust", empty, "--tenant", TENANT,
        "--allow-tool", LOOKUP, "--domain", empty, "--output", output, *option)
    assert result.exit_code != 0 and not output.exists()
