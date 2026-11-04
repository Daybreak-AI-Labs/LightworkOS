"""Offline CLI verifies actual native HTTP-exported bundles, not engine mocks.

The reusable API fixture stubs OIDC token verification; native crypto and tools
are real. File verification deliberately cannot inspect later service withdrawal.
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import time

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.flow.action_provenance import local_trust
from maverick.flow.recipe_lineage import validate_package
from maverick.paths import tenant_scope

from test_support.action_episode_api import (
    CREATE,
    LOOKUP,
    PRIVATE_REF,
    TENANT,
    _awaiting_review,
    _base,
    _review,
)
from test_support.action_episode_api import harness as harness


def write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


@pytest.fixture
def files(harness, tmp_path):
    harness.flags.update(action_recipe_lineage=True, require_action_recipe_lineage=False,
                         action_evidence_issuer="native-cli-test", action_evidence_revoked_keys=[])
    bundles = []
    for index in range(3):
        _source, run, record = _awaiting_review(harness, index=index, flow_id=f"cli-source-{index}")
        response = harness.client.post(_base(run) + "/review", json=_review(record))
        assert response.status_code == 200, response.text
        record = response.json()
        response = harness.client.post(_base(run) + "/training-grant", json={
            "expected_revision": record["revision"], "expected_episode_sha256": record["episode_sha256"],
            "use_until": record["retain_until"] - 1, "retain_derived_copies": True, "rationale": "CLI copy consent.",
        })
        assert response.status_code == 200, response.text
        record = response.json()
        response = harness.client.post(_base(run) + "/signed-export", json={
            "expected_revision": record["revision"], "expected_episode_sha256": record["episode_sha256"],
            "expected_grant_sha256": record["grant_sha256"],
        })
        assert response.status_code == 200, response.text
        bundles.append(response.json())
    with tenant_scope(tenant=TENANT):
        trust = local_trust(TENANT)
    return {"bundle": write(tmp_path, "bundle.json", bundles[0]),
            "bundles": write(tmp_path, "bundles.json", bundles[:2]),
            "more": write(tmp_path, "more.json", bundles[2:]),
            "trust": write(tmp_path, "trust.json", trust), "all": bundles}


def invoke(command, *options):
    return CliRunner().invoke(main, ["flow", "recipe", command, *map(str, options)])


def test_offline_verifier_reports_only_commitments_and_not_checked_live_status(files):
    result = invoke("verify-bundle", "--bundle", files["bundle"], "--trust", files["trust"], "--tenant", TENANT)
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["signature_status"] == "trusted" and report["commitments_status"] == "consistent"
    assert report["time_status"] == "valid" and report["live_status"] == "not_checked"
    assert PRIVATE_REF not in result.output and "body" not in report


def test_verified_learn_refine_and_inspection_draft_are_never_governed_admissions(files, tmp_path):
    package, refined, draft = [tmp_path / name for name in ("package.json", "refined.json", "draft.json")]
    result = invoke("learn-verified", "--bundles", files["bundles"], "--trust", files["trust"],
                    "--tenant", TENANT, "--allow-tool", LOOKUP, "--allow-tool", CREATE, "--output", package)
    assert result.exit_code == 0, result.output
    assert "Not governed-admitted" in result.output and "live status not checked" in result.output
    before = package.read_bytes()
    original = json.loads(before)
    result = invoke("refine-verified", "--package", package, "--bundles", files["more"],
                    "--trust", files["trust"], "--tenant", TENANT, "--output", refined)
    assert result.exit_code == 0, result.output
    updated = json.loads(refined.read_bytes())
    validate_package(updated, trust=json.loads(files["trust"].read_bytes()), expected_tenant=TENANT, now=time.time())
    assert updated["artifact"]["episode_count"] == 3 and len(updated["manifest"]) == 3
    assert updated["package_sha256"] != original["package_sha256"] and package.read_bytes() == before
    result = invoke("draft-verified", "--package", refined, "--trust", files["trust"], "--tenant", TENANT,
                    "--flow-id", "offline-inspection", "--name", "Inspection only", "--output", draft)
    assert result.exit_code == 0, result.output
    assert "no trusted governed lineage reference" in result.output
    flow = json.loads(draft.read_bytes())
    assert flow["learned_recipe"] == updated["artifact"] and "recipe_lineage" not in flow
    assert [node["kind"] for node in flow["nodes"]] == ["approval", "action", "approval", "action"]
    repeated = invoke("refine-verified", "--package", package, "--bundles", files["more"],
                      "--trust", files["trust"], "--tenant", TENANT, "--output", refined)
    assert repeated.exit_code != 0 and "already exists" in repeated.output


@pytest.mark.parametrize("fault", ["tenant", "untrusted_key", "revoked", "purpose", "tampered_review", "expired"])
def test_verifier_refuses_untrusted_or_tampered_evidence_without_raw_values(files, tmp_path, fault):
    bundle = copy.deepcopy(files["all"][0])
    trust = json.loads(files["trust"].read_bytes())
    tenant = TENANT
    if fault == "tenant":
        tenant = "other-tenant"
    elif fault == "untrusted_key":
        trust["keys"] = {}
    elif fault == "revoked":
        trust["revoked_keys"] = [bundle["signature"]["key_id"]]
    elif fault == "purpose":
        trust["purpose"] = "other_purpose"
    elif fault == "tampered_review":
        bundle["body"]["review"]["reviewer"] = "user:mallory"
    else:
        bundle["body"]["grant"]["use_until"] = 1
    path = write(tmp_path, "fault.json", bundle)
    trust_path = write(tmp_path, "fault-trust.json", trust)
    result = invoke("verify-bundle", "--bundle", path, "--trust", trust_path, "--tenant", tenant)
    assert result.exit_code != 0 and "verification refused" in result.output and PRIVATE_REF not in result.output


def test_verified_learning_rejects_unsigned_mixed_batches_without_partial_output(files, tmp_path):
    mixed = [files["all"][0], files["all"][1]["body"]["episode"]]
    source, output = write(tmp_path, "mixed.json", mixed), tmp_path / "must-not-exist.json"
    result = invoke("learn-verified", "--bundles", source, "--trust", files["trust"], "--tenant", TENANT,
                    "--allow-tool", LOOKUP, "--allow-tool", CREATE, "--output", output)
    assert result.exit_code != 0 and not output.exists()
    assert "learning refused" in result.output and PRIVATE_REF not in result.output


def test_verified_transformed_cli_keeps_domain_and_grammar_across_refinement(files, tmp_path):
    body = files["all"][0]["body"]
    contract = body["contract"]
    domain = copy.deepcopy({"inputs": contract["input_schema"], "steps": [
        contract["tool_data_schemas"][step["tool"]] for step in body["episode"]["steps"]]})
    # Spell out the learner's documented default so equality compares the
    # declared domain itself rather than incidental schema normalization.
    schemas = [domain["inputs"], *(schema for step in domain["steps"] for schema in step.values())]
    for schema in schemas:
        for field in schema["properties"].values():
            field.setdefault("minLength", 0)
    declared = write(tmp_path, "domain.json", domain)
    output, revised = tmp_path / "transformed.json", tmp_path / "transformed-refined.json"
    result = invoke("learn-verified", "--bundles", files["bundles"], "--trust", files["trust"], "--tenant", TENANT,
                    "--allow-tool", LOOKUP, "--allow-tool", CREATE, "--domain", declared,
                    "--max-operations", "1", "--operators", "strip", "--output", output)
    assert result.exit_code == 0, result.output
    package = json.loads(output.read_bytes())
    assert package["artifact"]["schema"] == "lightwork.action-recipe.v2"
    assert package["artifact"]["domain"] == domain
    assert package["artifact"]["grammar"]["operators"] == ["strip"]
    result = invoke("refine-verified", "--package", output, "--bundles", files["more"], "--trust", files["trust"],
                    "--tenant", TENANT, "--output", revised)
    assert result.exit_code == 0, result.output
    updated = json.loads(revised.read_bytes())
    assert updated["artifact"]["grammar"] == package["artifact"]["grammar"]
    validate_package(updated, trust=json.loads(files["trust"].read_bytes()), expected_tenant=TENANT, now=time.time())


@pytest.mark.parametrize("raw", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":' + '[' * 60 + '0' + ']' * 60 + '}'])
def test_lineage_file_parser_rejects_ambiguous_or_unbounded_json(tmp_path, raw):
    from maverick.cli._flow_recipe_groups import _read_lineage_json

    path = tmp_path / "malformed.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(Exception, match="bounded lineage JSON"):
        _read_lineage_json(path)


def test_lineage_file_limit_is_two_mib_and_does_not_silently_reuse_raw_artifact_limit(tmp_path):
    from maverick.cli._flow_recipe_groups import _read_lineage_json, _write_lineage_json
    from maverick.flow.recipe_lineage import MAX_PACKAGE_BYTES

    path = tmp_path / "bounded.json"
    value = {"long": "x" * 300_000}
    _write_lineage_json(path, value)
    assert _read_lineage_json(path) == value
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_PACKAGE_BYTES + 1))
    with pytest.raises(Exception, match="bounded lineage JSON"):
        _read_lineage_json(oversized)


def test_offline_verification_runs_in_a_fresh_cli_interpreter(files, tmp_path):
    result = subprocess.run([sys.executable, "-m", "maverick.cli", "--db", str(tmp_path / "cli.db"),
                             "flow", "recipe", "verify-bundle", "--bundle", str(files["bundle"]),
                             "--trust", str(files["trust"]), "--tenant", TENANT],
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["live_status"] == "not_checked"
    assert PRIVATE_REF not in result.stdout
    output = tmp_path / "subprocess-lineage.json"
    learned = subprocess.run([sys.executable, "-m", "maverick.cli", "--db", str(tmp_path / "learn.db"),
                              "flow", "recipe", "learn-verified", "--bundles", str(files["bundles"]),
                              "--trust", str(files["trust"]), "--tenant", TENANT,
                              "--allow-tool", LOOKUP, "--allow-tool", CREATE, "--output", str(output)],
                             capture_output=True, text=True, timeout=30, check=False)
    assert learned.returncode == 0, learned.stderr
    assert "Not governed-admitted" in learned.stdout and PRIVATE_REF not in learned.stdout
    package = json.loads(output.read_bytes())
    validate_package(package, trust=json.loads(files["trust"].read_bytes()), expected_tenant=TENANT, now=time.time())
    assert package["artifact"]["episode_count"] == 2
