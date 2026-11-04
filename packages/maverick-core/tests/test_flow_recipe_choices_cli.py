"""Choice CLI uses the actual learner and separately captured native teachers.

OIDC verification is stubbed by the API fixture. Native approvals, tool calls,
capture, encryption, signatures and reviewed-bundle import remain real.
"""
from __future__ import annotations

import copy
import importlib
import json
import subprocess
import sys
import time

import pytest
from click.testing import CliRunner
from maverick import tools
from maverick.cli import main
from maverick.flow import Flow, FlowNode, action_recipe, execution, store
from maverick.paths import tenant_scope

from test_support.action_episode_api import OWNER, TENANT, _base, _object, _resume, _review
from test_support.action_episode_api import harness as harness

PREFIX, APPROVE, REVIEW = "choice_open_case", "choice_approve_case", "choice_queue_review"
ALLOWED = [PREFIX, APPROVE, REVIEW]


def _integer():
    return {"type": "integer", "minimum": 0, "maximum": 20}


def _string():
    return {"type": "string", "minLength": 0, "maxLength": 64}


def domain():
    branch = {"arguments": _object(case_id=_string()), "result": _object(status=_string())}
    return {"inputs": _object(amount=_integer(), limit=_integer(), legacy_ok={"type": "boolean"}),
            "prefix": {"arguments": _object(amount=_integer()), "result": _object(case_id=_string())},
            "branches": {APPROVE: copy.deepcopy(branch), REVIEW: copy.deepcopy(branch)}}


def episode(index, amount, limit, legacy_ok, *, approved):
    case_id = f"fresh-case-{index}"
    return {"id": f"teacher-{index}", "inputs": {"amount": amount, "limit": limit, "legacy_ok": legacy_ok},
            "steps": [{"tool": PREFIX, "arguments": {"amount": amount}, "result": {"case_id": case_id}},
                      {"tool": APPROVE if approved else REVIEW, "arguments": {"case_id": case_id},
                       "result": {"status": "approved" if approved else "review"}}]}


def examples():
    return [episode(0, 1, 3, True, approved=True), episode(1, 2, 4, True, approved=True),
            episode(2, 5, 3, False, approved=False), episode(3, 6, 4, False, approved=False)]


def write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def invoke(command, *options):
    return CliRunner().invoke(main, ["flow", "recipe", command, *map(str, options)])


def raw_options(tmp_path):
    data = write(tmp_path, "episodes.json", examples())
    declared = write(tmp_path, "domain.json", domain())
    output = tmp_path / "choice.json"
    options = ["--episodes", data, "--output", output]
    for tool in ALLOWED:
        options.extend(["--allow-tool", tool])
    return options, declared, output


def test_raw_choice_cli_retains_complete_artifact_refinement_and_exact_generated_graph(tmp_path):
    options, declared, output = raw_options(tmp_path)
    result = invoke("learn", *options, "--choices", "--domain", declared, "--reviewed",
                    "--max-operations", "1", "--operators", "lt,le,not")
    assert result.exit_code == 0, result.output
    assert "one shared action" in result.output and "two terminal actions" in result.output
    assert "does not authenticate" in result.output
    before = output.read_bytes()
    artifact = json.loads(before)
    assert artifact["schema"] == "lightwork.action-choice.v1"
    action_recipe.validate_artifact(artifact)
    assert len(artifact["steps"]) == 1 and len(artifact["branches"]) == 2
    extra = write(tmp_path, "extra.json", [episode(4, 1, 5, False, approved=True)])
    refined, draft = tmp_path / "refined.json", tmp_path / "draft.json"
    result = invoke("refine", "--artifact", output, "--episodes", extra, "--reviewed", "--output", refined)
    assert result.exit_code == 0, result.output
    updated = json.loads(refined.read_bytes())
    action_recipe.validate_artifact(updated)
    assert updated["episode_count"] == 5 and output.read_bytes() == before
    assert updated["artifact_sha256"] != artifact["artifact_sha256"]
    result = invoke("draft", "--artifact", refined, "--flow-id", "choice-draft", "--name", "Choice draft", "--output", draft)
    assert result.exit_code == 0, result.output
    graph = Flow.from_dict(json.loads(draft.read_bytes()))
    assert graph.learned_recipe == updated and graph.start == "approval_0"
    nodes = list(graph.nodes.values())
    assert sum(node.kind == "approval" for node in nodes) == 3
    assert sum(node.kind == "action" for node in nodes) == 3
    assert sum(node.kind == "switch" for node in nodes) == 1
    assert "Not saved, published or executed" in result.output
    repeated = invoke("learn", *options, "--choices", "--domain", declared, "--reviewed",
                      "--max-operations", "1", "--operators", "lt,le,not")
    assert repeated.exit_code != 0 and "already exists" in repeated.output and output.read_bytes() == before


@pytest.mark.parametrize("mode", ["missing_review", "missing_domain", "both_modes", "raw_domain_only"])
def test_choice_options_require_explicit_mode_domain_and_review(tmp_path, mode):
    options, declared, output = raw_options(tmp_path)
    selected = {"missing_review": ["--choices", "--domain", declared],
                "missing_domain": ["--choices", "--reviewed"],
                "both_modes": ["--choices", "--transforms", "--domain", declared, "--reviewed"],
                "raw_domain_only": ["--domain", declared, "--reviewed"]}[mode]
    result = invoke("learn", *options, *selected)
    assert result.exit_code != 0 and not output.exists()
    assert {"missing_review": "--reviewed", "missing_domain": "--domain",
            "both_modes": "mutually exclusive", "raw_domain_only": "--transforms or --choices"}[mode] in result.output


@pytest.mark.parametrize("options", [["--operators", "lt,lt"], ["--operators", ""],
                                     ["--operators", "unknown"], ["--max-operations", "0"],
                                     ["--max-operations", "5"]])
def test_choice_cli_rejects_bad_grammar_without_partial_artifact(tmp_path, options):
    base, declared, output = raw_options(tmp_path)
    result = invoke("learn", *base, "--choices", "--domain", declared, "--reviewed", *options)
    assert result.exit_code != 0 and not output.exists()


@pytest.mark.parametrize("fault", ["missing_branch", "too_few_examples", "supplied_guard", "third_terminal"])
def test_choice_cli_rejects_unsupported_or_underobserved_topology(tmp_path, fault):
    base, declared, output = raw_options(tmp_path)
    data, schema = examples(), domain()
    if fault == "missing_branch":
        schema["branches"].pop(REVIEW)
    elif fault == "too_few_examples":
        data.pop()
    elif fault == "supplied_guard":
        schema["guard"] = {"field": "legacy_ok"}
    else:
        data[-1]["steps"][1]["tool"] = "unseen_terminal"
    write(tmp_path, "episodes.json", data)
    write(tmp_path, "domain.json", schema)
    result = invoke("learn", *base, "--choices", "--domain", declared, "--reviewed")
    assert result.exit_code != 0 and not output.exists()


def test_verified_choices_requires_domain_before_reading_raw_evidence(tmp_path):
    bundles = write(tmp_path, "bundles.json", [])
    trust = write(tmp_path, "trust.json", {})
    output = tmp_path / "none.json"
    result = invoke("learn-verified", "--bundles", bundles, "--trust", trust, "--tenant", TENANT,
                    "--allow-tool", PREFIX, "--choices", "--output", output)
    assert result.exit_code != 0 and "--choices requires --domain" in result.output and not output.exists()


@pytest.fixture
def signed_teachers(harness, tmp_path):
    """Each teacher is an ordinary two-action Flow, never a captured branch."""
    from maverick.flow.action_provenance import local_trust

    harness.flags.update(action_recipe_lineage=True, require_action_recipe_lineage=False,
                         action_evidence_issuer="choice-cli-native", action_evidence_revoked_keys=[])
    risk = importlib.import_module("maverick.safety.tool_risk")
    harness.monkeypatch.setattr(risk, "_load_overrides", lambda: dict.fromkeys(ALLOWED, "high"))
    registry = tools.ToolRegistry(principal=OWNER)
    calls = []

    def perform(tool, arguments):
        calls.append((tool, copy.deepcopy(arguments)))
        result = ({"case_id": f"native-fresh-{len(calls)}"} if tool == PREFIX
                  else {"status": "approved" if tool == APPROVE else "review"})
        return json.dumps(result)

    for tool in ALLOWED:
        registry.register(tools.Tool(name=tool, description="Local captured choice teacher",
                                    input_schema={"type": "object"}, fn=lambda args, tool=tool: perform(tool, args)))
    harness.monkeypatch.setattr(tools, "base_registry", lambda *a, **kw: registry)
    harness.native = execution.default_action_runner(None, user_id=OWNER)
    samples = [*examples(), episode(4, 1, 5, False, approved=True)]
    bundles, source_nodes = [], []
    for index, sample in enumerate(samples):
        terminal = sample["steps"][1]["tool"]
        source = Flow(id=f"choice-teacher-{index}", name="Reviewed straight-line teacher", owner=OWNER,
                      start="initial", nodes={
            "initial": FlowNode(id="initial", kind="approval", prompt="Review case creation", next="open"),
            "open": FlowNode(id="open", kind="action", tool=PREFIX, params={"amount": sample["inputs"]["amount"]},
                             output="opened", next="terminal_review"),
            "terminal_review": FlowNode(id="terminal_review", kind="approval", prompt="Review chosen follow-up", next="terminal"),
            "terminal": FlowNode(id="terminal", kind="action", tool=terminal,
                                 params={"case_id": '{{regex(opened, "native-fresh-[0-9]+")}}'}, output="done"),
        })
        source_nodes.append([node.kind for node in source.nodes.values()])
        with tenant_scope(tenant=TENANT):
            source = store.save_flow(source)
            run = execution.execute(source, owner=OWNER, data={"input": sample["inputs"]},
                                    action_runner=harness.native, agent_runner=lambda *a, **kw: pytest.fail("agent"))
        assert run.status == "paused_approval", run.error
        prepared = harness.client.get(_base(run) + "/enrollment")
        assert prepared.status_code == 200, prepared.text
        schema = domain()
        enrollment = {"expected_pause_binding": prepared.json()["expected_pause_binding"],
                      "allowed_tools": [PREFIX, terminal], "input_schema": schema["inputs"],
                      "tool_data_schemas": {PREFIX: schema["prefix"], terminal: schema["branches"][terminal]},
                      "retain_until": time.time() + 3600}
        response = harness.client.post(_base(run), json=enrollment)
        assert response.status_code == 200, response.text
        middle = _resume(harness, source, run)
        assert middle.status == "paused_approval", middle.error
        paused = harness.client.get(_base(run))
        assert paused.status_code == 200 and paused.json()["status"] == "paused", paused.text
        completed = _resume(harness, source, middle)
        assert completed.status == "completed", completed.error
        captured = harness.client.get(_base(run))
        assert captured.status_code == 200 and captured.json()["status"] == "awaiting_review", captured.text
        record = captured.json()
        response = harness.client.post(_base(run) + "/review", json=_review(record))
        assert response.status_code == 200, response.text
        record = response.json()
        response = harness.client.post(_base(run) + "/training-grant", json={
            "expected_revision": record["revision"], "expected_episode_sha256": record["episode_sha256"],
            "use_until": record["retain_until"] - 1, "retain_derived_copies": True, "rationale": "Choice example copy grant.",
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
    assert source_nodes == [["approval", "action", "approval", "action"]] * 5
    assert len(calls) == 10
    assert [arguments["case_id"] for tool, arguments in calls if tool != PREFIX] == [
        f"native-fresh-{index}" for index in (1, 3, 5, 7, 9)]
    return {"bundles": write(tmp_path, "signed.json", bundles[:4]),
            "more": write(tmp_path, "extra-signed.json", bundles[4:]), "all": bundles,
            "trust": write(tmp_path, "trust.json", trust), "domain": write(tmp_path, "declared.json", domain())}


def test_http_signed_choice_teachers_cli_learn_refine_and_governed_draft(signed_teachers, harness, tmp_path):
    from maverick.flow.recipe_lineage import validate_package

    source = signed_teachers
    package, refined, inspection = [tmp_path / name for name in ("package.json", "refined.json", "inspection.json")]
    options = ["--bundles", source["bundles"], "--trust", source["trust"], "--tenant", TENANT,
               "--choices", "--domain", source["domain"], "--max-operations", "1", "--operators", "lt,le,not",
               "--output", package]
    for tool in ALLOWED:
        options.extend(["--allow-tool", tool])
    result = invoke("learn-verified", *options)
    assert result.exit_code == 0, result.output
    assert "Not governed-admitted" in result.output and "live status not checked" in result.output
    value = json.loads(package.read_bytes())
    assert value["artifact"]["schema"] == "lightwork.action-choice.v1" and len(value["manifest"]) == 4
    result = invoke("refine-verified", "--package", package, "--bundles", source["more"],
                    "--trust", source["trust"], "--tenant", TENANT, "--output", refined)
    assert result.exit_code == 0, result.output
    updated = json.loads(refined.read_bytes())
    validate_package(updated, trust=json.loads(source["trust"].read_bytes()), expected_tenant=TENANT, now=time.time())
    assert len(updated["manifest"]) == 5 and updated["artifact"]["episode_count"] == 5
    result = invoke("draft-verified", "--package", refined, "--trust", source["trust"], "--tenant", TENANT,
                    "--flow-id", "choice-inspection", "--name", "Choice inspection", "--output", inspection)
    assert result.exit_code == 0, result.output
    assert "recipe_lineage" not in json.loads(inspection.read_bytes())
    admitted = harness.client.post("/api/v1/flows/recipe-lineage", json={"package": updated})
    assert admitted.status_code == 200, admitted.text
    drafted = harness.client.post("/api/v1/flows/recipe-lineage/" + admitted.json()["id"] + "/draft",
                                  json={"flow_id": "governed-choice", "name": "Governed choice"})
    assert drafted.status_code == 200, drafted.text
    assert drafted.json()["learned_recipe"] == updated["artifact"]
    assert drafted.json()["recipe_lineage"] == admitted.json()["reference"]
    subprocess_output = tmp_path / "fresh-process.json"
    command = [sys.executable, "-m", "maverick.cli", "--db", str(tmp_path / "subprocess.db"),
               "flow", "recipe", "learn-verified", *map(str, options)]
    command[command.index(str(package))] = str(subprocess_output)
    process = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert process.returncode == 0, process.stderr
    assert "Not governed-admitted" in process.stdout
    assert json.loads(subprocess_output.read_bytes())["package_sha256"] == value["package_sha256"]
