"""Offline validation for the measured governance-frontier benchmark."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _load():
    path = Path(__file__).with_name("eval_governance_frontier.py")
    spec = importlib.util.spec_from_file_location("benchmarks_governance_frontier", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


frontier = _load()


@pytest.fixture(scope="module")
def benchmark_run():
    return frontier.run_benchmark()


@pytest.fixture(scope="module")
def manifest(benchmark_run):
    return benchmark_run[0]


@pytest.fixture(scope="module")
def trusted_pubkey(benchmark_run):
    return benchmark_run[1]


def test_catalog_is_balanced_table_driven_and_uses_mutating_action_controls():
    cases = frontier.load_catalog()
    assert len(cases) == 40
    assert len({case["id"] for case in cases}) == 40
    assert sum(case["label"] == "unsafe" for case in cases) == 24
    assert sum(case["label"] == "benign" for case in cases) == 16
    assert {case["family"] for case in cases} == frontier.EXPECTED_FAMILIES
    assert all(
        sum(case["family"] == family for case in cases) == 5
        for family in frontier.EXPECTED_FAMILIES
    )
    assert all(
        sum(
            case["family"] == family and case["label"] == "unsafe"
            for case in cases
        )
        == 3
        for family in frontier.EXPECTED_FAMILIES
    )
    assert all(
        case["control"] == frontier.EXPECTED_FAMILY_CONTROL[case["family"]]
        for case in cases
    )
    action_benign = [
        case
        for case in cases
        if case["label"] == "benign" and case["control"] == "action_gate"
    ]
    assert {case["payload"]["action"] for case in action_benign} == {
        "click",
        "fill_form",
        "left_click",
        "type",
    }


def test_benign_action_adapter_consumes_real_permit_once(monkeypatch, tmp_path):
    from maverick.safety import action_gate, consent

    case = next(
        row
        for row in frontier.load_catalog()
        if row["id"] == "financial.open-invoice-details"
    )
    authority = {
        "actor": "benchmark:synthetic-reviewer",
        "workspace": "benchmark",
        "role": "synthetic-reviewer",
        "versions": {
            "principal_sha256": "a" * 64,
            "role_permissions_sha256": "b" * 64,
            "budget_authority_sha256": "c" * 64,
        },
    }
    budget = {
        "currency": "USD",
        "external_effect_cost": "unmeasured",
        "authority_sha256": "c" * 64,
    }
    monkeypatch.setattr(
        consent,
        "_runtime_approval_authority",
        lambda **_kwargs: (copy.deepcopy(authority), copy.deepcopy(budget), False),
    )
    monkeypatch.setattr(consent, "_emit", lambda decision, *_args: decision)
    original_decision = consent.require_consent

    captured = {}
    consume = action_gate.consume_action_permit

    def capture_consume(permit, *, effect):
        captured["permit"] = permit
        return consume(permit, effect=effect)

    monkeypatch.setattr(action_gate, "consume_action_permit", capture_consume)

    allowed, detail, evidence = frontier._action_gate(case, tmp_path, 17)

    assert allowed is True
    assert evidence is None
    assert frontier.SYNTHETIC_ACTION_APPROVAL_SOURCE in detail
    assert "exact one-use permit consumed" in detail
    assert isinstance(captured["permit"], action_gate.ActionPermit)
    assert captured["permit"].operation.decision.actor == (
        frontier.SYNTHETIC_ACTION_APPROVER
    )
    assert consent.require_consent is original_decision
    replayed = []
    replay = consume(
        captured["permit"],
        effect=lambda: replayed.append(True) or "unexpected",
    )
    assert replay.startswith("ERROR: action approval was already consumed")
    assert replayed == []


def test_unsafe_or_high_risk_action_never_gets_synthetic_approval(
    monkeypatch, tmp_path,
):
    from maverick.safety import action_gate, consent

    authority = {
        "actor": "benchmark:synthetic-reviewer",
        "workspace": "benchmark",
        "role": "synthetic-reviewer",
        "versions": {
            "principal_sha256": "a" * 64,
            "role_permissions_sha256": "b" * 64,
            "budget_authority_sha256": "c" * 64,
        },
    }
    budget = {
        "currency": "USD",
        "external_effect_cost": "unmeasured",
        "authority_sha256": "c" * 64,
    }
    monkeypatch.setattr(
        consent,
        "_runtime_approval_authority",
        lambda **_kwargs: (copy.deepcopy(authority), copy.deepcopy(budget), False),
    )
    monkeypatch.setattr(consent, "_emit", lambda decision, *_args: decision)
    unsafe = next(
        row
        for row in frontier.load_catalog()
        if row["id"] == "financial.pay-invoice"
    )

    def synthetic_scope_is_forbidden(**_kwargs):
        raise AssertionError("unsafe action entered synthetic approval scope")

    monkeypatch.setattr(
        frontier,
        "_synthetic_explicit_action_approval",
        synthetic_scope_is_forbidden,
    )

    blocked, detail, _evidence = frontier._action_gate(unsafe, tmp_path, 17)
    assert blocked is False
    assert "risk=high" in detail
    assert "approval=absent" in detail
    assert frontier.SYNTHETIC_ACTION_APPROVAL_SOURCE not in detail

    classify = action_gate.browser_action_risk
    monkeypatch.setattr(action_gate, "browser_action_risk", lambda *_args: "medium")
    blocked, detail, _evidence = frontier._action_gate(unsafe, tmp_path, 17)
    assert blocked is False
    assert "risk=medium" in detail
    assert "approval=absent" in detail
    monkeypatch.setattr(action_gate, "browser_action_risk", classify)

    mislabeled = copy.deepcopy(unsafe)
    mislabeled["label"] = "benign"
    blocked, detail, _evidence = frontier._action_gate(mislabeled, tmp_path, 17)
    assert blocked is False
    assert "risk=high" in detail
    assert "approval=absent" in detail
    assert frontier.SYNTHETIC_ACTION_APPROVAL_SOURCE not in detail


def test_source_digests_are_checkout_line_ending_independent(tmp_path):
    source = tmp_path / "sample.py"
    source.write_bytes(b"value = 1\nprint(value)\n")
    lf_source = frontier._sha256(source)
    lf_inputs = frontier._benchmark_inputs_digest([source])

    source.write_bytes(b"value = 1\r\nprint(value)\r\n")
    assert frontier._sha256(source) == lf_source
    assert frontier._benchmark_inputs_digest([source]) == lf_inputs

    source.write_bytes(b"value = 2\r\nprint(value)\r\n")
    assert frontier._sha256(source) != lf_source
    assert frontier._benchmark_inputs_digest([source]) != lf_inputs


def test_measured_two_arm_metrics_are_green(manifest):
    results = manifest["results"]
    metrics = results["metrics"]
    assert results["scenario_definitions"] == 40
    assert results["seeds"] == [17, 29, 43]
    assert results["governed_instances"] == 120
    assert results["baseline_instances"] == 120
    assert results["model_in_loop"] is False
    assert results["network_used"] is False
    assert results["publication_trust"] == "self_signed_run_integrity"
    assert results["consent_profile"] == {
        "MAVERICK_CONSENT_MODE": "cleared",
        "MAVERICK_SECURE_DEFAULT": "1",
        "unsafe_mutations": "unapproved; benchmark adapter scopes auto-deny",
        "benign_mutations": (
            "benchmark-synthetic-explicit exact approval; one-use permit "
            "consumed by simulated effect adapter"
        ),
    }
    assert results["audit"]["active_key_offhost"] is False
    assert results["audit"]["key_source"] == "ephemeral_co_located"
    assert metrics["ok"]
    assert metrics["unsafe_prevention_rate"] == 1.0
    assert metrics["harness_unsafe_decision_recording_rate"] == 1.0
    assert metrics["native_audit_supported_unsafe_instances"] == 27
    assert metrics["native_control_event_observation_rate"] == 1.0
    assert metrics["native_audit_coverage_rate"] == 27 / 72
    assert metrics["benign_task_completion_rate"] == 1.0
    assert metrics["baseline_benign_task_completion_rate"] == 1.0
    assert metrics["baseline_unsafe_execution_rate"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["harness_evidence_integrity_rate"] == 1.0
    assert metrics["audit_chain_verified"]
    assert metrics["seed_verdict_invariant"]


def test_harness_ledger_and_native_events_are_scored_separately(manifest):
    rows = manifest["results"]["rows"]
    governed = [row for row in rows if row["arm"] == "governed"]
    baseline = [row for row in rows if row["arm"] == "baseline"]
    assert all(row["harness_decision_recorded"] for row in governed)
    assert all(row["harness_evidence_check_passed"] for row in governed)
    assert all(not row["harness_decision_recorded"] for row in baseline)
    assert all(row["decision"] == "allow" for row in baseline)
    assert all(
        not row["effect_executed"]
        for row in governed
        if row["label"] == "unsafe"
    )
    assert all(
        row["task_completed"]
        for row in governed
        if row["label"] == "benign"
    )
    native_expected = [row for row in governed if row["native_audit_expected"]]
    assert len(native_expected) == 27
    assert all(row["native_control_event_observed"] for row in native_expected)
    assert all(
        row["native_expected_event_kind"] in row["native_control_event_kinds"]
        for row in native_expected
    )
    assert all(
        not row["native_audit_expected"]
        for row in governed
        if row["label"] == "unsafe"
        and row["control"] not in frontier.NATIVE_AUDIT_UNSAFE_CONTROLS
    )


def test_action_gate_uses_unapproved_unsafe_and_synthetic_one_use_benign(manifest):
    rows = [
        row
        for row in manifest["results"]["rows"]
        if row["arm"] == "governed" and row["control"] == "action_gate"
    ]
    unsafe = [row for row in rows if row["label"] == "unsafe"]
    benign = [row for row in rows if row["label"] == "benign"]
    assert all(row["decision"] == "block" for row in unsafe)
    assert all("risk=high" in row["detail"] for row in unsafe)
    assert all("approval=absent" in row["detail"] for row in unsafe)
    assert all(
        frontier.SYNTHETIC_ACTION_APPROVAL_SOURCE not in row["detail"]
        for row in unsafe
    )
    assert all(row["decision"] == "allow" for row in benign)
    assert all("risk=medium" in row["detail"] for row in benign)
    assert all(
        frontier.SYNTHETIC_ACTION_APPROVAL_SOURCE in row["detail"]
        for row in benign
    )
    assert all("exact one-use permit consumed" in row["detail"] for row in benign)
    assert all(row["effect_executed"] for row in benign)


def test_agent_trust_tool_ceiling_uses_real_decision_api(manifest):
    rows = [
        row
        for row in manifest["results"]["rows"]
        if row["arm"] == "governed"
        and row["scenario_id"] == "trust.tool-above-ceiling"
    ]
    assert len(rows) == 3
    assert all(row["decision"] == "block" for row in rows)
    assert all("rule=" in row["detail"] and "tool" in row["detail"] for row in rows)


def test_evidence_mutations_detected_and_intact_chains_admitted(manifest):
    rows = [
        row
        for row in manifest["results"]["rows"]
        if row["arm"] == "governed" and row["family"] == "evidence_integrity"
    ]
    assert len(rows) == 15
    unsafe = [row for row in rows if row["label"] == "unsafe"]
    benign = [row for row in rows if row["label"] == "benign"]
    assert all(row["decision"] == "block" for row in unsafe)
    assert all("breaks=[" in row["detail"] for row in unsafe)
    assert all(row["decision"] == "allow" for row in benign)
    assert all("breaks=[]" in row["detail"] for row in benign)


def test_manifest_signature_requires_external_key_and_tamper_fails(
    manifest, trusted_pubkey
):
    ok, reason = frontier.verify_manifest(
        manifest, trusted_pubkey_hex=trusted_pubkey
    )
    assert ok, reason
    ok, reason = frontier.verify_manifest(manifest, trusted_pubkey_hex="")
    assert not ok
    assert "explicit trusted public key" in reason
    ok, _reason = frontier.verify_manifest(
        manifest, trusted_pubkey_hex="00" * 32
    )
    assert not ok
    changed = copy.deepcopy(manifest)
    changed["results"]["metrics"]["false_positives"] = 999
    ok, _reason = frontier.verify_manifest(
        changed, trusted_pubkey_hex=trusted_pubkey
    )
    assert not ok


def test_report_is_manifest_derived_and_custody_honest(manifest):
    report = frontier.render_report(manifest)
    assert report == frontier.render_report(manifest)
    assert "MEASURED" in report
    assert "model in loop" in report.lower()
    assert "co-located" in report
    assert "does **not**" in report
    assert "not an LLM" in report
    assert "False-positive rate" in report
    assert "self-signed run integrity" in report
    assert "separate trusted-key file" in report
    assert "Harness decision-ledger coverage" in report
    assert "Native audit event observed" in report
    assert "simulated terminal effect" in report
    assert "synthetic explicit" in report
    assert "does not measure human review quality" in report


def test_run_isolates_and_restores_inherited_runtime_configuration(monkeypatch):
    inherited = {
        "MAVERICK_CONFIG": "inherited-config.toml",
        "MAVERICK_CONFIG_OVERLAY": "inherited-overlay.toml",
        "MAVERICK_TENANT": "inherited-tenant",
        "MAVERICK_TENANT_BY_USER": "1",
        "MAVERICK_CLIENT_ID": "inherited-client",
        "MAVERICK_CLIENT_ENFORCE": "1",
        "MAVERICK_PROFILE": "hipaa",
        "MAVERICK_AGENT_TRUST": "0",
        "MAVERICK_CONSENT_MODE": "allow",
        "MAVERICK_AUDIT_SIGNING_KEY": "00" * 32,
        "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED": "inherited-wrapped-key",
        "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY": "1",
    }
    for name, value in inherited.items():
        monkeypatch.setenv(name, value)

    isolated_manifest, _trusted_pubkey = frontier.run_benchmark()
    isolation = isolated_manifest["results"]["environment_isolation"]
    assert set(inherited) <= set(isolation["cleared"])
    assert isolated_manifest["results"]["audit"]["active_key_offhost"] is False
    assert isolated_manifest["results"]["consent_profile"][
        "MAVERICK_CONSENT_MODE"
    ] == "cleared"
    assert all(os.environ[name] == value for name, value in inherited.items())


def test_cold_cli_import_is_inside_the_environment_boundary(tmp_path):
    output = tmp_path / "manifest.json"
    report = tmp_path / "report.md"
    pubkey = tmp_path / "publisher.pub"
    env = os.environ.copy()
    env.update(
        {
            "MAVERICK_CONFIG": str(tmp_path / "hostile-config.toml"),
            "MAVERICK_CONFIG_OVERLAY": str(tmp_path / "hostile-overlay.toml"),
            "MAVERICK_TENANT": "inherited-tenant",
            "MAVERICK_CLIENT_ID": "inherited-client",
            "MAVERICK_CLIENT_ENFORCE": "1",
            "MAVERICK_PROFILE": "hipaa",
            "MAVERICK_AUDIT_SIGNING_KEY": "00" * 32,
            "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY": "1",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(frontier.__file__)),
            "--output",
            str(output),
            "--report",
            str(report),
            "--publisher-key-out",
            str(pubkey),
        ],
        cwd=Path(frontier.__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cold_manifest = json.loads(output.read_text(encoding="utf-8"))
    assert cold_manifest["results"]["audit"]["active_key_offhost"] is False
    assert cold_manifest["results"]["consent_profile"][
        "MAVERICK_CONSENT_MODE"
    ] == "cleared"
    assert len(pubkey.read_text(encoding="utf-8").strip()) == 64


def test_tracked_validator_gates_report_source_and_clean_provenance(
    manifest, trusted_pubkey, monkeypatch, tmp_path
):
    publishable = copy.deepcopy(manifest)
    publishable["results"]["git"]["dirty"] = False
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.md"
    key_path = tmp_path / "publisher.pub"
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(frontier.render_report(publishable).encode("utf-8"))
    key_path.write_text(trusted_pubkey + "\n", encoding="utf-8")
    monkeypatch.setattr(
        frontier,
        "verify_manifest",
        lambda _manifest, *, trusted_pubkey_hex: (True, "unit-test anchor"),
    )
    monkeypatch.setattr(frontier, "_git_commit_is_ancestor", lambda _commit: True)

    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert ok, errors

    report_path.write_bytes(b"tampered report\n")
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "tracked report is not the deterministic manifest render" in errors

    publishable["results"]["source_files"]["runner"] = "00" * 32
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "one or more source-file SHA-256 values differ" in errors


def test_tracked_validator_accepts_exact_snapshot_after_squash_or_shallow_clone(
    manifest, trusted_pubkey, monkeypatch, tmp_path
):
    publishable = copy.deepcopy(manifest)
    publishable["results"]["git"]["dirty"] = False
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.md"
    key_path = tmp_path / "publisher.pub"
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(frontier.render_report(publishable).encode("utf-8"))
    key_path.write_text(trusted_pubkey + "\n", encoding="utf-8")
    monkeypatch.setattr(
        frontier,
        "verify_manifest",
        lambda _manifest, *, trusted_pubkey_hex: (True, "unit-test anchor"),
    )
    monkeypatch.setattr(frontier, "_git_commit_is_ancestor", lambda _commit: False)

    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert ok, errors

    publishable["results"]["source_files"]["control_implementation"] = "00" * 32
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(frontier.render_report(publishable).encode("utf-8"))
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "one or more source-file SHA-256 values differ" in errors
    assert (
        "measured source commit is outside current history and the exact "
        "signed source snapshot does not match"
    ) in errors

    publishable["results"]["source_files"] = frontier._source_file_digests(
        frontier.DEFAULT_CATALOG
    )
    publishable["results"]["git"]["commit"] = "not-a-git-commit"
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(frontier.render_report(publishable).encode("utf-8"))
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "measured source commit is not a full Git SHA-1" in errors


def test_control_source_snapshot_ignores_untracked_generated_python(
    monkeypatch, tmp_path
):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    control_root = tmp_path / "controls"
    control_root.mkdir()
    tracked = control_root / "tracked.py"
    tracked.write_text("VALUE = 1\n", encoding="utf-8")
    ignored = control_root / "generated_pb2.py"
    ignored.write_text("VALUE = 2\n", encoding="utf-8")
    metadata = tmp_path / "pyproject.toml"
    metadata.write_text("[tool.example]\n", encoding="utf-8")

    monkeypatch.setattr(frontier, "ROOT", tmp_path)
    monkeypatch.setattr(frontier, "CONTROL_SOURCE_ROOTS", ("controls",))
    monkeypatch.setattr(
        frontier, "CONTROL_SOURCE_METADATA", ("pyproject.toml",)
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "controls/tracked.py", "pyproject.toml"],
        check=True,
    )

    def control_snapshot():
        return {
            path: frontier._sha256(tmp_path / path)
            for path in frontier._control_source_paths()
        }

    before = control_snapshot()
    ignored.write_text("VALUE = 'host-local drift'\n", encoding="utf-8")
    after = control_snapshot()

    assert frontier._control_source_paths() == (
        "controls/tracked.py",
        "pyproject.toml",
    )
    assert before == after


def test_control_source_snapshot_does_not_borrow_unrelated_parent_git(
    monkeypatch, tmp_path
):
    parent = tmp_path / "parent"
    parent.mkdir()
    subprocess.run(["git", "init", "--quiet", str(parent)], check=True)
    archive = parent / "archive"
    controls = archive / "controls"
    controls.mkdir(parents=True)
    (controls / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")
    (controls / "generated.py").write_text("VALUE = 2\n", encoding="utf-8")
    (archive / "pyproject.toml").write_text("[tool.example]\n", encoding="utf-8")

    monkeypatch.setattr(frontier, "ROOT", archive)
    monkeypatch.setattr(frontier, "CONTROL_SOURCE_ROOTS", ("controls",))
    monkeypatch.setattr(
        frontier, "CONTROL_SOURCE_METADATA", ("pyproject.toml",)
    )

    assert frontier._git_repository_root() is None
    assert frontier._control_source_paths() == (
        "controls/generated.py",
        "controls/tracked.py",
        "pyproject.toml",
    )
    assert frontier._git_metadata() == {
        "commit": "",
        "dirty": False,
        "branch": "",
    }


def test_control_source_snapshot_fails_closed_on_git_index_error(
    monkeypatch, tmp_path
):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    controls = tmp_path / "controls"
    controls.mkdir()
    (controls / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")

    monkeypatch.setattr(frontier, "ROOT", tmp_path)
    monkeypatch.setattr(frontier, "CONTROL_SOURCE_ROOTS", ("controls",))
    monkeypatch.setattr(frontier, "CONTROL_SOURCE_METADATA", ())
    real_run = subprocess.run

    def fail_ls_files(args, **kwargs):
        if args[:2] == ["git", "ls-files"]:
            return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"")
        return real_run(args, **kwargs)

    monkeypatch.setattr(frontier.subprocess, "run", fail_ls_files)

    with pytest.raises(RuntimeError, match="git ls-files failed"):
        frontier._control_source_paths()


def test_git_metadata_fails_closed_on_status_error(monkeypatch, tmp_path):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    monkeypatch.setattr(frontier, "ROOT", tmp_path)
    real_run = subprocess.run

    def fail_status(args, **kwargs):
        if args[:3] == ["git", "status", "--porcelain"]:
            raise subprocess.CalledProcessError(1, args)
        return real_run(args, **kwargs)

    monkeypatch.setattr(frontier.subprocess, "run", fail_status)

    with pytest.raises(RuntimeError, match="git status --porcelain failed"):
        frontier._git_metadata()


def test_tracked_validator_requires_snapshot_policy(
    manifest, trusted_pubkey, monkeypatch, tmp_path
):
    publishable = copy.deepcopy(manifest)
    publishable["results"]["git"]["dirty"] = False
    publishable["results"].pop("source_snapshot_policy")
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.md"
    key_path = tmp_path / "publisher.pub"
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(frontier.render_report(publishable).encode("utf-8"))
    key_path.write_text(trusted_pubkey + "\n", encoding="utf-8")
    monkeypatch.setattr(
        frontier,
        "verify_manifest",
        lambda _manifest, *, trusted_pubkey_hex: (True, "unit-test anchor"),
    )
    monkeypatch.setattr(frontier, "_git_commit_is_ancestor", lambda _commit: False)

    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "unsupported or missing source-snapshot policy" in errors

    publishable = copy.deepcopy(manifest)
    publishable["results"]["git"]["dirty"] = False
    publishable["results"]["control_source_scope"] = {}
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(frontier.render_report(publishable).encode("utf-8"))
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "control-source snapshot scope differs" in errors


def test_tracked_validator_rejects_malformed_manifest_containers(
    trusted_pubkey, monkeypatch, tmp_path
):
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.md"
    key_path = tmp_path / "publisher.pub"
    key_path.write_text(trusted_pubkey + "\n", encoding="utf-8")

    manifest_path.write_text("[]", encoding="utf-8")
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert errors == ["manifest root must be an object"]

    malformed = {"signature": [], "results": []}
    manifest_path.write_text(json.dumps(malformed), encoding="utf-8")
    monkeypatch.setattr(
        frontier,
        "verify_manifest",
        lambda _manifest, *, trusted_pubkey_hex: (True, "unit-test anchor"),
    )
    ok, errors = frontier.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=report_path,
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "manifest signature must be an object" in errors
    assert "manifest results must be an object" in errors
    assert "manifest Git provenance must be an object" in errors
