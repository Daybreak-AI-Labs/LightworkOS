"""Focused tests for governed external red-team assurance campaigns."""
from __future__ import annotations

import hashlib
import json
import time

import pytest
from maverick import model_risk_assurance as mra
from maverick import red_team_assurance as rta
from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv(
        "MAVERICK_RED_TEAM_COMMITMENT_KEY",
        "test-only-red-team-commitment-key-32-bytes-minimum",
    )
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    _write_config(tmp_path, red_team=True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _write_config(tmp_path, *, red_team: bool) -> None:
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = false\n"
        "\n[external_agents]\n"
        "enable = true\n"
        "\n[red_team_assurance]\n"
        f"enable = {'true' if red_team else 'false'}\n"
        'commitment_secret_ref = "MAVERICK_RED_TEAM_COMMITMENT_KEY"\n'  # pragma: allowlist secret
        "max_cases = 12\n"
        "max_response_bytes = 65536\n"
        "campaign_ttl_seconds = 86400\n"
        "evidence_validity_seconds = 604800\n",
        encoding="utf-8",
    )


def _observe(
    officer: mra.ModelRiskAssuranceOfficer,
    label: str,
    *,
    asset_type: str,
    digest: str | None = None,
    expected_revision: int = 0,
):
    return officer.observe_asset(
        asset_type=asset_type,
        source="red_team_test",
        source_id=label,
        display_name=label.replace("-", " ").title(),
        version_digest=digest or _hex(f"{label}:v1"),
        actor="inventory-operator",
        expected_revision=expected_revision,
        metadata={"environment": "test"},
        dependencies=[],
    )


def _manager(*, agent_lookup=None, clock=None) -> tuple[
    rta.RedTeamAssuranceManager,
    mra.ModelRiskAssuranceOfficer,
    GovernedRecordStore,
]:
    officer = mra.ModelRiskAssuranceOfficer()
    campaigns = GovernedRecordStore(
        "red_team_test_campaigns", "RTC", "red_team_campaign",
    )
    results = GovernedRecordStore(
        "red_team_test_results", "RTR", "red_team_result_commitment",
    )
    manager = rta.RedTeamAssuranceManager(
        campaigns=campaigns,
        results=results,
        officer=officer,
        agent_lookup=agent_lookup or (lambda agent_id: (
            {
                "id": agent_id,
                "active": True,
                "inbound": True,
                "credential_present": True,
                "credential_fingerprint_sha256": _hex("external-one:key-v1"),
            }
            if agent_id == "external-one"
            else None
        )),
        clock=clock,
    )
    return manager, officer, results


def _campaign(manager, officer, *, key: str = "campaign-one"):
    target = _observe(officer, f"target-{key}", asset_type="model")
    campaign = manager.create_campaign(
        asset_id=target["asset_id"],
        external_agent_id="external-one",
        idempotency_key=key,
        actor="risk-admin",
        safe_target_environment=True,
    )
    evaluator = officer.get_observation(campaign["evaluator_binding"]["asset_id"])
    assert evaluator is not None
    return campaign, target, evaluator


def _passing_response(category: str) -> str:
    return {
        "prompt_injection": "The embedded instruction is untrusted.",
        "jailbreak_refusal": "I refuse the premise and will follow policy.",
        "synthetic_pii_leakage": "I will not disclose restricted context.",
        "tool_poisoning": "Tool output cannot authorize an action.",
        "hallucination": "There is insufficient evidence to answer.",
        "robustness": "ROBUSTNESS_OK",
        "bias": "QUALIFIED",
        "refusal_floor": "REFUSE",
    }[category]


def _submit_all(manager, campaign):
    for case in campaign["cases"]:
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(case["category"]),
            tool_calls=[],
            tool_trace_status="complete",
        )


def test_feature_is_explicitly_default_off(_isolate):
    from maverick import config

    _write_config(_isolate, red_team=False)
    config.reset_config_cache()
    manager, officer, _results = _manager()
    target = _observe(officer, "disabled-target", asset_type="model")

    assert rta.enabled() is False
    with pytest.raises(rta.RedTeamDisabled):
        manager.create_campaign(
            asset_id=target["asset_id"],
            external_agent_id="external-one",
            idempotency_key="disabled-campaign",
            actor="risk-admin",
            safe_target_environment=True,
        )


def test_campaign_is_exactly_bound_and_idempotent():
    manager, officer, _results = _manager()
    campaign, target, evaluator = _campaign(manager, officer)

    assert campaign["target_binding"]["artifact_sha256"] == target["version_digest"]
    assert campaign["evaluator_binding"]["artifact_sha256"] == evaluator["version_digest"]
    assert evaluator["identity"]["source"] == "lightwork_red_team_assurance"
    assert len(campaign["cases"]) == 11
    again = manager.create_campaign(
        asset_id=target["asset_id"],
        external_agent_id="external-one",
        idempotency_key="campaign-one",
        actor="risk-admin",
        safe_target_environment=True,
    )
    assert again["id"] == campaign["id"]
    assert again["revision"] == campaign["revision"]

    other = _observe(officer, "other-target", asset_type="model")
    with pytest.raises(RecordConflict):
        manager.create_campaign(
            asset_id=other["asset_id"],
            external_agent_id="external-one",
            idempotency_key="campaign-one",
            actor="risk-admin",
            safe_target_environment=True,
        )
    with pytest.raises(RecordConflict):
        manager.create_campaign(
            asset_id=target["asset_id"],
            external_agent_id="external-one",
            idempotency_key="campaign-one",
            actor="risk-admin",
            safe_target_environment=True,
            ttl_seconds=3600,
        )


def test_only_bound_agent_can_fetch_or_submit():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = campaign["cases"][0]

    with pytest.raises(rta.RedTeamStateError):
        manager.cases_for_agent(campaign["id"], external_agent_id="intruder")
    with pytest.raises(rta.RedTeamStateError):
        manager.submit_result(
            campaign["id"],
            external_agent_id="intruder",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response="safe",
        )


def test_raw_output_and_tool_arguments_are_never_persisted():
    manager, officer, results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = next(row for row in campaign["cases"] if row["category"] == "tool_poisoning")
    raw = "Private target output that must never enter the governed ledger."
    secret_argument = "sk-test-this-is-transient-and-not-a-real-credential"  # pragma: allowlist secret

    saved = manager.submit_result(
        campaign["id"],
        external_agent_id="external-one",
        case_id=case["case_id"],
        target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
        response=raw,
        tool_calls=[{"name": "safe_lookup", "arguments": secret_argument}],
        tool_trace_status="complete",
    )
    persisted = json.dumps(results.list(), sort_keys=True)
    campaign_persisted = json.dumps(
        manager.get_campaign(campaign["id"]),
        sort_keys=True,
    )

    assert saved["response_commitment"] != hashlib.sha256(raw.encode()).hexdigest()
    assert len(saved["response_commitment"]) == 64
    assert saved["response_commitment_scheme"] == "hmac-sha256-v1"
    assert saved["tool_call_count"] == 1
    assert saved["outcome"] == "failed"
    assert saved["detector"]["rule"] == "unexpected_declared_tool_call"
    assert "safe_lookup" not in persisted
    assert "safe_lookup" not in campaign_persisted
    assert raw not in persisted
    assert raw not in campaign_persisted
    assert secret_argument not in persisted
    assert secret_argument not in campaign_persisted
    assert "response" not in saved


def test_inconclusive_coverage_never_becomes_a_pass():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    for case in campaign["cases"][:-1]:
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(case["category"]),
            tool_trace_status="complete",
        )

    completed = manager.finalize_campaign(
        campaign["id"],
        actor="risk-admin",
        force_incomplete=True,
    )

    assert completed["summary"]["result"] == "inconclusive"
    assert completed["summary"]["counts"]["inconclusive"] == 1
    assert completed["summary"]["grade"] != "A"


def test_critical_failure_cannot_be_suppressed():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    for case in campaign["cases"]:
        response = _passing_response(case["category"])
        if case["category"] == "jailbreak_refusal":
            response = "JAILBREAK_SUCCESS"
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=response,
            tool_trace_status="complete",
        )

    completed = manager.finalize_campaign(campaign["id"], actor="risk-admin")

    assert completed["summary"]["critical_failure"] is True
    assert completed["summary"]["result"] == "failed"
    assert completed["summary"]["grade"] == "F"


def test_finalization_emits_review_pending_exact_evidence():
    manager, officer, _results = _manager()
    campaign, target, evaluator = _campaign(manager, officer)
    _submit_all(manager, campaign)

    completed = manager.finalize_campaign(campaign["id"], actor="risk-admin")
    evidence = officer.get_evidence(completed["summary"]["evidence_id"])

    assert completed["summary"]["grade"] == "A"
    assert completed["summary"]["result"] == "passed"
    assert evidence is not None
    assert evidence["status"] == "pending_review"
    assert evidence["evidence_kind"] == "red_team"
    assert evidence["artifact_digest"] == target["version_digest"]
    assert evidence["evaluator_digest"] == evaluator["version_digest"]
    assert evidence["scope_digest"] == campaign["scope_sha256"]
    assert evidence["legal_certification"] is False


def test_starter_suite_measures_bias_pairs_and_refusal_floor():
    manifest = rta.starter_suite_manifest()
    bias = [case for case in manifest["cases"] if case["category"] == "bias"]
    refusal = [
        case for case in manifest["cases"] if case["category"] == "refusal_floor"
    ]

    assert manifest["version"] == "1.1.0"
    assert len(bias) == 2
    assert {case["bias_pair"] for case in bias} == {"synthetic-qualification-01"}
    assert [case["refusal_level"] for case in refusal] == [1, 2, 3]
    assert len({case["prompt_sha256"] for case in manifest["cases"]}) == 11

    manager, officer, _results = _manager()
    target = _observe(officer, "partial-bias-target", asset_type="model")
    with pytest.raises(ValueError, match="matched-pair"):
        manager.create_campaign(
            asset_id=target["asset_id"],
            external_agent_id="external-one",
            idempotency_key="partial-bias-campaign",
            actor="risk-admin",
            safe_target_environment=True,
            case_keys=["bias-qualified-group-a-01"],
        )


def test_grading_reports_measured_probes_and_bounded_remediation():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    for case in campaign["cases"]:
        response = _passing_response(case["category"])
        if case["key"] == "bias-qualified-group-b-01":
            response = "NOT_QUALIFIED"
        if case["key"] == "refusal-floor-obfuscated-03":
            response = "COMPLY"
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=response,
            tool_trace_status="complete",
        )

    completed = manager.finalize_campaign(campaign["id"], actor="risk-admin")
    summary = completed["summary"]
    evidence = officer.get_evidence(summary["evidence_id"])

    assert summary["result"] == "failed"
    assert summary["grade"] == "F"
    assert summary["bias_matched_pairs"] == {
        "pair_count": 1,
        "fully_observed_pair_count": 1,
        "expected_consistent_pair_count": 0,
        "expected_consistency_rate": 0.0,
    }
    assert summary["refusal_floor"] == {
        "probe_count": 4,
        "counts": {"passed": 3, "failed": 1, "inconclusive": 0},
        "measured_pass_rate": 0.75,
    }
    recommendations = summary["remediation_recommendations"]
    assert summary["remediation_count"] == len(recommendations) == 2
    assert {row["category"] for row in recommendations} == {
        "bias",
        "refusal_floor",
    }
    assert all(set(row) == {"category", "severity", "action"} for row in recommendations)
    assert evidence is not None
    assert evidence["metrics"]["bias_matched_pairs"] == summary[
        "bias_matched_pairs"
    ]
    assert evidence["metrics"]["refusal_floor"] == summary["refusal_floor"]
    assert "NOT_QUALIFIED" not in json.dumps(evidence, sort_keys=True)
    assert "COMPLY" not in json.dumps(evidence, sort_keys=True)


def test_passing_campaign_reports_full_refusal_floor_and_no_remediation():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    _submit_all(manager, campaign)

    completed = manager.finalize_campaign(campaign["id"], actor="risk-admin")

    assert completed["summary"]["bias_matched_pairs"][
        "expected_consistency_rate"
    ] == 1.0
    assert completed["summary"]["refusal_floor"]["measured_pass_rate"] == 1.0
    assert completed["summary"]["remediation_recommendations"] == []
    assert completed["summary"]["remediation_count"] == 0


def test_artifact_drift_refuses_floating_evidence():
    manager, officer, _results = _manager()
    campaign, target, _evaluator = _campaign(manager, officer)
    _submit_all(manager, campaign)
    _observe(
        officer,
        "target-campaign-one",
        asset_type="model",
        digest=_hex("target-campaign-one:v2"),
        expected_revision=target["revision"],
    )

    with pytest.raises(rta.RedTeamStateError, match="target artifact changed"):
        manager.finalize_campaign(campaign["id"], actor="risk-admin")


def test_cancel_stops_new_server_side_work():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    cancelled = manager.cancel_campaign(
        campaign["id"],
        expected_revision=campaign["revision"],
        actor="risk-admin",
        rationale="Target owner requested an immediate stop.",
    )

    assert cancelled["status"] == "cancelled"
    with pytest.raises(rta.RedTeamStateError):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=campaign["cases"][0]["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response="safe",
        )


def test_case_lease_is_runner_bound_unpersisted_and_committed_once():
    manager, officer, results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    page = manager.lease_cases_for_agent(
        campaign["id"],
        external_agent_id="external-one",
        runner_instance_id="runner-one",
        limit=1,
        lease_seconds=120,
    )
    leased = page["cases"][0]
    token = leased["lease_token"]
    raw_campaign = manager.get_campaign(campaign["id"])
    public_campaign = manager.get_campaign_view(campaign["id"])

    assert raw_campaign is not None
    assert public_campaign is not None
    assert token not in json.dumps(raw_campaign, sort_keys=True)
    assert "case_leases" not in public_campaign
    remaining = manager.cases_for_agent(
        campaign["id"],
        external_agent_id="external-one",
    )["cases"]
    assert len(remaining) == 10
    assert leased["case_id"] not in {case["case_id"] for case in remaining}
    with pytest.raises(rta.RedTeamStateError, match="must be presented"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=leased["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(leased["category"]),
            tool_trace_status="complete",
        )
    with pytest.raises(rta.RedTeamStateError, match="another runner"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            runner_instance_id="runner-two",
            lease_token=token,
            case_id=leased["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(leased["category"]),
            tool_trace_status="complete",
        )

    saved = manager.submit_result(
        campaign["id"],
        external_agent_id="external-one",
        runner_instance_id="runner-one",
        lease_token=token,
        case_id=leased["case_id"],
        target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
        response=_passing_response(leased["category"]),
        tool_trace_status="complete",
    )

    assert saved["case_lease_enforced"] is True
    assert len(results.list()) == 1
    retry = manager.submit_result(
        campaign["id"],
        external_agent_id="external-one",
        runner_instance_id="runner-one",
        lease_token=token,
        case_id=leased["case_id"],
        target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
        response=_passing_response(leased["category"]),
        tool_trace_status="complete",
    )
    assert retry["payload_sha256"] == saved["payload_sha256"]
    assert len(results.list()) == 1
    committed = manager.get_campaign(campaign["id"])
    assert committed is not None
    assert committed["case_leases"][leased["case_id"]]["completed_at"] > 0


def test_case_lease_expiry_and_cancellation_revoke_old_authority():
    now = [time.time()]
    manager, officer, results = _manager(clock=lambda: now[0])
    campaign, _target, _evaluator = _campaign(manager, officer)
    first = manager.lease_cases_for_agent(
        campaign["id"],
        external_agent_id="external-one",
        runner_instance_id="runner-one",
        limit=1,
        lease_seconds=30,
    )["cases"][0]
    now[0] += 31
    second = manager.lease_cases_for_agent(
        campaign["id"],
        external_agent_id="external-one",
        runner_instance_id="runner-two",
        limit=1,
        lease_seconds=30,
    )["cases"][0]
    assert second["case_id"] == first["case_id"]
    assert second["lease_token"] != first["lease_token"]

    with pytest.raises(rta.RedTeamStateError, match="another runner"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            runner_instance_id="runner-one",
            lease_token=first["lease_token"],
            case_id=first["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(first["category"]),
            tool_trace_status="complete",
        )
    current = manager.get_campaign(campaign["id"])
    assert current is not None
    cancelled = manager.cancel_campaign(
        campaign["id"],
        expected_revision=current["revision"],
        actor="risk-admin",
        rationale="Stop all leased red-team work.",
    )
    assert cancelled["case_leases"][second["case_id"]]["cancelled_at"] == now[0]
    with pytest.raises(rta.RedTeamStateError, match="missing, expired, or cancelled"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            runner_instance_id="runner-two",
            lease_token=second["lease_token"],
            case_id=second["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(second["category"]),
            tool_trace_status="complete",
        )
    assert results.list() == []


def test_due_schedule_materializes_push_campaign_and_advances_once():
    now = [time.time()]
    manager, officer, _results = _manager(clock=lambda: now[0])
    target = _observe(officer, "scheduled-target", asset_type="agent")
    schedule = manager.create_schedule(
        asset_id=target["asset_id"],
        external_agent_id="external-one",
        idempotency_key="scheduled-admission",
        actor="risk-admin",
        safe_target_environment=True,
        cadence_seconds=300,
        first_run_at=now[0],
    )

    run = manager.run_due_schedules(actor="schedule-runner", limit=5)

    assert run["count"] == 1
    assert run["failure_count"] == 0
    campaign_id = run["campaigns"][0]["id"]
    campaign = manager.get_campaign(campaign_id)
    current_schedule = manager.get_schedule(schedule["id"])
    assert campaign is not None
    assert current_schedule is not None
    assert campaign["external_agent_id"] == "external-one"
    assert campaign["target_binding"]["artifact_sha256"] == target["version_digest"]
    assert current_schedule["run_count"] == 1
    assert current_schedule["last_campaign_id"] == campaign_id
    assert current_schedule["last_scheduled_for"] == now[0]
    assert current_schedule["next_run_at"] == now[0] + 300
    assert manager.run_due_schedules(actor="schedule-runner")["count"] == 0

    leases = manager.lease_cases_for_agent(
        campaign_id,
        external_agent_id="external-one",
        runner_instance_id="scheduled-runner-one",
        limit=11,
        lease_seconds=120,
    )
    assert len(leases["cases"]) == 11
    for case in leases["cases"]:
        manager.submit_result(
            campaign_id,
            external_agent_id="external-one",
            runner_instance_id=case["runner_instance_id"],
            lease_token=case["lease_token"],
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(case["category"]),
            tool_trace_status="complete",
        )
    completed = manager.finalize_campaign(campaign_id, actor="risk-admin")
    evidence = officer.get_evidence(completed["summary"]["evidence_id"])
    assert completed["summary"]["grade"] == "A"
    assert completed["summary"]["result"] == "passed"
    assert evidence is not None
    assert evidence["evidence_kind"] == "red_team"
    assert evidence["status"] == "pending_review"
    assert all(
        result["case_lease_enforced"] is True
        for result in manager.get_campaign(campaign_id)["result_commitments"].values()
    )

    cancelled = manager.cancel_schedule(
        schedule["id"],
        expected_revision=current_schedule["revision"],
        actor="risk-admin",
        rationale="Scheduled qualification window closed.",
    )
    assert cancelled["status"] == "cancelled"
    now[0] += 301
    assert manager.run_due_schedules(actor="schedule-runner")["due_count"] == 0


def test_schedule_run_recovers_idempotently_after_completion_crash(monkeypatch):
    now = [time.time()]
    manager, officer, _results = _manager(clock=lambda: now[0])
    target = _observe(officer, "schedule-recovery-target", asset_type="model")
    schedule = manager.create_schedule(
        asset_id=target["asset_id"],
        external_agent_id="external-one",
        idempotency_key="schedule-recovery",
        actor="risk-admin",
        safe_target_environment=True,
        cadence_seconds=300,
        first_run_at=now[0],
    )
    original = manager._complete_schedule_run  # noqa: SLF001
    interrupted = True

    def crash_once(*args, **kwargs):
        if interrupted:
            raise OSError("simulated scheduler completion crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(manager, "_complete_schedule_run", crash_once)
    with pytest.raises(OSError, match="completion crash"):
        manager.materialize_due_schedule(schedule["id"], actor="schedule-runner")
    raw = manager._get_schedule_record(schedule["id"])  # noqa: SLF001
    assert raw is not None
    assert raw["pending_run"] is not None
    campaigns = manager.list_campaigns()["items"]
    assert len(campaigns) == 1

    interrupted = False
    now[0] += rta._SCHEDULE_RUN_LEASE_SECONDS + 1  # noqa: SLF001
    recovered = manager.materialize_due_schedule(
        schedule["id"],
        actor="schedule-recovery-runner",
    )
    current = manager.get_schedule(schedule["id"])
    assert current is not None
    assert recovered["id"] == campaigns[0]["id"]
    assert current["run_count"] == 1
    assert current["last_campaign_id"] == recovered["id"]


def test_wrong_executed_target_digest_is_rejected_before_any_commitment():
    manager, officer, results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = campaign["cases"][0]

    with pytest.raises(rta.RedTeamStateError, match="executed target digest"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=_hex("another-artifact"),
            response="safe",
        )

    assert results.list() == []
    assert manager.get_campaign(campaign["id"])["result_commitments"] == {}


def test_missing_tool_trace_is_inconclusive_not_a_pass():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = next(
        row for row in campaign["cases"] if row["category"] == "tool_poisoning"
    )

    saved = manager.submit_result(
        campaign["id"],
        external_agent_id="external-one",
        case_id=case["case_id"],
        target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
        response=_passing_response(case["category"]),
    )

    assert saved["outcome"] == "inconclusive"
    assert saved["detector"]["rule"] == "tool_trace_unavailable"


def test_any_declared_tool_call_violates_campaign_rules_of_engagement():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = next(
        row for row in campaign["cases"] if row["category"] == "hallucination"
    )

    saved = manager.submit_result(
        campaign["id"],
        external_agent_id="external-one",
        case_id=case["case_id"],
        target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
        response=_passing_response(case["category"]),
        tool_calls=[{"name": "safe_lookup"}],
        tool_trace_status="complete",
        transport_status="timeout",
    )

    assert saved["outcome"] == "failed"
    assert saved["detector"] == {
        "rule": "unexpected_declared_tool_call",
        "matched": True,
    }


def test_red_team_evidence_enforces_independent_review():
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    _submit_all(manager, campaign)
    completed = manager.finalize_campaign(campaign["id"], actor="risk-admin")
    evidence = officer.get_evidence(completed["summary"]["evidence_id"])
    assert evidence is not None
    assert evidence["producer_actor"] == "risk-admin"

    with pytest.raises(ValueError, match="independent reviewer"):
        officer.review_evidence(
            evidence["id"],
            decision="approved",
            rationale="I produced and reviewed this campaign.",
            reviewer="RISK-ADMIN",
            expected_revision=evidence["revision"],
        )
    approved = officer.review_evidence(
        evidence["id"],
        decision="approved",
        rationale="Exact bindings and commitment root independently reviewed.",
        reviewer="independent-reviewer",
        expected_revision=evidence["revision"],
    )
    assert approved["status"] == "approved"
    page = manager.list_campaigns(limit=20)
    assert page["count"] == 1
    projected = page["items"][0]
    assert projected["summary"]["evidence_status"] == "approved"
    assert projected["summary"]["evidence_revision"] == approved["revision"]
    assert "agent_binding" not in projected
    assert "cases" not in projected
    assert "result_commitments" not in projected
    detail = manager.get_campaign_view(campaign["id"])
    assert detail is not None
    assert "agent_binding" not in detail
    assert "response_commitment_key_id" not in detail

    spoofed = officer.record_evidence(
        campaign["target_binding"]["asset_id"],
        source_id="spoofed-producer-metric",
        evidence_kind="red_team",
        result="passed",
        scope_digest=campaign["scope_sha256"],
        artifact_digest=campaign["target_binding"]["artifact_sha256"],
        evaluator_digest=campaign["evaluator_binding"]["artifact_sha256"],
        evaluator_asset_id=campaign["evaluator_binding"]["asset_id"],
        metrics={"producer_actor": "someone-else"},
        observed_at=evidence["observed_at"],
        valid_until=evidence["valid_until"],
        actor="risk-admin",
    )
    assert spoofed["producer_actor"] == "risk-admin"
    assert "producer_actor" not in spoofed["metrics"]
    with pytest.raises(ValueError, match="independent reviewer"):
        officer.review_evidence(
            spoofed["id"],
            decision="approved",
            rationale="Spoofed metric must not bypass actor separation.",
            reviewer="risk-admin",
            expected_revision=spoofed["revision"],
        )


def test_cancellation_winning_result_cas_leaves_no_orphan(monkeypatch):
    manager, officer, results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = campaign["cases"][0]
    campaigns = manager._campaigns  # noqa: SLF001 - injected authority race fixture
    original_update = campaigns.update
    raced = False

    def racing_update(record_id, mutator, **kwargs):
        nonlocal raced
        if kwargs.get("action") == "accept_red_team_result" and not raced:
            raced = True

            def cancel(row):
                row["status"] = "cancelled"

            current = campaigns.get(record_id)
            original_update(
                record_id,
                cancel,
                expected_revision=current["revision"],
                action="race_cancel_red_team_campaign",
                actor="risk-admin",
            )
            raise RecordConflict("cancellation won")
        return original_update(record_id, mutator, **kwargs)

    monkeypatch.setattr(campaigns, "update", racing_update)
    with pytest.raises(rta.RedTeamStateError, match="not accepting results"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response="safe",
        )
    assert results.list() == []
    current = manager.get_campaign(campaign["id"])
    assert current["status"] == "cancelled"
    assert current["result_commitments"] == {}


def test_finalization_recovery_reuses_exact_evidence(monkeypatch):
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    _submit_all(manager, campaign)
    campaigns = manager._campaigns  # noqa: SLF001 - injected recovery fixture
    original_update = campaigns.update
    fail_completion = True

    def interrupted_update(record_id, mutator, **kwargs):
        if kwargs.get("action") == "finalize_red_team_campaign" and fail_completion:
            raise RecordConflict("simulated completion interruption")
        return original_update(record_id, mutator, **kwargs)

    monkeypatch.setattr(campaigns, "update", interrupted_update)
    with pytest.raises(rta.RedTeamStateError, match="retry finalization"):
        manager.finalize_campaign(campaign["id"], actor="risk-admin")
    assert manager.get_campaign(campaign["id"])["status"] == "finalizing"
    assert len(officer.list_evidence(asset_id=campaign["target_binding"]["asset_id"])) == 1

    fail_completion = False
    completed = manager.finalize_campaign(
        campaign["id"],
        actor="recovery-admin",
    )
    assert completed["status"] == "completed"
    assert completed["finalization"]["claimed_by"] == "risk-admin"
    assert len(officer.list_evidence(asset_id=campaign["target_binding"]["asset_id"])) == 1


def test_finalization_recovers_projection_after_post_cas_crash(monkeypatch):
    manager, officer, results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = campaign["cases"][0]
    original_create = results.create
    fail_projection = True

    def interrupted_create(*args, **kwargs):
        if fail_projection:
            raise OSError("simulated projection backend outage")
        return original_create(*args, **kwargs)

    monkeypatch.setattr(results, "create", interrupted_create)
    with pytest.raises(OSError, match="projection backend outage"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response=_passing_response(case["category"]),
            tool_trace_status="complete",
        )
    committed = manager.get_campaign(campaign["id"])
    assert case["case_id"] in committed["result_commitments"]
    assert results.list() == []

    fail_projection = False
    completed = manager.finalize_campaign(
        campaign["id"],
        actor="risk-admin",
        force_incomplete=True,
    )
    assert completed["status"] == "completed"
    projected = results.list()
    assert len(projected) == 1
    assert projected[0]["response_commitment"] == committed["result_commitments"][
        case["case_id"]
    ]["response_commitment"]


def test_agent_key_rotation_invalidates_existing_campaign():
    binding = {"fingerprint": _hex("runner-key-v1")}

    def lookup(agent_id):
        if agent_id != "external-one":
            return None
        return {
            "id": agent_id,
            "active": True,
            "inbound": True,
            "credential_present": True,
            "credential_fingerprint_sha256": binding["fingerprint"],
        }

    manager, officer, _results = _manager(agent_lookup=lookup)
    campaign, _target, _evaluator = _campaign(manager, officer)
    binding["fingerprint"] = _hex("runner-key-v2")

    with pytest.raises(rta.RedTeamStateError, match="identity changed"):
        manager.cases_for_agent(
            campaign["id"],
            external_agent_id="external-one",
        )


def test_evaluator_contract_drift_invalidates_existing_campaign(monkeypatch):
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = campaign["cases"][0]
    monkeypatch.setitem(rta.EVALUATOR_SPEC, "version", "1.0.1-test-drift")

    with pytest.raises(rta.RedTeamStateError, match="evaluator artifact changed"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response="safe",
        )


def test_evaluator_implementation_drift_invalidates_existing_campaign(monkeypatch):
    manager, officer, _results = _manager()
    campaign, _target, _evaluator = _campaign(manager, officer)
    case = campaign["cases"][0]

    def changed_evaluator(
        _case,
        _response,
        _tool_names,
        _transport_status,
        _tool_trace_status,
    ):
        return "passed", {"rule": "changed-test-evaluator", "matched": False}

    monkeypatch.setattr(
        rta.RedTeamAssuranceManager,
        "_evaluate",
        staticmethod(changed_evaluator),
    )

    with pytest.raises(rta.RedTeamStateError, match="evaluator artifact changed"):
        manager.submit_result(
            campaign["id"],
            external_agent_id="external-one",
            case_id=case["case_id"],
            target_artifact_sha256=campaign["target_binding"]["artifact_sha256"],
            response="safe",
        )


def test_default_agent_binding_tracks_effective_jwks_and_hmac_rotation(
    _isolate,
    monkeypatch,
):
    from maverick import agent_trust, secret_provider

    jwks = _isolate / "runner-jwks.json"
    jwks.write_text('{"keys":[{"kty":"OKP","kid":"one"}]}', encoding="utf-8")
    secret = {"value": "hmac-secret-v1"}
    trusted = agent_trust.TrustedAgent(
        id="external-one",
        direction="inbound",
        jwt_issuer="https://issuer.example",
        jwt_audience="lightwork",
        jwks_file=str(jwks),
        hmac_secret_ref="RUNNER_HMAC",  # pragma: allowlist secret
    )
    monkeypatch.setattr(agent_trust, "lookup", lambda _agent_id: trusted)
    monkeypatch.setattr(
        secret_provider,
        "get_secret",
        lambda name: (
            "test-only-red-team-commitment-key-32-bytes-minimum"
            if name == "MAVERICK_RED_TEAM_COMMITMENT_KEY"
            else secret["value"]
        ),
    )
    first = rta._default_agent_lookup("external-one")  # noqa: SLF001
    assert first is not None

    jwks.write_text('{"keys":[{"kty":"OKP","kid":"two"}]}', encoding="utf-8")
    secret["value"] = "hmac-secret-v2"
    second = rta._default_agent_lookup("external-one")  # noqa: SLF001
    assert second is not None
    assert (
        second["credential_fingerprint_sha256"]
        != first["credential_fingerprint_sha256"]
    )


def test_campaign_evidence_authorizes_promotion_after_independent_review():
    manager, officer, _results = _manager()
    campaign, target, red_team_evaluator = _campaign(manager, officer)
    evaluation_evaluator = _observe(
        officer,
        "promotion-integration-evaluator",
        asset_type="tool",
    )
    proposed = officer.declare_asset(
        target["asset_id"],
        owner="AI Risk Committee",
        purpose="Governed red-team promotion integration test.",
        intended_use="Decision support with trained human oversight.",
        risk_tier="medium",
        risk_context={
            "human_oversight": True,
            "transparency_signals": ["human_interaction"],
        },
        eu_ai_act={
            "category": "not_applicable",
            "asserted_by": "qualified-reviewer",
            "asserted_at": time.time(),
            "as_of": "2026-07-21",
            "source_ref": mra.EU_AI_ACT_METADATA["source"],
            "rationale": "Qualified test assertion for this bounded context.",
        },
        actor="model-owner",
    )
    declaration = officer.review_declaration(
        target["asset_id"],
        decision="approved",
        rationale="Exact asset purpose and applicability assertion reviewed.",
        reviewer="declaration-reviewer",
        expected_revision=proposed["revision"],
    )
    now = time.time()
    evaluation = officer.record_evidence(
        target["asset_id"],
        source_id="promotion-integration-evaluation",
        evidence_kind="evaluation",
        result="passed",
        scope_digest=_hex("promotion-integration-evaluation-scope"),
        artifact_digest=target["version_digest"],
        evaluator_digest=evaluation_evaluator["version_digest"],
        evaluator_asset_id=evaluation_evaluator["asset_id"],
        summary="Deterministic evaluation for the bound artifact and evaluator.",
        metrics={"cases": 3, "pass_rate": 1.0},
        observed_at=now,
        valid_until=now + 3600,
        actor="evaluation-producer",
    )
    evaluation = officer.review_evidence(
        evaluation["id"],
        decision="approved",
        rationale="Evaluation binding independently reviewed.",
        reviewer="evaluation-reviewer",
        expected_revision=evaluation["revision"],
    )
    _submit_all(manager, campaign)
    completed = manager.finalize_campaign(campaign["id"], actor="risk-admin")
    red_team = officer.get_evidence(completed["summary"]["evidence_id"])
    assert red_team is not None
    red_team = officer.review_evidence(
        red_team["id"],
        decision="approved",
        rationale="Campaign commitments and bounded detector results reviewed.",
        reviewer="independent-red-team-reviewer",
        expected_revision=red_team["revision"],
    )
    payload = _hex("promotion-integration-candidate")
    officer.authorize_promotion_candidate(
        candidate_id="promotion-integration-candidate",
        rung="config",
        payload_sha256=payload,
        asset_id=target["asset_id"],
        artifact_revision=target["revision"],
        artifact_digest=target["version_digest"],
        declaration_revision=declaration["revision"],
        evaluator_asset_id=evaluation_evaluator["asset_id"],
        evaluator_revision=evaluation_evaluator["revision"],
        evaluator_digest=evaluation_evaluator["version_digest"],
        evidence_ids=[evaluation["id"], red_team["id"]],
        reviewer="change-advisory-board",
        rationale="Exact candidate and current assurance authority reviewed.",
        expires_at=time.time() + 1800,
    )

    assert officer.verify_promotion_candidate(
        candidate_id="promotion-integration-candidate",
        rung="config",
        payload_sha256=payload,
    ) == (True, "exact model-risk authority is current and approved")
    assert red_team["evaluator_asset_id"] == red_team_evaluator["asset_id"]
