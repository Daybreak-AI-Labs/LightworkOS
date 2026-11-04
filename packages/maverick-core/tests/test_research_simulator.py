"""Acceptance tests for resettable worlds and swappable research baselines."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from maverick import research_simulator as simulator
from maverick.counterfactual_rollout import Transition
from maverick.governed_actions import ActionError
from maverick.governed_records import GovernedRecordStore
from maverick.outcome_accounting import OutcomeAccounting
from maverick.paths import tenant_scope
from maverick.procedural_memory import Memory
from maverick.research_simulator import (
    INTERFACE_VERSION,
    AuthenticatedHumanApprovalV1,
    AuthenticatedHumanIdentityV1,
    FaultSpec,
    FeaturePrefixBackoffBaseline,
    ProposalV1,
    ResearchBudgetExceeded,
    ResearchComponentV1,
    ResearchSimulationError,
    SimulatedOutcomeAcceptanceError,
    SoftwareWorldFixture,
    SoftwareWorldScenario,
    TabularResearchBaseline,
    TaskGeneratorFamily,
    WithheldFamilyPartition,
    compatibility_report,
    run_first_study,
)

_DESCRIPTOR_SHA256 = hashlib.sha256(b"test-controller-descriptor").hexdigest()


def _identity(principal="user:simulator-reviewer"):
    return AuthenticatedHumanIdentityV1(
        principal,
        hashlib.sha256(f"verified:{principal}".encode()).hexdigest(),
    )


def _approval(world, proposal, component_id="fault-replay-baseline-v1"):
    return AuthenticatedHumanApprovalV1.bind(
        _identity(),
        scenario_id=world.scenario_id,
        component_id=component_id,
        proposal=proposal,
    )


def _scenario(*, faults=(), suffix="one"):
    return SoftwareWorldScenario(
        scenario_id=f"software-world-{suffix}",
        seed=914_2026,
        mechanism_family="record-sync",
        application_family="vendor-onboarding",
        task={"key": "vendor-17", "value": "approved"},
        records={"vendor-17": "pending", "vendor-21": "pending", "vendor-33": "closed"},
        hidden_state={"reference_revision": 4},
        external_state={"vendor-17": "pending"},
        files={"policy.json": '{"version":1}'},
        queue=({"job": "initial"},),
        credentials={"external_write": True},
        memories=(Memory("upsert", 0.8, 0.9),),
        initial_clock=1_800_000_000.0,
        page_size=2,
        fault_schedule=tuple(faults),
    )


def _transitions():
    state = ("record-sync", "vendor-onboarding", "ready")
    return [Transition(state, "upsert", None, 1.0)] * 4


def _replay_all_faults(world):
    worker = world.open_worker(max_operations=6)
    initial = worker.initial_observation().to_dict()
    proposals = (
        ProposalV1("upsert", key="vendor-17", value="approved"),
        ProposalV1("read", key="vendor-17"),
        ProposalV1("upsert", key="vendor-17", value="approved"),
        ProposalV1("upsert", key="vendor-17", value="approved"),
        ProposalV1("list", cursor="0", limit=3),
        ProposalV1("upsert", key="vendor-17", value="approved"),
    )
    results = []
    observations = []
    for proposal in proposals:
        approval = (
            _approval(world, proposal)
            if proposal.action == "upsert"
            else None
        )
        result = worker.execute(
            proposal,
            component_id="fault-replay-baseline-v1",
            component_descriptor_sha256=_DESCRIPTOR_SHA256,
            approval=approval,
        )
        results.append(result.to_app_payload())
        observations.append(worker.observe(result).to_dict())
    return {
        "initial": initial,
        "results": results,
        "observations": observations,
        "oracle": world.oracle_snapshot(),
    }


def test_known_seed_and_fault_schedule_reset_replays_exactly_twice():
    """Reset makes initial, learner and oracle results deterministic."""
    faults = (
        FaultSpec(1, "partial_commit", "upsert"),
        FaultSpec(2, "stale_read", "read"),
        FaultSpec(3, "revoked_credential", "upsert"),
        FaultSpec(4, "conflicting_edit", "upsert"),
        FaultSpec(5, "pagination_change", "list"),
        FaultSpec(6, "interrupted_execution", "upsert"),
    )
    world = SoftwareWorldFixture(_scenario(faults=faults, suffix="faults"))

    first = _replay_all_faults(world)
    reset = world.reset()
    second = _replay_all_faults(world)

    assert first == second
    assert reset.clean is True
    assert reset.seed == 914_2026
    assert [row["status"] for row in first["results"]] == [
        "partial_commit",
        "stale_read",
        "credential_revoked",
        "conflict",
        "pagination_changed",
        "interrupted",
    ]
    assert [row["fault"] for row in first["results"]] == [
        "partial_commit",
        "stale_read",
        "revoked_credential",
        "conflicting_edit",
        "pagination_change",
        "interrupted_execution",
    ]
    # The learner sees the reset-time record during the stale read while the
    # oracle retains the earlier partial local commit and the fake external
    # state remains independently inspectable by the controller.
    assert first["observations"][1]["records"]["vendor-17"] == "pending"
    assert first["oracle"]["records"]["vendor-17"] == "approved"
    assert first["oracle"]["external_state"]["vendor-17"].startswith("conflict-")


def test_deterministic_operation_identity_is_namespaced_by_scenario():
    proposal = ProposalV1("read", key="vendor-17")
    operation_ids = []
    for suffix in ("identity-one", "identity-two"):
        world = SoftwareWorldFixture(_scenario(suffix=suffix))
        result = world.open_worker(max_operations=1).execute(
            proposal,
            component_id="operation-identity-baseline-v1",
            component_descriptor_sha256=_DESCRIPTOR_SHA256,
        )
        operation_ids.append(result.operation_id)
    assert operation_ids[0] != operation_ids[1]


def test_reset_removes_and_reports_every_cross_run_state_surface():
    """Hidden, external, records, clocks, RNG, files and queues reset."""
    world = SoftwareWorldFixture(_scenario(suffix="contamination"))
    stale_worker = world.open_worker(max_operations=1)
    baseline = world.oracle_snapshot()
    world.seed_contamination()

    status = world.reset_status()
    assert status["clean"] is False
    assert set(status["changed_surfaces"]) == {
        "records",
        "hidden_state",
        "external_state",
        "files",
        "queue",
        "credentials",
        "clock",
        "step",
        "page_size",
        "rng_probe",
        "procedural_memory",
    }

    receipt = world.reset()
    assert set(receipt.contamination_removed) == set(status["changed_surfaces"])
    assert world.reset_status()["clean"] is True
    assert world.oracle_snapshot() == baseline
    with pytest.raises(ResearchSimulationError, match="previous simulator reset"):
        stale_worker.execute(
            ProposalV1("read", key="vendor-17"),
            component_id="stale-session-baseline-v1",
            component_descriptor_sha256=_DESCRIPTOR_SHA256,
        )


def test_nested_scenario_input_cannot_redefine_the_captured_reset_oracle():
    scenario = _scenario(suffix="detached-definition")
    world = SoftwareWorldFixture(scenario)
    baseline = world.oracle_snapshot()
    scenario.records["vendor-17"] = "caller-mutated"
    scenario.hidden_state["reference_revision"] = "caller-mutated"
    scenario.external_state["vendor-17"] = "caller-mutated"

    assert world.reset().clean is True
    assert world.oracle_snapshot() == baseline


def test_swappable_components_keep_authority_budget_and_outcome_costs(tmp_path, monkeypatch):
    """Unchanged caller, same gates, real local accounting adapter."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    accounting = OutcomeAccounting(
        store=GovernedRecordStore(
            "test_research_simulator_accounting", "RSA", "outcome_accounting"
        )
    )
    components = (
        TabularResearchBaseline(_transitions()),
        FeaturePrefixBackoffBaseline(_transitions()),
    )
    runs = []
    reports = []

    with tenant_scope(tenant="research-tenant"):
        for index, component in enumerate(components):
            assert isinstance(component, ResearchComponentV1)
            world = SoftwareWorldFixture(_scenario(suffix=f"component-{index}"))
            admitted = accounting.admit(
                admission_id=f"research-simulator-admission-{index}",
                work_item_id=f"research-simulator-work-{index}",
                acceptance_contract_ref="contract:simulated-research:v1",
                owner_id="user:research-owner",
                actor="user:research-owner",
            )
            worker = world.open_worker(
                accounting=accounting,
                accounting_record_id=admitted["id"],
                actor="system:research-simulator",
                max_operations=1,
            )

            # The component swap cannot bypass the high-risk approval boundary.
            proposal = component.propose(worker.initial_observation())
            _descriptor, descriptor_sha256 = simulator._component_descriptor(component)
            assert worker.preview(proposal).risk == "high"
            with pytest.raises(ActionError, match="authenticated named-human"):
                worker.execute(
                    proposal,
                    component_id=component.component_id,
                    component_descriptor_sha256=descriptor_sha256,
                )
            assert world.reset_status()["clean"] is True
            assert worker.used_operations == 0
            assert accounting.report(admitted["id"])["costs"]["event_count"] == 0

            run = run_first_study(
                component,
                world,
                worker,
                approver_identity=_identity("user:independent-research-reviewer"),
            )
            runs.append(run)
            report = accounting.report(admitted["id"])
            reports.append(report)
            assert report["costs"]["event_count"] == 1
            event = report["costs"]["events"][0]
            assert event["quantity"] == "1"
            assert event["unit"] == "simulated_operation"
            assert event["amount"] == "0"
            assert event["budget_state"] == "within_limit"
            assert event["source_ref"].startswith("simulator:sim-")
            assert worker.actions.verify_lineage().startswith("VALID: 1 link")
            assert run.component_process_isolated is True
            assert run.action_lineage_sha256 == worker.actions.lineage[-1].hash
            assert run.accounting_event_id == event["id"]
            assert run.cost_accounting_persisted is True

            with pytest.raises(ResearchBudgetExceeded, match="budget exhausted"):
                worker.execute(
                    proposal,
                    component_id=component.component_id,
                    component_descriptor_sha256=descriptor_sha256,
                )
            assert accounting.report(admitted["id"])["costs"]["event_count"] == 1

    compatibility = compatibility_report(runs)
    assert compatibility == {
        "schema": "maverick.research-component-compatibility.v1",
        "interface_version": INTERFACE_VERSION,
        "compatible": True,
        "authority_policy_equal": True,
        "budget_equal": True,
        "behavior_equal": True,
        "controller_bindings_valid": True,
        "cost_accounting_active": True,
        "simulated_only": True,
        "components": compatibility["components"],
    }
    assert {row.result_status for row in runs} == {"succeeded"}
    assert all(row.component_passed and row.oracle_passed for row in runs)
    assert all(row.authority_requires_approval for row in runs)
    assert "not a proven learned world model" in runs[1].baseline_label
    assert all(report["business_outcome"]["status"] == "unresolved" for report in reports)


def test_withheld_generator_family_is_absent_from_development_environment():
    """Split whole families and retain params/answers under evaluator custody."""
    families = (
        TaskGeneratorFamily(
            "family-public-records",
            "record-sync",
            "vendor-onboarding",
            {"prompt": "Update the visible vendor record."},
            {"private_seed": "dev-private-seed"},
            {"action": "upsert", "key": "vendor-1"},
        ),
        TaskGeneratorFamily(
            "family-public-queues",
            "queue-retry",
            "support-routing",
            {"prompt": "Retry the visible queue item."},
            {"private_seed": "second-dev-private-seed"},
            {"action": "retry", "key": "queue-1"},
        ),
        TaskGeneratorFamily(
            "family-withheld-conflicts",
            "conflict-recovery",
            "invoice-reconciliation",
            {"prompt": "Reconcile the visible invoice."},
            {"private_seed": "withheld-secret-parameter"},
            {"reference": "withheld-reference-solution"},
        ),
    )
    partition = WithheldFamilyPartition(
        families, withheld_family_ids={"family-withheld-conflicts"}
    )
    evaluator_command = tuple(str(value) for value in partition._evaluator.args)
    assert evaluator_command[1] == "-I"
    assert evaluator_command[-1].endswith("research_holdout_worker.py")
    assert "withheld-secret-parameter" not in " ".join(evaluator_command)
    assert "withheld-reference-solution" not in " ".join(evaluator_command)

    environment = partition.development_environment()
    encoded = json.dumps(environment, sort_keys=True)
    assert environment["environment"] == {}
    assert environment["credentials"] == []
    assert environment["private_generator_parameters_available"] is False
    assert environment["reference_solutions_available"] is False
    assert environment["heldout_evaluator_process_isolated"] is True
    assert "family-withheld-conflicts" not in encoded
    assert "withheld-secret-parameter" not in encoded
    assert "withheld-reference-solution" not in encoded
    assert "dev-private-seed" not in encoded
    split = partition.split_report()
    assert split["partition_unit"] == "mechanism_application_family"
    assert split["disjoint"] is True
    assert split["evaluator_process_isolated"] is True
    assert len(split["evaluator_custody_sha256"]) == 64
    assert set(map(tuple, split["development_families"])).isdisjoint(
        set(map(tuple, split["withheld_families"]))
    )
    assert partition.evaluate_withheld(
        "family-withheld-conflicts",
        {"reference": "withheld-reference-solution"},
    ) is True
    assert not hasattr(partition, "_families")
    parent_material = " ".join(
        repr(getattr(partition, slot)) for slot in partition.__slots__
    )
    assert "withheld-secret-parameter" not in parent_material
    assert "withheld-reference-solution" not in parent_material
    assert "dev-private-seed" not in parent_material
    partition.close()


def test_family_partition_rejects_row_level_split_of_one_family():
    shared = (
        TaskGeneratorFamily("family-dev", "same-mechanism", "same-app", {}, {}, "a"),
        TaskGeneratorFamily("family-held", "same-mechanism", "same-app", {}, {}, "b"),
    )
    with pytest.raises(ValueError, match="cannot be split"):
        WithheldFamilyPartition(shared, withheld_family_ids={"family-held"})


def test_successful_fake_external_effect_is_simulated_and_cannot_be_accepted():
    """Success remains simulation-only evidence."""
    world = SoftwareWorldFixture(_scenario(suffix="acceptance-boundary"))
    worker = world.open_worker(max_operations=1)
    proposal = ProposalV1("upsert", key="vendor-17", value="approved")
    result = worker.execute(
        proposal,
        component_id="simulation-label-baseline-v1",
        component_descriptor_sha256=_DESCRIPTOR_SHA256,
        approval=_approval(
            world,
            proposal,
            component_id="simulation-label-baseline-v1",
        ),
    )

    assert result.success is True
    assert result.predicted_external_effect == "succeeded"
    assert world.assess().passed is True
    payload = result.to_app_payload()
    assert payload["evidence_class"] == "simulated"
    assert payload["result_class"] == "simulation"
    assert payload["live_effect"] is False
    assert payload["can_accept_business_outcome"] is False
    assert payload["authoritative_live_evidence_eligible"] is False
    assert payload["business_outcome_acceptance"] == "prohibited"
    assert payload["source_ref"] == f"simulator:{result.operation_id}"
    with pytest.raises(SimulatedOutcomeAcceptanceError, match="cannot accept"):
        result.accept_live_business_outcome()


def test_component_subprocess_receives_no_oracle_or_authority_capability(monkeypatch):
    """Adversarial A3: only the permitted JSON projections cross processes."""
    captured = []
    original = simulator._run_component_process

    def capture(request):
        captured.append(json.loads(json.dumps(request)))
        return original(request)

    monkeypatch.setattr(simulator, "_run_component_process", capture)
    component = TabularResearchBaseline(_transitions())
    world = SoftwareWorldFixture(_scenario(suffix="process-boundary"))
    worker = world.open_worker(max_operations=1)
    run = run_first_study(
        component,
        world,
        worker,
        approver_identity=_identity("user:process-boundary-reviewer"),
    )

    assert run.component_process_isolated is True
    assert [row["command"] for row in captured] == [
        "propose_execute",
        "observe_evaluate",
    ]
    transmitted = json.dumps(captured, sort_keys=True)
    for oracle_only in (
        "reference_revision",
        "external_state",
        "policy.json",
        "external_write",
        "last_successful_operation",
    ):
        assert oracle_only not in transmitted
    assert all("approval" not in row and "accounting" not in row for row in captured)


def test_component_process_environment_drops_host_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross-process-boundary")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", "must-not-cross-process-boundary")

    environment = simulator._isolated_process_environment(str(tmp_path))

    assert set(environment).issubset({
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
    })
    assert environment["TEMP"] == str(tmp_path)
    assert environment["TMP"] == str(tmp_path)
    assert "OPENAI_API_KEY" not in environment
    assert "MAVERICK_AUDIT_SIGNING_KEY" not in environment


def test_unregistered_structural_component_cannot_run_or_reach_the_worker():
    class HostileComponent:
        interface_version = INTERFACE_VERSION
        component_id = "hostile-structural-component-v1"
        baseline_label = "hostile"

        def __init__(self):
            self.called = False

        def propose(self, observation):
            self.called = True
            return ProposalV1("upsert", key="vendor-17", value="forged")

        def execute(self, proposal):
            self.called = True
            return proposal

        def observe(self, result, observation):
            self.called = True
            return observation

        def evaluate(self, observation, result):
            self.called = True
            return simulator.ComponentEvaluationV1(self.component_id, True, "forged")

    hostile = HostileComponent()
    assert isinstance(hostile, ResearchComponentV1)
    world = SoftwareWorldFixture(_scenario(suffix="hostile-component"))
    with pytest.raises(TypeError, match="registered isolated"):
        run_first_study(
            hostile,
            world,
            world.open_worker(max_operations=1),
            approver_identity=_identity("user:hostile-reviewer"),
        )
    assert hostile.called is False
    assert world.reset_status()["clean"] is True


def test_declared_interface_mismatch_fails_before_effect(monkeypatch):
    component = TabularResearchBaseline(_transitions())
    monkeypatch.setattr(
        TabularResearchBaseline,
        "interface_version",
        "maverick.research-component.v999",
    )
    world = SoftwareWorldFixture(_scenario(suffix="interface-mismatch"))
    worker = world.open_worker(max_operations=1)
    with pytest.raises(ResearchSimulationError, match="interface version"):
        run_first_study(
            component,
            world,
            worker,
            approver_identity=_identity("user:interface-reviewer"),
        )
    assert worker.used_operations == 0
    assert world.reset_status()["clean"] is True


def test_high_risk_simulation_rejects_system_string_and_mismatched_human_approval():
    world = SoftwareWorldFixture(_scenario(suffix="approval-authority"))
    worker = world.open_worker(max_operations=1)
    proposal = ProposalV1("upsert", key="vendor-17", value="approved")
    with pytest.raises(ValueError, match="named user"):
        AuthenticatedHumanIdentityV1(
            "system:self-approved",
            hashlib.sha256(b"system").hexdigest(),
        )
    with pytest.raises(ActionError, match="authenticated named-human"):
        worker.execute(
            proposal,
            component_id="approval-boundary-v1",
            component_descriptor_sha256=_DESCRIPTOR_SHA256,
            approval="user:self-approved",  # type: ignore[arg-type]
        )
    other = AuthenticatedHumanApprovalV1.bind(
        _identity("user:named-reviewer"),
        scenario_id=world.scenario_id,
        component_id="approval-boundary-v1",
        proposal=ProposalV1("upsert", key="vendor-17", value="different"),
    )
    with pytest.raises(ActionError, match="does not match"):
        worker.execute(
            proposal,
            component_id="approval-boundary-v1",
            component_descriptor_sha256=_DESCRIPTOR_SHA256,
            approval=other,
        )
    assert worker.used_operations == 0
    assert worker.cost_receipts == ()
    assert world.reset_status()["clean"] is True


def test_simulation_result_boundary_fields_are_not_constructor_or_replace_inputs():
    world = SoftwareWorldFixture(_scenario(suffix="result-invariants"))
    worker = world.open_worker(max_operations=1)
    proposal = ProposalV1("upsert", key="vendor-17", value="approved")
    result = worker.execute(
        proposal,
        component_id="result-boundary-v1",
        component_descriptor_sha256=_DESCRIPTOR_SHA256,
        approval=_approval(world, proposal, component_id="result-boundary-v1"),
    )

    with pytest.raises(TypeError):
        replace(result, evidence_class="live")
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(result, "evidence_class", "live")
    payload = result.to_app_payload()
    assert payload["evidence_class"] == "simulated"
    assert payload["result_class"] == "simulation"
    assert payload["authoritative_live_evidence_eligible"] is False


def test_compatibility_requires_persisted_controller_bindings_and_rejects_rewrites():
    component = TabularResearchBaseline(_transitions())
    world = SoftwareWorldFixture(_scenario(suffix="compatibility-bindings"))
    run = run_first_study(
        component,
        world,
        world.open_worker(max_operations=1),
        approver_identity=_identity("user:compatibility-reviewer"),
    )

    report = compatibility_report((run, run))
    assert report["controller_bindings_valid"] is True
    assert report["cost_accounting_active"] is False
    assert report["compatible"] is False
    with pytest.raises(ValueError, match="controller evidence"):
        replace(run, cost_accounting_persisted=True, accounting_event_id="forged")


def test_worker_observation_and_environment_exclude_complete_oracle_state():
    world = SoftwareWorldFixture(_scenario(suffix="oracle-boundary"))
    worker = world.open_worker(max_operations=1)
    visible = json.dumps({
        "environment": worker.enumerate_environment(),
        "observation": worker.initial_observation().to_dict(),
    }, sort_keys=True)
    assert "reference_revision" not in visible
    assert "external_state" not in visible
    assert "policy.json" not in visible
    assert "external_write" not in visible
    assert worker.enumerate_environment()["oracle_access"] is False


@pytest.mark.parametrize(
    ("fault", "operation"),
    [
        ("partial_commit", "upsert"),
        ("stale_read", "read"),
        ("revoked_credential", "upsert"),
        ("conflict", "upsert"),
        ("pagination_change", "list"),
        ("interruption", "upsert"),
    ],
)
def test_fault_aliases_and_operations_are_bounded(fault, operation):
    spec = FaultSpec(1, fault, operation)
    assert spec.kind in {
        "partial_commit",
        "stale_read",
        "revoked_credential",
        "conflicting_edit",
        "pagination_change",
        "interrupted_execution",
    }


def test_scenario_and_proposal_reject_malformed_or_unbounded_inputs():
    with pytest.raises(ValueError, match="fault kind"):
        FaultSpec(1, "network-magic")
    with pytest.raises(ValueError, match="duplicate"):
        _scenario(faults=(FaultSpec(1, "stale_read"), FaultSpec(1, "partial_commit")))
    with pytest.raises(ValueError, match="cursor"):
        ProposalV1("list", cursor="not-a-cursor")
    with pytest.raises(ValueError, match="limit"):
        ProposalV1("list", limit=101)
