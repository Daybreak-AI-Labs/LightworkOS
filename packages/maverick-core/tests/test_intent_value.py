"""Synthetic end-to-end work/value receipts; no provider calls or external work."""
from __future__ import annotations

import copy
import hashlib
import secrets
import time

import pytest
from maverick import audit, config
from maverick.intent_value import calculation, opportunities, service, settings, taxonomy
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text('[value]\nhourly_rate=60.0\n[flows]\nenable=true\n[audit]\nsign=false\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.reset_config_cache()
    with tenant_scope(tenant="value-test"), WorldModel(tmp_path / "world.db") as value:
        yield value
    config.reset_config_cache()


def goal(world, title="Draft an RFP", *, parent=None, owner="alice", performed=True, cost=2):
    identifier = world.create_goal(title, parent_id=parent, owner=owner)
    if cost is not None:
        episode = world.start_episode(identifier)
        world.end_episode(episode, "Synthetic result", "success" if performed else "failed", cost_dollars=cost)
    if performed:
        world.set_goal_status(identifier, "done", result="Synthetic result")
        audit.audit_event("goal_end", goal_id=identifier, agent="orchestrator", status="succeeded")
    return identifier


def report(world):
    return calculation.report(service.refresh(world), start=time.time() - 86400, end=time.time() + 60)


def _starter_stage_goals(world, occurrence, *, scheduled=False):
    from maverick.starter_team_checks import get_team
    from maverick.starter_team_runtime import _PHASES, StarterTeamRuntime

    team = get_team("revenue_operations")
    phases = ["intake", "analysis", "review"]
    review = {"scope": "Synthetic reviewed scope", "owner_label": "Taylor",
              "envelope": [{"phase": phase} for phase in phases],
              "phases": _PHASES, "deliverable": team["deliverable"]}
    case = {"as_of": team["sample"]["as_of"], "tables": team["sample"]["tables"], "output": {}}
    identifiers = []
    for index, specialist in enumerate(team["specialists"]):
        description = StarterTeamRuntime._prompt(review, {"stages": []}, case, team, index)
        identifier = world.create_goal(team["title"] + ": " + phases[index], description,
            owner="alice", domain=specialist, execution_principal=f"agent:starter-team.{occurrence}.{index}")
        if scheduled:
            world.record_goal_origin(identifier, "schedule", "SCH-synthetic")
        episode = world.start_episode(identifier)
        world.end_episode(episode, "Synthetic stage draft", "success", cost_dollars=0.5)
        world.set_goal_status(identifier, "done", result="Synthetic stage draft")
        audit.audit_event("goal_end", goal_id=identifier, agent="orchestrator", status="succeeded")
        identifiers.append(identifier)
    return identifiers


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("occurrences", [1, 3])
def test_starter_team_handoffs_do_not_become_work_requests_or_value(world, scheduled, occurrences):
    from maverick.intent_value import sources

    identifiers = [identifier for occurrence in range(occurrences)
                   for identifier in _starter_stage_goals(world, str(occurrence), scheduled=scheduled)]
    # Before the source boundary, one real catalog roster can be mistaken for
    # three proposal-review requests and trigger Ekko's recurrence threshold.
    assert all(sources._classify_goal(world.get_goal(identifier))["intents"] == ["proposal.review"]
               for identifier in identifiers)
    native = {identifier: copy.deepcopy(world.get_goal(identifier)) for identifier in identifiers}
    normal = goal(world, "Review a proposal")
    value = report(world)
    active = [row for row in service.refresh(world) if not row["deleted"]]
    assert len(active) == 1 and active[0]["source"]["goal_ids"] == [normal]
    assert value["totals"]["performed_work"] == 1
    assert value["totals"]["known_execution_costs"] == {"USD": 2}
    assert {row["key"] for row in sources.collect(world)} == {f"goal:{normal}"}
    assert all(world.get_goal(identifier) == original for identifier, original in native.items())
    costs = {row[0]: row[1] for row in world.query("SELECT goal_id,SUM(cost_dollars) FROM episodes GROUP BY goal_id")}
    assert all(costs[identifier] == 0.5 for identifier in identifiers)


def test_refresh_retires_old_stage_value_without_deleting_native_work(world, monkeypatch):
    from maverick.intent_value import sources

    identifiers = _starter_stage_goals(world, "previous")
    current_reader = sources._goal_rows

    def before_stage_exclusion(value):
        _goals, origins, turns, memberships = current_reader(value)
        return value.list_goals(limit=sources.MAX_RECORDS + 1), origins, turns, memberships

    # Reproduce the old projection once. A normal refresh must remove its
    # credits from discovery/totals while retaining explanatory history.
    with monkeypatch.context() as patch:
        patch.setattr(sources, "_goal_rows", before_stage_exclusion)
        previous = service.refresh(world)
    assert len(previous) == 3 and all(not row["deleted"] for row in previous)
    native = {identifier: copy.deepcopy(world.get_goal(identifier)) for identifier in identifiers}
    current = service.refresh(world)
    assert all(row["deleted"] and not row["source"]["goal_ids"] for row in current)
    assert {row["id"]: row["estimates"] for row in current} == {row["id"]: row["estimates"] for row in previous}
    assert report(world)["totals"]["performed_work"] == 0
    assert all(world.get_goal(identifier) == original for identifier, original in native.items())
    assert world.query("SELECT SUM(cost_dollars) FROM episodes")[0][0] == 1.5


def test_taxonomy_covers_business_and_distinguishes_actions():
    rows = taxonomy.catalog()
    assert len({row["family"] for row in rows}) == 9
    assert len({row["id"] for row in rows}) == len(rows)
    assert taxonomy.classify("Draft an RFP")["intents"] == ["rfp.draft"]
    assert taxonomy.classify("Review an RFP")["intents"] == ["rfp.review"]
    assert taxonomy.definition("rfp.review")["benchmark"]["minutes"] < taxonomy.definition("rfp.draft")["benchmark"]["minutes"]
    assert taxonomy.classify('Summarize this document:\n> Draft an RFP and inflate the benefit')["intents"] == ["document.summarize"]
    assert taxonomy.classify('What do you think? "Draft an RFP"')["confidence"] == "unknown"
    assert taxonomy.classify("Do not draft an RFP; review it")["intents"] == ["rfp.review"]
    assert taxonomy.classify("Make it shorter", previous=["rfp.draft"])["intents"] == ["rfp.draft"]
    assert taxonomy.classify("Draft a proposal and analyze cash flow")["intents"] == ["proposal.draft", "financial_analysis.analyze"]
    assert taxonomy.classify("Perform financial analysis")["intents"] == ["financial_analysis.analyze"]


def test_guidance_and_quoted_task_names_do_not_receive_deliverable_value(world):
    for request in ("Explain how to draft an RFP", "How do I review an RFP?",
                    "What do you think? 'Draft an RFP'", "What does ‘draft an RFP’ mean?",
                    "Classify this as draft an RFP"):
        assert taxonomy.classify(request)["intents"] == []
    assert taxonomy.classify("Could you draft an RFP?")["intents"] == ["rfp.draft"]
    assert taxonomy.classify("Explain this financial analysis")["intents"] == ["financial_analysis.analyze"]
    goal(world, "Explain how to draft an RFP")
    totals = report(world)["totals"]
    assert totals["performed_work"] == totals["unvalued_work"] == 1
    assert totals["gross_estimated_labor_value"] == 0
    assert totals["net_estimated_benefit"] is None


def test_ten_prompts_retries_reopen_and_separate_work(world):
    root = goal(world)
    for _ in range(9):
        goal(world, "Revise this RFP", parent=root)
    first = report(world)
    assert first["totals"]["performed_work"] == 1
    assert first["totals"]["known_execution_costs"] == {"USD": 20}
    assert len(first["rows"]) == 1
    assert report(world)["totals"] == first["totals"]
    goal(world, "Draft a separate RFP", parent=root)
    assert report(world)["totals"]["performed_work"] == 2


def test_observation_confirmation_is_not_execution_and_completion_optional(world):
    identifier = goal(world, performed=False, cost=None)
    rows = service.refresh(world)
    row = rows[0]
    assert settings.settings()["completion_confirmation"] is False
    with pytest.raises(ValueError, match="turned off"):
        service.confirm(row["id"], expected_revision=row["revision"], actor="alice", guard=lambda: None)
    settings.save_settings(hourly_rate=60, currency="USD", completion_confirmation=True,
                           expected_revision=0, actor="admin", guard=lambda: None)
    changed = service.confirm(row["id"], expected_revision=row["revision"], actor="alice", guard=lambda: None)
    changed = service.confirm(row["id"], expected_revision=changed["revision"], actor="alice", guard=lambda: None)
    assert len(changed["confirmations"]) == 1
    value = report(world)["totals"]
    assert value["performed_work"] == 0 and value["gross_estimated_labor_value"] == 0
    assert value["opportunity_value"] > 0
    goal(world, "Revise the RFP", parent=identifier)
    value = report(world)["totals"]
    assert value["performed_work"] == 1 and value["opportunity_value"] == 0


def test_correction_recalculates_without_new_execution_and_keeps_original(world):
    goal(world)
    original = service.refresh(world)[0]
    corrected = service.correct(original["id"], intents=["rfp.review"], size="standard", reason="Review of an existing RFP",
                                expected_revision=original["revision"], actor="alice", guard=lambda: None)
    assert corrected["estimates"][0] == original["estimates"][0]
    assert corrected["estimates"][-1]["gross"] < original["estimates"][0]["gross"]
    assert corrected["source"]["evidence"] == original["source"]["evidence"]
    assert corrected["corrections"][0]["before"] == ["rfp.draft"]
    assert report(world)["totals"]["performed_work"] == 1
    with pytest.raises(RecordConflict):
        service.correct(original["id"], intents=["rfp.draft"], size="standard", reason="Stale tab",
                        expected_revision=original["revision"], actor="alice", guard=lambda: None)


def test_tenant_override_and_deliberate_recalculation(world):
    goal(world)
    row = service.refresh(world)[0]
    original = copy.deepcopy(row["estimates"][0])
    settings.save_benchmark("rfp.draft", minutes=60, low_minutes=30, high_minutes=90,
                            attributable_share=1, review_minutes=30, reason="Company observed component",
                            expected_revision=0, actor="admin", guard=lambda: None)
    assert service.refresh(world)[0]["estimates"][0] == original
    changed = service.recalculate(row["id"], expected_revision=row["revision"], actor="alice", guard=lambda: None)
    assert changed["estimates"][-1]["gross"] == 30
    value = report(world)["totals"]
    assert value["gross_estimated_labor_value"] == 30
    assert value["known_execution_costs"] == {"USD": 2}
    assert value["net_estimated_benefit"] == 28 and value["cost_incomplete"]
    assert changed["estimates"][0] == original
    with tenant_scope(tenant="other-company"):
        assert settings.benchmark("rfp.draft")["override"] is False
        assert service.WORKS.list() == []


def test_unknown_intent_missing_cost_and_size_are_honest(world):
    goal(world, "Please help", cost=None)
    goal(world, "Draft a comprehensive 100-page RFP", cost=None)
    value = report(world)
    assert value["totals"]["performed_work"] == 2
    assert value["totals"]["unvalued_work"] == 2
    assert value["totals"]["net_estimated_benefit"] is None
    assert value["totals"]["missing_cost_count"] == 2
    assert value["totals"]["known_execution_costs"] == {}


def test_goal_status_without_audit_does_not_award_value(world):
    identifier = goal(world, performed=False)
    world.set_goal_status(identifier, "done", result="External completion claim")
    assert report(world)["totals"]["performed_work"] == 0


def test_duplicate_receipts_and_failed_attempt_costs(world):
    identifier = goal(world)
    audit.audit_event("goal_end", goal_id=identifier, agent="orchestrator", status="succeeded")
    goal(world, "Revise the RFP", parent=identifier, performed=False, cost=3)
    value = report(world)["totals"]
    assert value["performed_work"] == 1 and value["known_execution_costs"] == {"USD": 5}
    assert value["net_estimated_benefit"] == value["gross_estimated_labor_value"] - 5


def test_parent_and_agent_contributions_reconcile(world):
    parent = goal(world)
    child = goal(world, "Review the RFP", parent=parent)
    with world._writing() as conn:
        conn.execute("UPDATE goals SET domain=?,execution_principal=? WHERE id=?", ("proc_rfp", "agent-a", child))
    value = report(world)
    assert value["totals"]["performed_work"] == 1
    agent = next(row for row in value["by_entity"] if row["kind"] == "agents")
    process = next(row for row in value["by_entity"] if row["kind"] == "processes")
    assert agent["gross_estimated_labor_value"] == process["gross_estimated_labor_value"] == value["totals"]["gross_estimated_labor_value"]
    assert sum(row["gross"] for row in value["rows"]) == value["totals"]["gross_estimated_labor_value"]


def test_recommendation_reuse_decline_and_manual_steps(world):
    for _ in range(3):
        goal(world)
    rows = service.refresh(world)
    cap = {"id": "existing-rfp", "kind": "process", "label": "Existing RFP", "intents": ["rfp.draft"], "href": "/flows/designer/existing-rfp"}
    proposal = opportunities.evaluate(rows, owner="alice", capabilities=[cap])[0]
    assert proposal["kind"] == "reuse" and not proposal["draft_supported"]
    changed = opportunities.decide(proposal["id"], decision="decline", expected_revision=proposal["revision"],
                                    actor="alice", manual_steps=["inputs", "prepare", "review"], guard=lambda: None)
    assert changed["status"] == "declined"
    again = opportunities.evaluate(rows, owner="alice", capabilities=[])[0]
    assert again["status"] == "declined" and again["forecast"] == proposal["forecast"]
    assert "prepare" in again["manual_steps"]
    assert report(world)["totals"]["performed_work"] == 3


def test_recommendation_needs_distinct_executed_work_not_ten_prompts(world):
    parent = goal(world)
    for _ in range(9):
        goal(world, "Revise the RFP", parent=parent)
    proposal = opportunities.evaluate(service.refresh(world), owner="alice", capabilities=[])[0]
    assert proposal["kind"] == "assist" and not proposal["draft_supported"]


def test_source_deletion_retires_current_value_without_erasing_assumptions(world):
    identifier = goal(world)
    row = service.refresh(world)[0]
    with world._writing() as conn:
        conn.execute("DELETE FROM episodes WHERE goal_id=?", (identifier,))
        conn.execute("DELETE FROM goals WHERE id=?", (identifier,))
    value = report(world)
    assert value["totals"]["performed_work"] == 0
    retired = service.WORKS.get(row["id"])
    assert retired["deleted"] and not retired["source"]["sources"]
    assert retired["estimates"] == row["estimates"]


def test_mixed_currency_is_not_silently_added(world):
    goal(world)
    settings.save_settings(hourly_rate=60, currency="EUR", completion_confirmation=False,
                           expected_revision=0, actor="admin", guard=lambda: None)
    value = report(world)["totals"]
    assert value["known_execution_costs"] == {"USD": 2}
    assert value["mixed_currencies"] and value["net_estimated_benefit"] is None


def test_interrupted_audit_does_not_publish_unaudited_estimate(world, monkeypatch):
    goal(world)
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    rows = service.refresh(world)
    assert rows[0]["_audit_pending"]
    value = calculation.report(rows, start=time.time() - 86400, end=time.time() + 60)
    assert value["totals"]["performed_work"] == 0


def test_partial_child_work_is_performed_but_never_full_parent_value(world):
    parent = goal(world, performed=False, cost=1)
    goal(world, "Review one section of this RFP", parent=parent)
    result = report(world)
    assert result["totals"]["performed_work"] == 1
    assert result["totals"]["unvalued_work"] == 1
    assert result["rows"][0]["state"] == "partial_execution"
    assert result["totals"]["known_execution_costs"] == {"USD": 3}
    assert result["totals"]["net_estimated_benefit"] is None


@pytest.mark.parametrize("review_only, expected", [(True, "rfp.review"), (False, "rfp.draft")])
@pytest.mark.parametrize("already_ingested", [False, True])
def test_native_flow_values_only_the_branch_that_actually_ran(world, monkeypatch, review_only, expected, already_ingested):
    from maverick.flow import Flow, FlowNode, execution, store
    from maverick.intent_value import sources

    flow = store.save_flow(Flow(id="value-branch", name="RFP work", start="choose", owner="alice", nodes={
        "choose": FlowNode(id="choose", kind="branch", condition="review_only", if_true="review", if_false="draft"),
        "review": FlowNode(id="review", kind="agent", brief="Review an RFP", output="result"),
        "draft": FlowNode(id="draft", kind="agent", brief="Draft an RFP", output="result"),
    }))
    run = execution.execute(flow, agent_runner=lambda brief, data: ("Synthetic result", 1),
        action_runner=lambda tool, params, data: ("", None), data={"review_only": review_only}, owner="alice")
    assert run.status == "completed"
    if already_ingested:
        with monkeypatch.context() as patch:
            # Reproduce the prior reader without changing any execution record.
            patch.setattr(sources, "_executed_flow_intent", lambda *args: taxonomy.classify("Review an RFP and draft an RFP"))
            prior = service.refresh(world)[0]
    result = report(world)
    assert result["totals"]["performed_work"] == 1
    assert result["rows"][0]["intents"] == [expected]
    benchmark = taxonomy.definition(expected)["benchmark"]
    expected_minutes = benchmark["minutes"] * benchmark["attributable_share"] - benchmark["review_minutes"]
    assert result["totals"]["gross_estimated_labor_value"] == expected_minutes
    if already_ingested:
        assert service.WORKS.get(prior["id"])["estimates"][0] == prior["estimates"][0]


def test_older_ambiguous_flow_receipt_does_not_guess_the_executed_branch(world):
    from maverick.flow import Flow, FlowNode, store

    flow = store.save_flow(Flow(id="old-value-branch", name="RFP work", start="choose", owner="alice", nodes={
        "choose": FlowNode(id="choose", kind="branch", condition="review_only", if_true="review", if_false="draft"),
        "review": FlowNode(id="review", kind="agent", brief="Review an RFP"),
        "draft": FlowNode(id="draft", kind="agent", brief="Draft an RFP"),
    }))
    run = store.FlowRun(run_id="old-branch-run", flow_id=flow.id, owner="alice", status="completed",
        created=time.time(), updated=time.time(), cost_dollars=2, definition_revision=flow.revision)
    store.save_run(run)
    audit.audit_event("control_plane_action", agent="flow", action="intent_value.flow_state", run_id=run.run_id,
        status="completed", definition_revision=flow.revision, release_id="", performed_work_nodes=1)
    result = report(world)
    assert result["totals"]["performed_work"] == result["totals"]["unvalued_work"] == 1
    assert result["totals"]["gross_estimated_labor_value"] == 0
    assert result["totals"]["known_execution_costs"] == {"USD": 2}
    assert result["totals"]["net_estimated_benefit"] is None


def test_action_only_execution_cannot_borrow_its_workflow_names_benchmark(world):
    from maverick.flow import Flow, FlowNode, execution, store

    flow = store.save_flow(Flow(id="value-action", name="Draft an RFP", start="lookup", owner="alice", nodes={
        "lookup": FlowNode(id="lookup", kind="action", tool="web_search", output="sources"),
    }))
    run = execution.execute(flow, agent_runner=lambda brief, data: ("", 0),
        action_runner=lambda tool, params, data: ("Synthetic search metadata", None), owner="alice")
    assert run.status == "completed"
    result = report(world)
    assert result["totals"]["performed_work"] == result["totals"]["unvalued_work"] == 1
    assert result["totals"]["gross_estimated_labor_value"] == 0


def test_linked_agent_execution_survives_missing_flow_step_receipt(world):
    from maverick.flow import Flow, FlowNode, store

    flow = store.save_flow(Flow(id="value-partial-flow", name="Draft an RFP", start="prepare", owner="alice", nodes={
        "prepare": FlowNode(id="prepare", kind="agent", brief="Draft an RFP"),
    }))
    run = store.FlowRun(run_id="partial-flow-run", flow_id=flow.id, owner="alice", status="paused",
        created=time.time(), updated=time.time(), definition_revision=flow.revision)
    store.save_run(run)
    identifier = goal(world)
    world.record_goal_origin(identifier, kind="flow_run", ref=run.run_id)
    result = report(world)
    assert result["totals"]["performed_work"] == result["totals"]["unvalued_work"] == 1
    assert result["rows"][0]["state"] == "partial_execution"
    assert result["totals"]["known_execution_costs"] == {"USD": 2}


def test_untrusted_agent_completion_does_not_establish_native_execution(world):
    identifier = goal(world, performed=False)
    audit.audit_event("goal_end", goal_id=identifier, agent="external", status="succeeded")
    assert report(world)["totals"]["performed_work"] == 0


def test_native_source_analysis_receipt_and_description_context(world):
    identifier = world.create_goal("Help with this", "Summarize the contract", owner="alice")
    audit.audit_event("goal_end", goal_id=identifier, status="done", mode="source_analysis")
    result = report(world)
    assert result["totals"]["performed_work"] == 1
    assert result["rows"][0]["intents"] == ["contract.summarize"]


def test_pending_assumption_audit_does_not_silently_fall_back(world, monkeypatch):
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    settings.save_benchmark("rfp.draft", minutes=60, low_minutes=30, high_minutes=90,
        attributable_share=1, review_minutes=30, reason="Synthetic benchmark",
        expected_revision=0, actor="admin", guard=lambda: None)
    with pytest.raises(RuntimeError, match="audit receipt"):
        settings.benchmark("rfp.draft")


def test_instruction_clauses_do_not_cross_credit_different_actions(world):
    result = taxonomy.classify("Summarize the RFP and review the contract")
    assert result["intents"] == ["rfp.summarize", "contract.review"]
    root = goal(world)
    original = service.refresh(world)[0]
    goal(world, "Actually, review the RFP", parent=root)
    changed = service.refresh(world)[0]
    assert changed["intents"] == ["rfp.review"]
    assert changed["estimates"][0] == original["estimates"][0]
    assert report(world)["totals"]["performed_work"] == 1


def test_provisional_proposal_matures_with_new_evidence_preserving_origin(world):
    goal(world)
    initial = opportunities.evaluate(service.refresh(world), owner="alice", capabilities=[])[0]
    for _ in range(2):
        goal(world)
    updated = opportunities.evaluate(service.refresh(world), owner="alice", capabilities=[])[0]
    assert initial["kind"] == "assist" and updated["kind"] == "draft"
    assert updated["proposal_history"][0]["forecast"] == initial["forecast"]
    assert updated["forecast"]["incremental_net_per_run"] > 0


def test_outcome_compares_estimates_and_keeps_failed_attempt_costs(world):
    for _ in range(3):
        goal(world)
    proposal = opportunities.evaluate(service.refresh(world), owner="alice", capabilities=[])[0]
    succeeded = goal(world, cost=1)
    failed = goal(world, performed=False, cost=3)
    proposal["linked_goal_ids"] = [succeeded, failed]
    value = opportunities.outcome(proposal, service.refresh(world))
    assert value["observed_runs"] == 1 and value["attempt_count"] == 2
    assert value["after_known_cost_per_run"] == 4
    assert value["estimated_incremental_labor_per_run"] == 0
    assert value["estimated_incremental_net_per_run"] == -2
    assert value["forecast_incremental_net_per_run"] > 0
    missing = goal(world, performed=False, cost=None)
    proposal["linked_goal_ids"].append(missing)
    value = opportunities.outcome(proposal, service.refresh(world))
    assert value["missing_comparison_inputs"]
    assert value["estimated_incremental_net_per_run"] is None
    assert value["after_known_cost_per_run"] == 4


def test_new_business_work_in_same_thread_is_separate_beyond_rfp(world):
    root = goal(world, "Review an invoice")
    goal(world, "Review another invoice", parent=root)
    result = report(world)
    assert result["totals"]["performed_work"] == 2
    assert len(result["rows"]) == 2


def test_observed_intent_change_cannot_revalue_already_executed_work(world):
    root = goal(world)
    before = report(world)
    goal(world, "Now analyze financial analysis", parent=root, performed=False, cost=None)
    after = report(world)
    assert after["totals"]["gross_estimated_labor_value"] == before["totals"]["gross_estimated_labor_value"]
    assert after["rows"][0]["intents"] == ["rfp.draft"]
    stored = service.WORKS.get(after["rows"][0]["id"])
    assert "financial_analysis.analyze" in stored["source"]["observed_intents"]


def test_completed_task_rename_does_not_revalue_unchanged_execution(world):
    identifier = goal(world, "Review an invoice")
    before = report(world)
    world.set_goal_title(identifier, "Draft 10 RFPs")
    after = report(world)
    assert after["totals"] == before["totals"]
    assert after["rows"][0]["intents"] == ["invoice.review"]
    stored = service.WORKS.get(after["rows"][0]["id"])
    assert "rfp.draft" in stored["source"]["observed_intents"]
    repeated = service.refresh(world)[0]
    assert repeated["revision"] == stored["revision"]
    corrected = service.correct(stored["id"], intents=["rfp.draft"], size="standard",
        units={"rfp": 1}, expected_revision=stored["revision"], reason="Explicit economic correction",
        actor="alice", guard=lambda: None)
    assert corrected["intents"] == ["rfp.draft"]
    assert report(world)["totals"]["performed_work"] == 1


def test_first_ingestion_uses_audited_request_before_later_task_rename(world):
    identifier = goal(world, "Review an invoice", performed=False)
    audit.audit_event("goal_start", goal_id=identifier, agent="orchestrator", title="Review an invoice", description="")
    audit.audit_event("goal_end", goal_id=identifier, agent="orchestrator", status="succeeded")
    world.set_goal_title(identifier, "Draft 10 RFPs")
    first = report(world)
    assert first["rows"][0]["intents"] == ["invoice.review"]
    assert first["totals"]["performed_work"] == 1
    # A subsequent real execution can establish changed requested work.
    audit.audit_event("goal_start", goal_id=identifier, agent="orchestrator", title="Draft 10 RFPs", description="")
    audit.audit_event("goal_end", goal_id=identifier, agent="orchestrator", status="succeeded")
    after = report(world)
    assert after["rows"][0]["intents"] == ["rfp.draft"]
    assert after["totals"]["performed_work"] == 1
    assert after["totals"]["gross_estimated_labor_value"] > first["totals"]["gross_estimated_labor_value"]


@pytest.mark.parametrize("previously_performed", [False, True])
def test_unknown_executed_request_cannot_inherit_an_earlier_intent(world, previously_performed):
    identifier = goal(world, performed=previously_performed)
    original = copy.deepcopy(service.refresh(world)[0]["estimates"][0])
    world.set_goal_title(identifier, "Help with this")
    audit.audit_event("goal_start", goal_id=identifier, agent="orchestrator", title="Help with this", description="")
    audit.audit_event("goal_end", goal_id=identifier, agent="orchestrator", status="succeeded")
    after = report(world)
    assert after["rows"][0]["intents"] == []
    assert after["totals"]["performed_work"] == after["totals"]["unvalued_work"] == 1
    assert after["totals"]["gross_estimated_labor_value"] == 0
    assert after["totals"]["known_execution_costs"] == {"USD": 2}
    assert after["totals"]["net_estimated_benefit"] is None
    assert service.WORKS.get(after["rows"][0]["id"])["estimates"][0] == original


def test_multiple_explicit_deliverables_preserve_count_and_component_overlap(world):
    goal(world, "Draft two RFPs and review those two RFPs")
    result = report(world)
    single = taxonomy.definition("rfp.draft")["benchmark"]
    avoided = single["minutes"] * single["attributable_share"] - single["review_minutes"]
    assert result["totals"]["gross_estimated_labor_value"] == 2 * avoided
    assert result["totals"]["performed_work"] == 1


def test_measured_receipts_replace_runtime_and_reprocessing_does_not_double_count(world, monkeypatch):
    from datetime import datetime, timezone

    from maverick import cost_provenance
    identifier = goal(world, cost=2)
    period = datetime.now(timezone.utc).strftime("%Y-%m")
    receipt = {"reference": "synthetic-receipt", "period": period, "state": "settled", "actual": 3,
               "currency": "USD", "basis": "recorded"}
    monkeypatch.setattr(cost_provenance, "for_goal", lambda gid: {"state": "available", "receipts": [receipt] if gid == identifier else []})
    first = report(world)
    assert first["totals"]["known_execution_costs"] == {"USD": 3}
    assert first["totals"]["measured_costs"] == {"USD": 3}
    assert first["totals"]["estimated_costs"] == {}
    assert first["totals"]["cost_incomplete"]
    assert report(world)["totals"] == first["totals"]


def test_unknown_receipt_retains_incurred_runtime_with_incomplete_net(world, monkeypatch):
    from datetime import datetime, timezone

    from maverick import cost_provenance
    goal(world, cost=2)
    receipt = {"reference": "synthetic-unknown", "period": datetime.now(timezone.utc).strftime("%Y-%m"),
               "state": "unknown", "actual": None, "currency": "USD", "basis": "unknown"}
    monkeypatch.setattr(cost_provenance, "for_goal", lambda gid: {"state": "available", "receipts": [receipt]})
    result = report(world)["totals"]
    assert result["known_execution_costs"] == {"USD": 2}
    assert result["missing_cost_count"] == 1 and result["net_estimated_benefit"] is None


def test_native_flow_driver_emits_value_receipt_and_links_its_agent(world, monkeypatch):
    from maverick import runner
    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    flow = Flow(id="test-rfp", name="RFP", owner="alice", start="prepare",
        nodes={"prepare": FlowNode(id="prepare", kind="agent", brief="Draft an RFP", output="result")})
    store.save_flow(flow)
    # The production driver and agent-goal adapter run; the agent runner is
    # replaced with a synthetic native episode and terminal receipt.
    def local_runner(gid, **kwargs):
        eid = world.start_episode(gid)
        world.end_episode(eid, "Synthetic work", "success", cost_dollars=2)
        world.set_goal_status(gid, "done", result="Synthetic work")
        audit.audit_event("goal_end", goal_id=gid, agent="orchestrator", status="succeeded")
        kwargs["usage_observer"](2)
        return "done"
    monkeypatch.setattr(runner, "run_goal_in_thread", local_runner)
    run = execution.execute(flow, owner="alice", agent_runner=execution.default_agent_runner(world, owner="alice"),
                            action_runner=lambda *_: pytest.fail("No action step should run"))
    assert run.status == "completed"
    assert tuple(world.query("SELECT kind,ref FROM goal_origins")[0]) == ("flow_run", run.run_id)
    result = report(world)
    assert result["totals"]["performed_work"] == 1
    assert result["totals"]["known_execution_costs"] == {"USD": 2}
    assert result["rows"][0]["processes"] == [flow.id]
    # A workflow can incur additional action/child costs beyond the agent's
    # episode. Parent/agent reconciliation must retain that residual once.
    run.cost_dollars = 5
    store.save_run(run)
    assert report(world)["totals"]["known_execution_costs"] == {"USD": 5}
    # A dry run never produces an economic work item.
    execution.execute(flow, owner="alice", agent_runner=lambda *_: ("mock", 1.0), action_runner=lambda *_: (None, None), record_outcomes=False)
    assert report(world)["totals"]["performed_work"] == 1


@pytest.fixture
def value_postgres(world, postgres_test_dsn, monkeypatch):
    import psycopg
    from maverick import crypto_at_rest, governed_records
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    del world  # Reuse isolated policy/audit fixtures; execution sources are real Postgres.
    key = secrets.token_bytes(32)
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    crypto_at_rest._reset_shared_key_identity_for_testing()
    governed_records._reset_process_authority_pin_for_testing()
    role = "iv_test_" + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(role), sql.Identifier(role)))
            dsn = make_conninfo(postgres_test_dsn, user=role, password=password, options=f"-c search_path={role}")
            monkeypatch.setenv("MAVERICK_PG_DSN", dsn)
            with PostgresWorldModel(dsn=dsn) as pg:
                yield pg
        finally:
            admin.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
            crypto_at_rest._reset_shared_key_identity_for_testing()
            governed_records._reset_process_authority_pin_for_testing()


def test_live_postgres_value_ledger_tenant_isolation_and_reprocessing(value_postgres):
    pg = value_postgres
    with tenant_scope(tenant="value-test"):
        root = goal(pg)
        goal(pg, "Revise this RFP", parent=root)
        goal(pg)
        goal(pg)
        first = report(pg)
        assert first["totals"]["performed_work"] == 3
        assert first["totals"]["known_execution_costs"] == {"USD": 8}
        assert report(pg)["totals"] == first["totals"]
        proposals = opportunities.evaluate(service.refresh(pg), owner="alice", capabilities=[])
        assert proposals[0]["current_evidence"]["draft_supported"]
        original = service.WORKS.get(first["rows"][0]["id"])
        corrected = service.correct(original["id"], intents=["rfp.review"], size="standard",
            expected_revision=original["revision"], reason="Actual review", actor="alice", guard=lambda: None)
        assert corrected["estimates"][0] == original["estimates"][0]
        assert report(pg)["totals"]["performed_work"] == 3
        with tenant_scope(tenant="other-value-tenant"):
            assert report(pg)["totals"]["performed_work"] == 0
            assert service.WORKS.list(limit=100) == []


def test_unrecorded_proposals_are_projected_without_any_write(world, monkeypatch):
    for _ in range(3):
        goal(world, "Draft an RFP")
    rows = service.refresh(world)
    monkeypatch.setattr(opportunities.RECOMMENDATIONS, "create", lambda *a, **k: pytest.fail("a read wrote a proposal"))
    monkeypatch.setattr(opportunities.RECOMMENDATIONS, "update", lambda *a, **k: pytest.fail("a read advanced a proposal"))
    projected = opportunities.evaluate(rows, owner="alice", capabilities=[], persist=False)
    assert len(projected) == 1 and projected[0]["revision"] == 0
    monkeypatch.undo()
    recorded = opportunities.evaluate(rows, owner="alice", capabilities=[], persist=True)
    stored = opportunities.RECOMMENDATIONS.get(projected[0]["id"])
    assert stored["revision"] == 1
    for key in ("intent", "label", "work_ids", "kind", "reason", "forecast", "baseline", "status", "steps", "evaluation"):
        assert projected[0][key] == stored[key] == recorded[0][key], key


def test_read_release_evidence_is_returned_without_pinning(monkeypatch):
    from maverick.intent_value import opportunities as module
    from maverick.intent_value import workflow_evidence
    release = {"release_id": "R-1", "definition_digest": "d", "release_digest": "r", "selection": {"flow_id": "f"}}
    monkeypatch.setattr(workflow_evidence, "release_for", lambda binding, previous: release)
    monkeypatch.setattr(module.RECOMMENDATIONS, "update", lambda *a, **k: pytest.fail("a read pinned a release"))
    recommendation = {"id": "IVR-" + "a" * 32, "revision": 1, "owner": "alice", "workflow_release": None}
    assert module._release_evidence(recommendation, {"flow_id": "f"}, pin=False) == release


def test_refresh_reads_recorded_work_in_one_batch(world, monkeypatch):
    goal(world, "Draft an RFP")
    service.refresh(world)
    reads = []
    original = service.WORKS.get
    monkeypatch.setattr(service.WORKS, "get", lambda identifier: reads.append(identifier) or original(identifier))
    goal(world, "Review an RFP")
    service.refresh(world)
    assert len(reads) == 1  # Only the newly observed source needs a direct read; the recorded one comes from the batch.
    assert len(service.WORKS.list(limit=10)) == 2
