"""Offline sample acceptance and durable starter-team authority boundaries."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from maverick import config
from maverick import starter_team_checks as checks
from maverick.budget import Budget, BudgetExceeded
from maverick.governed_operations import ServiceContext, digest


def test_catalog_has_all_37_requested_teams_and_review_requirements():
    teams = checks.catalog()
    assert len(teams) == 37
    assert len({team["id"] for team in teams}) == 37
    assert len({team["title"] for team in teams}) == 37
    domains = Path(checks.__file__).with_name("domains")
    for team in teams:
        assert 2 <= len(team["specialists"]) <= 4
        for specialist in team["specialists"]:
            assert (domains / f"{specialist}.toml").is_file(), (team["id"], specialist)
        for field in ("inputs", "connections", "acceptance", "stop_conditions", "blocked_actions"):
            assert team[field], (team["id"], field)
        assert team["sample"]["expected_findings"], team["id"]
        assert all(connection["access"] == "read" for connection in team["connections"])
        assert all(connection["prerequisites"] for connection in team["connections"])


@pytest.mark.parametrize("team", checks.catalog(), ids=lambda team: team["id"])
def test_every_team_sample_matches_exact_findings_with_complete_provenance(team):
    sample = team["sample"]
    original = copy.deepcopy(sample["tables"])
    output = checks.evaluate(team["id"], sample["tables"], as_of=sample["as_of"])
    assert {finding["id"] for finding in output["findings"]} == set(sample["expected_findings"])
    assert len(output["findings"]) == len(sample["expected_findings"])
    assert all(finding["kind"] == "review_required" for finding in output["findings"])
    assert output["input_sha256"] == digest(original)
    assert output["catalog_sha256"] == checks.team_digest(team)
    expected_sources = {
        (name, row["id"]): (row["source"], digest(row))
        for name, rows in original.items() for row in rows
    }
    actual_sources = {
        (row["table"], row["row_id"]): (row["source"], row["sha256"])
        for row in output["evidence"]
    }
    assert actual_sources == expected_sources
    assert len(output["evidence"]) == sum(map(len, original.values()))
    for finding in output["findings"]:
        source, row_digest = expected_sources[finding["table"], finding["row_id"]]
        assert finding["source"] == source
        assert finding["evidence_sha256"] == row_digest
        assert finding["status"] == "awaiting_human_review"
    assert [handoff["stage"] for handoff in output["handoffs"]] == ["intake", "analysis", "review"]
    assert all(handoff["specialist"] in team["specialists"] for handoff in output["handoffs"])
    assert all(handoff["execution"] == "deterministic_check_engine" for handoff in output["handoffs"])
    assert output["external_effects"] == []
    assert output["usage"] == {"provider_calls": 0, "tool_calls": 0, "dollars": 0}
    assert output["readiness"] == "structured_inputs_only"
    assert output["business_acceptance"] == "pending_human_review"
    assert checks.evaluate(team["id"], original, as_of=sample["as_of"]) == output
    assert sample["tables"] == original


def _first_sample():
    team = checks.catalog()[0]
    return team, copy.deepcopy(team["sample"]["tables"])


@pytest.mark.parametrize("change", ["missing_source", "duplicate_id", "undeclared_column", "nested_cell", "nan"])
def test_invalid_evidence_is_refused_before_any_result(change):
    team, tables = _first_sample()
    rows = next(iter(tables.values()))
    if change == "missing_source":
        rows[0].pop("source")
    elif change == "duplicate_id":
        rows.append(copy.deepcopy(rows[0]))
    elif change == "undeclared_column":
        rows[0]["unreviewed_field"] = "unexpected"
    elif change == "nested_cell":
        rows[0]["source"] = {"url": "https://example.test"}
    else:
        key = next(key for key in rows[0] if key not in {"id", "source"})
        rows[0][key] = float("nan")
    with pytest.raises(ValueError):
        checks.evaluate(team["id"], tables, as_of=team["sample"]["as_of"])


@pytest.mark.parametrize("as_of", ["2026-02-30", "tomorrow", "2026-1-2", "2026-11-02T12:00:00Z", None])
def test_evaluation_requires_unambiguous_as_of_date(as_of):
    team, tables = _first_sample()
    with pytest.raises(ValueError):
        checks.evaluate(team["id"], tables, as_of=as_of)


def test_unknown_team_and_unrecognized_tables_are_refused():
    with pytest.raises(KeyError):
        checks.get_team("unknown_team")
    team, tables = _first_sample()
    tables["unrequested_export"] = [{"id": "1", "source": "sample://extra"}]
    with pytest.raises(ValueError):
        checks.evaluate(team["id"], tables, as_of=team["sample"]["as_of"])


def test_bounded_rows_and_budget_are_enforced():
    team, tables = _first_sample()
    with pytest.raises(ValueError, match="row limit"):
        checks.validate_tables(team, tables, max_rows=1)
    with pytest.raises(BudgetExceeded):
        checks.evaluate(team["id"], tables, as_of=team["sample"]["as_of"],
                        budget=Budget(max_wall_seconds=0))


def _rule_team(rule, *, records, references=None):
    team = copy.deepcopy(checks.catalog()[0])
    columns = sorted({key for row in records for key in row})
    team["inputs"] = [{"key": "records", "label": "Records", "description": "Synthetic check input", "columns": columns}]
    team["rules"] = [{"id": "check", "title": "Owner review required", "table": "records",
                      "action": "Ask the source owner to review.", **rule}]
    tables = {"records": records}
    if references is not None:
        team["inputs"].append({"key": "references", "label": "References", "description": "Synthetic reference input",
                               "columns": sorted({key for row in references for key in row})})
        tables["references"] = references
    return team, tables


def _row(row_id, **fields):
    return {"id": row_id, "source": f"sample://rules/{row_id}", **fields}


@pytest.mark.parametrize("rule,records,expected", [
    ({"kind": "required", "field": "owner"}, [_row("a", owner=" "), _row("b", owner="Taylor")], {"check:a"}),
    ({"kind": "equals", "field": "approved", "value": True}, [_row("a", approved=1), _row("b", approved=True)], {"check:a"}),
    ({"kind": "compare", "field": "invoice", "other_field": "po", "operator": "eq"},
     [_row("a", invoice=100, po=90), _row("b", invoice=100, po=100)], {"check:a"}),
    ({"kind": "compare", "field": "limit", "other_field": "required", "operator": "gte"},
     [_row("a", limit=900, required=1000), _row("b", limit=1000, required=1000)], {"check:a"}),
    ({"kind": "compare", "field": "expense", "other_field": "cap", "operator": "lte"},
     [_row("a", expense=110, cap=100), _row("b", expense=100, cap=100)], {"check:a"}),
    ({"kind": "deadline", "field": "due", "within_days": 7, "unless_field": "status", "unless_value": "complete"},
     [_row("a", due="2026-11-09", status="open"), _row("b", due="2026-11-10", status="open"),
      _row("c", due="2026-10-01", status="complete")], {"check:a"}),
    ({"kind": "unique", "fields": ["vendor", "invoice"]},
     [_row("a", vendor="Supplier A", invoice="100"), _row("b", vendor="Supplier A", invoice="100"),
      _row("c", vendor="Supplier B", invoice="100")], {"check:a", "check:b"}),
])
def test_declared_checks_preserve_business_boundary_cases(monkeypatch, rule, records, expected):
    team, tables = _rule_team(rule, records=records)
    monkeypatch.setattr(checks, "get_team", lambda _: team)
    output = checks.evaluate(team["id"], tables, as_of="2026-11-02")
    assert {row["id"] for row in output["findings"]} == expected
    assert all(row["kind"] == "review_required" for row in output["findings"])


def test_reference_check_distinguishes_missing_and_ambiguous_evidence(monkeypatch):
    rule = {"kind": "reference", "field": "supplier", "reference_table": "references", "reference_field": "supplier"}
    team, tables = _rule_team(rule, records=[_row("a", supplier="Known"), _row("b", supplier="Missing")],
                              references=[_row("r1", supplier="Known"), _row("r2", supplier="Known")])
    monkeypatch.setattr(checks, "get_team", lambda _: team)
    output = checks.evaluate(team["id"], tables, as_of="2026-11-02")
    findings = {row["id"]: row for row in output["findings"]}
    assert findings["check:a"]["kind"] == "input_exception"
    assert "ambiguous" in findings["check:a"]["reason"]
    assert findings["check:b"]["kind"] == "review_required"


@pytest.mark.parametrize("invalid", [None, True, "100", float("inf")])
def test_invalid_numeric_inputs_never_clear_a_check(monkeypatch, invalid):
    team, tables = _rule_team({"kind": "compare", "field": "actual", "other_field": "expected", "operator": "eq"},
                              records=[_row("a", actual=invalid, expected=100)])
    monkeypatch.setattr(checks, "get_team", lambda _: team)
    if invalid == float("inf"):
        with pytest.raises(ValueError):
            checks.evaluate(team["id"], tables, as_of="2026-11-02")
    else:
        output = checks.evaluate(team["id"], tables, as_of="2026-11-02")
        assert output["findings"][0]["kind"] == "input_exception"


@pytest.fixture
def service_setup(tmp_path, monkeypatch):
    from maverick import audit, governed_records
    from maverick.starter_teams import StarterTeamService

    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_SHORING", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_REPLICA_COUNT", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    ctx = ServiceContext("sample-tenant-a", "reviewer@example.test", "team-owner",
                         "reviewer@example.test", "structured-input", human=True,
                         authorization_role="operator", authorization_policy="operator-policy-v1",
                         budget_authority="test-budget", workspace_authority="workspace-a")
    denied = set()
    calls = []

    def authorize(context, operation, team):
        calls.append((context, operation, team))
        return operation not in denied

    svc = StarterTeamService(ctx, authorize)
    yield svc, ctx, authorize, denied, calls
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _saved(service):
    team = checks.catalog()[0]
    review = service.preview_setup(team["id"], "Taylor, business owner", "Synthetic evidence review only")
    return service.save_setup(review, confirmed=True), review


def test_setup_requires_exact_confirmed_human_review(service_setup):
    service, ctx, authorize, *_ = service_setup
    from maverick.starter_teams import StarterTeamService

    team = checks.catalog()[0]
    review = service.preview_setup(team["id"], "Taylor", "Synthetic control evidence only")
    with pytest.raises((ValueError, PermissionError)):
        service.save_setup(review, confirmed=False)
    altered = copy.deepcopy(review)
    altered["scope"] = "Unreviewed wider business scope"
    with pytest.raises((ValueError, PermissionError)):
        service.save_setup(altered, confirmed=True)
    nonhuman = StarterTeamService(replace(ctx, human=False), authorize)
    with pytest.raises(PermissionError):
        nonhuman.save_setup(review, confirmed=True)
    assert service.list_setups() == []


def test_review_replay_recovers_original_setup_and_restart_preserves_case(service_setup):
    service, ctx, authorize, *_ = service_setup
    from maverick.starter_teams import StarterTeamService

    setup, review = _saved(service)
    assert service.save_setup(review, confirmed=True)["id"] == setup["id"]
    assert service.setup_for_review(review)["id"] == setup["id"]
    first = service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    restarted = StarterTeamService(ctx, authorize)
    again = restarted.run_sample(setup["id"], idempotency_key="sample-request-0001")
    assert again["id"] == first["id"]
    assert restarted.get_case(first["id"])["output"] == first["output"]
    assert restarted.get_case_for_key(setup["id"], "sample-request-0001")["id"] == first["id"]
    assert len(restarted.list_setups()) == 1
    assert len(restarted.list_cases(setup["id"])) == 1


def test_idempotency_key_cannot_be_reused_with_changed_input_or_date(service_setup):
    service, *_ = service_setup
    setup, _ = _saved(service)
    team = checks.get_team(setup["team_id"])
    tables = copy.deepcopy(team["sample"]["tables"])
    case = service.run_inputs(setup["id"], tables, as_of="2026-11-02", idempotency_key="input-request-0001")
    assert service.run_inputs(setup["id"], tables, as_of="2026-11-02", idempotency_key="input-request-0001")["id"] == case["id"]
    changed = copy.deepcopy(tables)
    next(iter(changed.values()))[0]["source"] = "sample://changed-source"
    with pytest.raises((ValueError, PermissionError)):
        service.run_inputs(setup["id"], changed, as_of="2026-11-02", idempotency_key="input-request-0001")
    with pytest.raises((ValueError, PermissionError)):
        service.run_inputs(setup["id"], tables, as_of="2026-11-03", idempotency_key="input-request-0001")
    assert len(service.list_cases(setup["id"])) == 1


@pytest.mark.parametrize("changed", [{"tenant": "sample-tenant-b"}, {"resource_owner": "other-owner"},
                                     {"workspace_authority": "workspace-b"}])
def test_other_authorities_cannot_read_or_run_saved_work(service_setup, changed):
    service, ctx, authorize, *_ = service_setup
    from maverick.starter_teams import StarterTeamService

    setup, _ = _saved(service)
    case = service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    other = StarterTeamService(replace(ctx, **changed), authorize)
    assert other.list_setups() == []
    for read in (lambda: other.get_setup(setup["id"]), lambda: other.get_case(case["id"]),
                 lambda: other.run_sample(setup["id"], idempotency_key="sample-request-0002")):
        with pytest.raises((KeyError, PermissionError)):
            read()


def test_pause_blocks_new_work_and_resume_requires_current_revision(service_setup):
    service, *_ = service_setup
    from maverick.governed_records import RecordConflict

    setup, _ = _saved(service)
    first = service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    paused = service.set_paused(setup["id"], paused=True, expected_revision=setup["revision"])
    assert paused["paused"] is True
    assert service.get_case(first["id"])["id"] == first["id"]
    with pytest.raises((ValueError, PermissionError)):
        service.run_sample(setup["id"], idempotency_key="sample-request-0002")
    with pytest.raises((ValueError, RecordConflict)):
        service.set_paused(setup["id"], paused=False, expected_revision=setup["revision"])
    resumed = service.set_paused(setup["id"], paused=False, expected_revision=paused["revision"])
    assert resumed["paused"] is False
    assert service.run_sample(setup["id"], idempotency_key="sample-request-0002")["id"] != first["id"]


def test_current_permission_is_rechecked_after_review_and_before_run(service_setup):
    service, _, _, denied, calls = service_setup
    team = checks.catalog()[0]
    review = service.preview_setup(team["id"], "Taylor", "Synthetic evidence")
    denied.add("setup")
    with pytest.raises(PermissionError):
        service.save_setup(review, confirmed=True)
    denied.clear()
    setup = service.save_setup(review, confirmed=True)
    denied.add("run")
    with pytest.raises(PermissionError):
        service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    assert service.list_cases(setup["id"]) == []
    assert any(operation == "setup" for _, operation, _ in calls)
    assert any(operation == "run" for _, operation, _ in calls)


def test_false_or_missing_authorization_never_grants_setup(service_setup):
    _, ctx, *_ = service_setup
    from maverick.starter_teams import StarterTeamService

    for result in (None, False, "allowed"):
        service = StarterTeamService(ctx, lambda *args, result=result: result)
        with pytest.raises(PermissionError):
            service.preview_setup(checks.catalog()[0]["id"], "Taylor", "Synthetic evidence")


def test_disabled_shoring_preserves_records_but_refuses_new_access(service_setup, monkeypatch):
    service, *_ = service_setup
    setup, _ = _saved(service)
    monkeypatch.setenv("MAVERICK_SHORING", "0")
    with pytest.raises((ValueError, PermissionError)):
        service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    monkeypatch.setenv("MAVERICK_SHORING", "1")
    assert service.get_setup(setup["id"])["id"] == setup["id"]


def test_expired_review_cannot_create_setup_but_original_receipt_remains_readable(service_setup):
    service, *_ = service_setup
    service.clock = lambda: 1_800_000_000.0
    setup, saved_review = _saved(service)
    team = checks.catalog()[0]
    pending_review = service.preview_setup(team["id"], "Taylor", "Pending synthetic evidence scope")
    service.clock = lambda: 1_800_010_000.0
    with pytest.raises(ValueError, match="expired"):
        service.save_setup(pending_review, confirmed=True)
    assert service.setup_for_review(saved_review)["id"] == setup["id"]
    assert service.save_setup(saved_review, confirmed=True)["id"] == setup["id"]
    assert len(service.list_setups()) == 1


def test_catalog_change_invalidates_review_and_saved_execution(service_setup, monkeypatch):
    from maverick import starter_teams as native

    service, *_ = service_setup
    setup, _ = _saved(service)
    original_get = native.get_team
    review = service.preview_setup(setup["team_id"], "Taylor", "Pending synthetic evidence scope")

    def changed_get(team_id):
        team = original_get(team_id)
        team["blocked_actions"] = [*team["blocked_actions"], "Newly reviewed restriction"]
        return team

    monkeypatch.setattr(native, "get_team", changed_get)
    with pytest.raises(ValueError, match="catalog changed"):
        service.save_setup(review, confirmed=True)
    with pytest.raises(ValueError, match="definition changed"):
        service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    assert service.list_cases(setup["id"]) == []


@pytest.mark.parametrize("changed", [{"actor": "other@example.test"}, {"authorization_role": "reader"},
                                     {"authorization_policy": "operator-policy-v2"}, {"budget_authority": "budget-v2"}])
def test_changed_authority_cannot_reuse_setup_approval_or_start_work(service_setup, changed):
    from maverick.starter_teams import StarterTeamService

    service, ctx, authorize, *_ = service_setup
    setup, review = _saved(service)
    current = StarterTeamService(replace(ctx, **changed), authorize)
    with pytest.raises(ValueError, match="authority changed"):
        current.save_setup(review, confirmed=True)
    with pytest.raises(PermissionError, match="authority changed"):
        current.run_sample(setup["id"], idempotency_key="sample-request-0001")


def test_authority_revocation_at_physical_write_prevents_setup(service_setup):
    from maverick.starter_teams import StarterTeamService

    service, ctx, _, *_ = service_setup
    team = checks.catalog()[0]
    review = service.preview_setup(team["id"], "Taylor", "Synthetic evidence")
    checked = 0

    def authorize(context, operation, selected_team):
        nonlocal checked
        checked += 1
        return checked == 1

    revoked = StarterTeamService(ctx, authorize)
    with pytest.raises(PermissionError):
        revoked.save_setup(review, confirmed=True)
    assert checked >= 2
    assert service.list_setups() == []


def test_sample_run_cannot_be_replayed_as_customer_evidence(service_setup):
    service, *_ = service_setup
    setup, _ = _saved(service)
    team = checks.get_team(setup["team_id"])
    sample = service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    assert sample["mode"] == "sample"
    assert sample["output"]["readiness"] == "sample_qualified"
    assert sample["output"]["business_acceptance"] == "pending_human_review"
    with pytest.raises(ValueError, match="different inputs"):
        service.run_inputs(setup["id"], team["sample"]["tables"], as_of=team["sample"]["as_of"],
                           idempotency_key="sample-request-0001")


def test_all_37_samples_can_be_reviewed_saved_run_and_recovered(service_setup):
    service, *_ = service_setup
    for team in checks.catalog():
        review = service.preview_setup(team["id"], "Taylor, sample owner", "Synthetic catalog qualification only")
        setup = service.save_setup(review, confirmed=True)
        case = service.run_sample(setup["id"], idempotency_key="catalog-qualification-0001")
        assert case["status"] == "awaiting_review", team["id"]
        assert case["output"]["readiness"] == "sample_qualified", team["id"]
        assert {item["id"] for item in case["output"]["findings"]} == set(team["sample"]["expected_findings"])
        assert service.get_case_for_key(setup["id"], "catalog-qualification-0001")["id"] == case["id"]
    assert len(service.list_setups()) == 37


def test_simultaneous_retries_create_one_case(service_setup):
    service, *_ = service_setup
    setup, _ = _saved(service)
    with ThreadPoolExecutor(max_workers=4) as pool:
        cases = list(pool.map(lambda _: service.run_sample(setup["id"], idempotency_key="concurrent-sample-0001"), range(4)))
    assert len({case["id"] for case in cases}) == 1
    assert len(service.list_cases(setup["id"])) == 1


def test_pause_receipt_is_bound_to_the_exact_change(service_setup):
    service, *_ = service_setup
    setup, _ = _saved(service)
    paused = service.set_paused(setup["id"], paused=True, expected_revision=setup["revision"],
                                idempotency_key="pause-operation-0001")
    replay = service.set_paused(setup["id"], paused=True, expected_revision=setup["revision"],
                                idempotency_key="pause-operation-0001")
    assert replay["revision"] == paused["revision"]
    receipt = service.get_pause_for_key(setup["id"], "pause-operation-0001")
    assert receipt["paused"] is True
    assert receipt["before_revision"] == setup["revision"]
    with pytest.raises(ValueError, match="different pause change"):
        service.set_paused(setup["id"], paused=False, expected_revision=paused["revision"],
                           idempotency_key="pause-operation-0001")


def test_revocation_after_analysis_retains_prepared_case_without_claiming_completion(service_setup, monkeypatch):
    from maverick import starter_teams as native

    service, _, _, denied, _ = service_setup
    setup, _ = _saved(service)
    original = native.evaluate

    def revoke_after_analysis(*args, **kwargs):
        output = original(*args, **kwargs)
        denied.add("run")
        return output

    monkeypatch.setattr(native, "evaluate", revoke_after_analysis)
    with pytest.raises(PermissionError):
        service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    prepared = service.get_case_for_key(setup["id"], "sample-request-0001")
    assert prepared["status"] == "prepared"
    assert prepared["output"] is None
    denied.clear()
    monkeypatch.setattr(native, "evaluate", original)
    completed = service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    assert completed["id"] == prepared["id"]
    assert completed["status"] == "awaiting_review"
    assert len(service.list_cases(setup["id"])) == 1


def test_invalid_date_and_reviewed_row_limit_stop_before_case_creation(service_setup):
    service, *_ = service_setup
    team = checks.catalog()[0]
    review = service.preview_setup(team["id"], "Taylor", "One row only", max_rows=1)
    setup = service.save_setup(review, confirmed=True)
    with pytest.raises(ValueError, match="row limit"):
        service.run_sample(setup["id"], idempotency_key="sample-request-0001")
    assert service.list_cases(setup["id"]) == []
    normal, _ = _saved(service)
    with pytest.raises(ValueError):
        service.run_inputs(normal["id"], team["sample"]["tables"], as_of="next week",
                           idempotency_key="invalid-date-0001")
    assert service.list_cases(normal["id"]) == []
