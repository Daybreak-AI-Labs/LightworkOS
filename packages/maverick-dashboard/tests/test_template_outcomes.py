from maverick_dashboard.template_outcomes_api import project_report


def test_all_planned_cases_remain_denominator_and_missing_cost_is_unknown():
    report = {"cases": [
        {"status": "paired", "source": {"status": "done"}, "measurement": {"corrections": 1}},
        {"status": "incomplete", "source": {"status": "failed"}},
        {"status": "incomplete", "source": {"status": "cancelled"}},
        {"status": "unavailable"},
    ], "groups": {"all": {"accepted": 1, "reported_cost_difference": "10", "currency": "USD"}}}
    result = project_report(report)
    assert result["planned_cases"] == 4 and result["acceptance_rate"] == 0.25
    assert result["failed_cases"] == result["cancelled_cases"] == 1
    assert result["correction_observed_cases"] == 1 and result["correction_rate"] == 0.25
    assert result["reported_cost_difference"] is None and not result["reported_cost_complete"]
    assert result["attempt_count"] is None and result["provider_invoice_verified"] is False


def test_mixed_currencies_or_missing_cost_family_never_form_complete_total():
    from maverick.outcome_accounting import COST_COVERAGE_FAMILIES

    measurement = {"corrections": 0, "ai_total_cost": "1", "baseline_cost": "2",
                   "cost_coverage": {key: {"status": "included"} for key in COST_COVERAGE_FAMILIES}}
    report = {"cases": [{"status": "paired", "measurement": measurement}],
              "groups": {"all": {"accepted": 1, "reported_cost_difference": None, "currency": None}}}
    assert project_report(report)["reported_cost_complete"] is False
    report["groups"]["all"].update(reported_cost_difference="1", currency="USD")
    assert project_report(report)["reported_cost_complete"] is True
    measurement["cost_coverage"].pop(next(iter(measurement["cost_coverage"])))
    assert project_report(report)["reported_cost_difference"] is None


def test_each_pilot_is_read_once_so_one_removed_meanwhile_cannot_break_the_page(monkeypatch):
    # The page listed the pilots, then read each one again: twice the reads, and
    # a pilot removed between the two reads raised an unhandled LookupError (500).
    from types import SimpleNamespace

    from maverick_dashboard import outcome_pilots
    from maverick_dashboard import template_outcomes_api as api

    context = "c" * 64
    record = {"id": "OP-1", "title": "Pilot", "revision": 1, "workflow": "intake", "context": context,
              "created_at": 1.0, "cases": []}
    reads = []

    def get(record_id):
        reads.append(record_id)
        return dict(record) if len(reads) == 1 else None  # removed right after the listing read

    monkeypatch.setattr(api, "_context", lambda request: context)
    monkeypatch.setattr(api, "_template", lambda request, name: (SimpleNamespace(generation=1), "v" * 64))
    monkeypatch.setattr(outcome_pilots.STORE, "iter_record_ids",
                        lambda start_after="", limit=100: [("OP-1", "OP-1")] if not start_after else [])
    monkeypatch.setattr(outcome_pilots.STORE, "get", get)
    result = api.template_outcomes(object(), "intake-template")
    assert result["pilot_choices"] == [{"id": "OP-1", "title": "Pilot", "revision": 1, "workflow": "intake"}]
    assert result["evidence"] == [] and reads == ["OP-1"]
