"""Finance observations route into the existing human-owned GRC workflow."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest
from maverick.finance import control_testing as controls


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        """[finance_operations]
enable = true
control_test_interval_seconds = 86400
evidence_due_days = 5
control_owner = "Finance Assurance"
""",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


class SimulatedCrash(BaseException):
    """Represents process loss, so the cycle's Exception handler cannot run."""


class FakeGRC:
    def __init__(self, *, fail=False, fail_after="", crash=False):
        self.fail = fail
        self.fail_after = fail_after
        self.crash = crash
        self.failed_once = False
        self.tests = []
        self.requests = []
        self.engagements = {}
        self.evidence = {}
        self.create_count = 0

    @staticmethod
    def enabled():
        return True

    def _after_commit(self, stage):
        if self.fail_after != stage or self.failed_once:
            return
        self.failed_once = True
        if self.crash:
            raise SimulatedCrash(stage)
        raise RuntimeError(f"simulated {stage} post-commit failure")

    def create_audit_engagement(self, name, framework, scope, owner, **kwargs):
        assert framework == controls.CONTROL_SET_VERSION
        assert owner == "Finance Assurance"
        assert "not an audit opinion" in scope
        self.create_count += 1
        engagement_id = kwargs.pop("engagement_id", f"AUD-test-{self.create_count}")
        row = {
            "id": engagement_id,
            "revision": 1,
            "name": name,
            "framework": framework,
            "scope": scope,
            "owner": owner,
            "control_tests": [],
            "evidence_requests": [],
            **kwargs,
        }
        self.engagements[engagement_id] = row
        self._after_commit("engagement")
        return deepcopy(row)

    def get_audit_engagement(self, engagement_id):
        row = self.engagements.get(engagement_id)
        return deepcopy(row) if row is not None else None

    def list_audit_engagements(self):
        return [deepcopy(row) for row in self.engagements.values()]

    def get_evidence(self, evidence_id):
        row = self.evidence.get(evidence_id)
        return deepcopy(row) if row is not None else None

    def record_control_test(
        self,
        engagement_id,
        control_id,
        procedure,
        result,
        *,
        evidence_ids,
        tested_by,
        expected_revision,
    ):
        if self.fail:
            raise RuntimeError("provider secret must never leak")
        assert result == "needs_review"
        assert evidence_ids == []
        body = json.loads(procedure)
        assert body["required_human_result"] is True
        assert body["automated_observation"]["citations"]
        self.tests.append((control_id, tested_by, expected_revision))
        row = self.engagements[engagement_id]
        assert row["revision"] == expected_revision
        row["control_tests"].append(
            {
                "id": f"TST-{len(self.tests)}",
                "control_id": control_id,
                "procedure": procedure,
                "result": result,
                "evidence_ids": list(evidence_ids),
                "tested_by": tested_by,
            }
        )
        row["revision"] += 1
        self._after_commit("test")
        return deepcopy(row)

    def add_evidence_request(
        self,
        engagement_id,
        description,
        owner,
        due_at,
        *,
        control_ids,
        requested_by,
        expected_revision,
    ):
        self.requests.append((description, tuple(control_ids), owner, due_at, requested_by))
        row = self.engagements[engagement_id]
        assert row["revision"] == expected_revision
        row["evidence_requests"].append(
            {
                "id": f"REQ-{len(self.requests)}",
                "description": description,
                "owner": owner,
                "due_at": due_at,
                "control_ids": list(control_ids),
                "requested_by": requested_by,
            }
        )
        row["revision"] += 1
        self._after_commit("request")
        return deepcopy(row)


def _observations():
    return [
        controls.FinanceControlObservation(
            "FIN-TEST-01",
            "Deterministic test control",
            "active",
            "The bounded probe executed.",
            "Finance controls",
            ("https://example.test/primary-source",),
        ),
        controls.FinanceControlObservation(
            "FIN-TEST-02",
            "Second deterministic test control",
            "action_needed",
            "The probe found a configuration gap.",
            "Finance controls",
            ("urn:test:control-source",),
        ),
    ]


def test_cycle_summary_projection_is_read_bounded_and_cursor_traversable(monkeypatch):
    class SummaryStore:
        backend_kind = "local"

        def __init__(self):
            self.reads = 0
            self.rows = {
                f"FCT-{index}": {
                    "id": f"FCT-{index}",
                    "schema": controls.CYCLE_SCHEMA,
                    "status": "pending_human_evidence",
                    "observations": [],
                    "revision": 1,
                }
                for index in range(3)
            }

        def iter_record_ids(self, *, start_after="", limit=100):
            identifiers = sorted(self.rows)
            pivot = next(
                (
                    index
                    for index, identifier in enumerate(identifiers)
                    if identifier > start_after
                ),
                len(identifiers),
            )
            for identifier in (identifiers[pivot:] + identifiers[:pivot])[:limit]:
                yield identifier, identifier

        def get(self, record_id):
            self.reads += 1
            return deepcopy(self.rows.get(record_id))

    store = SummaryStore()
    monkeypatch.setattr(controls, "_CYCLES", store)

    first = controls.list_cycle_summaries(limit=1)
    assert store.reads == 1
    assert first["has_more"] is True
    assert first["next_cursor"]
    assert "observations" not in first["cycles"][0]

    second = controls.list_cycle_summaries(
        limit=1,
        cursor=first["next_cursor"],
    )
    assert store.reads == 2
    assert second["cycles"][0]["id"] != first["cycles"][0]["id"]

    store.reads = 0
    summary = controls.cycle_status_summary(scan_limit=2)
    assert summary["record_reads"] == 2
    assert summary["truncated"] is True
    assert store.reads == 2


def test_aml_freshness_observation_fails_closed_on_inventory_sentinel(monkeypatch):
    from maverick.finance import aml_screening

    monkeypatch.setattr(
        aml_screening,
        "list_versions",
        lambda **_kwargs: [{"id": f"FSL-{index}"} for index in range(10_001)],
    )

    observation = controls._aml_freshness_observation(1_900_000_000)

    assert observation.control_id == "FIN-AML-02"
    assert observation.observed_state == "action_needed"
    assert "truncated" in observation.detail


def _record_fake_human_result(
    grc: FakeGRC,
    engagement_id: str,
    control_id: str,
    result: str,
    *,
    evidence_status: str = "approved",
) -> None:
    row = grc.engagements[engagement_id]
    evidence_id = f"EVD-{engagement_id}-{control_id}"
    grc.evidence[evidence_id] = {"id": evidence_id, "status": evidence_status}
    request = next(
        item
        for item in row["evidence_requests"]
        if control_id in item["control_ids"]
    )
    request["status"] = "accepted"
    request["evidence_ids"] = [evidence_id]
    row["control_tests"].append(
        {
            "id": f"TST-human-{control_id}-{len(row['control_tests']) + 1}",
            "control_id": control_id,
            "procedure": "Human evidence review and control disposition.",
            "result": result,
            "evidence_ids": [evidence_id],
            "tested_by": "qualified-reviewer@example.com",
            "tested_at": 1_900_000_100.0,
        }
    )
    row["revision"] += 2


def test_cycle_routes_needs_review_tests_and_evidence_requests():
    grc = FakeGRC()
    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=_observations(),
        ops=grc,
    )

    assert cycle["status"] == "pending_human_evidence"
    assert cycle["engagement_id"] == controls._engagement_id(cycle["id"])
    assert cycle["engagement_revision"] == 5
    assert cycle["step_cursor"] == {"control_index": 2, "phase": "complete"}
    assert cycle["control_owner"] == "Finance Assurance"
    assert cycle["evidence_due_days"] == 5
    assert [item[0] for item in grc.tests] == ["FIN-TEST-01", "FIN-TEST-02"]
    assert [item[1] for item in grc.requests] == [("FIN-TEST-01",), ("FIN-TEST-02",)]
    assert all(item[2] == "Finance Assurance" for item in grc.requests)


def test_cycle_reconciles_against_the_real_security_grc_store():
    from maverick import security_ops

    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=security_ops,
    )

    engagement = security_ops.get_audit_engagement(cycle["engagement_id"])
    assert engagement is not None
    assert len(engagement["control_tests"]) == 1
    assert len(engagement["evidence_requests"]) == 1
    assert engagement["control_tests"][0]["result"] == "needs_review"
    assert controls._engagement_marker(cycle["id"]) in engagement["scope"]


def test_grc_readback_stays_pending_until_every_control_has_human_evidence():
    grc = FakeGRC()
    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=_observations(),
        ops=grc,
    )
    _record_fake_human_result(grc, cycle["engagement_id"], "FIN-TEST-01", "pass")

    partial = controls.reconcile_control_cycle(
        cycle["id"],
        actor="system:finance-control-scheduler",
        ops=grc,
    )

    assert partial["status"] == "pending_human_evidence"
    assert partial["grc_result_counts"] == {
        "total": 2,
        "pass": 1,
        "fail": 0,
        "pending": 1,
    }
    assert partial["grc_pending_control_ids"] == ["FIN-TEST-02"]
    assert partial["grc_results"][0]["test_id"] == "TST-human-FIN-TEST-01-3"

    _record_fake_human_result(grc, cycle["engagement_id"], "FIN-TEST-02", "fail")
    completed = controls.reconcile_control_cycle(
        cycle["id"],
        actor="system:finance-control-scheduler",
        ops=grc,
    )
    assert completed["status"] == "human_review_failed"
    assert completed["grc_result_counts"] == {
        "total": 2,
        "pass": 1,
        "fail": 1,
        "pending": 0,
    }
    assert completed["grc_pending_control_ids"] == []
    assert completed["human_review_completed_at"] > 0

    unchanged = controls.reconcile_control_cycle(
        cycle["id"],
        actor="system:finance-control-scheduler",
        ops=grc,
    )
    assert unchanged["revision"] == completed["revision"]


def test_scheduled_readback_rechecks_a_changed_terminal_grc_disposition():
    grc = FakeGRC()
    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=grc,
    )
    _record_fake_human_result(grc, cycle["engagement_id"], "FIN-TEST-01", "pass")
    passed = controls.reconcile_control_cycle(
        cycle["id"],
        actor="system:finance-control-scheduler",
        ops=grc,
    )
    assert passed["status"] == "human_review_passed"

    _record_fake_human_result(grc, cycle["engagement_id"], "FIN-TEST-01", "fail")
    reconciled = controls.reconcile_scheduled_cycles(
        actor="system:finance-control-scheduler",
        scan_limit=1,
        priority_cycle_id=cycle["id"],
        ops=grc,
    )

    [revised] = [row for row in reconciled if row["id"] == cycle["id"]]
    assert revised["status"] == "human_review_failed"
    assert revised["grc_result_counts"]["fail"] == 1


def test_grc_readback_fails_closed_on_unapproved_terminal_evidence():
    grc = FakeGRC()
    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=grc,
    )
    _record_fake_human_result(
        grc,
        cycle["engagement_id"],
        "FIN-TEST-01",
        "pass",
        evidence_status="pending_review",
    )

    with pytest.raises(RuntimeError, match="not approved"):
        controls.reconcile_control_cycle(
            cycle["id"],
            actor="system:finance-control-scheduler",
            ops=grc,
        )
    assert controls.get_cycle(cycle["id"])["status"] == "pending_human_evidence"


def test_grc_readback_does_not_promote_a_test_while_its_request_is_open():
    grc = FakeGRC()
    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=grc,
    )
    _record_fake_human_result(
        grc,
        cycle["engagement_id"],
        "FIN-TEST-01",
        "pass",
    )
    grc.engagements[cycle["engagement_id"]]["evidence_requests"][0]["status"] = "open"

    reconciled = controls.reconcile_control_cycle(
        cycle["id"],
        actor="system:finance-control-scheduler",
        ops=grc,
    )

    assert reconciled["status"] == "pending_human_evidence"
    assert reconciled["grc_results"] == []
    assert reconciled["grc_result_counts"]["pending"] == 1


def test_grc_readback_uses_real_approved_evidence_and_human_verdict():
    from maverick import security_ops

    cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=security_ops,
    )
    evidence = security_ops.map_evidence(
        "Finance control evidence",
        "A qualified reviewer inspected the cited finance control run evidence.",
        submitted_by="evidence-owner@example.com",
    )
    approved = security_ops.decide_evidence(
        evidence["id"],
        "approved",
        "Source and integrity were reviewed.",
        "evidence-approver@example.com",
        evidence["revision"],
    )
    engagement = security_ops.get_audit_engagement(cycle["engagement_id"])
    accepted = security_ops.update_evidence_request(
        engagement["id"],
        engagement["evidence_requests"][0]["id"],
        "accepted",
        evidence_ids=[approved["id"]],
        updated_by="audit-owner@example.com",
        expected_revision=engagement["revision"],
    )
    tested = security_ops.record_control_test(
        accepted["id"],
        "FIN-TEST-01",
        "Human reviewed approved evidence for this finance control cycle.",
        "pass",
        evidence_ids=[approved["id"]],
        tested_by="qualified-reviewer@example.com",
        expected_revision=accepted["revision"],
    )

    reconciled = controls.reconcile_control_cycle(
        cycle["id"],
        actor="system:finance-control-scheduler",
        ops=security_ops,
    )

    assert reconciled["status"] == "human_review_passed"
    assert reconciled["engagement_revision"] == tested["revision"]
    assert reconciled["grc_results"] == [
        {
            "control_id": "FIN-TEST-01",
            "result": "pass",
            "test_id": tested["control_tests"][-1]["id"],
            "evidence_request_id": accepted["evidence_requests"][0]["id"],
            "evidence_ids": [approved["id"]],
            "tested_by": "qualified-reviewer@example.com",
            "tested_at": tested["control_tests"][-1]["tested_at"],
        }
    ]


def test_scheduled_readback_uses_a_bounded_rotating_cursor_across_periods():
    grc = FakeGRC()
    old_cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=grc,
    )
    new_cycle = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_086_400,
        observations=[_observations()[0]],
        ops=grc,
    )
    _record_fake_human_result(
        grc, old_cycle["engagement_id"], "FIN-TEST-01", "pass"
    )
    _record_fake_human_result(
        grc, new_cycle["engagement_id"], "FIN-TEST-01", "pass"
    )

    [first] = controls.reconcile_scheduled_cycles(
        actor="system:finance-control-scheduler",
        scan_limit=1,
        ops=grc,
    )
    [second] = controls.reconcile_scheduled_cycles(
        actor="system:finance-control-scheduler",
        scan_limit=1,
        ops=grc,
    )

    assert {first["id"], second["id"]} == {old_cycle["id"], new_cycle["id"]}
    assert first["status"] == second["status"] == "human_review_passed"


def test_scheduled_readback_continues_past_one_invalid_grc_cycle():
    grc = FakeGRC()
    invalid = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_000_000,
        observations=[_observations()[0]],
        ops=grc,
    )
    valid = controls.run_control_cycle(
        actor="system:finance-control-scheduler",
        now=1_900_086_400,
        observations=[_observations()[0]],
        ops=grc,
    )
    _record_fake_human_result(
        grc,
        invalid["engagement_id"],
        "FIN-TEST-01",
        "pass",
        evidence_status="pending_review",
    )
    _record_fake_human_result(
        grc, valid["engagement_id"], "FIN-TEST-01", "pass"
    )

    with pytest.raises(RuntimeError, match="1 scheduled GRC reconciliation"):
        controls.reconcile_scheduled_cycles(
            actor="system:finance-control-scheduler",
            scan_limit=2,
            ops=grc,
        )

    assert controls.get_cycle(invalid["id"])["status"] == "pending_human_evidence"
    assert controls.get_cycle(valid["id"])["status"] == "human_review_passed"
    assert controls._RECONCILE_STATE.get(controls._RECONCILE_STATE_ID)["cursor"]


def test_cycle_period_is_idempotent_and_does_not_duplicate_grc_work():
    first_grc = FakeGRC()
    first = controls.run_control_cycle(
        actor="scheduler",
        now=1_900_000_000,
        observations=_observations(),
        ops=first_grc,
    )
    second_grc = FakeGRC()
    second = controls.run_control_cycle(
        actor="scheduler-retry",
        now=1_900_000_001,
        observations=_observations(),
        ops=second_grc,
    )
    assert second["id"] == first["id"]
    assert second_grc.tests == []
    assert second_grc.requests == []


def test_failed_grc_call_is_visible_but_error_text_is_redacted():
    with pytest.raises(RuntimeError, match="provider secret"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=_observations(),
            ops=FakeGRC(fail=True),
        )
    [cycle] = controls.list_cycles()
    assert cycle["status"] == "failed"
    assert cycle["engagement_id"] == controls._engagement_id(cycle["id"])
    assert cycle["error_type"] == "RuntimeError"
    assert "provider secret" not in json.dumps(cycle)


@pytest.mark.parametrize("failure_stage", ["test", "request"])
def test_failed_post_commit_step_reconciles_without_orphan_or_duplicate(failure_stage):
    grc = FakeGRC(fail_after=failure_stage)
    with pytest.raises(RuntimeError, match="post-commit failure"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=_observations(),
            ops=grc,
        )

    [failed] = controls.list_cycles()
    assert failed["status"] == "failed"

    completed = controls.run_control_cycle(
        actor="scheduler-retry",
        now=1_900_000_001,
        observations=[
            # Retry input is deliberately different; the durable cycle's
            # original observation snapshot remains authoritative.
            {
                "control_id": "SHOULD-NOT-REPLACE",
                "title": "Ignored retry input",
                "observed_state": "unknown",
                "detail": "Ignored.",
                "framework": "Ignored",
                "citations": ["urn:test:ignored"],
            }
        ],
        ops=grc,
    )

    assert completed["status"] == "pending_human_evidence"
    assert completed["attempt_count"] == 2
    assert grc.create_count == 1
    assert [item[0] for item in grc.tests] == ["FIN-TEST-01", "FIN-TEST-02"]
    assert [item[1] for item in grc.requests] == [
        ("FIN-TEST-01",),
        ("FIN-TEST-02",),
    ]


def test_engagement_post_commit_error_recovers_by_direct_deterministic_id():
    grc = FakeGRC(fail_after="engagement")
    grc.list_audit_engagements = lambda: pytest.fail(
        "recovery must not enumerate all GRC engagements"
    )

    cycle = controls.run_control_cycle(
        actor="scheduler",
        now=1_900_000_000,
        observations=_observations(),
        ops=grc,
    )

    assert cycle["status"] == "pending_human_evidence"
    assert cycle["engagement_id"] == controls._engagement_id(cycle["id"])
    assert grc.create_count == 1
    assert len(grc.engagements) == 1


def test_retry_reuses_persisted_owner_and_evidence_deadline(_isolate):
    from maverick import config

    grc = FakeGRC(fail_after="request")
    with pytest.raises(RuntimeError, match="post-commit failure"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=_observations(),
            ops=grc,
        )

    config_path = _isolate / "config.toml"
    config_path.write_text(
        """[finance_operations]
enable = true
control_test_interval_seconds = 86400
evidence_due_days = 30
control_owner = "Changed Owner"
""",
        encoding="utf-8",
    )
    config.reset_config_cache()

    completed = controls.run_control_cycle(
        actor="scheduler-retry",
        now=1_900_000_001,
        observations=_observations(),
        ops=grc,
    )

    assert completed["control_owner"] == "Finance Assurance"
    assert completed["evidence_due_days"] == 5
    assert [request[2] for request in grc.requests] == [
        "Finance Assurance",
        "Finance Assurance",
    ]
    assert [request[3] for request in grc.requests] == [
        1_900_000_000 + 5 * 86400,
        1_900_000_000 + 5 * 86400,
    ]


def test_recoverable_legacy_cycle_backfills_execution_config_once():
    grc = FakeGRC(fail_after="test")
    with pytest.raises(RuntimeError, match="post-commit failure"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=_observations(),
            ops=grc,
        )
    [failed] = controls.list_cycles()

    def _make_legacy(record):
        record.pop("control_owner")
        record.pop("evidence_due_days")

    legacy = controls._CYCLES.update(
        failed["id"],
        _make_legacy,
        expected_revision=failed["revision"],
        action="test_legacy_cycle",
        actor="test",
    )
    assert legacy is not None
    assert controls.get_cycle(failed["id"])["status"] == "failed"

    completed = controls.run_control_cycle(
        actor="scheduler-recovery",
        now=1_900_000_001,
        observations=_observations(),
        ops=grc,
    )

    assert completed["control_owner"] == "Finance Assurance"
    assert completed["evidence_due_days"] == 5
    assert completed["attempt_count"] == 2
    assert grc.create_count == 1


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda record: record.pop("control_owner"), "configuration is incomplete"),
        (lambda record: record.__setitem__("evidence_due_days", 0), "evidence_due_days"),
    ],
)
def test_cycle_load_fails_closed_on_invalid_execution_config(mutate, message):
    cycle = controls.run_control_cycle(
        actor="scheduler",
        now=1_900_000_000,
        observations=_observations(),
        ops=FakeGRC(),
    )
    corrupted = controls._CYCLES.update(
        cycle["id"],
        mutate,
        expected_revision=cycle["revision"],
        action="test_corrupt_cycle",
        actor="test",
    )
    assert corrupted is not None

    with pytest.raises(ValueError, match=message):
        controls.get_cycle(cycle["id"])
    with pytest.raises(ValueError, match=message):
        controls.list_cycles()


def test_expired_running_cycle_resumes_after_process_crash_without_duplicate(
    monkeypatch,
):
    monkeypatch.setattr(controls, "_CYCLE_LEASE_SECONDS", 0.0)
    grc = FakeGRC(fail_after="test", crash=True)
    with pytest.raises(SimulatedCrash):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=_observations(),
            ops=grc,
        )

    [abandoned] = controls.list_cycles()
    assert abandoned["status"] == "running"

    completed = controls.run_control_cycle(
        actor="scheduler-recovery",
        now=1_900_000_001,
        observations=_observations(),
        ops=grc,
    )

    assert completed["status"] == "pending_human_evidence"
    assert completed["run_generation"] == 2
    assert grc.create_count == 1
    assert [item[0] for item in grc.tests] == ["FIN-TEST-01", "FIN-TEST-02"]
    assert [item[1] for item in grc.requests] == [
        ("FIN-TEST-01",),
        ("FIN-TEST-02",),
    ]


def test_disabled_grc_does_not_create_cycle():
    class Disabled(FakeGRC):
        @staticmethod
        def enabled():
            return False

    with pytest.raises(RuntimeError, match="disabled"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=_observations(),
            ops=Disabled(),
        )
    assert controls.list_cycles() == []


def test_observations_require_citations_and_unique_control_ids():
    with pytest.raises(ValueError, match="citation"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=[{
                "control_id": "FIN-X",
                "title": "Missing source",
                "observed_state": "active",
                "detail": "No provenance.",
                "framework": "Finance",
                "citations": [],
            }],
            ops=FakeGRC(),
        )

    with pytest.raises(ValueError, match="requires a citation"):
        controls.run_control_cycle(
            actor="scheduler",
            now=1_900_000_000,
            observations=[{
                "control_id": "FIN-WHITESPACE",
                "title": "Whitespace source",
                "observed_state": "active",
                "detail": "No usable provenance.",
                "framework": "Finance",
                "citations": ["   ", "\t"],
            }],
            ops=FakeGRC(),
        )


def test_long_procedure_is_valid_bounded_json_not_a_raw_slice():
    grc = FakeGRC()
    row = controls.FinanceControlObservation(
        "FIN-LONG-01",
        "Long deterministic observation",
        "active",
        "x" * 10_000,
        "Finance controls",
        ("https://example.test/primary-source",),
    )

    cycle = controls.run_control_cycle(
        actor="scheduler",
        now=1_900_000_000,
        observations=[row],
        ops=grc,
    )

    [test] = grc.engagements[cycle["engagement_id"]]["control_tests"]
    assert len(test["procedure"]) <= 4_000
    decoded = json.loads(test["procedure"])
    assert decoded["automated_observation"]["detail_truncated"] is True
    assert decoded["automated_observation"]["detail"]


def test_licensing_observation_claims_the_implemented_fifty_states_only():
    observation = controls._licensing_observation()
    assert "50-state versioned packs" in observation.detail
    assert "plus DC" not in observation.detail
    assert observation.observed_state == "action_needed"
    assert "legal determinations" in observation.detail


def test_schedule_configuration_rejects_sub_minute_busy_loop(_isolate):
    tmp_path = _isolate
    from maverick import config

    (tmp_path / "config.toml").write_text(
        "[finance_operations]\nenable = true\ncontrol_test_interval_seconds = 10\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    with pytest.raises(ValueError, match="between 300"):
        controls.schedule_config()
