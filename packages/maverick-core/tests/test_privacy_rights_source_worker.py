from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import privacy_rights_orchestration as rights
from maverick import privacy_rights_source_worker as worker


class Clock:
    def __init__(self) -> None:
        self.value = 2_100_000_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _subject_digest(tenant_id: str, value: str) -> str:
    material = (
        tenant_id.encode()
        + b"\x00subject_reference\x00"
        + value.encode()
    )
    return hmac.new(b"k" * 32, material, hashlib.sha256).hexdigest()


def _prepared() -> worker.PreparedProviderMutation:
    return worker.PreparedProviderMutation(
        status="ready",
        target_ref="target:one",
        target_binding_sha256=_digest("target-one"),
        acknowledgement_sha256=_digest("prepared-ack"),
        acknowledgement_ref="provider:prepared",
        provider_evidence_sha256=_digest("prepared-evidence"),
        opaque_ref="provider:prepared-evidence",
        record_count=1,
        provider_retention_state="active",
    )


def _mutation_success() -> worker.ProviderOutcome:
    return worker.ProviderOutcome(
        status="complete",
        record_count=1,
        acknowledgement_sha256=_digest("mutation-ack"),
        acknowledgement_ref="provider:mutation",
        provider_evidence_sha256=_digest("mutation-evidence"),
        opaque_ref="provider:mutation-evidence",
        external_side_effect=True,
    )


def _already_absent() -> worker.PreparedProviderMutation:
    return worker.PreparedProviderMutation(
        status="not_found",
        target_ref=None,
        target_binding_sha256=None,
        acknowledgement_sha256=_digest("already-absent-ack"),
        acknowledgement_ref="provider:already-absent",
        provider_evidence_sha256=_digest("already-absent-evidence"),
        opaque_ref="provider:already-absent-evidence",
        record_count=0,
        provider_retention_state="already_absent",
    )


@pytest.fixture()
def estate(tmp_path: Path):
    actor = {"value": "planner"}
    clock = Clock()
    counter = {"value": 0}

    def token() -> str:
        counter["value"] += 1
        return f"lease-token-{counter['value']}"

    store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / "rights.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=clock,
        token_factory=token,
    )
    return store, actor, clock


def _prepare(
    estate,
    *,
    case_id: str,
    phase: str,
    requested_right: str,
    source=None,
):
    store, actor, clock = estate
    source = source or store.enroll_source(
        "tenant-a",
        "crm",
        adapter_ref="salesforce-contact-v1",
        credential_ref="env:SALESFORCE_RIGHTS_TOKEN",
        capabilities=[phase],
        expected_revision=0,
        idempotency_key=f"source-{case_id}",
    )
    case = store.open_case(
        "tenant-a",
        case_id,
        request_version=1,
        external_request_ref=f"request-{case_id}",
        subject_reference="person@example.test",
        rights=[requested_right],
        retained_until=clock() + 600,
        idempotency_key=f"open-{case_id}",
    )
    case = store.set_identity_verification(
        "tenant-a",
        case_id,
        status="verified",
        evidence_sha256=_digest("identity"),
        evidence_ref=f"identity:{case_id}",
        expected_revision=case.revision,
        idempotency_key=f"verify-{case_id}",
    )
    task = store.plan_source_tasks(
        "tenant-a",
        case_id,
        "crm",
        phases=[phase],
        max_attempts=3,
        expected_case_revision=case.revision,
        idempotency_key=f"plan-{case_id}",
    )[0]
    if task.destructive:
        actor["value"] = "approver"
        task = store.approve_destructive_work(
            "tenant-a",
            task.task_id,
            expected_revision=task.revision,
            idempotency_key=f"approve-{case_id}",
        )
    actor["value"] = "source-worker"
    return source, case, task


def _runtime(
    estate,
    adapter,
    source,
    case,
    *,
    subject_resolver=None,
    credential_resolver=None,
    adapter_authority_sha256=None,
):
    store, _actor, clock = estate
    subject_sha256 = _subject_digest("tenant-a", "person@example.test")
    return worker.PrivacyRightsSourceWorker(
        store_factory=lambda _tenant, _principal: store,
        subject_resolver=(
            subject_resolver
            or (
                lambda tenant, case_id, _source_id: worker.SubjectBinding(
                    tenant_id=tenant,
                    case_id=case_id,
                    subject_reference="person@example.test",
                    authority_sha256=subject_sha256,
                    expires_at=clock() + 60,
                )
            )
        ),
        credential_resolver=(
            credential_resolver or (lambda *_: "ephemeral-provider-token")
        ),
        adapter_resolver=lambda tenant, source_id: worker.AdapterBinding(
            tenant_id=tenant,
            source_id=source_id,
            adapter_ref=source.adapter_ref,
            credential_ref=source.credential_ref,
            capabilities=source.capabilities,
            authority_sha256=(
                adapter_authority_sha256
                or worker.adapter_authority_sha256(
                    tenant_id=tenant,
                    source_id=source_id,
                    adapter_ref=source.adapter_ref,
                    credential_ref=source.credential_ref,
                    capabilities=source.capabilities,
                )
            ),
            adapter=adapter,
        ),
        owned_source_ids=(source.source_id,),
        subject_digest_resolver=_subject_digest,
        clock=clock,
    )


def test_worker_atomically_completes_provider_evidence_without_raw_values(estate) -> None:
    source, case, task = _prepare(
        estate,
        case_id="case-read",
        phase="discover",
        requested_right="access",
    )
    calls: list[dict[str, object]] = []

    class Adapter:
        def execute(self, **kwargs):
            calls.append(kwargs)
            return worker.ProviderOutcome(
                status="complete",
                record_count=1,
                acknowledgement_sha256=_digest("ack"),
                acknowledgement_ref="salesforce:ack",
                provider_evidence_sha256=_digest("evidence"),
                opaque_ref="salesforce:evidence",
                external_side_effect=False,
            )

    result = _runtime(estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-read",
    )

    store, _actor, _clock = estate
    assert result.claimed == 1
    assert result.completed == 1
    assert result.provider_writes_possible is False
    assert store.get_task("tenant-a", task.task_id).state == "complete"
    assert calls[0]["subject_reference"] == "person@example.test"
    assert calls[0]["credential"] == "ephemeral-provider-token"
    exported = store.export_case(
        "tenant-a",
        case.case_id,
        "export:no-raw-values",
        retained_until=_clock() + 60,
        idempotency_key="export-no-raw-values",
    )
    assert "person@example.test" not in repr(exported)
    assert "ephemeral-provider-token" not in repr(exported)


def test_uncertain_delete_is_parked_and_never_lease_replayed(estate) -> None:
    source, case, _task = _prepare(
        estate,
        case_id="case-delete",
        phase="delete",
        requested_right="erasure",
    )

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            return _prepared()

        def execute_prepared(self, **_kwargs):
            raise RuntimeError("socket closed after request bytes were sent")

    result = _runtime(estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-delete",
        lease_seconds=10,
    )
    store, _actor, clock = estate
    assert result.ambiguous == 1
    assert result.provider_writes_possible is True
    clock.advance(30)
    assert (
        store.claim_callbacks(
            "tenant-a",
            limit=10,
            lease_seconds=10,
            idempotency_key="must-not-replay-delete",
        )
        == ()
    )


@pytest.mark.parametrize(
    ("disposition", "expected_state", "result_field"),
    [
        ("applied", "acked", "resolved"),
        ("absent", "ambiguous", "still_ambiguous"),
        ("unknown", "ambiguous", "still_ambiguous"),
    ],
)
def test_ambiguous_delete_is_read_only_reconciled_without_optimistic_replay(
    estate,
    disposition: str,
    expected_state: str,
    result_field: str,
) -> None:
    source, case, task = _prepare(
        estate,
        case_id=f"case-reconcile-{disposition}",
        phase="delete",
        requested_right="erasure",
    )
    calls = {"mutations": 0, "probes": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            return _prepared()

        def execute_prepared(self, **_kwargs):
            calls["mutations"] += 1
            raise RuntimeError("connection closed after request send")

        def reconcile_mutation(self, **_kwargs):
            calls["probes"] += 1
            return worker.ProviderReconciliationOutcome(
                disposition=disposition,
                provider_evidence_sha256=_digest(f"probe-{disposition}"),
                provider_evidence_ref=f"provider:probe:{disposition}",
                record_count=1 if disposition == "absent" else 0,
                provider_retention_state={
                    "applied": "purged",
                    "absent": "active",
                    "unknown": "unknown",
                }[disposition],
            )

    runtime = _runtime(estate, Adapter(), source, case)
    first = runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id=f"run-ambiguous-{disposition}",
    )
    assert first.ambiguous == 1

    reconciled = runtime.reconcile_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id=f"reconcile-{disposition}",
        retry_delay_seconds=10,
    )
    store, _actor, _clock = estate
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert reconciled.inspected == 1
    assert getattr(reconciled, result_field) == 1
    assert callback.state == expected_state
    assert calls == {"mutations": 1, "probes": 1}
    assert reconciled.provider_writes_performed is False
    assert reconciled.optimistic_replays_performed == 0
    if disposition == "applied":
        completed = store.get_task("tenant-a", task.task_id)
        assert completed.state == "complete"
        assert completed.evidence_id is not None
    else:
        assert store.get_task("tenant-a", task.task_id).state == "planned"
        # A persisted unknown result must honor its retry time across workers.
        again = _runtime(estate, Adapter(), source, case).reconcile_once(
            "tenant-a", worker_ref="source-worker", run_id="before-retry",
            retry_delay_seconds=10,
        )
        assert again.inspected == 0
        assert calls == {"mutations": 1, "probes": 1}
        _clock.advance(10)
        due = runtime.reconcile_once(
            "tenant-a", worker_ref="source-worker", run_id="retry-due",
            retry_delay_seconds=10,
        )
        assert due.inspected == 1
        assert calls == {"mutations": 1, "probes": 2}


def test_failing_reconciliation_defers_durably_and_next_case_progresses(estate):
    source, first, _ = _prepare(
        estate, case_id="case-failing", phase="delete", requested_right="erasure",
    )
    _prepare(estate, case_id="case-ready", phase="delete", requested_right="erasure", source=source)
    calls = []
    mutation_calls = []

    class Adapter:
        fail_case = None

        def prepare_mutation(self, **_kwargs):
            return _prepared()

        def execute_prepared(self, **kwargs):
            mutation_calls.append(kwargs["case_id"])
            raise RuntimeError("connection closed after send")

        def reconcile_mutation(self, **kwargs):
            calls.append(kwargs["case_id"])
            if kwargs["case_id"] == self.fail_case:
                raise worker.ProviderRetryableError
            return worker.ProviderReconciliationOutcome(
                disposition="applied", provider_evidence_sha256=_digest("probe-applied"),
                provider_evidence_ref="provider:probe:applied", record_count=0,
                provider_retention_state="purged",
            )

    adapter = Adapter()
    runtime = _runtime(estate, adapter, source, first)
    assert runtime.run_once("tenant-a", worker_ref="source-worker", run_id="mutate").ambiguous == 2
    store, _, clock = estate
    pending = store.due_reconciliation_callbacks("tenant-a", source_ids=("crm",), limit=2)
    adapter.fail_case = pending[0].case_id
    assert store.due_reconciliation_callbacks("tenant-a", source_ids=("other",), limit=1) == ()
    failed = runtime.reconcile_once(
        "tenant-a", worker_ref="source-worker", run_id="failed-read", limit=1, retry_delay_seconds=30,
    )
    assert failed.errors == 1
    replacement = _runtime(estate, adapter, source, first)
    progressed = replacement.reconcile_once(
        "tenant-a", worker_ref="source-worker", run_id="next-read", limit=1, retry_delay_seconds=30,
    )
    assert progressed.resolved == 1
    assert calls == [pending[0].case_id, pending[1].case_id]
    assert replacement.reconcile_once(
        "tenant-a", worker_ref="source-worker", run_id="too-soon", limit=1,
    ).inspected == 0
    clock.advance(30)
    assert replacement.reconcile_once(
        "tenant-a", worker_ref="source-worker", run_id="due-again", limit=1,
    ).errors == 1
    assert len(mutation_calls) == 2  # reconciliation never replays a provider mutation


@pytest.mark.parametrize("unavailable", ["subject", "credential"])
def test_pre_dispatch_authority_outage_retries_delete_without_false_ambiguity(
    estate,
    unavailable: str,
) -> None:
    source, case, task = _prepare(
        estate,
        case_id=f"case-authority-{unavailable}",
        phase="delete",
        requested_right="erasure",
    )
    adapter_calls = {"value": 0}

    class Adapter:
        def execute(self, **_kwargs):
            adapter_calls["value"] += 1
            raise AssertionError("provider I/O must not start")

    def unavailable_authority(*_args):
        raise RuntimeError("temporary authority outage")

    runtime = _runtime(
        estate,
        Adapter(),
        source,
        case,
        subject_resolver=(unavailable_authority if unavailable == "subject" else None),
        credential_resolver=(
            unavailable_authority if unavailable == "credential" else None
        ),
    )
    result = runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id=f"run-authority-{unavailable}",
        retry_delay_seconds=10,
    )
    store, _actor, _clock = estate
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert result.retried == 1
    assert result.ambiguous == 0
    assert result.dead_lettered == 0
    assert callback.state == "pending"
    assert callback.ambiguous_operation_ref is None
    assert store.get_task("tenant-a", task.task_id).state == "planned"
    assert adapter_calls["value"] == 0


@pytest.mark.parametrize(
    ("raised", "expected_state", "expected_count"),
    [
        (worker.ProviderRetryableError("provider_rate_limited"), "pending", "retried"),
        (worker.ProviderPermanentError("provider_scope_denied"), "dead_letter", "dead_lettered"),
    ],
)
def test_worker_distinguishes_definitive_retry_and_permanent_failures(
    tmp_path: Path,
    raised: Exception,
    expected_state: str,
    expected_count: str,
) -> None:
    actor = {"value": "planner"}
    clock = Clock()
    store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / f"{expected_state}.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=clock,
        token_factory=lambda: "lease-token",
    )
    local_estate = (store, actor, clock)
    source, case, _task = _prepare(
        local_estate,
        case_id=f"case-{expected_state}",
        phase="discover",
        requested_right="access",
    )

    class Adapter:
        def execute(self, **_kwargs):
            raise raised

    result = _runtime(local_estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id=f"run-{expected_state}",
        retry_delay_seconds=30,
    )
    callback = store.get_callback(
        "tenant-a",
        f"callback:{hashlib.sha256(_task.task_id.encode()).hexdigest()[:40]}",
    )
    assert callback.state == expected_state
    assert getattr(result, expected_count) == 1


def test_same_run_id_concurrency_reserves_one_provider_mutation(estate) -> None:
    source, case, _task = _prepare(
        estate,
        case_id="case-concurrent-delete",
        phase="delete",
        requested_right="erasure",
    )
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    mutation_calls = {"value": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            barrier.wait(timeout=5)
            return _prepared()

        def execute_prepared(self, **_kwargs):
            with lock:
                mutation_calls["value"] += 1
            return _mutation_success()

    runtime = _runtime(estate, Adapter(), source, case)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                runtime.run_once,
                "tenant-a",
                worker_ref="source-worker",
                run_id="same-concurrent-run",
            )
            for _ in range(2)
        ]
        results = [future.result(timeout=10) for future in futures]

    store, _actor, _clock = estate
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert mutation_calls["value"] == 1
    assert sum(result.ambiguous for result in results) == 1
    assert callback.state == "ambiguous"
    assert callback.provider_operation_performed is True
    assert callback.lease_token is None


def test_process_exit_after_provider_success_is_never_lease_replayed(estate) -> None:
    source, case, _task = _prepare(
        estate,
        case_id="case-process-exit",
        phase="delete",
        requested_right="erasure",
    )
    mutation_calls = {"value": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            return _prepared()

        def execute_prepared(self, **_kwargs):
            mutation_calls["value"] += 1
            # Model provider success followed by process death before the
            # worker can observe or persist the response.
            raise SystemExit(71)

    runtime = _runtime(estate, Adapter(), source, case)
    with pytest.raises(SystemExit, match="71"):
        runtime.run_once(
            "tenant-a",
            worker_ref="source-worker",
            run_id="run-process-exit",
            lease_seconds=10,
        )

    store, _actor, clock = estate
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert callback.state == "ambiguous"
    assert callback.lease_until is None
    clock.advance(60)
    replay = runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-after-process-exit",
        lease_seconds=10,
    )
    assert replay.claimed == 0
    assert mutation_calls["value"] == 1


def test_lease_expiry_during_prepare_blocks_provider_mutation(estate) -> None:
    source, case, _task = _prepare(
        estate,
        case_id="case-expired-before-dispatch",
        phase="delete",
        requested_right="erasure",
    )
    store, _actor, clock = estate
    mutation_calls = {"value": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            clock.advance(11)
            return _prepared()

        def execute_prepared(self, **_kwargs):
            mutation_calls["value"] += 1
            return _mutation_success()

    result = _runtime(estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-expired-before-dispatch",
        lease_seconds=10,
    )
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert result.ambiguous == 0
    assert mutation_calls["value"] == 0
    assert callback.state == "leased"
    assert callback.lease_until is not None and callback.lease_until <= clock()


def test_legal_hold_added_during_prepare_blocks_provider_mutation(estate) -> None:
    source, case, _task = _prepare(
        estate,
        case_id="case-hold-before-dispatch",
        phase="delete",
        requested_right="erasure",
    )
    store, _actor, _clock = estate
    mutation_calls = {"value": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            store.set_legal_hold(
                "tenant-a",
                case.case_id,
                active=True,
                evidence_sha256=_digest("dispatch-hold"),
                evidence_ref="hold:dispatch",
                expected_revision=case.revision,
                idempotency_key="hold-before-provider-dispatch",
            )
            return _prepared()

        def execute_prepared(self, **_kwargs):
            mutation_calls["value"] += 1
            return _mutation_success()

    result = _runtime(estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-hold-before-dispatch",
    )
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert result.ambiguous == 0
    assert mutation_calls["value"] == 0
    assert callback.state == "leased"


def test_source_rotation_after_approval_requires_replan_with_zero_provider_calls(
    estate,
) -> None:
    source, case, task = _prepare(
        estate,
        case_id="case-source-rotation",
        phase="delete",
        requested_right="erasure",
    )
    store, _actor, _clock = estate
    store.enroll_source(
        "tenant-a",
        source.source_id,
        adapter_ref=source.adapter_ref,
        credential_ref="env:ROTATED_RIGHTS_TOKEN",
        capabilities=source.capabilities,
        expected_revision=source.revision,
        idempotency_key="rotate-source-after-approval",
    )
    calls = {"prepare": 0, "mutate": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            calls["prepare"] += 1
            return _prepared()

        def execute_prepared(self, **_kwargs):
            calls["mutate"] += 1
            return _mutation_success()

    result = _runtime(estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-after-source-rotation",
    )
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert result.claimed == 0
    assert calls == {"prepare": 0, "mutate": 0}
    assert callback.state == "pending"
    assert store.get_task("tenant-a", task.task_id).state == "planned"


def test_adapter_authority_rotation_after_approval_makes_zero_provider_calls(
    estate,
) -> None:
    source, case, task = _prepare(
        estate,
        case_id="case-adapter-authority-rotation",
        phase="delete",
        requested_right="erasure",
    )
    calls = {"prepare": 0, "mutate": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            calls["prepare"] += 1
            return _prepared()

        def execute_prepared(self, **_kwargs):
            calls["mutate"] += 1
            return _mutation_success()

    result = _runtime(
        estate,
        Adapter(),
        source,
        case,
        adapter_authority_sha256=_digest("rotated-adapter-authority"),
    ).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-after-adapter-authority-rotation",
    )
    store, _actor, _clock = estate
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert result.retried == 1
    assert calls == {"prepare": 0, "mutate": 0}
    assert callback.state == "pending"
    assert callback.last_error_code == "provider_authority_drift"
    assert store.get_task("tenant-a", task.task_id).state == "planned"


def test_worker_claims_only_owned_sources_in_mixed_estate(estate) -> None:
    source, case, _task = _prepare(
        estate,
        case_id="case-owned-source",
        phase="discover",
        requested_right="access",
    )
    store, actor, clock = estate
    actor["value"] = "planner"
    external_source = store.enroll_source(
        "tenant-a",
        "externally-managed",
        adapter_ref="external:directory:v1",
        credential_ref="env:EXTERNAL_DIRECTORY_TOKEN",
        capabilities=["discover"],
        expected_revision=0,
        idempotency_key="enroll-external-source",
    )
    external_case = store.open_case(
        "tenant-a",
        "case-external-source",
        request_version=1,
        external_request_ref="request-external-source",
        subject_reference="person@example.test",
        rights=["access"],
        retained_until=clock() + 600,
        idempotency_key="open-external-source-case",
    )
    external_case = store.set_identity_verification(
        "tenant-a",
        external_case.case_id,
        status="verified",
        evidence_sha256=_digest("external-identity"),
        evidence_ref="identity:external",
        expected_revision=external_case.revision,
        idempotency_key="verify-external-source-case",
    )
    store.plan_source_tasks(
        "tenant-a",
        external_case.case_id,
        external_source.source_id,
        phases=["discover"],
        max_attempts=3,
        expected_case_revision=external_case.revision,
        idempotency_key="plan-external-source",
    )
    actor["value"] = "source-worker"
    calls = {"value": 0}

    class Adapter:
        def execute(self, **_kwargs):
            calls["value"] += 1
            return worker.ProviderOutcome(
                status="complete",
                record_count=1,
                acknowledgement_sha256=_digest("owned-ack"),
                acknowledgement_ref="provider:owned",
                provider_evidence_sha256=_digest("owned-evidence"),
                opaque_ref="provider:owned-evidence",
                external_side_effect=False,
            )

    result = _runtime(estate, Adapter(), source, case).run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-owned-source-only",
        limit=10,
    )
    callbacks = store.list_callbacks("tenant-a", limit=10)
    external_callback = next(
        item for item in callbacks if item.source_id == external_source.source_id
    )
    assert result.claimed == 1
    assert result.completed == 1
    assert calls["value"] == 1
    assert external_callback.state == "pending"
    assert external_callback.attempts == 0


def test_already_absent_delete_completes_as_truthful_no_change(estate) -> None:
    source, case, task = _prepare(
        estate,
        case_id="case-already-absent",
        phase="delete",
        requested_right="erasure",
    )
    mutation_calls = {"value": 0}

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            return _already_absent()

        def execute_prepared(self, **_kwargs):
            mutation_calls["value"] += 1
            raise AssertionError("already-absent delete must not mutate")

    runtime = _runtime(estate, Adapter(), source, case)
    result = runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-already-absent",
    )
    store, _actor, clock = estate
    completed = store.get_task("tenant-a", task.task_id)
    exported = store.export_case(
        "tenant-a",
        case.case_id,
        "export:already-absent",
        retained_until=clock() + 60,
        idempotency_key="export-already-absent",
    )
    evidence = exported.body["evidence"][0]
    assert result.not_found == 1
    assert result.ambiguous == 0
    assert mutation_calls["value"] == 0
    assert completed.state == "complete"
    assert evidence["provider_operation_performed"] is False
    assert evidence["provider_retention_state"] == "already_absent"
    assert exported.body["limitations"]["provider_operations_performed"] is False


def test_reconciled_mutation_persists_immutable_execution_provenance(estate) -> None:
    source, case, task = _prepare(
        estate,
        case_id="case-provenance",
        phase="delete",
        requested_right="erasure",
    )

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            return _prepared()

        def execute_prepared(self, **_kwargs):
            return _mutation_success()

        def reconcile_mutation(self, **_kwargs):
            return worker.ProviderReconciliationOutcome(
                disposition="applied",
                provider_evidence_sha256=_digest("purge-proof"),
                provider_evidence_ref="provider:purge-proof",
                record_count=0,
                provider_retention_state="purged",
            )

    runtime = _runtime(estate, Adapter(), source, case)
    dispatched = runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-provenance-dispatch",
    )
    reconciled = runtime.reconcile_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-provenance-reconcile",
    )
    store, _actor, clock = estate
    exported = store.export_case(
        "tenant-a",
        case.case_id,
        "export:provenance",
        retained_until=clock() + 60,
        idempotency_key="export-provenance",
    )
    evidence = exported.body["evidence"][0]
    assert dispatched.ambiguous == 1
    assert reconciled.resolved == 1
    assert store.get_task("tenant-a", task.task_id).state == "complete"
    assert evidence["provider_operation_id"].startswith("prso:")
    assert len(evidence["provider_operation_sha256"]) == 64
    assert evidence["provider_operation_performed"] is True
    assert evidence["source_revision"] == source.revision
    assert evidence["source_integrity_sha256"] == source.integrity_sha256
    assert evidence["adapter_ref"] == source.adapter_ref
    assert evidence["credential_ref"] == source.credential_ref
    assert evidence["adapter_authority_sha256"] == worker.adapter_authority_sha256(
        tenant_id="tenant-a",
        source_id=source.source_id,
        adapter_ref=source.adapter_ref,
        credential_ref=source.credential_ref,
        capabilities=source.capabilities,
    )
    assert evidence["provider_contract"] == source.adapter_ref
    assert evidence["target_binding_sha256"] == _digest("target-one")
    assert evidence["provider_retention_state"] == "purged"
    assert exported.body["limitations"]["provider_operations_performed"] is True


def test_soft_deleted_provider_record_keeps_delete_ambiguous(estate) -> None:
    source, case, task = _prepare(
        estate,
        case_id="case-soft-deleted-retained",
        phase="delete",
        requested_right="erasure",
    )

    class Adapter:
        def prepare_mutation(self, **_kwargs):
            return _prepared()

        def execute_prepared(self, **_kwargs):
            return _mutation_success()

        def reconcile_mutation(self, **_kwargs):
            return worker.ProviderReconciliationOutcome(
                disposition="unknown",
                provider_evidence_sha256=_digest("soft-delete-proof"),
                provider_evidence_ref="provider:soft-delete-proof",
                record_count=1,
                provider_retention_state="soft_deleted",
            )

    runtime = _runtime(estate, Adapter(), source, case)
    runtime.run_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="run-soft-delete",
    )
    reconciled = runtime.reconcile_once(
        "tenant-a",
        worker_ref="source-worker",
        run_id="reconcile-soft-delete",
    )
    store, _actor, _clock = estate
    callback = store.list_callbacks("tenant-a", limit=10)[0]
    assert reconciled.still_ambiguous == 1
    assert reconciled.resolved == 0
    assert callback.state == "ambiguous"
    assert callback.last_error_code == "provider_soft_delete_retained"
    assert store.get_task("tenant-a", task.task_id).state == "planned"


def test_claim_history_is_minimized_and_garbage_collected(tmp_path: Path) -> None:
    actor = {"value": "planner"}
    clock = Clock()
    store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / "claim-history.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=clock,
        token_factory=lambda: "raw-lease-token-must-not-enter-history",
        claim_history_retention_seconds=60,
    )
    local_estate = (store, actor, clock)
    _prepare(
        local_estate,
        case_id="case-claim-history",
        phase="discover",
        requested_right="access",
    )
    first = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-history-first",
    )[0]
    with sqlite3.connect(store.path) as connection:
        batch_payload = connection.execute(
            "SELECT payload_json FROM rights_claim_batches WHERE tenant_id=?",
            ("tenant-a",),
        ).fetchone()[0]
        operation_count = connection.execute(
            "SELECT COUNT(*) FROM rights_operations WHERE tenant_id=? "
            "AND result_kind='claim_batch'",
            ("tenant-a",),
        ).fetchone()[0]
    decoded = json.loads(batch_payload)
    assert decoded["callbacks"] == [
        {
            "callback_id": first.callback_id,
            "lease_token_sha256": hashlib.sha256(
                (first.lease_token or "").encode()
            ).hexdigest(),
            "revision": first.revision,
        }
    ]
    assert "raw-lease-token-must-not-enter-history" not in batch_payload
    assert operation_count == 1

    clock.advance(61)
    # The old lease is recoverable, while its historical claim response is
    # independently past retention and removed before the new batch is stored.
    store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-history-after-gc",
    )
    with sqlite3.connect(store.path) as connection:
        batch_ids = {
            row[0]
            for row in connection.execute(
                "SELECT batch_id FROM rights_claim_batches WHERE tenant_id=?",
                ("tenant-a",),
            ).fetchall()
        }
    expired_batch_id = (
        "batch:" + hashlib.sha256(b"claim-history-first").hexdigest()[:32]
    )
    assert expired_batch_id not in batch_ids
    assert (
        store.claim_callbacks(
            "tenant-a",
            limit=1,
            lease_seconds=10,
            source_ids=("not-configured",),
            idempotency_key="empty-poll",
        )
        == ()
    )
    with sqlite3.connect(store.path) as connection:
        empty_poll_operations = connection.execute(
            "SELECT COUNT(*) FROM rights_operations WHERE tenant_id=? "
            "AND operation_sha256=?",
            ("tenant-a", hashlib.sha256(b"empty-poll").hexdigest()),
        ).fetchone()[0]
    assert empty_poll_operations == 0
