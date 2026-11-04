from __future__ import annotations

import hashlib
import hmac
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick.consent_experiments import (
    AssignmentContext,
    ConsentExperimentAuthority,
    ConsentExperimentConfigError,
    ConsentExperimentConflict,
    ConsentExperimentIntegrityError,
    ConsentExperimentPermissionDenied,
    ConsentExperimentStateError,
    ConsentExperimentValidationError,
    ExperimentSpec,
    ExperimentVariant,
    experiments_enabled,
)

ENABLED = {
    "consent_preferences": {
        "enable": True,
        "experiments": {"enable": True},
    }
}


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class FakeKeyAuthority:
    def __init__(self, root: bytes = b"e" * 32) -> None:
        self.root = root

    def key_for(self, tenant_id: str, capability: str) -> bytes:
        assert capability == "lightwork.consent-experiments.v1"
        return hmac.new(
            self.root,
            tenant_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()


def _variant(
    variant_id: str,
    allocation_bps: int,
    *,
    control: bool = False,
    holdout: bool = False,
) -> ExperimentVariant:
    seed = hashlib.sha256(variant_id.encode()).hexdigest()
    return ExperimentVariant(
        variant_id=variant_id,
        allocation_bps=allocation_bps,
        content_ref=f"bundle:{variant_id}",
        content_sha256=seed,
        accessibility_evidence_sha256=hashlib.sha256(
            f"a11y:{variant_id}".encode()
        ).hexdigest(),
        equal_choice_evidence_sha256=hashlib.sha256(
            f"parity:{variant_id}".encode()
        ).hexdigest(),
        is_control=control,
        is_holdout=holdout,
    )


def _spec(
    experiment_id: str = "banner-copy-v1",
    *,
    min_sample: int = 20,
    retention_days: int = 30,
    audience: dict[str, list[str]] | None = None,
) -> ExperimentSpec:
    return ExperimentSpec(
        experiment_id=experiment_id,
        metric_id="preference-completion",
        variants=(
            _variant("control", 5_000, control=True),
            _variant("treatment", 5_000),
        ),
        starts_at=900.0,
        ends_at=2_000.0,
        max_exposures=100_000,
        min_sample_per_variant=min_sample,
        max_analysis_looks=5,
        dedupe_retention_days=retention_days,
        audience=audience,
    )


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def authority(tmp_path: Path, clock: Clock) -> ConsentExperimentAuthority:
    return ConsentExperimentAuthority(
        tmp_path / "consent-experiments.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: ENABLED,
        clock=clock,
    )


def _create_and_activate(
    authority: ConsentExperimentAuthority,
    tenant: str = "tenant-a",
    spec: ExperimentSpec | None = None,
) -> None:
    definition = spec or _spec()
    authority.create_experiment(
        tenant,
        definition,
        created_by="human:owner@example.test",
        idempotency_key="create-experiment-001",
    )
    authority.approve(
        tenant,
        definition.experiment_id,
        expected_revision=0,
        approved_by="human:privacy-reviewer@example.test",
        idempotency_key="approve-experiment-001",
    )
    authority.activate(
        tenant,
        definition.experiment_id,
        expected_revision=1,
        activated_by="human:release-manager@example.test",
        idempotency_key="activate-experiment-001",
    )


def test_config_gate_is_exact_nested_and_fail_closed(tmp_path: Path) -> None:
    assert experiments_enabled(ENABLED)
    assert not experiments_enabled({})
    assert not experiments_enabled(
        {"consent_preferences": {"enable": 1, "experiments": {"enable": True}}}
    )
    assert not experiments_enabled(
        {"consent_preferences": {"enable": True, "experiments": {"enable": "true"}}}
    )
    disabled = ConsentExperimentAuthority(
        tmp_path / "disabled.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: {
            "consent_preferences": {
                "enable": True,
                "experiments": {"enable": False},
            }
        },
        clock=Clock(),
    )
    with pytest.raises(ConsentExperimentConfigError):
        disabled.create_experiment(
            "tenant-a",
            _spec(),
            created_by="owner",
            idempotency_key="disabled-create-001",
        )

    unavailable = ConsentExperimentAuthority(
        tmp_path / "unavailable.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: (_ for _ in ()).throw(OSError("no config")),
        clock=Clock(),
    )
    with pytest.raises(ConsentExperimentConfigError):
        unavailable.get_experiment("tenant-a", "banner-copy-v1")


def test_unicode_tenants_are_isolated_and_object_ids_stay_strict(
    authority: ConsentExperimentAuthority,
) -> None:
    first = authority.create_experiment(
        "Café 北 America",
        _spec(),
        created_by="owner-a",
        idempotency_key="unicode-create-001",
    )
    second = authority.create_experiment(
        "Another Tenant",
        _spec(),
        created_by="owner-b",
        idempotency_key="unicode-create-002",
    )
    assert first["state"] == second["state"] == "draft"
    authority.approve(
        "Café 北 America",
        "banner-copy-v1",
        expected_revision=0,
        approved_by="reviewer",
        idempotency_key="unicode-approve-001",
    )
    assert authority.get_experiment("Café 北 America", "banner-copy-v1")["state"] == "approved"
    assert authority.get_experiment("Another Tenant", "banner-copy-v1")["state"] == "draft"

    with pytest.raises(ConsentExperimentValidationError):
        authority.get_experiment("Café 北 America", "not a strict id")
    with pytest.raises(ConsentExperimentValidationError):
        authority.create_experiment(
            "Café 北 America",
            _spec("invalid experiment id"),
            created_by="owner-a",
            idempotency_key="invalid-object-id-001",
        )


def test_definitions_are_immutable_and_human_approval_is_required(
    authority: ConsentExperimentAuthority,
) -> None:
    created = authority.create_experiment(
        "tenant-a",
        _spec(),
        created_by="owner",
        idempotency_key="human-create-001",
    )
    assert created["revision"] == 0
    with pytest.raises(ConsentExperimentStateError, match="human approval"):
        authority.activate(
            "tenant-a",
            "banner-copy-v1",
            expected_revision=0,
            activated_by="release-manager",
            idempotency_key="premature-activate-001",
        )
    with pytest.raises(
        ConsentExperimentPermissionDenied,
        match="cannot approve their own",
    ):
        authority.approve(
            "tenant-a",
            "banner-copy-v1",
            expected_revision=0,
            approved_by="owner",
            idempotency_key="self-approve-denied-001",
        )
    approved = authority.approve(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=0,
        approved_by="privacy-reviewer",
        idempotency_key="human-approve-001",
    )
    assert approved["approved_definition_sha256"] == approved["definition_sha256"]
    assert approved["approved_by_token"] != "privacy-reviewer"
    with sqlite3.connect(authority.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE consent_experiments SET definition_json = '{}'"
            )


def test_approval_verifies_creation_identity_audit_before_four_eyes(
    authority: ConsentExperimentAuthority,
) -> None:
    authority.create_experiment(
        "tenant-a",
        _spec(),
        created_by="owner",
        idempotency_key="tamper-creator-create-001",
    )
    with sqlite3.connect(authority.path) as connection:
        connection.execute("DROP TRIGGER consent_experiment_audit_no_update")
        connection.execute(
            "UPDATE consent_experiment_audit SET actor_token = ? "
            "WHERE tenant = ? AND experiment_id = ? AND event_index = 1",
            ("0" * 64, "tenant-a", "banner-copy-v1"),
        )
    with pytest.raises(ConsentExperimentIntegrityError, match="creation audit"):
        authority.approve(
            "tenant-a",
            "banner-copy-v1",
            expected_revision=0,
            approved_by="privacy-reviewer",
            idempotency_key="tamper-creator-approve-001",
        )


def test_assignment_is_sticky_across_restarts_and_audience_is_bounded(
    tmp_path: Path,
    clock: Clock,
) -> None:
    path = tmp_path / "sticky.sqlite3"
    keys = FakeKeyAuthority()
    first = ConsentExperimentAuthority(
        path,
        key_authority=keys,
        config_loader=lambda: ENABLED,
        clock=clock,
    )
    _create_and_activate(
        first,
        spec=_spec(audience={"country_codes": ["US"], "channels": ["web"]}),
    )
    context = AssignmentContext(country_code="US", channel="web")
    assignment = first.assign("tenant-a", "banner-copy-v1", "raw-user@example.test", context)
    assert assignment.eligible

    second = ConsentExperimentAuthority(
        path,
        key_authority=keys,
        config_loader=lambda: ENABLED,
        clock=clock,
    )
    restarted = second.assign(
        "tenant-a",
        "banner-copy-v1",
        "raw-user@example.test",
        context,
    )
    assert restarted == assignment
    outside = second.assign(
        "tenant-a",
        "banner-copy-v1",
        "another-user",
        AssignmentContext(country_code="CA", channel="web"),
    )
    assert not outside.eligible
    assert outside.reason == "outside_audience"
    assert outside.is_control


def test_holdout_is_a_first_class_sticky_assignment(
    authority: ConsentExperimentAuthority,
) -> None:
    spec = ExperimentSpec(
        experiment_id="holdout-v1",
        metric_id="preference-completion",
        variants=(
            _variant("control", 4_000, control=True),
            _variant("holdout", 2_000, holdout=True),
            _variant("treatment", 4_000),
        ),
        starts_at=900.0,
        ends_at=2_000.0,
        min_sample_per_variant=20,
    )
    _create_and_activate(authority, spec=spec)
    for index in range(10_000):
        subject = f"holdout-subject-{index}"
        assignment = authority.assign(
            "tenant-a", "holdout-v1", subject, AssignmentContext()
        )
        if assignment.is_holdout:
            assert assignment.eligible
            assert assignment.reason == "holdout"
            assert authority.assign(
                "tenant-a", "holdout-v1", subject, AssignmentContext()
            ) == assignment
            return
    pytest.fail("deterministic assignment did not reach the configured holdout")


@pytest.mark.parametrize(
    ("context", "reason"),
    [
        (AssignmentContext(privacy_signals=("gpc",)), "legal_signal_precedence"),
        (AssignmentContext(required_purpose=True), "required_purpose_precedence"),
        (AssignmentContext(accessibility_supported=False), "accessibility_guardrail"),
        (AssignmentContext(equal_choice_prominence=False), "choice_parity_guardrail"),
    ],
)
def test_legal_and_safety_signals_always_precede_experiment_assignment(
    authority: ConsentExperimentAuthority,
    context: AssignmentContext,
    reason: str,
) -> None:
    _create_and_activate(authority)
    assignment = authority.assign(
        "tenant-a", "banner-copy-v1", "subject-sensitive", context
    )
    assert not assignment.eligible
    assert assignment.is_control
    assert assignment.reason == reason
    result = authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        "subject-sensitive",
        context,
        idempotency_key=f"guardrail-{reason}-001",
    )
    assert not result["recorded"]
    assert authority.audit_export("tenant-a", "banner-copy-v1")["aggregates"] == [
        {
            "variant_id": "control",
            "exposures": 0,
            "outcomes": 0,
            "successes": 0,
            "failures": 0,
            "revision": 0,
        },
        {
            "variant_id": "treatment",
            "exposures": 0,
            "outcomes": 0,
            "successes": 0,
            "failures": 0,
            "revision": 0,
        },
    ]


def test_exposure_and_outcome_dedupe_without_raw_identity_or_event_retention(
    authority: ConsentExperimentAuthority,
) -> None:
    _create_and_activate(authority)
    identity = "very-sensitive-person@example.test"
    context = AssignmentContext(country_code="US", region_code="OH", channel="web")
    first = authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        identity,
        context,
        idempotency_key="privacy-exposure-001",
    )
    replay = authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        identity,
        context,
        idempotency_key="privacy-exposure-001",
    )
    duplicate = authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        identity,
        context,
        idempotency_key="privacy-exposure-002",
    )
    assert replay == first
    assert duplicate["deduplicated"]

    outcome = authority.record_outcome(
        "tenant-a",
        "banner-copy-v1",
        identity,
        success=True,
        idempotency_key="privacy-outcome-001",
    )
    outcome_duplicate = authority.record_outcome(
        "tenant-a",
        "banner-copy-v1",
        identity,
        success=True,
        idempotency_key="privacy-outcome-002",
    )
    assert outcome["recorded"]
    assert outcome_duplicate["deduplicated"]
    export = authority.audit_export("tenant-a", "banner-copy-v1")
    assert export["pseudonymous_dedupe_record_count"] == 1
    assert export["raw_identity_retained"] is False
    assert export["raw_profile_retained"] is False
    assert export["raw_event_payload_retained"] is False
    serialized = str(export)
    assert identity not in serialized
    assert "OH" not in serialized
    assert identity.encode() not in authority.path.read_bytes()
    with sqlite3.connect(authority.path) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "consent_experiment_dedupe" in tables
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(consent_experiment_dedupe)"
            ).fetchall()
        }
        assert not {"user_id", "profile_id", "context_json", "event_json"} & columns
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_outcome_requires_prior_unexpired_exposure(
    authority: ConsentExperimentAuthority,
) -> None:
    _create_and_activate(authority)
    with pytest.raises(ConsentExperimentStateError, match="exposure"):
        authority.record_outcome(
            "tenant-a",
            "banner-copy-v1",
            "never-exposed",
            success=True,
            idempotency_key="no-exposure-outcome-001",
        )


def test_expired_pseudonymous_dedupe_can_be_purged(
    tmp_path: Path,
    clock: Clock,
) -> None:
    authority = ConsentExperimentAuthority(
        tmp_path / "retention.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: ENABLED,
        clock=clock,
    )
    _create_and_activate(authority, spec=_spec(retention_days=1))
    authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        "temporary-subject",
        AssignmentContext(),
        idempotency_key="retention-exposure-001",
    )
    clock.value = 90_000.0
    result = authority.purge_expired_dedupe(
        "tenant-a",
        purged_by="privacy-operator",
        idempotency_key="retention-purge-001",
    )
    assert result["records_purged"] == 1
    export = authority.audit_export("tenant-a", "banner-copy-v1")
    assert export["pseudonymous_dedupe_record_count"] == 0
    assert sum(row["exposures"] for row in export["aggregates"]) == 1


def test_concurrent_state_changes_enforce_revision_cas(
    authority: ConsentExperimentAuthority,
) -> None:
    _create_and_activate(authority)

    def pause(index: int) -> object:
        try:
            return authority.pause(
                "tenant-a",
                "banner-copy-v1",
                expected_revision=2,
                paused_by=f"operator-{index}",
                idempotency_key=f"concurrent-pause-{index:03d}",
            )
        except Exception as exc:  # returned for deterministic thread assertion
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(pause, range(2)))
    successes = [outcome for outcome in outcomes if isinstance(outcome, dict)]
    conflicts = [
        outcome for outcome in outcomes if isinstance(outcome, ConsentExperimentConflict)
    ]
    assert len(successes) == 1
    assert successes[0]["revision"] == 3
    assert len(conflicts) == 1


def test_tampered_definition_and_aggregate_are_rejected(
    authority: ConsentExperimentAuthority,
) -> None:
    _create_and_activate(authority)
    with sqlite3.connect(authority.path) as connection:
        connection.execute("DROP TRIGGER consent_experiment_definition_immutable")
        connection.execute(
            "UPDATE consent_experiments SET definition_json = ? "
            "WHERE tenant = ? AND experiment_id = ?",
            ("{}", "tenant-a", "banner-copy-v1"),
        )
        connection.commit()
    with pytest.raises(ConsentExperimentIntegrityError, match="definition"):
        authority.get_experiment("tenant-a", "banner-copy-v1")

    separate = ConsentExperimentAuthority(
        authority.path.parent / "aggregate-tamper.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: ENABLED,
        clock=Clock(),
    )
    _create_and_activate(separate)
    with sqlite3.connect(separate.path) as connection:
        connection.execute(
            "UPDATE consent_experiment_aggregates SET exposures = 999 "
            "WHERE tenant = ? AND experiment_id = ? AND variant_id = ?",
            ("tenant-a", "banner-copy-v1", "control"),
        )
        connection.commit()
    with pytest.raises(ConsentExperimentIntegrityError, match="aggregate"):
        separate.audit_export("tenant-a", "banner-copy-v1")


def test_non_ascii_stored_macs_are_integrity_errors_not_type_errors(
    authority: ConsentExperimentAuthority,
) -> None:
    # A MAC column edited to non-ASCII text must not raise TypeError from
    # hmac.compare_digest instead of the integrity refusal.
    _create_and_activate(authority)
    with sqlite3.connect(authority.path) as connection:
        connection.execute(
            "UPDATE consent_experiment_aggregates SET record_mac = ? WHERE tenant = ?",
            ("é" * 64, "tenant-a"),
        )
        connection.commit()
    with pytest.raises(ConsentExperimentIntegrityError, match="aggregate"):
        authority.audit_export("tenant-a", "banner-copy-v1")
    with sqlite3.connect(authority.path) as connection:
        connection.execute(
            "UPDATE consent_experiments SET state_mac = ? WHERE tenant = ?",
            ("é" * 64, "tenant-a"),
        )
        connection.commit()
    with pytest.raises(ConsentExperimentIntegrityError, match="state"):
        authority.get_experiment("tenant-a", "banner-copy-v1")


def test_analysis_never_declares_a_winner_before_minimum_sample(
    authority: ConsentExperimentAuthority,
) -> None:
    _create_and_activate(authority)
    counts = {"control": 0, "treatment": 0}
    index = 0
    while min(counts.values()) < 5:
        subject = f"analysis-subject-{index}"
        assignment = authority.assign(
            "tenant-a", "banner-copy-v1", subject, AssignmentContext()
        )
        if counts[assignment.variant_id] < 5:
            authority.record_exposure(
                "tenant-a",
                "banner-copy-v1",
                subject,
                AssignmentContext(),
                idempotency_key=f"analysis-exposure-{index:05d}",
            )
            authority.record_outcome(
                "tenant-a",
                "banner-copy-v1",
                subject,
                success=assignment.variant_id == "treatment",
                idempotency_key=f"analysis-outcome-{index:05d}",
            )
            counts[assignment.variant_id] += 1
        index += 1
        assert index < 10_000
    early = authority.analyze(
        "tenant-a",
        "banner-copy-v1",
        analyzed_by="statistical-reviewer",
        idempotency_key="analysis-look-early-001",
    )
    assert early["winner_variant_id"] is None
    assert early["causal_claim_authorized"] is False
    assert early["decision"] == "no_winner"
    assert all(not comparison["thresholds_met"] for comparison in early["comparisons"])
    assert all(len(cell["confidence_interval"]) == 2 for cell in early["cells"])

    while min(counts.values()) < 25:
        subject = f"analysis-subject-{index}"
        assignment = authority.assign(
            "tenant-a", "banner-copy-v1", subject, AssignmentContext()
        )
        if counts[assignment.variant_id] < 25:
            authority.record_exposure(
                "tenant-a",
                "banner-copy-v1",
                subject,
                AssignmentContext(),
                idempotency_key=f"analysis-exposure-{index:05d}",
            )
            authority.record_outcome(
                "tenant-a",
                "banner-copy-v1",
                subject,
                success=assignment.variant_id == "treatment",
                idempotency_key=f"analysis-outcome-{index:05d}",
            )
            counts[assignment.variant_id] += 1
        index += 1
        assert index < 10_000
    mature = authority.analyze(
        "tenant-a",
        "banner-copy-v1",
        analyzed_by="statistical-reviewer",
        idempotency_key="analysis-look-mature-001",
    )
    assert mature["winner_variant_id"] == "treatment"
    assert mature["causal_claim_authorized"] is True
    assert mature["look_number"] == 2


def test_pause_resume_kill_and_rollback_fail_to_control(
    authority: ConsentExperimentAuthority,
) -> None:
    _create_and_activate(authority)
    active = authority.assign(
        "tenant-a", "banner-copy-v1", "pause-subject", AssignmentContext()
    )
    assert active.eligible
    paused = authority.pause(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=2,
        paused_by="safety-officer",
        idempotency_key="pause-state-001",
    )
    assert paused["state"] == "paused"
    blocked = authority.assign(
        "tenant-a", "banner-copy-v1", "pause-subject", AssignmentContext()
    )
    assert not blocked.eligible and blocked.reason == "paused" and blocked.is_control
    resumed = authority.resume(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=3,
        resumed_by="safety-officer",
        idempotency_key="resume-state-001",
    )
    assert resumed["state"] == "active"
    rolled_back = authority.rollback(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=4,
        rolled_back_by="safety-officer",
        idempotency_key="rollback-state-001",
    )
    assert rolled_back["state"] == "rolled_back"
    assert rolled_back["rollback_variant_id"] == "control"
    fallback = authority.assign(
        "tenant-a", "banner-copy-v1", "pause-subject", AssignmentContext()
    )
    assert not fallback.eligible
    assert fallback.reason == "rolled_back"
    assert fallback.variant_id == "control"

    second = ConsentExperimentAuthority(
        authority.path.parent / "kill.sqlite3",
        key_authority=FakeKeyAuthority(),
        config_loader=lambda: ENABLED,
        clock=Clock(),
    )
    _create_and_activate(second)
    killed = second.kill(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=2,
        killed_by="safety-officer",
        idempotency_key="kill-state-001",
    )
    assert killed["state"] == "killed"
    assert second.assign(
        "tenant-a", "banner-copy-v1", "subject", AssignmentContext()
    ).reason == "killed"


def test_idempotency_replays_lifecycle_after_clock_advances(
    authority: ConsentExperimentAuthority,
    clock: Clock,
) -> None:
    authority.create_experiment(
        "tenant-a",
        _spec(),
        created_by="owner",
        idempotency_key="clock-create-001",
    )
    first = authority.approve(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=0,
        approved_by="reviewer",
        idempotency_key="clock-approve-001",
    )
    clock.value += 100
    replay = authority.approve(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=0,
        approved_by="reviewer",
        idempotency_key="clock-approve-001",
    )
    assert replay == first
    activated = authority.activate(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=1,
        activated_by="release-manager",
        idempotency_key="clock-activate-001",
    )
    clock.value += 100
    assert authority.activate(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=1,
        activated_by="release-manager",
        idempotency_key="clock-activate-001",
    ) == activated

    exposure = authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        "clock-subject",
        AssignmentContext(),
        idempotency_key="clock-exposure-001",
        occurred_at=1_200.0,
    )
    authority.pause(
        "tenant-a",
        "banner-copy-v1",
        expected_revision=2,
        paused_by="safety-officer",
        idempotency_key="clock-pause-001",
    )
    assert authority.record_exposure(
        "tenant-a",
        "banner-copy-v1",
        "clock-subject",
        AssignmentContext(),
        idempotency_key="clock-exposure-001",
        occurred_at=1_200.0,
    ) == exposure
