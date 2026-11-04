from __future__ import annotations

import hashlib
import inspect
import itertools
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from maverick import privacy_rights_orchestration as orchestration
from maverick.privacy_rights_intake import (
    IDENTITY_EVIDENCE_SCHEMA,
    ConsumerRightsIdentityEvidence,
    ConsumerRightsIntakeAuthority,
    ConsumerRightsSigningKey,
    PrivacyRightsIntakeConfigError,
    PrivacyRightsIntakeConflict,
    PrivacyRightsIntakeIntegrityError,
    PrivacyRightsIntakeNotFound,
    PrivacyRightsIntakeStore,
    PrivacyRightsIntakeValidationError,
    SignedConsumerRightsStatus,
    enabled,
)


class Clock:
    def __init__(self, value: float = 1_900_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def object_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def authority(clock: Clock, **overrides: object) -> ConsumerRightsIntakeAuthority:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "property_sha256": digest("tenant-a:property"),
        "property_revision": 3,
        "profile_sha256": digest("tenant-a:profile"),
        "profile_credential_sha256": digest("tenant-a:profile-credential"),
        "profile_binding_sha256": digest("tenant-a:profile-binding"),
        "profile_revision": 5,
        "subject_binding_sha256": digest("tenant-a:subject-binding"),
        "client_credential_sha256": digest("tenant-a:client-credential"),
        "client_record_sha256": digest("tenant-a:client-record"),
        "client_revision": 4,
        "publication_sha256": digest("tenant-a:publication"),
        "publication_bundle_sha256": digest("tenant-a:publication-bundle"),
        "configuration_sha256": digest("tenant-a:configuration"),
        "policy_sha256": digest("tenant-a:policy"),
        "policy_version": 7,
        "trust_context_sha256": digest("tenant-a:trust-context"),
        "trust_context_revision": 6,
        "capability_grant_sha256": digest("tenant-a:rights-intake-grant"),
        "channel": "browser-origin",
        "channel_binding_sha256": digest("https://privacy.example.test"),
        "identity_authority_sha256": digest("tenant-a:independent-idp"),
        "minimum_identity_assurance": "substantial",
        "valid_until": clock() + 3_600,
        "revoked": False,
    }
    values.update(overrides)
    return ConsumerRightsIntakeAuthority(**values)  # type: ignore[arg-type]


def identity(
    admitted: ConsumerRightsIntakeAuthority,
    clock: Clock,
    **overrides: object,
) -> ConsumerRightsIdentityEvidence:
    body: dict[str, object] = {
        "schema": IDENTITY_EVIDENCE_SCHEMA,
        "tenant_id": admitted.tenant_id,
        "property_sha256": admitted.property_sha256,
        "profile_sha256": admitted.profile_sha256,
        "profile_binding_sha256": admitted.profile_binding_sha256,
        "subject_binding_sha256": admitted.subject_binding_sha256,
        "channel": admitted.channel,
        "channel_binding_sha256": admitted.channel_binding_sha256,
        "verification_authority_sha256": admitted.identity_authority_sha256,
        "verification_method": "passkey",
        "assurance_level": "high",
        "evidence_ref": "provider-idv-evidence-raw-ref",
        "evidence_revision": 11,
        "verified_at": clock() - 5,
        "valid_until": clock() + 600,
        "revoked": False,
    }
    body.update(overrides)
    return ConsumerRightsIdentityEvidence(
        **body,
        evidence_sha256=object_digest(body),
    )  # type: ignore[arg-type]


class Keyring:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        first = ConsumerRightsSigningKey(
            tenant_id="tenant-a",
            key_ref="kms:privacy-rights-status/key-one",
            revision=1,
            key=b"1" * 32,
            valid_from=clock() - 300,
            valid_until=clock() + 3_600,
        )
        self.keys = {(first.key_ref, first.revision): first}
        self.current = (first.key_ref, first.revision)

    def __call__(
        self,
        tenant_id: str,
        key_ref: str | None,
        revision: int | None,
    ) -> ConsumerRightsSigningKey:
        selected = self.current if key_ref is None and revision is None else (key_ref, revision)
        value = self.keys[selected]
        if value.tenant_id != tenant_id:
            raise KeyError(tenant_id)
        return value

    def rotate(self) -> ConsumerRightsSigningKey:
        second = ConsumerRightsSigningKey(
            tenant_id="tenant-a",
            key_ref="kms:privacy-rights-status/key-two",
            revision=2,
            key=b"2" * 32,
            valid_from=self.clock() - 60,
            valid_until=self.clock() + 7_200,
        )
        self.keys[(second.key_ref, second.revision)] = second
        self.current = (second.key_ref, second.revision)
        return second

    def revoke(self, key_ref: str, revision: int) -> None:
        current = self.keys[(key_ref, revision)]
        self.keys[(key_ref, revision)] = replace(current, revoked=True)


def rights_store(path: Path, clock: Clock):
    return orchestration.PrivacyRightsOrchestrationStore(
        path,
        config_gate=lambda: None,
        principal_resolver=lambda: "privacy-intake-service",
        digest_key_resolver=lambda _tenant: b"o" * 32,
        clock=clock,
        token_factory=lambda: "fixed-lease-token",
    )


def enroll(store: object, source_id: str, *, key: str | None = None) -> None:
    store.enroll_source(  # type: ignore[attr-defined]
        "tenant-a",
        source_id,
        adapter_ref=f"adapter-{source_id}",
        credential_ref=f"env:RIGHTS_{source_id.upper()}_TOKEN",
        capabilities=sorted(orchestration.TASK_PHASES),
        expected_revision=0,
        idempotency_key=key or f"enroll-{source_id}",
    )


def intake_store(
    path: Path,
    store: object,
    admitted: dict[str, ConsumerRightsIntakeAuthority],
    evidence: dict[str, ConsumerRightsIdentityEvidence],
    keyring: Keyring,
    clock: Clock,
    *,
    request_ttl_seconds: int = 300,
    retention_seconds: int = 600,
    max_active_requests: int = 1_000,
    max_active_requests_per_subject: int | None = None,
    maintenance: bool = True,
) -> PrivacyRightsIntakeStore:
    return PrivacyRightsIntakeStore(
        path,
        rights_store=store,
        authority_resolver=lambda: admitted["value"],
        identity_evidence_resolver=lambda: evidence["value"],
        signing_key_resolver=keyring,
        request_ttl_seconds=request_ttl_seconds,
        retention_seconds=retention_seconds,
        max_active_requests=max_active_requests,
        max_active_requests_per_subject=max_active_requests_per_subject,
        maintenance_authorizer=lambda: maintenance,
        config_gate=lambda: None,
        clock=clock,
    )


def setup(
    tmp_path: Path,
    *,
    sources: tuple[str, ...] = ("crm",),
    retention_seconds: int = 600,
):
    clock = Clock()
    store = rights_store(tmp_path / "orchestration.sqlite3", clock)
    for source in sources:
        enroll(store, source)
    expected = authority(clock)
    admitted = {"value": expected}
    evidence = {"value": identity(expected, clock)}
    keyring = Keyring(clock)
    intake = intake_store(
        tmp_path / "intake.sqlite3",
        store,
        admitted,
        evidence,
        keyring,
        clock,
        retention_seconds=retention_seconds,
    )
    return clock, store, expected, admitted, evidence, keyring, intake


def complete_config() -> dict[str, object]:
    return {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "trust_center": {"enable": True},
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "rights_consumer_intake": {"enable": True},
        },
    }


def test_feature_gate_is_exact_and_default_off() -> None:
    assert enabled(complete_config())
    assert not enabled({})
    config = complete_config()
    config["privacy_automation"]["rights_consumer_intake"]["enable"] = 1  # type: ignore[index]
    assert not enabled(config)
    config = complete_config()
    del config["consent_preferences"]["trust_center"]  # type: ignore[index]
    assert not enabled(config)


def test_constructor_enforces_default_gate(tmp_path: Path) -> None:
    clock = Clock()
    store = rights_store(tmp_path / "rights.sqlite3", clock)
    expected = authority(clock)
    with pytest.raises(PrivacyRightsIntakeConfigError):
        PrivacyRightsIntakeStore(
            tmp_path / "intake.sqlite3",
            rights_store=store,
            authority_resolver=lambda: expected,
            identity_evidence_resolver=lambda: identity(expected, clock),
            signing_key_resolver=Keyring(clock),
        )


def test_public_creation_surface_keeps_server_authority_server_owned() -> None:
    parameters = set(inspect.signature(PrivacyRightsIntakeStore.create_request).parameters)
    assert parameters == {
        "self",
        "authority",
        "rights",
        "expected_revision",
        "idempotency_key",
    }
    assert not parameters.intersection(
        {
            "tenant_id",
            "subject_reference",
            "source_id",
            "legal_hold",
            "retained_until",
            "destructive_approval",
        }
    )


def test_creation_is_signed_idempotent_digest_only_and_delete_unapproved(
    tmp_path: Path,
) -> None:
    _, store, expected, _, _, _, intake = setup(tmp_path)
    raw_key = "consumer-raw-idempotency-key"
    status = intake.create_request(
        expected,
        rights=("access", "erasure"),
        expected_revision=0,
        idempotency_key=raw_key,
    )
    replay = intake.create_request(
        expected,
        rights=("access", "erasure"),
        expected_revision=0,
        idempotency_key=raw_key,
    )

    assert status.payload["case_id"] == replay.payload["case_id"]
    assert status.payload["rights"] == ["access", "erasure"]
    assert status.payload["destructive_approval_required"] is True
    assert intake.verify_signed_status(status)
    rights_case = store.get_case("tenant-a", str(status.payload["case_id"]))
    assert rights_case.identity_status == "verified"

    with sqlite3.connect(store.path) as connection:
        task_payloads = [
            json.loads(row[0])
            for row in connection.execute("SELECT payload_json FROM rights_tasks")
        ]
    delete_tasks = [item for item in task_payloads if item["phase"] == "delete"]
    assert len(delete_tasks) == 1
    assert delete_tasks[0]["state"] == "planned"
    assert delete_tasks[0]["approved_by"] is None

    persisted = intake.path.read_bytes() + store.path.read_bytes()
    for forbidden in (
        raw_key,
        "provider-idv-evidence-raw-ref",
        "person@example.test",
        "raw-oidc-subject",
        "raw-identity-token",
        "raw-reauthentication-receipt",
    ):
        assert forbidden.encode() not in persisted
    rendered = json.dumps(asdict(status), sort_keys=True)
    assert "provider-idv-evidence-raw-ref" not in rendered


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tenant_id", "tenant-b"),
        ("property_sha256", digest("other-property")),
        ("profile_binding_sha256", digest("other-profile-binding")),
        ("client_record_sha256", digest("other-client")),
        ("publication_sha256", digest("other-publication")),
        ("configuration_sha256", digest("other-configuration")),
        ("policy_version", 8),
        ("trust_context_revision", 7),
        ("capability_grant_sha256", digest("other-grant")),
    ],
)
def test_exact_authority_pin_substitution_fails_closed(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    _, _, expected, admitted, _, _, intake = setup(tmp_path)
    admitted["value"] = replace(expected, **{field: replacement})
    with pytest.raises(PrivacyRightsIntakeConflict):
        intake.create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="substitution-attempt",
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"valid_until": 1_899_999_999.0},
        {"revoked": True},
        {"subject_binding_sha256": digest("other-subject")},
        {"channel": "mobile-app"},
        {"verification_authority_sha256": digest("self-asserted-subject")},
        {"assurance_level": "low"},
    ],
)
def test_stale_revoked_self_asserted_or_misbound_identity_is_rejected(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    clock, _, expected, _, evidence, _, intake = setup(tmp_path)
    if "verification_authority_sha256" in overrides:
        overrides["verification_authority_sha256"] = expected.subject_binding_sha256
    evidence["value"] = identity(expected, clock, **overrides)
    with pytest.raises(PrivacyRightsIntakeConflict):
        intake.create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="bad-evidence",
        )


def test_double_resolution_rejects_authority_and_identity_drift(tmp_path: Path) -> None:
    clock = Clock()
    store = rights_store(tmp_path / "rights.sqlite3", clock)
    expected = authority(clock)
    other = replace(expected, policy_version=expected.policy_version + 1)
    calls = iter((expected, other))
    with pytest.raises(PrivacyRightsIntakeConflict):
        PrivacyRightsIntakeStore(
            tmp_path / "authority.sqlite3",
            rights_store=store,
            authority_resolver=lambda: next(calls),
            identity_evidence_resolver=lambda: identity(expected, clock),
            signing_key_resolver=Keyring(clock),
            config_gate=lambda: None,
            clock=clock,
        ).create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="authority-drift",
        )

    first = identity(expected, clock)
    second = identity(expected, clock, evidence_revision=12, evidence_ref="new-idv-ref")
    evidence_calls = iter((first, second))
    intake = PrivacyRightsIntakeStore(
        tmp_path / "identity.sqlite3",
        rights_store=store,
        authority_resolver=lambda: expected,
        identity_evidence_resolver=lambda: next(evidence_calls),
        signing_key_resolver=Keyring(clock),
        config_gate=lambda: None,
        clock=clock,
    )
    with pytest.raises(PrivacyRightsIntakeConflict):
        intake.create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="identity-drift",
        )


def test_closed_right_codes_and_idempotency_conflicts(tmp_path: Path) -> None:
    _, _, expected, _, _, _, intake = setup(tmp_path)
    intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="one-operation",
    )
    with pytest.raises(PrivacyRightsIntakeConflict):
        intake.create_request(
            expected,
            rights=("portability",),
            expected_revision=0,
            idempotency_key="one-operation",
        )
    with pytest.raises(PrivacyRightsIntakeValidationError):
        intake.create_request(
            expected,
            rights=("invented-right",),
            expected_revision=0,
            idempotency_key="unsupported-right",
        )
    with pytest.raises(PrivacyRightsIntakeValidationError):
        intake.create_request(
            expected,
            rights=("access", "access"),
            expected_revision=0,
            idempotency_key="duplicate-right",
        )
    with pytest.raises(PrivacyRightsIntakeConflict):
        intake.create_request(
            expected,
            rights=("access",),
            expected_revision=1,
            idempotency_key="wrong-revision",
        )


@pytest.mark.parametrize(
    "stage",
    ("reserve", "open_case", "set_identity", "plan_first", "plan_second", "finalize"),
)
def test_crash_recovery_at_every_durable_saga_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    _, store, expected, admitted, evidence, keyring, intake = setup(
        tmp_path,
        sources=("crm", "lake"),
    )
    target: object
    name: str
    if stage == "reserve":
        target, name = intake, "_reserve"
    elif stage == "open_case":
        target, name = store, "open_case"
    elif stage == "set_identity":
        target, name = store, "set_identity_verification"
    elif stage.startswith("plan_"):
        target, name = store, "plan_source_tasks"
    else:
        target, name = intake, "_finalize"
    original = getattr(target, name)
    calls = 0
    crash_on = 1 if stage != "plan_second" else 2

    def crash_after(*args: object, **kwargs: object):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == crash_on:
            raise RuntimeError(f"simulated crash after {stage}")
        return result

    monkeypatch.setattr(target, name, crash_after)
    with pytest.raises(RuntimeError, match="simulated crash"):
        intake.create_request(
            expected,
            rights=("erasure",),
            expected_revision=0,
            idempotency_key="recoverable-operation",
        )
    monkeypatch.setattr(target, name, original)

    recovered = intake_store(
        intake.path,
        store,
        admitted,
        evidence,
        keyring,
        Clock(),
    ).create_request(
        expected,
        rights=("erasure",),
        expected_revision=0,
        idempotency_key="recoverable-operation",
    )
    assert recovered.payload["planned_source_count"] == 2
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_cases").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM rights_tasks").fetchone()[0] == 6


def test_concurrent_duplicate_submission_creates_one_case(tmp_path: Path) -> None:
    clock, store, expected, _, _, _, intake = setup(tmp_path, sources=("crm", "lake"))
    ticks = itertools.count()

    def advancing_clock() -> float:
        return clock() + next(ticks) / 1_000

    store._clock = advancing_clock
    intake._clock = advancing_clock

    def submit(_: int) -> str:
        status = intake.create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="concurrent-operation",
        )
        return str(status.payload["case_id"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        case_ids = list(pool.map(submit, range(16)))
    assert len(set(case_ids)) == 1
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_cases").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM rights_tasks").fetchone()[0] == 6


def test_source_authority_drift_blocks_status(tmp_path: Path) -> None:
    _, store, expected, _, _, _, intake = setup(tmp_path)
    status = intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="source-pinned-operation",
    )
    store.enroll_source(
        "tenant-a",
        "crm",
        adapter_ref="adapter-crm-v2",
        credential_ref="env:RIGHTS_CRM_TOKEN_V2",
        capabilities=sorted(orchestration.TASK_PHASES),
        expected_revision=1,
        idempotency_key="rotate-source-authority",
    )
    with pytest.raises(PrivacyRightsIntakeConflict, match="source changed"):
        intake.get_status(expected, str(status.payload["case_id"]))


def test_source_authority_drift_blocks_incomplete_saga_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, expected, _, _, _, intake = setup(tmp_path)
    original = intake._reserve

    def crash_after_reserve(*args: object, **kwargs: object):
        original(*args, **kwargs)
        raise RuntimeError("simulated reserve crash")

    monkeypatch.setattr(intake, "_reserve", crash_after_reserve)
    with pytest.raises(RuntimeError, match="reserve crash"):
        intake.create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="source-drift-recovery",
        )
    monkeypatch.setattr(intake, "_reserve", original)
    store.enroll_source(
        "tenant-a",
        "crm",
        adapter_ref="adapter-crm-v2",
        credential_ref="env:RIGHTS_CRM_TOKEN_V2",
        capabilities=sorted(orchestration.TASK_PHASES),
        expected_revision=1,
        idempotency_key="drift-source-before-recovery",
    )
    with pytest.raises(PrivacyRightsIntakeConflict, match="source changed"):
        intake.create_request(
            expected,
            rights=("access",),
            expected_revision=0,
            idempotency_key="source-drift-recovery",
        )


def test_status_signature_tamper_rotation_and_revocation(tmp_path: Path) -> None:
    _, _, expected, _, _, keyring, intake = setup(tmp_path)
    first = intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="signed-status-operation",
    )
    assert intake.verify_signed_status(first)
    tampered_payload = dict(first.payload)
    tampered_payload["status"] = "completed"
    assert not intake.verify_signed_status(replace(first, payload=tampered_payload))
    assert not intake.verify_signed_status(replace(first, signature="0" * 64))

    second_key = keyring.rotate()
    second = intake.get_status(expected, str(first.payload["case_id"]))
    assert second.signing_key_ref == second_key.key_ref
    assert intake.verify_signed_status(first)
    assert intake.verify_signed_status(second)
    keyring.revoke(first.signing_key_ref, first.signing_key_revision)
    assert not intake.verify_signed_status(first)
    assert intake.verify_signed_status(second)


def test_active_tenant_request_limit_recovers_after_ttl(
    tmp_path: Path,
) -> None:
    clock, store, expected, admitted, evidence, keyring, _ = setup(tmp_path)
    intake = intake_store(
        tmp_path / "bounded-intake.sqlite3",
        store,
        admitted,
        evidence,
        keyring,
        clock,
        request_ttl_seconds=60,
        retention_seconds=600,
        max_active_requests=1,
    )
    first = intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="bounded-first",
    )
    assert first.payload["intake_active_until"] == clock() + 60
    with pytest.raises(PrivacyRightsIntakeConflict, match="maximum active"):
        intake.create_request(
            expected,
            rights=("portability",),
            expected_revision=0,
            idempotency_key="bounded-second",
        )

    clock.value += 61
    admitted["value"] = replace(expected, valid_until=clock() + 3_600)
    evidence["value"] = identity(admitted["value"], clock, evidence_revision=12)
    recovered = intake.create_request(
        admitted["value"],
        rights=("portability",),
        expected_revision=0,
        idempotency_key="bounded-second",
    )
    assert recovered.payload["case_id"] != first.payload["case_id"]


def test_active_subject_limit_cannot_be_evaded_inside_tenant(tmp_path: Path) -> None:
    clock, store, expected, admitted, evidence, keyring, _ = setup(tmp_path)
    intake = intake_store(
        tmp_path / "subject-bounded-intake.sqlite3",
        store,
        admitted,
        evidence,
        keyring,
        clock,
        max_active_requests=3,
        max_active_requests_per_subject=1,
    )
    intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="subject-first",
    )
    with pytest.raises(PrivacyRightsIntakeConflict, match="active subject"):
        intake.create_request(
            expected,
            rights=("portability",),
            expected_revision=0,
            idempotency_key="subject-second",
        )

    other = replace(
        expected,
        subject_binding_sha256=digest("another-subject"),
    )
    admitted["value"] = other
    evidence["value"] = identity(other, clock, evidence_revision=12)
    accepted = intake.create_request(
        other,
        rights=("portability",),
        expected_revision=0,
        idempotency_key="another-subject-first",
    )
    assert accepted.payload["case_id"].startswith("PRI-")
    with sqlite3.connect(intake.path) as connection:
        plans = " ".join(
            str(row)
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT COUNT(*) "
                "FROM consumer_rights_intake_active "
                "WHERE tenant_id=? AND subject_binding_sha256=? AND active_until>?",
                ("tenant-a", other.subject_binding_sha256, clock()),
            ).fetchall()
        )
    assert "consumer_rights_intake_active_subject_idx" in plans


def test_revoked_or_drifting_public_authority_hides_status(tmp_path: Path) -> None:
    _, _, expected, admitted, _, _, intake = setup(tmp_path)
    status = intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="hidden-status-operation",
    )
    admitted["value"] = replace(expected, revoked=True)
    with pytest.raises(PrivacyRightsIntakeNotFound):
        intake.get_status(expected, str(status.payload["case_id"]))
    admitted["value"] = replace(expected, policy_version=expected.policy_version + 1)
    with pytest.raises(PrivacyRightsIntakeNotFound):
        intake.get_status(expected, str(status.payload["case_id"]))


def test_fresh_rotated_identity_can_read_but_not_change_subject(tmp_path: Path) -> None:
    clock, _, expected, _, evidence, _, intake = setup(tmp_path)
    status = intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="fresh-status-evidence",
    )
    evidence["value"] = identity(
        expected,
        clock,
        evidence_ref="new-provider-idv-ref",
        evidence_revision=12,
    )
    refreshed = intake.get_status(expected, str(status.payload["case_id"]))
    assert refreshed.payload["identity_evidence_revision"] == 12
    evidence["value"] = identity(
        expected,
        clock,
        subject_binding_sha256=digest("substituted-subject"),
    )
    with pytest.raises(PrivacyRightsIntakeNotFound):
        intake.get_status(expected, str(status.payload["case_id"]))


def test_retention_purge_removes_local_binding_and_audit(tmp_path: Path) -> None:
    clock, _, expected, _, _, _, intake = setup(tmp_path, retention_seconds=60)
    status = intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="expiring-operation",
    )
    clock.value += 61
    with pytest.raises(PrivacyRightsIntakeNotFound):
        intake.get_status(expected, str(status.payload["case_id"]))
    assert intake.purge_expired() == {
        "requests_deleted": 1,
        "operations_deleted": 1,
        "audit_events_deleted": 2,
    }
    with sqlite3.connect(intake.path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM consumer_rights_intake_requests").fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM consumer_rights_intake_operations").fetchone()[
                0
            ]
            == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM consumer_rights_intake_audit").fetchone()[0]
            == 0
        )


def test_purge_requires_maintenance_authority(tmp_path: Path) -> None:
    clock, store, expected, admitted, evidence, keyring, _ = setup(tmp_path)
    intake = intake_store(
        tmp_path / "maintenance.sqlite3",
        store,
        admitted,
        evidence,
        keyring,
        clock,
        maintenance=False,
    )
    with pytest.raises(PrivacyRightsIntakeConfigError):
        intake.purge_expired()
    assert expected.tenant_id == "tenant-a"


def test_integrity_verification_detects_sqlite_record_corruption(tmp_path: Path) -> None:
    _, _, expected, _, _, _, intake = setup(tmp_path)
    intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="integrity-operation",
    )
    verified = intake.verify_integrity("tenant-a")
    assert verified["requests"] == 1
    assert verified["operations"] == 1
    assert verified["audit_events"] == 2
    with sqlite3.connect(intake.path) as connection:
        connection.execute(
            "UPDATE consumer_rights_intake_requests SET integrity_sha256=?",
            ("0" * 64,),
        )
    with pytest.raises(PrivacyRightsIntakeIntegrityError):
        intake.verify_integrity("tenant-a")


def test_integrity_verification_detects_physical_sqlite_corruption(
    tmp_path: Path,
) -> None:
    _, _, expected, _, _, _, intake = setup(tmp_path)
    intake.create_request(
        expected,
        rights=("access",),
        expected_revision=0,
        idempotency_key="physical-integrity-operation",
    )
    with sqlite3.connect(intake.path) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    intake.path.write_bytes(intake.path.read_bytes()[:200])
    with pytest.raises(PrivacyRightsIntakeIntegrityError):
        intake.verify_integrity("tenant-a")


def test_product_boundaries_are_explicit() -> None:
    boundaries = PrivacyRightsIntakeStore.product_boundaries()
    assert boundaries["orchestration_is_sole_case_task_authority"] is True
    assert boundaries["independent_identity_resolver_required"] is True
    assert boundaries["network_io"] is False
    assert boundaries["provider_writes"] is False
    assert boundaries["identity_verification_performed"] is False
    assert boundaries["response_delivery_performed"] is False
    assert boundaries["destructive_work_auto_approved"] is False
    assert boundaries["live_provider_acceptance_verified"] is False


def test_wrong_status_type_is_not_verifiable(tmp_path: Path) -> None:
    _, _, _, _, _, _, intake = setup(tmp_path)
    assert not intake.verify_signed_status(object())  # type: ignore[arg-type]
    assert not intake.verify_signed_status(
        SignedConsumerRightsStatus({}, "bad", 1, "0" * 64, "0" * 64, "0" * 64)
    )
