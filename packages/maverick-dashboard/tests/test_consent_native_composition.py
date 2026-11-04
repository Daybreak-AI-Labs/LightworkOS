from __future__ import annotations

import gc
import hashlib
import sqlite3
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from maverick.consent_native_sdk import (
    NativeApplicationAuthority,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeConsentDeviceRegistry,
    NativeEnrollmentEvidence,
    VerifiedNativeAttestation,
)
from maverick_dashboard import consent_native_composition as composition
from maverick_dashboard.consent_public_api import PublicConsentDependencies


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _public_key() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def _settings(**changes) -> composition.NativeConsentSettings:
    values = {
        "receipt_key_id": "native-receipt",
        "receipt_key_revision": 1,
        "receipt_key_secret_ref": "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY",
        "max_applications": 100,
        "max_devices": 1_000,
        "max_requests": 10_000,
        "requests_per_minute": 120,
        "require_profile_linking": False,
        "require_rights_requests": False,
        "standards_wire_required": False,
    }
    values.update(changes)
    return composition.NativeConsentSettings(**values)


def _authority(*, tenant: str, application_ref: str) -> NativeApplicationAuthority:
    return NativeApplicationAuthority(
        application_ref=application_ref,
        tenant_id=tenant,
        property_id="property-main",
        application_id=f"com.example.{tenant}",
        platform="ios",
        public_client_credential_sha256=_digest(f"client:{tenant}"),
        public_client_revision=1,
        public_client_record_sha256=_digest(f"client-record:{tenant}"),
        property_revision=1,
        property_sha256=_digest(f"property:{tenant}"),
        publication_sha256=_digest(f"publication:{tenant}"),
        publication_bundle_sha256=_digest(f"bundle:{tenant}"),
        configuration_sha256=_digest(f"configuration:{tenant}"),
        policy_id="policy-main",
        policy_version=1,
        policy_sha256=_digest(f"policy:{tenant}"),
        standards_contract_sha256=_digest(f"standards:{tenant}"),
        minimum_sdk_version=1,
        default_locale="en-US",
        locales=("en-US",),
    )


class _Verifier:
    def verify(
        self,
        evidence: NativeEnrollmentEvidence,
        _attestation_material: bytes,
    ) -> VerifiedNativeAttestation:
        now = time.time()
        return VerifiedNativeAttestation(
            authority="external-platform-verifier",
            application_ref=evidence.application_ref,
            tenant_id=evidence.tenant_id,
            application_id=evidence.application_id,
            platform=evidence.platform,
            install_subject_sha256=evidence.install_subject_sha256,
            public_key_hex=evidence.public_key_hex,
            attestation_nonce=evidence.attestation_nonce,
            attestation_evidence_sha256=evidence.attestation_evidence_sha256,
            verified_at=now,
            valid_until=now + 3_600,
            verdict="allow",
            sdk_version=evidence.sdk_version,
        )


def _evidence(
    authority: NativeApplicationAuthority,
    *,
    public_key_hex: str,
    nonce: str,
    material: bytes,
    tenant_id: str | None = None,
) -> NativeEnrollmentEvidence:
    now = time.time()
    return NativeEnrollmentEvidence(
        application_ref=authority.application_ref,
        tenant_id=tenant_id or authority.tenant_id,
        application_id=authority.application_id,
        platform=authority.platform,
        install_subject_sha256=_digest("install-one"),
        public_key_hex=public_key_hex,
        attestation_nonce=nonce,
        attestation_evidence_sha256=hashlib.sha256(material).hexdigest(),
        issued_at=int(now) - 1,
        expires_at=int(now) + 120,
    )


def test_closed_settings_require_public_authorities_and_callback_dependencies() -> None:
    config = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "standards": {"gpp": True, "tcf": False},
            "native_sdk": {
                "enable": True,
                "receipt_key_id": "native-receipt-prod",
                "receipt_key_revision": 2,
                "receipt_key_secret_ref": "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY",
                "max_applications": 1_000,
                "max_devices": 100_000,
                "max_requests": 1_000_000,
                "requests_per_minute": 120,
                "require_profile_linking": True,
                "require_rights_requests": True,
            },
        }
    }
    settings = composition.native_consent_settings(config)
    assert settings is not None
    assert settings.standards_wire_required is True
    assert settings.require_profile_linking is True
    assert settings.require_rights_requests is True

    config["consent_preferences"]["public_api"]["enable"] = False
    with pytest.raises(composition.NativeConsentCompositionError, match="public API"):
        composition.native_consent_settings(config)


def test_directory_is_globally_unambiguous_and_registries_remain_tenant_private(
    tmp_path,
) -> None:
    directory = composition.NativeApplicationDirectory(tmp_path / "global" / "directory.db")
    settings = _settings()
    alpha = _authority(tenant="alpha", application_ref="mobile-alpha")
    beta = _authority(tenant="beta", application_ref="mobile-beta")
    alpha_registry = NativeConsentDeviceRegistry(tmp_path / "alpha" / "registry.db")
    beta_registry = NativeConsentDeviceRegistry(tmp_path / "beta" / "registry.db")
    alpha_key = _public_key()
    beta_key = _public_key()

    assert directory.register_new(
        alpha,
        registry=alpha_registry,
        settings=settings,
        public_key_hex=alpha_key,
        expected_revision=0,
    )["directory_revision"] == 1
    directory.register_new(
        beta,
        registry=beta_registry,
        settings=settings,
        public_key_hex=beta_key,
        expected_revision=0,
    )

    with pytest.raises(NativeConsentDenied, match="tenant authority"):
        directory.resolve("mobile-alpha", claimed_tenant_id="beta")
    with pytest.raises(NativeConsentConflict, match="already registered"):
        directory.register_new(
            _authority(tenant="beta", application_ref="mobile-alpha"),
            registry=beta_registry,
            settings=settings,
            public_key_hex=beta_key,
            expected_revision=0,
        )
    assert alpha_registry.path != beta_registry.path
    assert alpha_registry.get_application("mobile-alpha")[0].tenant_id == "alpha"
    assert beta_registry.get_application("mobile-beta")[0].tenant_id == "beta"

    rotated = directory.rotate_receipt_key(
        "mobile-alpha",
        tenant_id="alpha",
        expected_directory_revision=1,
        key_id="native-receipt-next",
        key_revision=2,
        public_key_hex=_public_key(),
    )
    assert rotated["directory_revision"] == 2
    keys = directory.receipt_keys("mobile-alpha")
    assert len(keys["keys"]) == 2
    assert sum(item["current"] is True for item in keys["keys"]) == 1
    assert directory.verify_integrity() is True
    with sqlite3.connect(directory.path) as connection:
        connection.execute(
            "UPDATE native_consent_application_directory SET current_public_key_hex=? "
            "WHERE application_ref=?",
            ("f" * 64, "mobile-alpha"),
        )
    with pytest.raises(composition.NativeConsentCompositionError, match="directory changed"):
        directory.verify_integrity()


def test_multiplexer_requires_external_attestation_and_safely_routes_refresh(
    tmp_path,
    monkeypatch,
) -> None:
    settings = _settings()
    authority = _authority(tenant="alpha", application_ref="mobile-alpha")
    registry = NativeConsentDeviceRegistry(tmp_path / "alpha" / "registry.db")
    directory = composition.NativeApplicationDirectory(tmp_path / "global" / "directory.db")
    directory.register_new(
        authority,
        registry=registry,
        settings=settings,
        public_key_hex=_public_key(),
        expected_revision=0,
    )
    app = FastAPI()
    injected = composition._InjectedAttestationVerifier(app)
    limiter = composition._BoundedRateLimiter()
    multiplexer = composition._RegistryMultiplexer(directory, injected, limiter)
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: settings)
    monkeypatch.setattr(composition, "_registry_for", lambda _tenant, _settings: registry)

    material = b"external-attestation-one"
    public_key = _public_key()
    enrollment = _evidence(
        authority,
        public_key_hex=public_key,
        nonce="nonce-enroll",
        material=material,
    )
    assert injected.available() is False
    with pytest.raises(NativeConsentDenied, match="unavailable"):
        multiplexer.enroll_device(
            enrollment,
            verifier=injected,
            attestation_material=material,
            sdk_version=1,
        )

    app.state.consent_native_attestation_verifier = _Verifier()
    device = multiplexer.enroll_device(
        enrollment,
        verifier=injected,
        attestation_material=material,
        sdk_version=1,
    )
    rebound = _evidence(
        authority,
        public_key_hex=public_key,
        nonce="nonce-refresh-wrong-tenant",
        material=b"external-attestation-wrong-tenant",
        tenant_id="beta",
    )
    with pytest.raises(NativeConsentDenied, match="tenant authority"):
        multiplexer.refresh_device_authority(
            device.device_id,
            rebound,
            verifier=injected,
            attestation_material=b"external-attestation-wrong-tenant",
            expected_revision=device.revision,
        )

    refresh_material = b"external-attestation-refresh"
    refresh = _evidence(
        authority,
        public_key_hex=public_key,
        nonce="nonce-refresh",
        material=refresh_material,
    )
    updated = multiplexer.refresh_device_authority(
        device.device_id,
        refresh,
        verifier=injected,
        attestation_material=refresh_material,
        expected_revision=device.revision,
    )
    assert updated.revision == device.revision + 1
    assert updated.application_authority_sha256 == authority.authority_sha256


def test_environment_receipt_keys_are_tenant_and_revision_separated(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY",
        "root-secret-material-that-is-long-enough-for-production-custody",
    )
    first = composition._environment_receipt_signer(
        tenant_id="alpha",
        settings=_settings(),
    )
    second = composition._environment_receipt_signer(
        tenant_id="beta",
        settings=_settings(),
    )
    rotated = composition._environment_receipt_signer(
        tenant_id="alpha",
        settings=_settings(receipt_key_revision=2),
    )
    assert len(first.public_key_hex) == 64
    assert len({first.public_key_hex, second.public_key_hex, rotated.public_key_hex}) == 3
    assert len(first.sign(b"receipt")) == 64


def test_application_and_device_lists_are_tenant_bound_and_carry_no_key_material(
    tmp_path,
    monkeypatch,
) -> None:
    settings = _settings()
    authority = _authority(tenant="alpha", application_ref="mobile-alpha")
    registry = NativeConsentDeviceRegistry(tmp_path / "alpha" / "registry.db")
    beta_registry = NativeConsentDeviceRegistry(tmp_path / "beta" / "registry.db")
    directory = composition.NativeApplicationDirectory(tmp_path / "global" / "directory.db")
    directory.register_new(
        authority,
        registry=registry,
        settings=settings,
        public_key_hex=_public_key(),
        expected_revision=0,
    )
    directory.register_new(
        _authority(tenant="beta", application_ref="mobile-beta"),
        registry=beta_registry,
        settings=settings,
        public_key_hex=_public_key(),
        expected_revision=0,
    )
    listed = composition.list_native_applications(
        directory, registry, tenant_id="alpha", limit=10
    )
    assert [item["application_ref"] for item in listed["items"]] == ["mobile-alpha"]
    row = listed["items"][0]
    assert row["application_id"] == "com.example.alpha"
    assert row["directory_revision"] == 1
    assert not any("sha256" in key or "public_key" in key for key in row)

    assert composition.list_native_devices(registry, application_ref="mobile-alpha") == {
        "items": [],
        "truncated": False,
    }
    app = FastAPI()
    app.state.consent_native_attestation_verifier = _Verifier()
    injected = composition._InjectedAttestationVerifier(app)
    multiplexer = composition._RegistryMultiplexer(
        directory, injected, composition._BoundedRateLimiter()
    )
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: settings)
    monkeypatch.setattr(composition, "_registry_for", lambda _tenant, _settings: registry)
    material = b"external-attestation-list"
    device = multiplexer.enroll_device(
        _evidence(authority, public_key_hex=_public_key(), nonce="nonce-list", material=material),
        verifier=injected,
        attestation_material=material,
        sdk_version=1,
    )
    devices = composition.list_native_devices(registry, application_ref="mobile-alpha")
    assert [item["device_id"] for item in devices["items"]] == [device.device_id]
    assert devices["items"][0]["revision"] == device.revision
    assert devices["items"][0]["status"] == "active"
    assert not any(
        key in devices["items"][0]
        for key in ("public_key_hex", "install_subject_sha256", "attestation_evidence_sha256")
    )
    assert composition.list_native_devices(beta_registry, application_ref="mobile-alpha") == {
        "items": [],
        "truncated": False,
    }


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_timed_verdict_reuses_a_pass_until_it_expires() -> None:
    clock = _Clock()
    runs: list[float] = []

    def check() -> bool:
        runs.append(clock.now)
        return True

    verdict = composition._TimedVerdict(check, pass_seconds=30, fail_seconds=5, clock=clock)
    assert [verdict(), verdict(), verdict()] == [True, True, True]
    assert runs == [100.0]
    clock.now += 29.9
    assert verdict() is True
    assert runs == [100.0]
    clock.now += 0.2
    assert verdict() is True
    assert runs == [100.0, 130.1]


def test_timed_verdict_rechecks_a_changed_revision_and_refuses_a_racing_write() -> None:
    clock = _Clock()
    revision = [0]
    runs: list[int] = []

    def check() -> bool:
        runs.append(revision[0])
        if len(runs) == 1:
            revision[0] = 1  # a write during the replay cannot be certified
        return True

    verdict = composition._TimedVerdict(
        check, pass_seconds=30, fail_seconds=5, clock=clock,
        revision=lambda: revision[0],
    )
    assert verdict() is False
    assert verdict() is True
    assert runs == [0, 1]
    assert verdict() is True  # unchanged burst does not replay
    revision[0] = 2
    assert verdict() is True
    assert runs == [0, 1, 2]


def test_shared_directory_revision_reads_the_database_wal_position(monkeypatch) -> None:
    monkeypatch.setattr(composition.consent_storage, "shared", lambda: True)
    directory = object.__new__(composition.NativeApplicationDirectory)
    sql: list[str] = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, statement):
            sql.append(statement)
            return self

        def fetchone(self):
            return ("0/DEADBEEF",)

    monkeypatch.setattr(directory, "_connect", lambda: Connection())
    assert directory.integrity_revision() == ("postgres", "0/DEADBEEF")
    assert sql == ["SELECT pg_current_wal_insert_lsn()"]


def test_timed_verdict_fails_closed_and_retries_a_failure_sooner_than_a_pass() -> None:
    clock = _Clock()
    outcomes: list[object] = [RuntimeError("database is locked"), False, True]
    runs: list[float] = []

    def check() -> bool:
        runs.append(clock.now)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return bool(outcome)

    verdict = composition._TimedVerdict(check, pass_seconds=30, fail_seconds=5, clock=clock)
    assert verdict() is False  # an error closes the gate, it never opens it
    clock.now += 4.9
    assert verdict() is False
    assert len(runs) == 1  # not re-run on every request while broken
    clock.now += 0.2
    assert verdict() is False  # a clean "no" is retried after the same short wait
    clock.now += 5.1
    assert verdict() is True
    assert len(runs) == 3
    clock.now += 29
    assert verdict() is True
    assert len(runs) == 3


def test_timed_verdict_treats_anything_but_true_as_a_failure() -> None:
    verdict = composition._TimedVerdict(lambda: 1, pass_seconds=30, fail_seconds=5)  # type: ignore[arg-type,return-value]
    assert verdict() is False


def test_timed_verdict_never_swallows_interpreter_shutdown() -> None:
    runs: list[int] = []

    def check() -> bool:
        runs.append(1)
        raise KeyboardInterrupt

    verdict = composition._TimedVerdict(check, pass_seconds=30, fail_seconds=5)
    for _ in range(2):
        with pytest.raises(KeyboardInterrupt):
            verdict()
    assert len(runs) == 2  # the interrupt was not remembered as an answer


def test_timed_verdict_runs_one_check_for_concurrent_callers() -> None:
    runs: list[int] = []

    def check() -> bool:
        runs.append(1)
        time.sleep(0.2)
        return True

    verdict = composition._TimedVerdict(check, pass_seconds=30, fail_seconds=5)
    answers: list[bool] = []
    threads = [threading.Thread(target=lambda: answers.append(verdict())) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert answers == [True] * 8
    assert len(runs) == 1


def _fresh_app() -> FastAPI:
    app = FastAPI()
    app.state.consent_native_attestation_verifier = _Verifier()
    return app


def _public_dependencies() -> PublicConsentDependencies:
    return PublicConsentDependencies(
        credential_store=None,  # type: ignore[arg-type]
        publishing_store_for=lambda _tenant: None,
        preference_store_for=lambda _tenant: None,
        gate=lambda: True,
        rate_limit=lambda *_args: None,
        context_resolver=lambda *_args: None,  # type: ignore[arg-type,return-value]
    )


def test_public_gate_scans_the_directory_once_for_a_burst_of_requests(
    tmp_path, monkeypatch
) -> None:
    """Every anonymous native request used to replay the whole directory audit
    chain (about 40 ms with 300 registered apps, growing with the fleet)."""

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    scans: list[int] = []
    real_scan = composition.NativeApplicationDirectory.verify_integrity

    def counting_scan(self) -> bool:
        scans.append(1)
        return real_scan(self)

    monkeypatch.setattr(composition.NativeApplicationDirectory, "verify_integrity", counting_scan)
    monkeypatch.setattr(
        composition.NativeApplicationDirectory, "has_active_application", lambda _self: True
    )
    dependencies = composition.attach_consent_native_composition(
        _fresh_app(), public_dependencies=_public_dependencies()
    )
    assert [dependencies.gate() for _ in range(25)] == [True] * 25
    assert len(scans) == 1


@pytest.mark.parametrize("mutation", ["alter", "delete"])
def test_public_gate_stays_closed_for_a_changed_directory_and_without_an_application(
    tmp_path, monkeypatch, mutation
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    dependencies = composition.attach_consent_native_composition(
        _fresh_app(), public_dependencies=_public_dependencies()
    )
    assert dependencies.gate() is False  # nothing registered yet

    directory = composition.NativeApplicationDirectory(
        composition.data_dir(
            "consent_public_api",
            "native-consent-application-directory.sqlite3",
            tenant=None,
        )
    )
    alpha = _authority(tenant="alpha", application_ref="mobile-alpha")
    directory.register_new(
        alpha,
        registry=NativeConsentDeviceRegistry(tmp_path / "alpha" / "registry.db"),
        settings=_settings(),
        public_key_hex=_public_key(),
        expected_revision=0,
    )
    assert dependencies.gate() is True  # registering opens it at once

    before_revision = directory.integrity_revision()
    with sqlite3.connect(directory.path) as connection:
        if mutation == "alter":
            connection.execute(
                "UPDATE native_consent_application_directory SET current_public_key_hex=? "
                "WHERE application_ref=?",
                ("f" * 64, "mobile-alpha"),
            )
        else:
            connection.execute("DROP TRIGGER native_consent_directory_audit_no_delete")
            connection.execute("DELETE FROM native_consent_directory_audit")
    after_revision = directory.integrity_revision()
    assert before_revision != after_revision, (before_revision, after_revision)
    # A cached pass must be invalidated as soon as a normal file mutation is
    # observable, even before its 30-second expiry.
    assert dependencies.gate() is False
    fresh = composition.attach_consent_native_composition(
        _fresh_app(), public_dependencies=_public_dependencies()
    )
    assert fresh.gate() is False


def test_revision_observer_closes_when_the_directory_is_released(tmp_path, monkeypatch) -> None:
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: an observer not closed on release stays open.
    opened = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(composition.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        released = composition.NativeApplicationDirectory(tmp_path / "other" / "directory.db")
        released.integrity_revision()
        observer = opened[-1]
        del released
        with pytest.raises(sqlite3.ProgrammingError):
            observer.execute("SELECT 1")
    finally:
        gc.enable()


def test_revision_observer_stays_open_for_reuse_and_closes_on_close(tmp_path, monkeypatch) -> None:
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: a connection that is not closed on release stays open.
    opened = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(composition.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        directory = composition.NativeApplicationDirectory(tmp_path / "global" / "directory.db")
        before = len(opened)
        directory.integrity_revision()
        directory.integrity_revision()
        observers = opened[before:]
        # One observer serves every revision check: PRAGMA data_version needs the same handle.
        assert len(observers) == 1
        assert observers[0].execute("SELECT 1").fetchone() == (1,)
        directory.close()
        directory.close()
        with pytest.raises(sqlite3.ProgrammingError):
            observers[0].execute("SELECT 1")
    finally:
        gc.enable()
