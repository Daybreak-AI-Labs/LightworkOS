from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from maverick import consent_global_opt_out as goo


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _config(enabled: bool = True) -> dict:
    return {
        "consent_preferences": {
            "enable": True,
            "global_opt_out": {
                "enable": enabled,
                "retention_seconds": 3_600,
                "submission_ttl_seconds": 300,
                "max_records": 100,
            },
        }
    }


def _fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    clock = [time.time()]
    principal = "global-opt-out-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    application = {
        "tenant_id": "alpha",
        "application_ref": "public-client-main",
        "public_client_revision": 4,
        "public_client_record_sha256": _digest("client-v4"),
        "property_revision": 8,
        "property_sha256": _digest("property-v8"),
        "publication_sha256": _digest("publication-v3"),
        "publication_bundle_sha256": _digest("bundle-v3"),
        "configuration_sha256": _digest("public-configuration-v3"),
        "policy_id": "public-consent",
        "policy_version": 2,
        "policy_sha256": _digest("policy-v2"),
        "channel": "browser-origin",
        "origin_or_service_sha256": _digest("https://example.test"),
        "valid_until": clock[0] + 10_000,
        "revoked": False,
    }

    def application_resolver(tenant, principal_ref, application_ref):
        assert tenant == "alpha"
        assert principal_ref == principal
        assert application_ref == application["application_ref"]
        return goo.issue_application_authority(**application)

    limits = goo.load_global_opt_out_limits(_config())
    admin = goo.GlobalOptOutStore(
        tenant_id="alpha",
        principal_ref=principal,
        application_authority_resolver=application_resolver,
        principal_resolver=lambda: principal,
        config_gate=lambda: _config(),
        limits=limits,
        maintenance_authorizer=lambda: True,
        clock=lambda: clock[0],
    )
    created = admin.create_configuration(
        application["application_ref"],
        locale="en-US",
        mobile_ui={
            "enabled": True,
            "title": "Privacy choice",
            "body": "Submit an opt-out request.",
            "submit_label": "Opt out",
            "success_message": "Request accepted.",
        },
        email_ui={
            "enabled": True,
            "title": "Privacy request",
            "body": "Submit a verified opt-out request.",
            "submit_label": "Submit request",
            "success_message": "Request accepted.",
        },
        supported_devices=["browser", "ios"],
        supported_services=["website", "email"],
        expires_at=None,
        expected_revision=0,
        idempotency_key="create-global-opt-out",
    )
    active = admin.activate_configuration(
        created["configuration_id"],
        expected_revision=created["revision"],
        idempotency_key="activate-global-opt-out",
    )
    intake = SimpleNamespace(
        tenant_id="alpha",
        property_sha256=application["property_sha256"],
        profile_sha256=_digest("profile"),
        profile_binding_sha256=_digest("profile-binding"),
        rights=("opt_out",),
    )
    public_values = {
        **application,
        "profile_sha256": intake.profile_sha256,
        "profile_binding_sha256": intake.profile_binding_sha256,
        "profile_revision": 6,
        "intake_authority_sha256": goo.authority_material_sha256(intake),
    }
    public = [goo.issue_public_authority(**public_values)]
    submitted: list[tuple[object, tuple[str, ...], int, str]] = []

    def submitter(authority, rights, expected_revision, idempotency_key):
        submitted.append((authority, tuple(rights), expected_revision, idempotency_key))
        return goo.GlobalOptOutDSARResult(
            case_id="PRI-real-opt-out-case",
            result_sha256=_digest("verified-signed-status"),
        )

    public_store = goo.GlobalOptOutStore(
        tenant_id="alpha",
        principal_ref="global-opt-out-public-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        application_authority_resolver=lambda *_args: goo.issue_application_authority(
            **application
        ),
        principal_resolver=lambda: "global-opt-out-public-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        config_gate=lambda: _config(),
        limits=limits,
        public_authority_resolver=lambda: public[0],
        intake_authority_resolver=lambda: intake,
        privacy_rights_submitter=submitter,
        clock=lambda: clock[0],
    )
    return admin, public_store, clock, application, public, intake, submitted, active


def test_config_public_submit_is_exact_digest_only_and_idempotent(tmp_path, monkeypatch):
    admin, public_store, _clock, _application, public, _intake, submitted, active = _fixture(
        tmp_path, monkeypatch
    )
    configuration = public_store.get_public_configuration(public[0])
    assert configuration["configuration_id"] == active["configuration_id"]
    assert configuration["configuration_version"] == 1
    assert configuration["mobile_ui"]["enabled"] is True

    first = public_store.submit(
        public[0],
        configuration_version=configuration["configuration_version"],
        configuration_sha256=configuration["configuration_sha256"],
        authority_revision=configuration["authority_revision"],
        authority_sha256=configuration["authority_sha256"],
        idempotency_key="public-opt-out-one",
    )
    replay = public_store.submit(
        public[0],
        configuration_version=configuration["configuration_version"],
        configuration_sha256=configuration["configuration_sha256"],
        authority_revision=configuration["authority_revision"],
        authority_sha256=configuration["authority_sha256"],
        idempotency_key="public-opt-out-one",
    )

    assert replay == first
    assert first["state"] == "submitted"
    assert first["case_reference_sha256"] == _digest("PRI-real-opt-out-case")
    assert first["dsar_result_sha256"] == _digest("verified-signed-status")
    assert len(submitted) == 1
    assert submitted[0][1:] == (("opt_out",), 0, submitted[0][3])

    raw = public_store._call("get", first["submission_id"])  # noqa: SLF001
    encoded = json.dumps(raw, sort_keys=True)
    assert "PRI-real-opt-out-case" not in encoded
    assert "https://example.test" not in encoded
    assert "case_reference_sha256" in encoded
    assert admin.verify_integrity()["ok"] is True


def test_non_ascii_submission_digest_is_stale_not_a_type_error(tmp_path, monkeypatch):
    # Public submission digests are caller-supplied; a non-ASCII value used to
    # raise TypeError from hmac.compare_digest instead of the stale refusal.
    _admin, public_store, _clock, _application, public, _intake, submitted, _active = _fixture(
        tmp_path, monkeypatch
    )
    configuration = public_store.get_public_configuration(public[0])
    for field in ("configuration_sha256", "authority_sha256"):
        values = {
            "configuration_sha256": configuration["configuration_sha256"],
            "authority_sha256": configuration["authority_sha256"],
            field: "é" * 64,
        }
        with pytest.raises(goo.GlobalOptOutAuthorityStale):
            public_store.submit(
                public[0],
                configuration_version=configuration["configuration_version"],
                authority_revision=configuration["authority_revision"],
                idempotency_key="public-opt-out-one",
                **values,
            )
    assert submitted == []


def test_authority_drift_revocation_and_cross_tenant_fail_closed(tmp_path, monkeypatch):
    admin, public_store, _clock, application, public, _intake, _submitted, active = _fixture(
        tmp_path, monkeypatch
    )
    drifted = {**application, "public_client_revision": 5}
    public[0] = goo.issue_public_authority(
        **drifted,
        profile_sha256=_digest("profile"),
        profile_binding_sha256=_digest("profile-binding"),
        profile_revision=6,
        intake_authority_sha256=public[0].intake_authority_sha256,
    )
    with pytest.raises(goo.GlobalOptOutAuthorityStale):
        public_store.get_public_configuration()

    public[0] = goo.issue_public_authority(
        **application,
        profile_sha256=_digest("profile"),
        profile_binding_sha256=_digest("profile-binding"),
        profile_revision=6,
        intake_authority_sha256=public[0].intake_authority_sha256,
    )
    revoked = admin.revoke_configuration(
        active["configuration_id"],
        expected_revision=active["revision"],
        idempotency_key="revoke-global-opt-out",
    )
    assert revoked["state"] == "revoked"
    with pytest.raises(goo.GlobalOptOutNotConfigured):
        public_store.get_public_configuration(public[0])

    beta = goo.GlobalOptOutStore(
        tenant_id="beta",
        principal_ref="global-opt-out-public-cccccccccccccccccccccccccccccccc",
        application_authority_resolver=lambda *_args: goo.issue_application_authority(
            **{**application, "tenant_id": "beta"}
        ),
        principal_resolver=lambda: "global-opt-out-public-cccccccccccccccccccccccccccccccc",
        config_gate=lambda: _config(),
        public_authority_resolver=lambda: goo.issue_public_authority(
            **{**application, "tenant_id": "beta"},
            profile_sha256=_digest("profile"),
            profile_binding_sha256=_digest("profile-binding"),
            profile_revision=6,
            intake_authority_sha256=_digest("intake"),
        ),
    )
    with pytest.raises(goo.GlobalOptOutNotConfigured):
        beta.get_public_configuration()


def test_interrupted_dsar_is_reserved_and_recovers_without_duplicate_case(tmp_path, monkeypatch):
    _admin, public_store, _clock, _application, public, _intake, _submitted, _active = (
        _fixture(tmp_path, monkeypatch)
    )
    configuration = public_store.get_public_configuration(public[0])

    def unavailable(*_args):
        raise RuntimeError("provider detail must not escape")

    public_store._privacy_rights_submitter = unavailable  # noqa: SLF001
    with pytest.raises(goo.GlobalOptOutDSARUnavailable, match="unavailable"):
        public_store.submit(
            public[0],
            configuration_version=configuration["configuration_version"],
            configuration_sha256=configuration["configuration_sha256"],
            authority_revision=configuration["authority_revision"],
            authority_sha256=configuration["authority_sha256"],
            idempotency_key="recover-public-opt-out",
        )

    calls = []

    def recovered(_authority, rights, expected_revision, key):
        calls.append((tuple(rights), expected_revision, key))
        return goo.GlobalOptOutDSARResult("PRI-recovered-case", _digest("recovered"))

    public_store._privacy_rights_submitter = recovered  # noqa: SLF001
    result = public_store.submit(
        public[0],
        configuration_version=configuration["configuration_version"],
        configuration_sha256=configuration["configuration_sha256"],
        authority_revision=configuration["authority_revision"],
        authority_sha256=configuration["authority_sha256"],
        idempotency_key="recover-public-opt-out",
    )
    assert result["state"] == "submitted"
    assert len(calls) == 1
    assert calls[0][0] == ("opt_out",)
    assert calls[0][1] == 0
    assert calls[0][2].startswith("global-opt-out-")


def test_disabled_integrity_and_retention_paths_are_closed(tmp_path, monkeypatch):
    admin, _public_store, clock, _application, _public, _intake, _submitted, active = (
        _fixture(tmp_path, monkeypatch)
    )
    disabled = goo.GlobalOptOutStore(
        tenant_id="alpha",
        principal_ref="global-opt-out-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        application_authority_resolver=lambda *_args: pytest.fail("resolver must not run"),
        principal_resolver=lambda: "global-opt-out-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        config_gate=lambda: _config(False),
    )
    with pytest.raises(goo.GlobalOptOutDisabled):
        disabled.list_configurations()

    revoked = admin.revoke_configuration(
        active["configuration_id"],
        expected_revision=active["revision"],
        idempotency_key="revoke-before-purge",
    )
    clock[0] = float(revoked["retained_until"]) + 1
    assert admin.purge_retained()["purged"] == 1
    purged = admin.get_configuration(active["configuration_id"])
    assert purged["state"] == "purged"
    assert purged["mobile_ui"] is None

    raw = admin._call("get", active["configuration_id"])  # noqa: SLF001

    def tamper(record):
        record["locale"] = "fr-FR"

    admin._call(  # noqa: SLF001
        "update",
        active["configuration_id"],
        tamper,
        expected_revision=raw["revision"],
        action="test_tamper",
        actor=_digest("tamper"),
    )
    with pytest.raises(goo.GlobalOptOutIntegrityError):
        admin.get_configuration(active["configuration_id"])
