from __future__ import annotations

import copy
import gc
import hashlib
import inspect
import json
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick import config as maverick_config
from maverick import consumer_trust_center as trust_center_module
from maverick.consent_profile_data import ProfileExport, PublicProfileAuthority
from maverick.consumer_trust_center import (
    TRUST_CENTER_EXPORT_SCHEMA,
    TRUST_CENTER_SCHEMA,
    ConsumerTrustCenterSourceAdapter,
    ConsumerTrustCenterStore,
    TrustCenterCapabilityGrant,
    TrustCenterConflict,
    TrustCenterContext,
    TrustCenterIntegrityError,
    TrustCenterRightsAuthorization,
    trust_center_enabled,
)

NOW = 1_900_000_000.0
TENANT = "Ténant-α"
PROPERTY = "property-1"
PROFILE = "profile-1"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _text_sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _authority(tenant: str = TENANT) -> PublicProfileAuthority:
    return PublicProfileAuthority(
        tenant_id=tenant,
        profile_id=PROFILE,
        property_id=PROPERTY,
        catalog_id="catalog-1",
        catalog_version=1,
        publication_sha256=_digest("publication"),
        bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="policy-1",
        policy_version=1,
        policy_sha256=_digest("policy"),
        profile_capability_sha256=_digest("profile-capability"),
    )


def _grant(capability: str, *, tenant: str = TENANT, **changes: object):
    raw = TrustCenterCapabilityGrant(
        capability=capability,
        grant_ref=f"grant-{capability}",
        tenant_sha256=_text_sha(tenant),
        property_id=PROPERTY,
        profile_sha256=_text_sha(PROFILE),
        approved_by_sha256=_digest("approver-one"),
        second_approved_by_sha256=_digest("approver-two"),
        valid_until=NOW + 1_000,
        grant_sha256=_digest("placeholder"),
        revoked=False,
    )
    raw = replace(raw, **changes)
    return replace(
        raw,
        grant_sha256=ConsumerTrustCenterSourceAdapter.capability_grant_sha256(raw),
    )


def _rights_authorization(**changes: object) -> TrustCenterRightsAuthorization:
    raw = TrustCenterRightsAuthorization(
        case_id="case-1",
        expected_case_sha256=_digest("case-integrity"),
        approved_by_sha256=_digest("rights-approver-one"),
        second_approved_by_sha256=_digest("rights-approver-two"),
        valid_until=NOW + 1_000,
        authorization_sha256=_digest("placeholder"),
        revoked=False,
    )
    raw = replace(raw, **changes)
    return replace(
        raw,
        authorization_sha256=(ConsumerTrustCenterSourceAdapter.rights_authorization_sha256(raw)),
    )


def _resign(context: TrustCenterContext) -> TrustCenterContext:
    return replace(
        context,
        context_sha256=ConsumerTrustCenterSourceAdapter.context_sha256(context),
    )


def _context(
    *capabilities: str,
    tenant: str = TENANT,
    grants: tuple[TrustCenterCapabilityGrant, ...] | None = None,
    rights_authorizations: tuple[TrustCenterRightsAuthorization, ...] | None = None,
    profile_authority: PublicProfileAuthority | None = None,
    retained_until: float = NOW + 500,
) -> TrustCenterContext:
    selected = capabilities or (
        "active_publication",
        "consent_history",
        "profile_data",
        "rights_cases",
    )
    if grants is None:
        grants = tuple(_grant(item, tenant=tenant) for item in selected)
    if rights_authorizations is None:
        rights_authorizations = (_rights_authorization(),) if "rights_cases" in selected else ()
    if profile_authority is None and "profile_data" in selected:
        profile_authority = _authority(tenant)
    raw = TrustCenterContext(
        tenant_id=tenant,
        property_id=PROPERTY,
        profile_id=PROFILE,
        actor_sha256=_digest("trust-center-actor"),
        requested_locale="en-US",
        server_origin="https://tenant.example/private?token=SECRET-URL",
        server_bundle_id=None,
        server_platform=None,
        jurisdiction="US-CA",
        country_code="US",
        region_code="CA",
        profile_authority=profile_authority,
        capability_grants=grants,
        rights_authorizations=rights_authorizations,
        publication_history_limit=10,
        receipt_limit=10,
        retained_until=retained_until,
        revision=3,
        valid_until=NOW + 1_000,
        context_sha256=_digest("placeholder"),
        revoked=False,
    )
    return _resign(raw)


def _publication(tenant: str, revision: int = 1) -> dict[str, object]:
    body: dict[str, object] = {
        "schema": "lightwork.consent-publication.v1",
        "tenant_sha256": _text_sha(tenant),
        "publication_id": f"publication-{revision}",
        "property_id": PROPERTY,
        "publication_revision": revision,
        "action": "publish",
        "source_publication_id": None,
        "property_revision": 4,
        "bundle_sha256": _digest(f"bundle-{revision}"),
        "created_at": NOW - 100 + revision,
    }
    return {**body, "publication_sha256": _sha(body)}


class FakePublishing:
    def __init__(
        self,
        tenant: str = TENANT,
        *,
        drift: bool = False,
        branded: bool = False,
        unsafe_branding: bool = False,
    ) -> None:
        self.tenant = tenant
        self.drift = drift
        self.branded = branded
        self.unsafe_branding = unsafe_branding
        self.resolve_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.history_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self._generation = 0
        self._last_revision = 1

    def _result(self, revision: int) -> dict[str, object]:
        publication = _publication(self.tenant, revision)
        configuration = {
            "consent_mode": "opt_in",
            "purposes": [{"id": "analytics", "title": "SECRET PURPOSE PROSE"}],
            "topics": [],
            "custom_preferences": [],
            "notice": {
                "id": "notice-1",
                "version": 1,
                "resource_sha256": _digest("notice-resource"),
                "document_sha256": _digest("notice-document"),
                "title": "SECRET LEGAL TITLE",
                "body": "SECRET LEGAL BODY",
            },
            "template": {"body": "SECRET TEMPLATE PROSE"},
        }
        if self.branded:
            branding_body = {
                "theme_token_id": "brand-default",
                "version": 2,
                "resource_sha256": _digest("theme-resource"),
                "display_name": "Example",
                "heading": "Example Privacy Trust Center",
                "description": "Manage your choices and volunteered data.",
                "primary_color": "ffffff" if self.unsafe_branding else "174b3f",
                "primary_text_color": "eeeeee" if self.unsafe_branding else "ffffff",
                "surface_color": "ffffff",
                "text_color": "16211d",
            }
            configuration["branding"] = {
                **branding_body,
                "branding_sha256": _sha(branding_body),
            }
        property_data = {
            "property_id": PROPERTY,
            "kind": "web",
            "consent_group_id": "group-1",
            "revision": 4,
        }
        rule = {
            "rule_id": "rule-1",
            "rule_sha256": _digest("rule"),
            "locale": "en-US",
        }
        digest_body = {
            "publication_sha256": publication["publication_sha256"],
            "property_id": PROPERTY,
            "property_revision": 4,
            "consent_group_id": "group-1",
            "rule_id": "rule-1",
            "rule_sha256": rule["rule_sha256"],
            "locale": "en-US",
            "configuration": configuration,
        }
        return {
            "allowed": True,
            "property": property_data,
            "publication": publication,
            "rule": rule,
            "configuration": configuration,
            "configuration_sha256": _sha(digest_body),
        }

    def resolve_public_configuration(self, *args: object, **kwargs: object):
        self.resolve_calls.append((args, kwargs))
        self._generation += 1
        self._last_revision = self._generation if self.drift else 1
        return copy.deepcopy(self._result(self._last_revision))

    def publication_history(self, *args: object, **kwargs: object):
        self.history_calls.append((args, kwargs))
        return {
            "items": [copy.deepcopy(_publication(self.tenant, self._last_revision))],
            "truncated": False,
        }


class FakePreferences:
    def __init__(self, tenant: str = TENANT, *, drift: bool = False) -> None:
        self.tenant = tenant
        self.drift = drift
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def export_profile(self, *args: object, **kwargs: object):
        self.calls.append((args, kwargs))
        call = len(self.calls)
        receipt_id = f"receipt-{call}" if self.drift else "receipt-1"
        body = {
            "schema": "lightwork.consent-profile-export.v1",
            "requested_profile_id": PROFILE,
            "profiles": [
                {
                    "profile_id": PROFILE,
                    "identity_kind": "email",
                    "subject_sha256": _digest("SECRET RAW SUBJECT"),
                    "revision": 2,
                    "created_at": NOW - 1_000,
                }
            ],
            "receipts": [
                {
                    "schema": "lightwork.consent-receipt.v1",
                    "receipt_id": receipt_id,
                    "tenant_sha256": _text_sha(self.tenant),
                    "profile_id": PROFILE,
                    "profile_revision": 2,
                    "policy_id": "policy-1",
                    "policy_version": 1,
                    "policy_sha256": _digest("policy"),
                    "context": {"url": "https://secret/?raw=query"},
                    "context_sha256": _digest("receipt-context"),
                    "choices": [
                        {
                            "purpose_id": "analytics",
                            "action": "grant",
                            "channel": "web",
                            "vendor_id": "all",
                            "expires_at": None,
                        }
                    ],
                    "actor_sha256": _digest("SECRET RECEIPT ACTOR"),
                    "previous_receipt_sha256": None,
                    "receipt_sha256": _digest(f"receipt-integrity-{receipt_id}"),
                    "created_at": NOW - 50,
                    "retention_until": NOW + 5_000,
                }
            ],
            "receipts_truncated": False,
            # Deliberately volatile; normalized state must remain stable.
            "generated_at": NOW + call / 100,
        }
        return {**body, "export_sha256": _sha(body)}


class FakeProfileData:
    def __init__(
        self,
        tenant: str = TENANT,
        *,
        raw_value: object = True,
        retained_until: float = NOW + 5_000,
    ) -> None:
        self.tenant = tenant
        self.raw_value = raw_value
        self.retained_until = retained_until
        self.calls: list[PublicProfileAuthority] = []

    def export_profile(self, authority: PublicProfileAuthority) -> ProfileExport:
        self.calls.append(authority)
        call = len(self.calls)
        current = {
            "tenant_id": self.tenant,
            "profile_id": PROFILE,
            "preference_id": "newsletter",
            "value_type": "boolean",
            "value": self.raw_value,
            "status": "active",
            "revision": 2,
            "expires_at": None,
            "retained_until": self.retained_until,
            "binding_sha256": _digest("profile-binding"),
            "updated_at": NOW - 20,
            "integrity_sha256": _digest("profile-record"),
        }
        history = {
            "tenant_id": self.tenant,
            "profile_id": PROFILE,
            "sequence": 1,
            "preference_id": "newsletter",
            "action": "set",
            "value_type": "boolean",
            "value": self.raw_value,
            "status": "active",
            "expires_at": None,
            "retained_until": self.retained_until,
            "binding_sha256": _digest("profile-binding"),
            "occurred_at": NOW - 20,
            "integrity_sha256": _digest("profile-history"),
        }
        body = {
            "schema": "lightwork.consent-profile-export.v1",
            "tenant_id": self.tenant,
            "profile_id": PROFILE,
            "current_records": [current],
            "active_values": {"newsletter": self.raw_value},
            "history": [history],
            "prompt_interactions": [{"answer": "SECRET PROMPT FREE TEXT"}],
            "generated_at": NOW + call / 100,
            "product_boundaries": {"live": False},
        }
        return ProfileExport(
            schema="lightwork.consent-profile-export.v1",
            tenant_id=self.tenant,
            profile_id=PROFILE,
            body=body,
            export_sha256=_sha(body),
        )


class FakeRights:
    def __init__(self, tenant: str = TENANT, *, retained_until: float = NOW + 10_000) -> None:
        self.tenant = tenant
        self.retained_until = retained_until
        self.calls: list[tuple[str, str]] = []

    def get_case(self, tenant_id: str, case_id: str):
        self.calls.append((tenant_id, case_id))
        return SimpleNamespace(
            tenant_id=self.tenant,
            case_id=case_id,
            request_version=1,
            rights=("access", "delete"),
            identity_status="verified",
            status="in_progress",
            revision=4,
            created_at=NOW - 500,
            updated_at=NOW - 10,
            retained_until=self.retained_until,
            integrity_sha256=_digest("case-integrity"),
            subject_sha256=_digest("SECRET RIGHTS SUBJECT"),
            identity_evidence_ref="vault://SECRET-RIGHTS-EVIDENCE",
            opened_by="SECRET RIGHTS ACTOR",
        )


def _adapter(
    context: TrustCenterContext | None = None,
    *,
    publishing: object | None = None,
    preferences: object | None = None,
    profile_data: object | None = None,
    rights: object | None = None,
    resolver=None,
):
    context = context or _context()
    publishing = publishing or FakePublishing(context.tenant_id)
    preferences = preferences or FakePreferences(context.tenant_id)
    profile_data = profile_data if profile_data is not None else FakeProfileData(context.tenant_id)
    rights = rights if rights is not None else FakeRights(context.tenant_id)
    adapter = ConsumerTrustCenterSourceAdapter(
        publishing_store=publishing,
        preference_store=preferences,
        profile_data_store=profile_data,
        rights_store=rights,
        context_resolver=resolver or (lambda: context),
        clock=lambda: NOW,
    )
    return adapter, publishing, preferences, profile_data, rights


@pytest.mark.parametrize(
    ("loaded", "expected"),
    [
        ({}, False),
        ({"consent_preferences": {"enable": True}}, False),
        (
            {
                "consent_preferences": {
                    "enable": True,
                    "trust_center": {"enable": False},
                }
            },
            False,
        ),
        (
            {
                "consent_preferences": {
                    "enable": False,
                    "trust_center": {"enable": True},
                }
            },
            False,
        ),
        (
            {
                "consent_preferences": {
                    "enable": True,
                    "trust_center": {"enable": True},
                }
            },
            True,
        ),
    ],
)
def test_exact_default_off_gate(monkeypatch, loaded, expected):
    monkeypatch.setattr(maverick_config, "config_source_errors", list)
    monkeypatch.setattr(maverick_config, "load_config", lambda: loaded)
    assert trust_center_enabled() is expected
    monkeypatch.setattr(maverick_config, "config_source_errors", lambda: ["bad config"])
    assert trust_center_enabled() is False


def test_unified_snapshot_is_pinned_minimized_and_server_bound():
    adapter, publishing, preferences, profile_data, rights = _adapter()
    snapshot = adapter()

    assert snapshot["schema"] == TRUST_CENTER_SCHEMA
    assert snapshot["tenant_sha256"] == _text_sha(TENANT)
    assert snapshot["profile_ref_sha256"] == _text_sha(PROFILE)
    assert set(snapshot["sections"]) == {"publication", "consent", "profile_data", "rights"}
    assert snapshot["source_pins"] == {
        key: value["source_sha256"] for key, value in snapshot["sections"].items()
    }
    rights_section = snapshot["sections"]["rights"]
    assert rights_section["authorization_scope"] == "explicit_case_refs_only"
    assert rights_section["completeness_claimed"] is False
    assert snapshot["boundaries"] == {
        "tenant_local_read_model": True,
        "public_authority_methods_only": True,
        "raw_identity_exposed": False,
        "free_text_exposed": False,
        "legal_prose_exposed": False,
        "network_io": False,
        "provider_write": False,
        "site_mutation": False,
        "native_identity_proof": False,
        "live_acceptance_verified": False,
    }
    serialized = json.dumps(snapshot, sort_keys=True)
    for secret in (
        TENANT,
        PROFILE,
        "SECRET-URL",
        "SECRET LEGAL",
        "SECRET PURPOSE",
        "SECRET TEMPLATE",
        "secret/?raw=query",
        "SECRET PROMPT",
        "SECRET RIGHTS",
        "subject_sha256",
        "identity_evidence_ref",
        "opened_by",
        '"title"',
        '"body"',
    ):
        assert secret not in serialized
    assert all(call[0] == (TENANT, PROPERTY) for call in publishing.resolve_calls)
    assert all(call[0] == (TENANT, PROFILE) for call in preferences.calls)
    assert all(item == _authority() for item in profile_data.calls)
    assert rights.calls == [(TENANT, "case-1"), (TENANT, "case-1")]


def test_snapshot_includes_only_digest_pinned_accessible_branding() -> None:
    adapter, *_ = _adapter(publishing=FakePublishing(branded=True))
    snapshot = adapter()
    branding = snapshot["sections"]["publication"]["branding"]
    assert branding == {
        "theme_token_id": "brand-default",
        "version": 2,
        "resource_sha256": _digest("theme-resource"),
        "display_name": "Example",
        "heading": "Example Privacy Trust Center",
        "description": "Manage your choices and volunteered data.",
        "primary_color": "174b3f",
        "primary_text_color": "ffffff",
        "surface_color": "ffffff",
        "text_color": "16211d",
        "branding_sha256": branding["branding_sha256"],
    }
    assert len(branding["branding_sha256"]) == 64
    with pytest.raises(TrustCenterIntegrityError, match="contrast"):
        _adapter(publishing=FakePublishing(branded=True, unsafe_branding=True))[0]()


def test_capability_omission_avoids_unapproved_sources():
    context = _context("consent_history")
    adapter, _, preferences, _, _ = _adapter(
        context,
        profile_data=None,
        rights=None,
    )
    snapshot = adapter()
    assert snapshot["capabilities"] == ["consent_history"]
    assert set(snapshot["sections"]) == {"consent"}
    assert len(preferences.calls) == 2


@pytest.mark.parametrize("drifting_source", ["publishing", "preferences"])
def test_source_drift_fails_closed(drifting_source):
    kwargs = {
        "publishing": FakePublishing(drift=drifting_source == "publishing"),
        "preferences": FakePreferences(drift=drifting_source == "preferences"),
    }
    adapter, *_ = _adapter(**kwargs)
    with pytest.raises(TrustCenterConflict, match="drifted"):
        adapter()


def test_context_is_reresolved_and_revocation_after_first_read_fails_closed():
    current = _context()
    calls = 0

    def resolve():
        nonlocal calls
        calls += 1
        return current if calls == 1 else replace(current, revoked=True)

    adapter, *_ = _adapter(current, resolver=resolve)
    with pytest.raises(TrustCenterConflict, match="expired or revoked"):
        adapter()


@pytest.mark.parametrize(
    "bad_grant",
    [
        _grant("consent_history", revoked=True),
        _grant("consent_history", valid_until=NOW),
        _grant("consent_history", tenant_sha256=_digest("other-tenant")),
        _grant(
            "consent_history",
            second_approved_by_sha256=_digest("approver-one"),
        ),
        _grant("consent_history", approved_by_sha256=_digest("trust-center-actor")),
    ],
)
def test_capability_grants_require_exact_fresh_four_eyes_authority(bad_grant):
    context = _context("consent_history", grants=(bad_grant,))
    adapter, *_ = _adapter(context)
    with pytest.raises(TrustCenterConflict, match="grant"):
        adapter()


def test_grant_and_context_digest_tamper_fail_closed():
    grant = replace(_grant("consent_history"), grant_sha256=_digest("tampered"))
    context = _context("consent_history", grants=(grant,))
    with pytest.raises(TrustCenterConflict, match="grant"):
        _adapter(context)[0]()
    context = replace(_context("consent_history"), context_sha256=_digest("tampered"))
    with pytest.raises(TrustCenterIntegrityError, match="context digest"):
        _adapter(context)[0]()


@pytest.mark.parametrize(
    "bad_authorization",
    [
        _rights_authorization(revoked=True),
        _rights_authorization(valid_until=NOW),
        _rights_authorization(second_approved_by_sha256=_digest("rights-approver-one")),
        _rights_authorization(approved_by_sha256=_digest("trust-center-actor")),
        _rights_authorization(expected_case_sha256=_digest("stale-case")),
    ],
)
def test_rights_summaries_require_fresh_independent_exact_authorization(
    bad_authorization,
):
    context = _context(
        "rights_cases",
        rights_authorizations=(bad_authorization,),
    )
    adapter, *_ = _adapter(context)
    with pytest.raises(TrustCenterConflict):
        adapter()


def test_profile_authority_and_closed_values_fail_closed():
    wrong_authority = replace(_authority(), profile_id="profile-other")
    context = _context("profile_data", profile_authority=wrong_authority)
    with pytest.raises(TrustCenterConflict, match="authority"):
        _adapter(context)[0]()

    context = _context("profile_data")
    adapter, *_ = _adapter(
        context,
        profile_data=FakeProfileData(raw_value="This is raw volunteered free text"),
    )
    with pytest.raises(TrustCenterIntegrityError, match="non-closed"):
        adapter()


def test_expired_retained_source_records_fail_closed():
    context = _context("profile_data")
    adapter, *_ = _adapter(
        context,
        profile_data=FakeProfileData(retained_until=NOW),
    )
    with pytest.raises(TrustCenterConflict, match="profile-data retention"):
        adapter()

    context = _context("rights_cases")
    adapter, *_ = _adapter(context, rights=FakeRights(retained_until=NOW))
    with pytest.raises(TrustCenterConflict, match="case retention"):
        adapter()

    context = _context("consent_history")
    preferences = FakePreferences()
    original = preferences.export_profile

    def expired_receipt(*args, **kwargs):
        export = original(*args, **kwargs)
        body = {
            key: copy.deepcopy(value) for key, value in export.items() if key != "export_sha256"
        }
        body["receipts"][0]["retention_until"] = NOW
        return {**body, "export_sha256": _sha(body)}

    preferences.export_profile = expired_receipt
    with pytest.raises(TrustCenterConflict, match="receipt retention"):
        _adapter(context, preferences=preferences)[0]()


def test_unicode_tenant_is_canonical_and_distinct_authority_cannot_cross():
    decomposed = "Te\u0301nant-α"
    capabilities = (
        "active_publication",
        "consent_history",
        "profile_data",
        "rights_cases",
    )
    context = _context(
        *capabilities,
        tenant=decomposed,
        grants=tuple(_grant(item, tenant=TENANT) for item in capabilities),
        profile_authority=_authority(TENANT),
    )
    publishing = FakePublishing(TENANT)
    preferences = FakePreferences(TENANT)
    adapter, *_ = _adapter(
        context,
        publishing=publishing,
        preferences=preferences,
        profile_data=FakeProfileData(TENANT),
        rights=FakeRights(TENANT),
    )
    snapshot = adapter()
    assert snapshot["tenant_sha256"] == _text_sha(TENANT)
    assert publishing.resolve_calls[0][0][0] == TENANT
    assert preferences.calls[0][0][0] == TENANT

    mismatched = _grant("consent_history", tenant="Tenant-a")
    context = _context(
        "consent_history",
        tenant=TENANT,
        grants=(mismatched,),
    )
    with pytest.raises(TrustCenterConflict, match="grant"):
        _adapter(context)[0]()


def test_context_and_all_history_limits_are_fail_closed():
    context = replace(_context("consent_history"), receipt_limit=1)
    context = _resign(context)
    preferences = FakePreferences()
    original = preferences.export_profile

    def oversized(*args, **kwargs):
        export = original(*args, **kwargs)
        body = {
            key: copy.deepcopy(value) for key, value in export.items() if key != "export_sha256"
        }
        body["receipts"] = body["receipts"] * 2
        return {**body, "export_sha256": _sha(body)}

    preferences.export_profile = oversized
    with pytest.raises(TrustCenterIntegrityError, match="export"):
        _adapter(context, preferences=preferences)[0]()


def _store(tmp_path, *, context: TrustCenterContext | None = None):
    adapter, publishing, preferences, profile_data, rights = _adapter(context)
    counter = 0

    def new_id(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter}"

    store = ConsumerTrustCenterStore(
        tmp_path / "trust-center.sqlite3",
        snapshot_resolver=adapter,
        signing_key_resolver=lambda tenant_sha, _key_ref: (
            b"external-resolver-key-material!!" + tenant_sha[:4].encode()
        ),
        clock=lambda: NOW,
        id_factory=new_id,
        gate=lambda: None,
    )
    return store, publishing, preferences, profile_data, rights


def test_signed_export_is_exact_idempotent_and_tamper_evident(tmp_path):
    store, *_ = _store(tmp_path)
    first = store.export_signed(idempotency_key="request-1")
    replay = store.export_signed(idempotency_key="request-1")
    assert replay == first
    assert first["payload"]["schema"] == TRUST_CENTER_EXPORT_SCHEMA
    assert store.verify_export(first) is True
    assert store.verify_integrity() == {
        "exports": 1,
        "idempotency": 1,
        "audit_events": 1,
    }

    tampered = copy.deepcopy(first)
    tampered["payload"]["snapshot"]["property_id"] = "property-other"
    assert store.verify_export(tampered) is False


def test_idempotency_rebind_detects_changed_source_state(tmp_path):
    store, _, preferences, *_ = _store(tmp_path)
    store.export_signed(idempotency_key="request-1")
    preferences.drift = True
    # Keep each bracketed read stable while changing the source state from the first export.
    preferences.calls.clear()
    preferences.drift = False
    original = preferences.export_profile

    def changed(*args, **kwargs):
        export = original(*args, **kwargs)
        body = {
            key: copy.deepcopy(value) for key, value in export.items() if key != "export_sha256"
        }
        body["receipts"][0]["receipt_id"] = "receipt-changed"
        body["receipts"][0]["receipt_sha256"] = _digest("changed-receipt")
        return {**body, "export_sha256": _sha(body)}

    preferences.export_profile = changed
    with pytest.raises(TrustCenterConflict, match="rebound"):
        store.export_signed(idempotency_key="request-1")


def test_retention_purge_removes_payload_and_replay_but_preserves_audit(tmp_path):
    context = _context(retained_until=NOW + 10)
    store, *_ = _store(tmp_path, context=context)
    store.export_signed(idempotency_key="request-1")
    due = store.retention_due(before=NOW + 11)
    assert len(due["items"]) == 1
    assert store.purge_expired(before=NOW + 11) == {
        "exports_deleted": 1,
        "cutoff": NOW + 11,
    }
    assert store.verify_integrity() == {
        "exports": 0,
        "idempotency": 0,
        "audit_events": 2,
    }


def test_database_payload_and_audit_tamper_are_detected_or_blocked(tmp_path):
    store, *_ = _store(tmp_path)
    store.export_signed(idempotency_key="request-1")
    with sqlite3.connect(store._path) as connection:
        connection.execute(
            "UPDATE trust_center_exports SET payload_sha256=?",
            (_digest("tampered"),),
        )
        connection.commit()
    with pytest.raises(TrustCenterIntegrityError, match="export"):
        store.verify_integrity()

    store_two, *_ = _store(tmp_path / "other")
    store_two.export_signed(idempotency_key="request-1")
    with sqlite3.connect(store_two._path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("DELETE FROM trust_center_audit")


def test_untrusted_snapshot_shape_cannot_bypass_source_pins(tmp_path):
    unsafe_section = {"raw_identity": "SECRET"}
    unsafe_pin = _sha(unsafe_section)
    raw = {
        "schema": TRUST_CENTER_SCHEMA,
        "tenant_sha256": _text_sha(TENANT),
        "property_id": PROPERTY,
        "profile_ref_sha256": _text_sha(PROFILE),
        "context_revision": 1,
        "context_sha256": _digest("context"),
        "capabilities": ["consent_history"],
        "source_pins": {"consent": unsafe_pin},
        "sections": {
            "consent": {
                **unsafe_section,
                "source_sha256": unsafe_pin,
            }
        },
        "generated_at": NOW,
        "retained_until": NOW + 10,
        "boundaries": ConsumerTrustCenterSourceAdapter.product_boundaries(),
    }
    raw["snapshot_sha256"] = _sha(raw)
    store = ConsumerTrustCenterStore(
        tmp_path / "bad.sqlite3",
        snapshot_resolver=lambda: raw,
        signing_key_resolver=lambda _tenant, _key_ref: b"k" * 32,
        gate=lambda: None,
    )
    with pytest.raises(TrustCenterIntegrityError, match="forbidden raw field"):
        store.snapshot()


def _alternate_brand_snapshot(branding: dict[str, object]) -> dict[str, object]:
    section_body = {"branding": branding}
    section = {**section_body, "source_sha256": _sha(section_body)}
    raw: dict[str, object] = {
        "schema": TRUST_CENTER_SCHEMA,
        "tenant_sha256": _text_sha(TENANT),
        "property_id": PROPERTY,
        "profile_ref_sha256": _text_sha(PROFILE),
        "context_revision": 1,
        "context_sha256": _digest("context"),
        "capabilities": ["active_publication"],
        "source_pins": {"publication": section["source_sha256"]},
        "sections": {"publication": section},
        "generated_at": NOW,
        "retained_until": NOW + 10,
        "boundaries": ConsumerTrustCenterSourceAdapter.product_boundaries(),
    }
    return {**raw, "snapshot_sha256": _sha(raw)}


@pytest.mark.parametrize("operation", ["snapshot", "export"])
@pytest.mark.parametrize(
    "overrides, expected_error",
    [
        ({"primary_color": "ffffff", "primary_text_color": "eeeeee"}, "contrast"),
        ({"branding_sha256": "0" * 64}, "failed integrity"),
        ({"description": "x" * 513}, "bounded plain text"),
        ({"description": "javascript:brand"}, "executable URI"),
    ],
)
def test_alternate_resolver_cannot_bypass_strict_branding_before_return_or_signing(
    tmp_path,
    operation: str,
    overrides: dict[str, object],
    expected_error: str,
) -> None:
    body: dict[str, object] = {
        "theme_token_id": "brand-default",
        "version": 1,
        "resource_sha256": _digest("theme-resource"),
        "display_name": "Example",
        "heading": "Example Privacy Trust Center",
        "description": "Manage your choices.",
        "primary_color": "174b3f",
        "primary_text_color": "ffffff",
        "surface_color": "ffffff",
        "text_color": "16211d",
    }
    normalized_overrides = dict(overrides)
    supplied_digest = normalized_overrides.pop("branding_sha256", None)
    body.update(normalized_overrides)
    branding = {
        **body,
        "branding_sha256": supplied_digest if supplied_digest is not None else _sha(body),
    }
    raw = _alternate_brand_snapshot(branding)
    store = ConsumerTrustCenterStore(
        tmp_path / f"alternate-brand-{operation}.sqlite3",
        snapshot_resolver=lambda: raw,
        signing_key_resolver=lambda _tenant, _key_ref: b"k" * 32,
        gate=lambda: None,
    )
    with pytest.raises(TrustCenterIntegrityError, match=expected_error):
        if operation == "snapshot":
            store.snapshot()
        else:
            store.export_signed(idempotency_key="alternate-brand-export")


def test_public_entrypoints_do_not_accept_tenant_profile_or_property_authority():
    assert list(inspect.signature(ConsumerTrustCenterSourceAdapter.__call__).parameters) == ["self"]
    assert list(inspect.signature(ConsumerTrustCenterStore.snapshot).parameters) == ["self"]
    assert list(inspect.signature(ConsumerTrustCenterStore.export_signed).parameters) == [
        "self",
        "idempotency_key",
    ]


def test_store_connections_close_when_row_setup_fails(tmp_path, monkeypatch):
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    store, *_ = _store(tmp_path)
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect
    fail_row_setup = {"on": True}

    class _RowSetupFails(sqlite3.Connection):
        def __setattr__(self, name, value):
            if name == "row_factory" and fail_row_setup["on"]:
                raise sqlite3.OperationalError("row setup failed")
            super().__setattr__(name, value)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_RowSetupFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(trust_center_module.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            with store._connect():
                pass
        fail_row_setup["on"] = False
        with store._connect() as connection:
            assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        gc.enable()
    assert len(opened) == 2  # the failed setup, the working call
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
