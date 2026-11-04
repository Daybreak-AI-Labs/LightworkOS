"""Bounded, signed, governed policy-pack authority."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from maverick import governed_records, policy_packs
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


@pytest.fixture(autouse=True)
def _policy_pack_state(tmp_path, monkeypatch):
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    for name in (
        "MAVERICK_GOVERNED_RECORDS_BACKEND",
        "MAVERICK_PG_DSN",
        "MAVERICK_WORLD_BACKEND",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    governed_records._reset_process_authority_pin_for_testing()


def _keys() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    return private_hex, public_hex


def _mapping(control_id: str) -> dict:
    return {
        "framework": "Example primary framework",
        "control_id": control_id,
        "relationship": "informative",
        "non_certifying": True,
        "non_legal_advice": True,
        "notice": policy_packs.MAPPING_NOTICE,
    }


def _control(
    control_id: str,
    *,
    requirement_id: str,
    description: str,
    title: str | None = None,
) -> dict:
    return {
        "control_id": control_id,
        "title": title or f"Control {control_id}",
        "objective": f"Bounded objective for {control_id}.",
        "evidence_requirements": [
            {
                "requirement_id": requirement_id,
                "evidence_kind": "evaluation",
                "description": description,
                "minimum_count": 1,
                "accepted_schemas": ["example.evidence.v1"],
                "validity_days": None,
            }
        ],
        "mappings": [_mapping(control_id)],
        "citations": [
            {
                "title": "Example primary source",
                "url": "https://standards.example.test/framework",
                "locator": control_id,
            }
        ],
    }


def _pack(
    version: str = "1.0.0",
    *,
    first_requirement: str = "Keep exact evaluation evidence.",
    first_title: str = "Control CTRL-1",
) -> dict:
    return policy_packs.finalize_pack(
        {
            "schema": policy_packs.PACK_SCHEMA,
            "pack_id": "example-ai-policy",
            "version": version,
            "framework": {
                "name": "Example Framework",
                "version": "2026",
                "as_of": "2026-08-23",
            },
            "scope": {
                "coverage": "test_subset",
                "description": "A test-only decision-support subset.",
            },
            "controls": [
                _control(
                    "CTRL-1",
                    requirement_id="REQ-1",
                    description=first_requirement,
                    title=first_title,
                ),
                _control(
                    "CTRL-2",
                    requirement_id="REQ-2",
                    description="Keep a second exact evaluation record.",
                ),
            ],
            "notice": {
                "certification": False,
                "legal_advice": False,
                "human_review_required": True,
                "text": policy_packs.NON_CERTIFICATION_NOTICE,
            },
        }
    )


def _envelope(pack: dict, private_hex: str) -> dict:
    return policy_packs.sign_update(
        pack,
        private_key_hex=private_hex,
        key_id="publisher-1",
    )


def _stage(service: policy_packs.PolicyPackService, pack: dict, private_hex: str, public_hex: str):
    return service.stage_signed_update(
        _envelope(pack, private_hex),
        trusted_public_keys={"publisher-1": public_hex},
        actor="release-admin",
    )


def _activate(
    service: policy_packs.PolicyPackService,
    entry: dict,
    expected_revision: int,
) -> dict:
    return service.activate(
        entry["id"],
        actor="global-admin",
        expected_revision=expected_revision,
        admin=True,
    )


def _evidence(evidence_id: str, revision: int = 1) -> dict:
    digest = hashlib.sha256(f"{evidence_id}:{revision}".encode()).hexdigest()
    return {
        "id": evidence_id,
        "revision": revision,
        "content_sha256": digest,
        "evidence_kind": "evaluation",
        "schema": "example.evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def _binding(requirement_id: str, evidence: dict) -> dict:
    return {
        "requirement_id": requirement_id,
        "evidence_id": evidence["id"],
        "evidence_revision": evidence["revision"],
        "evidence_sha256": evidence["content_sha256"],
    }


def test_bundled_manifests_are_bounded_and_explicitly_non_certifying():
    manifests = policy_packs.bundled_manifests()
    assert set(manifests) == {
        "nist-ai-rmf-1.0-starter",
        "eu-ai-act-2026-decision-support",
    }
    assert len(manifests["nist-ai-rmf-1.0-starter"]["controls"]) == 4
    assert len(manifests["eu-ai-act-2026-decision-support"]["controls"]) == 10
    for manifest in manifests.values():
        assert policy_packs.validate_pack(manifest) == manifest
        assert len(policy_packs.canonical_pack_bytes(manifest)) <= policy_packs.MAX_PACK_BYTES
        assert manifest["notice"] == {
            "certification": False,
            "legal_advice": False,
            "human_review_required": True,
            "text": policy_packs.NON_CERTIFICATION_NOTICE,
        }
        for control in manifest["controls"]:
            assert all(item["non_certifying"] for item in control["mappings"])
            assert all(item["non_legal_advice"] for item in control["mappings"])
            assert all(
                citation["url"].startswith(
                    ("https://nvlpubs.nist.gov/", "https://eur-lex.europa.eu/")
                )
                for citation in control["citations"]
            )


def test_schema_semver_bounds_and_canonical_digest_are_strict():
    original = _pack()
    reordered = copy.deepcopy(original)
    reordered.pop("content_sha256")
    for control in reordered["controls"]:
        control.pop("requirements_sha256")
        for requirement in control["evidence_requirements"]:
            requirement.pop("semantic_sha256")
    reordered["controls"].reverse()
    assert policy_packs.finalize_pack(reordered)["content_sha256"] == original[
        "content_sha256"
    ]
    assert policy_packs.compare_semver("1.0.0-alpha.1", "1.0.0") < 0
    assert policy_packs.compare_semver("1.2.0+build.1", "1.2.0+build.2") == 0

    invalid = copy.deepcopy(original)
    invalid["version"] = "01.0.0"
    with pytest.raises(policy_packs.PolicyPackValidationError, match="SemVer"):
        policy_packs.finalize_pack(invalid)
    invalid = copy.deepcopy(original)
    invalid["controls"][0]["objective"] = "x" * 2_001
    with pytest.raises(policy_packs.PolicyPackValidationError, match="safe text bound"):
        policy_packs.finalize_pack(invalid)
    invalid = copy.deepcopy(original)
    invalid["controls"][0]["evidence_requirements"][0]["description"] += " changed"
    with pytest.raises(policy_packs.PolicyPackValidationError, match="semantic_sha256"):
        policy_packs.validate_pack(invalid)


def test_signature_requires_explicit_trust_and_binds_exact_pack():
    private_hex, public_hex = _keys()
    envelope = _envelope(_pack(), private_hex)
    verified, signer = policy_packs.verify_update(
        envelope, trusted_public_keys={"publisher-1": public_hex}
    )
    assert signer == "publisher-1"
    assert verified["content_sha256"] == envelope["content_sha256"]
    with pytest.raises(policy_packs.PolicyPackUpdateRefused, match="no trusted"):
        policy_packs.verify_update(envelope, trusted_public_keys={})
    other_private, other_public = _keys()
    assert other_private
    with pytest.raises(policy_packs.PolicyPackUpdateRefused, match="not trusted"):
        policy_packs.verify_update(
            envelope, trusted_public_keys={"publisher-1": other_public}
        )
    tampered = copy.deepcopy(envelope)
    tampered["pack"]["scope"]["description"] += " tampered"
    with pytest.raises(policy_packs.PolicyPackUpdateRefused):
        policy_packs.verify_update(
            tampered, trusted_public_keys={"publisher-1": public_hex}
        )


def test_stage_then_admin_cas_activate_never_auto_activates():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    entry_v1 = _stage(service, _pack(), private_hex, public_hex)
    assert service.active_pack("example-ai-policy") is None
    with pytest.raises(PermissionError, match="global admin"):
        service.activate(
            entry_v1["id"],
            actor="operator",
            expected_revision=0,
            admin=False,
        )
    active_v1 = _activate(service, entry_v1, 0)
    assert active_v1["pack_version"] == "1.0.0"

    entry_v2 = _stage(service, _pack("1.1.0"), private_hex, public_hex)
    assert service.active_pack("example-ai-policy")["version"] == "1.0.0"
    with pytest.raises(RecordConflict, match="revision conflict"):
        _activate(service, entry_v2, 0)
    active_v2 = _activate(service, entry_v2, active_v1["revision"])
    assert active_v2["pack_version"] == "1.1.0"
    with pytest.raises(policy_packs.PolicyPackUpdateRefused, match="downgrade"):
        _activate(service, entry_v1, active_v2["revision"])


def test_same_version_different_digest_is_rejected():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    _stage(service, _pack(), private_hex, public_hex)
    collision = _pack(first_requirement="A materially different requirement.")
    with pytest.raises(policy_packs.PackVersionCollision, match="same pack_id/version"):
        _stage(service, collision, private_hex, public_hex)


def test_subscription_is_tenant_scoped_and_malformed_active_state_fails_closed():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    entry = _stage(service, _pack(), private_hex, public_hex)
    _activate(service, entry, 0)
    with tenant_scope(tenant="alpha"):
        alpha = service.subscribe("example-ai-policy", actor="alpha-admin")
        assert service.active_subscription("example-ai-policy")["id"] == alpha["id"]
    with tenant_scope(tenant="beta"):
        assert service.get_subscription("example-ai-policy") is None
        beta = service.subscribe("example-ai-policy", actor="beta-admin")
        assert beta["id"] == alpha["id"]
        assert beta["subscribed_by"] == "beta-admin"
    with tenant_scope(tenant="alpha"):
        corrupted = service.subscriptions.update(
            alpha["id"],
            lambda row: row.__setitem__("requirements", []),
            expected_revision=alpha["revision"],
            action="test-corrupt",
            actor="test",
        )
        assert corrupted is not None
        with pytest.raises(policy_packs.PolicyPackStateError, match="requirements"):
            service.active_subscription("example-ai-policy")

    with pytest.raises(policy_packs.PolicyPackTenantRequired):
        service.subscribe("example-ai-policy", actor="unbound-admin")
    with pytest.raises(policy_packs.PolicyPackTenantRequired):
        service.list_subscriptions()
    with pytest.raises(policy_packs.PolicyPackTenantRequired):
        service.get_subscription("example-ai-policy")


def test_changed_requirements_stale_exact_attestation_unchanged_remains_current():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    entry_v1 = _stage(service, _pack(), private_hex, public_hex)
    active_v1 = _activate(service, entry_v1, 0)
    evidence_1 = _evidence("ev-one")
    evidence_2 = _evidence("ev-two")
    evidence = {item["id"]: item for item in (evidence_1, evidence_2)}

    with tenant_scope(tenant="alpha"):
        subscription = service.subscribe("example-ai-policy", actor="reviewer")
        first = service.attest_control(
            subscription["id"],
            "CTRL-1",
            evidence_bindings=[_binding("REQ-1", evidence_1)],
            evidence_resolver=evidence.get,
            expected_revision=subscription["revision"],
            actor="reviewer",
            idempotency_key="attest-ctrl-1-v1",
        )
        second = service.attest_control(
            subscription["id"],
            "CTRL-2",
            evidence_bindings=[_binding("REQ-2", evidence_2)],
            evidence_resolver=evidence.get,
            expected_revision=first["subscription"]["revision"],
            actor="reviewer",
            idempotency_key="attest-ctrl-2-v1",
        )
        old_first_attestation = first["attestation"]["id"]

    entry_v2 = _stage(
        service,
        _pack("1.1.0", first_requirement="Keep evaluation and adversarial evidence."),
        private_hex,
        public_hex,
    )
    _activate(service, entry_v2, active_v1["revision"])
    with tenant_scope(tenant="alpha"):
        with pytest.raises(policy_packs.PolicyPackStateError, match="refresh"):
            service.active_subscription("example-ai-policy")
        refreshed = service.refresh_subscription(
            second["subscription"]["id"],
            expected_revision=second["subscription"]["revision"],
            actor="reviewer",
        )
        assert refreshed["requirements"]["CTRL-1"]["status"] == "stale"
        assert (
            refreshed["requirements"]["CTRL-1"]["attestation_id"]
            == old_first_attestation
        )
        assert refreshed["requirements"]["CTRL-2"]["status"] == "current"
        assert refreshed["last_diff"]["requirements_changed"] == ["CTRL-1"]
        change_detail = service.get_subscription_change_detail(
            "example-ai-policy"
        )
        assert change_detail is not None
        assert change_detail["last_diff"]["requirements_changed"] == ["CTRL-1"]
        by_control = {
            row["control_id"]: row for row in change_detail["controls"]
        }
        assert by_control["CTRL-1"]["status"] == "stale"
        assert by_control["CTRL-1"]["attestation_present"] is True
        assert by_control["CTRL-2"]["status"] == "current"
        assert change_detail["certification"] is False
        assert "attestation_id" not in json.dumps(change_detail)
        assert "ev-one" not in json.dumps(change_detail)

        evidence_3 = _evidence("ev-three", revision=2)
        evidence[evidence_3["id"]] = evidence_3
        reattested = service.attest_control(
            refreshed["id"],
            "CTRL-1",
            evidence_bindings=[_binding("REQ-1", evidence_3)],
            evidence_resolver=evidence.get,
            expected_revision=refreshed["revision"],
            actor="reviewer",
            idempotency_key="attest-ctrl-1-v2",
        )
        assert reattested["subscription"]["requirements"]["CTRL-1"]["status"] == "current"
        assert reattested["attestation"]["id"] != old_first_attestation
        assert service.attestations.get(old_first_attestation) is not None
        current_detail = service.get_subscription_change_detail(
            "example-ai-policy"
        )
        assert current_detail is not None
        assert all(
            row["status"] == "current" for row in current_detail["controls"]
        )

        wrong = _binding("REQ-1", evidence_3)
        wrong["evidence_revision"] = 1
        with pytest.raises(policy_packs.PolicyPackValidationError, match="mismatch"):
            service.attest_control(
                refreshed["id"],
                "CTRL-1",
                evidence_bindings=[wrong],
                evidence_resolver=evidence.get,
                expected_revision=reattested["subscription"]["revision"],
                actor="reviewer",
                idempotency_key="bad-evidence-binding",
            )


def test_fetch_refuses_hostile_off_host_and_oversized_updates_then_only_stages():
    private_hex, public_hex = _keys()
    envelope = _envelope(_pack(), private_hex)
    body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    service = policy_packs.PolicyPackService()
    calls: list[str] = []

    def good_transport(url: str, maximum: int) -> policy_packs.FetchResponse:
        calls.append(url)
        assert len(body) <= maximum
        return policy_packs.FetchResponse(
            url=url,
            status_code=200,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
            body=body,
        )

    with pytest.raises(policy_packs.PolicyPackUpdateRefused, match="HTTPS"):
        service.fetch_and_stage(
            "http://updates.example.test/pack.json",
            trusted_public_keys={"publisher-1": public_hex},
            actor="admin",
            transport=good_transport,
        )
    assert not calls

    def redirect_off_host(url: str, maximum: int) -> policy_packs.FetchResponse:
        return policy_packs.FetchResponse(
            url=url,
            status_code=302,
            headers={"Location": "https://evil.example/pack.json"},
            body=b"",
        )

    with pytest.raises(policy_packs.PolicyPackUpdateRefused, match="off-host"):
        service.fetch_and_stage(
            "https://updates.example.test/pack.json",
            trusted_public_keys={"publisher-1": public_hex},
            actor="admin",
            transport=redirect_off_host,
        )

    def oversized(url: str, maximum: int) -> policy_packs.FetchResponse:
        return policy_packs.FetchResponse(
            url=url,
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b"x" * (maximum + 1),
        )

    with pytest.raises(policy_packs.PolicyPackUpdateRefused, match="oversized"):
        service.fetch_and_stage(
            "https://updates.example.test/pack.json",
            trusted_public_keys={"publisher-1": public_hex},
            actor="admin",
            transport=oversized,
        )

    staged = service.fetch_and_stage(
        "https://updates.example.test/pack.json",
        trusted_public_keys={"publisher-1": public_hex},
        actor="admin",
        transport=good_transport,
    )
    assert staged["pack_version"] == "1.0.0"
    assert service.active_pack("example-ai-policy") is None


def test_bounded_read_pages_redact_authority_and_preserve_tenant_scope():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    entry_v1 = _stage(service, _pack(), private_hex, public_hex)
    _stage(service, _pack("1.1.0"), private_hex, public_hex)
    _activate(service, entry_v1, 0)

    catalog = policy_packs.list_catalog(limit=1)
    assert catalog["count"] == 1
    assert catalog["truncated"] is True
    assert catalog["limit"] == 1
    assert set(catalog["items"][0]).isdisjoint(
        {"pack", "provenance", "signature", "publisher_key", "public_key"}
    )
    assert "signature" not in json.dumps(catalog)

    channels = policy_packs.list_channels()
    assert channels["count"] == 1
    assert channels["items"][0]["pack_version"] == "1.0.0"
    assert "pack" not in channels["items"][0]

    evidence = _evidence("ev-read")
    with tenant_scope(tenant="alpha"):
        subscription = service.subscribe("example-ai-policy", actor="alpha-admin")
        attested = service.attest_control(
            subscription["id"],
            "CTRL-1",
            evidence_bindings=[_binding("REQ-1", evidence)],
            evidence_resolver=lambda evidence_id: (
                evidence if evidence_id == evidence["id"] else None
            ),
            expected_revision=subscription["revision"],
            actor="reviewer",
            idempotency_key="read-page-attestation",
        )
        subscriptions = policy_packs.list_subscriptions()
        assert subscriptions["count"] == 1
        view = subscriptions["items"][0]
        assert view["current_count"] == 1
        assert view["missing_count"] == 1
        assert view["stale_count"] == 0
        assert view["needs_refresh"] is False
        assert view["revision"] == attested["subscription"]["revision"]
        serialized = json.dumps(subscriptions)
        assert "attestation_id" not in serialized
        assert "evidence" not in serialized
    with tenant_scope(tenant="beta"):
        assert policy_packs.list_subscriptions()["items"] == []
        # Catalog/channel authorities remain deployment-global under a tenant context.
        assert policy_packs.list_catalog()["count"] == 2
        assert policy_packs.list_channels()["count"] == 1

    for operation in (
        policy_packs.list_catalog,
        policy_packs.list_channels,
    ):
        with pytest.raises(policy_packs.PolicyPackValidationError, match="read limit"):
            operation(limit=0)
        with pytest.raises(policy_packs.PolicyPackValidationError, match="read limit"):
            operation(limit=policy_packs.MAX_READ_LIMIT + 1)
    with tenant_scope(tenant="alpha"):
        with pytest.raises(policy_packs.PolicyPackValidationError, match="read limit"):
            policy_packs.list_subscriptions(limit=0)
        with pytest.raises(policy_packs.PolicyPackValidationError, match="read limit"):
            policy_packs.list_subscriptions(
                limit=policy_packs.MAX_READ_LIMIT + 1,
            )


def test_read_pages_fail_closed_on_malformed_records_including_sentinel():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    entry_v1 = _stage(service, _pack(), private_hex, public_hex)
    entry_v2 = _stage(service, _pack("1.1.0"), private_hex, public_hex)
    _activate(service, entry_v1, 0)

    # Corrupt the second row through the underlying test authority. list_catalog
    # reads limit+1 and must validate this omitted sentinel instead of hiding it.
    corrupted = service.catalog.update(
        entry_v2["id"],
        lambda row: row.__setitem__("content_sha256", "0" * 64),
        expected_revision=entry_v2["revision"],
        action="test-corrupt",
        actor="test",
    )
    assert corrupted is not None
    with pytest.raises(policy_packs.PolicyPackStateError, match="identity"):
        service.list_catalog(limit=1)


@pytest.mark.parametrize(
    "stored",
    ["not-an-object", {"unexpected": "field"}],
)
def test_stored_semantic_diff_shape_corruption_is_a_state_error(stored):
    with pytest.raises(policy_packs.PolicyPackStateError, match="malformed"):
        policy_packs._safe_diff_projection(
            stored,
            pack_id="example-ai-policy",
            pack_version="1.0.0",
            pack_sha256="0" * 64,
        )


def test_enabled_is_default_off_and_requires_literal_true(tmp_path):
    config = tmp_path / "config.toml"
    assert policy_packs.enabled() is False
    config.write_text('[policy_packs]\nenable = "true"\n', encoding="utf-8")
    assert policy_packs.enabled() is False
    config.write_text("[policy_packs]\nenable = true\n", encoding="utf-8")
    assert policy_packs.enabled() is True


def test_subscription_changes_view_shows_exact_pending_and_applied_deltas():
    private_hex, public_hex = _keys()
    service = policy_packs.PolicyPackService()
    entry_v1 = _stage(service, _pack(), private_hex, public_hex)
    active_v1 = _activate(service, entry_v1, 0)
    evidence_1 = _evidence("ev-one")
    evidence = {evidence_1["id"]: evidence_1}

    with pytest.raises(policy_packs.PolicyPackTenantRequired):
        service.subscription_changes("example-ai-policy")

    with tenant_scope(tenant="alpha"):
        assert service.subscription_changes("example-ai-policy") is None
        subscription = service.subscribe("example-ai-policy", actor="reviewer")
        attested = service.attest_control(
            subscription["id"],
            "CTRL-1",
            evidence_bindings=[_binding("REQ-1", evidence_1)],
            evidence_resolver=evidence.get,
            expected_revision=subscription["revision"],
            actor="reviewer",
            idempotency_key="attest-ctrl-1-v1",
        )

        aligned = service.subscription_changes("example-ai-policy")
        assert aligned["needs_refresh"] is False
        assert aligned["pending_diff"] is None
        assert aligned["applied_diff"] is None
        assert aligned["requirements"]["CTRL-1"]["status"] == "current"
        assert aligned["requirements"]["CTRL-2"]["status"] == "missing"

    entry_v2 = _stage(
        service,
        _pack("1.1.0", first_requirement="Keep evaluation and adversarial evidence."),
        private_hex,
        public_hex,
    )
    _activate(service, entry_v2, active_v1["revision"])

    with tenant_scope(tenant="alpha"):
        pending = service.subscription_changes("example-ai-policy")
        assert pending["needs_refresh"] is True
        assert pending["refresh_is_forward"] is True
        assert pending["pack_version"] == "1.0.0"
        assert pending["active_pack_version"] == "1.1.0"
        # The exact change is named before anything mutates: CTRL-1's
        # requirements moved, CTRL-2 is untouched.
        assert pending["pending_diff"]["requirements_changed"] == ["CTRL-1"]
        assert pending["pending_diff"]["requirements_unchanged"] == ["CTRL-2"]
        assert pending["pending_diff"]["controls_added"] == []
        assert pending["applied_diff"] is None
        # The read-only view moved nothing.
        assert pending["requirements"]["CTRL-1"]["status"] == "current"

        refreshed = service.refresh_subscription(
            attested["subscription"]["id"],
            expected_revision=attested["subscription"]["revision"],
            actor="reviewer",
        )
        applied = service.subscription_changes("example-ai-policy")
        assert applied["needs_refresh"] is False
        assert applied["pending_diff"] is None
        assert applied["applied_diff"]["requirements_changed"] == ["CTRL-1"]
        assert applied["requirements"]["CTRL-1"]["status"] == "stale"
        assert applied["requirements"]["CTRL-1"]["stale_reason"]
        assert applied["revision"] == refreshed["revision"]

    # Tenant isolation: another tenant sees no subscription at all.
    with tenant_scope(tenant="beta"):
        assert service.subscription_changes("example-ai-policy") is None
