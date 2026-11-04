"""Adversarial contracts for governed bank MRM evidence packages."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest
from maverick import ai_bank_mrm as bank_mrm
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"
OTHER_ASSET = "MAA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EVIDENCE = "MRE-0123456789abcdef0123456789abcdef"


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float = 1.0) -> None:
        self.value += seconds


class Registry:
    def __init__(self) -> None:
        self.revision = 1
        self.digest = _hex("asset-v1")

    def __call__(self, asset_id: str):
        if asset_id != ASSET:
            return None
        return {
            "asset_id": ASSET,
            "revision": self.revision,
            "version_digest": self.digest,
        }

    def change(self) -> None:
        self.revision += 1
        self.digest = _hex(f"asset-v{self.revision}")


class Evidence:
    def __init__(self) -> None:
        self.digest = _hex("evidence-v1")
        self.status = "approved"
        self.current = True
        self.result = "passed"
        self.asset_id = ASSET

    def __call__(self, evidence_id: str):
        if evidence_id != EVIDENCE:
            return None
        return {
            "evidence_id": EVIDENCE,
            "digest": self.digest,
            "status": self.status,
            "current": self.current,
            "result": self.result,
            "asset_id": self.asset_id,
        }


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[ai_bank_mrm]\nenable = true\n", encoding="utf-8"
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _store(label: str) -> GovernedRecordStore:
    return GovernedRecordStore(
        f"test_ai_bank_mrm_{label}", "BMP", "test_ai_bank_mrm_package"
    )


def _service(label: str = "main"):
    store = _store(label)
    registry = Registry()
    evidence = Evidence()
    clock = Clock()
    service = bank_mrm.AIBankMRMService(
        packages=store,
        asset_lookup=registry,
        evidence_resolver=evidence,
        clock=clock,
    )
    return service, store, registry, evidence, clock


VALUES = {
    "inventory_classification": {
        "model_name": "Retail credit propensity model",
        "model_purpose": "Estimate a bounded portfolio propensity score.",
        "business_use": "Portfolio monitoring and governed analyst review.",
        "owner_role": "model-owner",
        "model_tier": "tier-1",
        "materiality": "high",
        "deployment_state": "production",
    },
    "validation_scope": {
        "validation_type": "periodic",
        "scope_summary": "Conceptual, data, performance, and control review.",
        "population_code": "retail-portfolio",
        "exclusions_summary": "External service availability was not retested.",
    },
    "validation_results": {
        "outcome": "satisfactory-with-conditions",
        "results_summary": "Documented results include two tracked findings.",
        "open_findings": 2,
        "high_findings": 0,
        "observed_at": NOW,
    },
    "conceptual_soundness": {
        "methodology_code": "gradient-boosted-ranking",
        "assumptions_summary": "Use is limited to the documented population.",
        "soundness_summary": "Method and assumptions were independently challenged.",
    },
    "outcomes_monitoring": {
        "monitoring_summary": "Performance and stability metrics are reviewed monthly.",
        "metric_set_code": "performance-stability-v2",
        "cadence_days": 30,
        "last_observed_at": NOW,
    },
    "limitations": {
        "limitations_summary": "Performance is sensitive to population shift.",
        "limitation_count": 1,
        "residual_risk": "moderate",
    },
    "change_controls": {
        "change_policy_code": "model-change-control-v3",
        "change_summary": "Material changes require independent review before use.",
        "last_change_at": NOW - 86_400,
    },
    "issues_remediation": {
        "issues_summary": "Two open findings have assigned remediation tracking.",
        "open_issues": 2,
        "overdue_issues": 0,
        "highest_severity": "moderate",
    },
    "independent_review": {
        "review_type": "independent-validation",
        "reviewer_role": "independent-model-validation",
        "conclusion": "satisfactory-with-conditions",
        "reviewed_at": NOW,
    },
}


def _section(name: str, *, reverse: bool = False):
    rows = [
        {"field": field, "state": "verified", "value": value}
        for field, value in VALUES[name].items()
    ]
    if reverse:
        rows.reverse()
    return {
        "schema": bank_mrm.SECTION_SCHEMA,
        "state": "verified",
        "assertions": rows,
        "evidence_ids": [EVIDENCE],
    }


def _content(*, reverse: bool = False):
    names = list(VALUES)
    if reverse:
        names.reverse()
    return {name: _section(name, reverse=reverse) for name in names}


def _set_state(content, section: str, field: str, state: str) -> None:
    target = next(
        row for row in content[section]["assertions"] if row["field"] == field
    )
    target["state"] = state
    target["value"] = None
    content[section]["state"] = state


def _bindings(evidence: Evidence):
    return [{"evidence_id": EVIDENCE, "digest": evidence.digest}]


def _create(
    service,
    evidence,
    *,
    content=None,
    operation: str = "prepare-bank-mrm-001",
    actor: str = "user:preparer",
):
    return service.create_package(
        "bank-mrm-packet",
        asset_id=ASSET,
        content=content or _content(),
        evidence_bindings=_bindings(evidence),
        idempotency_key=operation,
        actor=actor,
    )


def test_feature_is_explicit_default_off_and_tenant_is_required(_isolate):
    from maverick import config

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert bank_mrm.enabled() is False
    service, *_ = _service("disabled")
    with tenant_scope(tenant="acme"):
        with pytest.raises(bank_mrm.AIBankMRMConfigError, match="disabled"):
            service.list_packages()

    (_isolate / "config.toml").write_text(
        '[ai_bank_mrm]\nenable = "true"\n', encoding="utf-8"
    )
    config.reset_config_cache()
    assert bank_mrm.enabled() is False

    (_isolate / "config.toml").write_text(
        "[ai_bank_mrm]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    assert bank_mrm.enabled() is True
    with pytest.raises(bank_mrm.AIBankMRMStateError, match="explicit tenant"):
        service.list_packages()


def test_exact_bindings_are_safe_and_actors_are_pseudonymized():
    service, store, registry, evidence, _ = _service("binding")
    with tenant_scope(tenant="acme"):
        package = _create(service, evidence)
        persisted = json.dumps(store.list(limit=1))

    version = package["versions"][0]
    assert version["asset_binding"] == {
        "asset_id": ASSET,
        "revision": registry.revision,
        "version_digest": registry.digest,
    }
    assert version["evidence_bindings"] == _bindings(evidence)
    assert version["complete"] is True
    assert version["exportable"] is False
    assert "user:preparer" not in json.dumps(package)
    assert "user:preparer" not in persisted
    assert "prepare-bank-mrm-001" not in persisted
    assert "prepared_by_ref" not in json.dumps(package)


def test_records_are_tenant_isolated_and_ids_can_repeat():
    service, _, _, evidence, _ = _service("tenants")
    with tenant_scope(tenant="acme"):
        _create(service, evidence)
        assert len(service.list_packages()) == 1
    with tenant_scope(tenant="globex"):
        assert service.list_packages() == []
        _create(service, evidence)
        assert service.get_package("bank-mrm-packet") is not None
    with tenant_scope(tenant="acme"):
        assert len(service.list_packages()) == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.update(status="draft"), "not approved"),
        (lambda row: row.update(current=False), "not current"),
        (lambda row: row.update(digest=_hex("changed")), "digest changed"),
        (lambda row: row.update(result="failed"), "not a passing"),
        (lambda row: row.update(asset_id=OTHER_ASSET), "different Model Risk asset"),
    ],
)
def test_only_exact_current_approved_evidence_is_admitted(mutation, message):
    service, _, _, evidence, _ = _service(f"evidence-{message.replace(' ', '-')}")
    original = evidence.__call__

    def resolve(evidence_id: str):
        row = original(evidence_id)
        assert row is not None
        mutation(row)
        return row

    service._evidence_resolver = resolve
    with tenant_scope(tenant="acme"):
        with pytest.raises(bank_mrm.AIBankMRMEvidenceError, match=message):
            _create(service, evidence)


def test_asset_lookup_identity_and_shape_fail_closed():
    service, _, _, evidence, _ = _service("bad-asset")
    with tenant_scope(tenant="acme"):
        service._asset_lookup = lambda _asset: {
            "asset_id": OTHER_ASSET,
            "revision": 1,
            "version_digest": _hex("other"),
        }
        with pytest.raises(bank_mrm.AIBankMRMAssetError, match="changed identity"):
            _create(service, evidence)
        service._asset_lookup = lambda _asset: {"asset_id": ASSET, "revision": 0}
        with pytest.raises(bank_mrm.AIBankMRMAssetError, match="malformed"):
            _create(service, evidence)


def test_citations_must_exactly_match_content_and_are_canonical():
    service, _, _, evidence, _ = _service("citations")
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="exactly match"):
            service.create_package(
                "bank-mrm-packet",
                asset_id=ASSET,
                content=_content(),
                evidence_bindings=[],
                idempotency_key="missing-binding",
                actor="user:preparer",
            )
        with pytest.raises(ValueError, match="duplicates"):
            service.create_package(
                "bank-mrm-packet",
                asset_id=ASSET,
                content=_content(),
                evidence_bindings=_bindings(evidence) * 2,
                idempotency_key="duplicate-binding",
                actor="user:preparer",
            )


@pytest.mark.parametrize(
    ("unsafe", "message"),
    [
        ("raw prompt: decide this applicant", "raw prompt"),
        ("password=correct-horse-battery-staple", "secret"),
        ("Contact jane@example.com for details", "personal contact"),
        ("Contact 212-555-1212 for details", "personal contact"),
        ("The model is regulator-approved", "prohibited assurance claim"),
        ("x" * 513, "invalid"),
    ],
)
def test_free_text_rejects_raw_payloads_secrets_pii_claims_and_overflow(
    unsafe, message
):
    service, _, _, evidence, _ = _service(f"unsafe-{len(unsafe)}-{message[:4]}")
    content = _content()
    target = next(
        row
        for row in content["validation_results"]["assertions"]
        if row["field"] == "results_summary"
    )
    target["value"] = unsafe
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match=message):
            _create(service, evidence, content=content)


def test_closed_schema_rejects_extensions_and_implicit_gap_values():
    service, _, _, evidence, _ = _service("closed")
    content = _content()
    content["raw_outputs"] = []
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="unexpected"):
            _create(service, evidence, content=content)

    content = _content()
    content["limitations"]["assertions"][0]["unexpected"] = True
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="unexpected"):
            _create(service, evidence, content=content)

    content = _content()
    _set_state(content, "limitations", "limitation_count", "missing")
    target = next(
        row
        for row in content["limitations"]["assertions"]
        if row["field"] == "limitation_count"
    )
    target["value"] = 0
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="must not imply verified data"):
            _create(service, evidence, content=content)


def test_explicit_missing_and_unverified_states_survive_safe_export():
    service, _, _, evidence, _ = _service("gaps")
    content = _content()
    _set_state(content, "limitations", "limitation_count", "missing")
    _set_state(content, "validation_results", "results_summary", "unverified")
    with tenant_scope(tenant="acme"):
        package = _create(service, evidence, content=content)
        version = package["versions"][0]
        assert version["complete"] is False
        assert "limitations.limitation_count:missing" in version["completeness_gaps"]
        assert (
            "validation_results.results_summary:unverified"
            in version["completeness_gaps"]
        )
        package = service.approve_package(
            "bank-mrm-packet",
            1,
            expected_revision=package["revision"],
            actor="user:independent-approver",
        )
        packet = service.export_package("bank-mrm-packet")

    assert package["versions"][0]["approval_scope"] == "package-integrity-only"
    assert packet["completeness"]["complete"] is False
    assert packet["claims"] == {
        "model_approved": False,
        "validation_conclusion": False,
        "compliance_determination": False,
        "certification": False,
        "regulatory_acceptance": False,
        "supervisory_acceptance": False,
    }
    assert packet["approval"]["scope"] == "package-integrity-only"


def test_normalization_is_deterministic_across_input_order():
    first, _, _, first_evidence, _ = _service("deterministic-a")
    second, _, _, second_evidence, _ = _service("deterministic-b")
    with tenant_scope(tenant="acme"):
        a = _create(first, first_evidence, content=_content())
        b = _create(second, second_evidence, content=_content(reverse=True))
    assert a["versions"][0]["content"] == b["versions"][0]["content"]
    assert a["versions"][0]["content_sha256"] == b["versions"][0]["content_sha256"]
    assert a["versions"][0]["authority_sha256"] == b["versions"][0]["authority_sha256"]


def test_create_and_version_operations_are_idempotent_or_conflict():
    service, _, _, evidence, _ = _service("idempotency")
    with tenant_scope(tenant="acme"):
        first = _create(service, evidence)
        assert _create(service, evidence) == first
        changed = _content()
        changed["limitations"]["assertions"][0]["value"] = "Changed limitation."
        with pytest.raises(bank_mrm.AIBankMRMIdempotencyConflict):
            _create(service, evidence, content=changed)

        versioned = service.add_version(
            "bank-mrm-packet",
            content=changed,
            evidence_bindings=_bindings(evidence),
            expected_revision=first["revision"],
            idempotency_key="version-002",
            actor="user:preparer",
        )
        retried = service.add_version(
            "bank-mrm-packet",
            content=changed,
            evidence_bindings=_bindings(evidence),
            expected_revision=first["revision"],
            idempotency_key="version-002",
            actor="user:preparer",
        )
        assert retried == versioned
        conflicting = copy.deepcopy(changed)
        conflicting["limitations"]["assertions"][0]["value"] = "Different limitation."
        with pytest.raises(bank_mrm.AIBankMRMIdempotencyConflict):
            service.add_version(
                "bank-mrm-packet",
                content=conflicting,
                evidence_bindings=_bindings(evidence),
                expected_revision=versioned["revision"],
                idempotency_key="version-002",
                actor="user:preparer",
            )


def test_versions_are_immutable_and_updates_require_cas():
    service, _, _, evidence, _ = _service("versions")
    changed = _content()
    changed["limitations"]["assertions"][0]["value"] = "Updated limitation."
    with tenant_scope(tenant="acme"):
        first = _create(service, evidence)
        first_digest = first["versions"][0]["content_sha256"]
        with pytest.raises(RecordConflict):
            service.add_version(
                "bank-mrm-packet",
                content=changed,
                evidence_bindings=_bindings(evidence),
                expected_revision=first["revision"] + 1,
                idempotency_key="version-cas",
                actor="user:preparer",
            )
        current = service.add_version(
            "bank-mrm-packet",
            content=changed,
            evidence_bindings=_bindings(evidence),
            expected_revision=first["revision"],
            idempotency_key="version-cas",
            actor="user:preparer",
        )
    assert len(current["versions"]) == 2
    assert current["versions"][0]["content_sha256"] == first_digest
    assert current["versions"][1]["content_sha256"] != first_digest


def test_approval_requires_latest_version_four_eyes_and_cas():
    service, store, _, evidence, _ = _service("approval")
    with tenant_scope(tenant="acme"):
        package = _create(service, evidence)
        with pytest.raises(bank_mrm.AIBankMRMApprovalError, match="different human"):
            service.approve_package(
                "bank-mrm-packet",
                1,
                expected_revision=package["revision"],
                actor="user:preparer",
            )
        with pytest.raises(RecordConflict):
            service.approve_package(
                "bank-mrm-packet",
                1,
                expected_revision=package["revision"] + 1,
                actor="user:approver",
            )
        approved = service.approve_package(
            "bank-mrm-packet",
            1,
            expected_revision=package["revision"],
            actor="user:approver",
        )
        persisted = json.dumps(store.list(limit=1))

    version = approved["versions"][0]
    assert version["status"] == "approved"
    assert version["four_eyes_approved"] is True
    assert version["approval_scope"] == "package-integrity-only"
    assert "user:approver" not in persisted


def test_asset_or_evidence_change_stales_approval_and_blocks_export():
    service, _, registry, evidence, _ = _service("stale")
    with tenant_scope(tenant="acme"):
        package = _create(service, evidence)
        package = service.approve_package(
            "bank-mrm-packet",
            1,
            expected_revision=package["revision"],
            actor="user:approver",
        )
        assert service.export_package("bank-mrm-packet")["version"] == 1

        registry.change()
        stale = service.get_package("bank-mrm-packet")
        assert stale is not None
        assert stale["status"] == "stale"
        assert "asset_authority_changed" in stale["versions"][0]["stale_reasons"]
        with pytest.raises(bank_mrm.AIBankMRMStaleError, match="stale"):
            service.export_package("bank-mrm-packet")

        registry.revision = 1
        registry.digest = _hex("asset-v1")
        evidence.digest = _hex("evidence-v2")
        stale = service.get_package("bank-mrm-packet")
        assert stale is not None
        assert stale["status"] == "stale"
        assert stale["versions"][0]["stale_reasons"] == [
            f"evidence_authority_changed:{EVIDENCE}"
        ]


def test_approved_export_is_bounded_verifiable_and_contains_no_actor_or_raw_data():
    service, _, _, evidence, _ = _service("export")
    with tenant_scope(tenant="acme"):
        package = _create(service, evidence)
        package = service.approve_package(
            "bank-mrm-packet",
            1,
            expected_revision=package["revision"],
            actor="user:independent-approver",
        )
        packet = service.export_package("bank-mrm-packet")

    encoded = json.dumps(packet, sort_keys=True)
    assert packet["schema"] == bank_mrm.EXPORT_SCHEMA
    assert len(encoded.encode("utf-8")) < 256 * 1024
    assert len(packet["packet_sha256"]) == 64
    assert "user:" not in encoded
    assert "prepared_by_ref" not in encoded
    assert "approved_by_ref" not in encoded
    assert "raw_prompt" not in encoded
    assert "raw_output" not in encoded
    assert packet["notice"] == bank_mrm.NOTICE


@pytest.mark.parametrize("target", ["content", "authority", "state"])
def test_persisted_tampering_or_corruption_fails_closed(target):
    service, store, _, evidence, _ = _service(f"tamper-{target}")
    with tenant_scope(tenant="acme"):
        package = _create(service, evidence)
        raw = store.list(limit=1)[0]

        def mutate(row):
            if target == "content":
                row["versions"][0]["content"]["limitations"]["assertions"][0][
                    "value"
                ] = "Tampered summary."
            elif target == "authority":
                row["versions"][0]["authority_sha256"] = _hex("tampered")
            else:
                row["state_sha256"] = _hex("tampered")

        store.update(
            raw["id"],
            mutate,
            expected_revision=package["revision"],
            action="simulate_tamper",
            actor="test",
        )
        with pytest.raises(bank_mrm.AIBankMRMStateError, match="malformed"):
            service.get_package("bank-mrm-packet")
