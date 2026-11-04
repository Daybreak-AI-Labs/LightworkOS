"""Adversarial contracts for governed insurance-assurance projections."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest
from maverick import ai_insurability as assurance
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"
EVIDENCE = "MRE-0123456789abcdef0123456789abcdef"


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
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

    def __call__(self, evidence_id: str):
        if evidence_id != EVIDENCE:
            return None
        return {
            "evidence_id": EVIDENCE,
            "digest": self.digest,
            "status": self.status,
            "current": self.current,
            "asset_id": ASSET,
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
        "[ai_insurability]\nenable = true\n", encoding="utf-8"
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _store(label: str) -> GovernedRecordStore:
    return GovernedRecordStore(
        f"test_ai_insurability_{label}", "IAP", "test_ai_insurability_profile"
    )


def _service(label: str = "main"):
    store = _store(label)
    registry = Registry()
    evidence = Evidence()
    clock = Clock()
    service = assurance.AIInsurabilityService(
        profiles=store,
        asset_lookup=registry,
        evidence_resolver=evidence,
        clock=clock,
    )
    return service, store, registry, evidence, clock


def _measurement(*, state: str = "measured", value: float = 95.0):
    if state != "measured":
        return {
            "schema": assurance.MEASUREMENT_SCHEMA,
            "state": state,
            "value": None,
            "unit": "percent",
            "window_start": None,
            "window_end": None,
            "sample_count": 0,
            "confidence": None,
            "evidence_ids": [],
        }
    return {
        "schema": assurance.MEASUREMENT_SCHEMA,
        "state": "measured",
        "value": value,
        "unit": "percent",
        "window_start": NOW - 3600,
        "window_end": NOW,
        "sample_count": 10_000,
        "confidence": 0.95,
        "evidence_ids": [EVIDENCE],
    }


def _content():
    return {
        "governance_posture": {
            "frameworks": [
                {
                    "framework_id": "nist-ai-rmf",
                    "posture": "implemented",
                    "evidence_ids": [EVIDENCE],
                }
            ],
            "accountable_role": "model-risk-owner",
            "review_cadence_days": 90,
        },
        "measurements": {
            name: _measurement(value=99.0 if name == "uptime" else 92.0)
            for name in (
                "evaluation",
                "red_team",
                "drift",
                "runtime",
                "uptime",
                "refusal",
            )
        },
        "incident_summary": {
            "data_state": "measured",
            "as_of": NOW,
            "open_count": 0,
            "closed_count": 3,
            "highest_open_severity": "none",
            "evidence_ids": [EVIDENCE],
        },
        "open_findings_summary": {
            "data_state": "measured",
            "as_of": NOW,
            "total_open": 2,
            "critical_open": 0,
            "overdue_open": 0,
            "evidence_ids": [EVIDENCE],
        },
        "safeguards": [
            {
                "control_id": "runtime-policy-gate",
                "status": "verified",
                "evidence_ids": [EVIDENCE],
            }
        ],
        "exclusions": ["Live third-party dependencies are outside this packet."],
        "limitations": ["Measurements describe only the cited observation windows."],
        "verifier_instructions": {
            "schema_version": "v1",
            "steps": [
                "Recompute each cited digest from the approved evidence record.",
                "Confirm the asset revision remains current in Model Risk.",
            ],
        },
    }


def _citations(evidence: Evidence):
    return [{"evidence_id": EVIDENCE, "digest": evidence.digest}]


def _create(service, evidence, *, content=None, operation="prepare-001"):
    return service.create_profile(
        "underwriter-packet",
        asset_id=ASSET,
        content=content or _content(),
        evidence_bindings=_citations(evidence),
        idempotency_key=operation,
        actor="user:preparer",
    )


def test_feature_is_explicit_default_off_and_tenant_is_required(_isolate):
    from maverick import config

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert assurance.enabled() is False
    service, *_ = _service("disabled")
    with tenant_scope(tenant="acme"):
        with pytest.raises(assurance.AIInsurabilityConfigError, match="disabled"):
            service.list_profiles()

    (_isolate / "config.toml").write_text(
        "[ai_insurability]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    assert assurance.enabled() is True
    with pytest.raises(assurance.AIInsurabilityStateError, match="explicit tenant"):
        service.list_profiles()


def test_profile_is_exact_asset_and_evidence_bound_with_safe_projection():
    service, store, registry, evidence, _ = _service("binding")
    with tenant_scope(tenant="acme"):
        profile = _create(service, evidence)
        persisted = json.dumps(store.list(limit=1))

    version = profile["versions"][0]
    assert version["asset_binding"] == {
        "asset_id": ASSET,
        "revision": registry.revision,
        "version_digest": registry.digest,
    }
    assert version["evidence_bindings"] == _citations(evidence)
    assert version["exportable"] is False
    serialized = json.dumps(profile)
    assert "user:preparer" not in serialized
    assert "user:preparer" not in persisted
    assert "idempotency" not in serialized
    assert "prompt" not in serialized.lower()
    assert "model output" not in serialized.lower()


def test_records_are_tenant_isolated_and_semantic_ids_can_repeat():
    service, _, _, evidence, _ = _service("tenants")
    with tenant_scope(tenant="acme"):
        _create(service, evidence)
        assert len(service.list_profiles()) == 1
    with tenant_scope(tenant="globex"):
        assert service.list_profiles() == []
        _create(service, evidence)
        assert service.get_profile("underwriter-packet") is not None
    with tenant_scope(tenant="acme"):
        assert len(service.list_profiles()) == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row.update(status="draft"), "not approved"),
        (lambda row: row.update(current=False), "not current"),
        (lambda row: row.update(digest=_hex("changed")), "digest changed"),
        (lambda row: row.update(asset_id="MAA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "different asset"),
    ],
)
def test_only_exact_current_approved_asset_evidence_is_admitted(mutation, message):
    service, _, _, evidence, _ = _service(f"evidence-{message.replace(' ', '-')}")
    original = evidence.__call__

    def resolve(evidence_id: str):
        row = original(evidence_id)
        assert row is not None
        mutation(row)
        return row

    service._evidence_resolver = resolve
    with tenant_scope(tenant="acme"):
        with pytest.raises(assurance.AIInsurabilityEvidenceError, match=message):
            _create(service, evidence)


def test_missing_data_is_explicit_but_blocks_human_approval():
    service, _, _, evidence, _ = _service("missing")
    content = _content()
    content["measurements"]["runtime"] = _measurement(state="missing")
    # The exact set of citations remains one item because other sections cite it.
    with tenant_scope(tenant="acme"):
        draft = _create(service, evidence, content=content)
        assert draft["versions"][0]["completeness_gaps"] == ["measurement:runtime"]
        with pytest.raises(assurance.AIInsurabilityApprovalError, match="missing required"):
            service.approve_profile(
                "underwriter-packet",
                1,
                expected_revision=draft["revision"],
                actor="user:approver",
            )


def test_measurement_windows_counts_confidence_and_closed_schema_are_bounded():
    service, _, _, evidence, _ = _service("bounds")
    cases = []
    content = _content()
    content["measurements"]["uptime"]["sample_count"] = 0
    cases.append((content, "sample_count"))
    content = _content()
    content["measurements"]["runtime"]["confidence"] = 1.01
    cases.append((content, "confidence"))
    content = _content()
    content["measurements"]["evaluation"]["window_start"] = NOW + 1
    cases.append((content, "window"))
    content = _content()
    content["measurements"]["drift"]["raw_output"] = "forbidden"
    cases.append((content, "unexpected or missing"))

    with tenant_scope(tenant="acme"):
        for index, (candidate, message) in enumerate(cases):
            with pytest.raises(ValueError, match=message):
                service.create_profile(
                    f"packet-{index}",
                    asset_id=ASSET,
                    content=candidate,
                    evidence_bindings=_citations(evidence),
                    idempotency_key=f"operation-{index}",
                    actor="user:preparer",
                )


def test_human_cas_four_eyes_and_deterministic_export():
    service, _, _, evidence, _ = _service("approval")
    with tenant_scope(tenant="acme"):
        draft = _create(service, evidence)
        with pytest.raises(RecordConflict, match="expected revision"):
            service.approve_profile(
                "underwriter-packet", 1, expected_revision=99, actor="user:approver"
            )
        with pytest.raises(assurance.AIInsurabilityApprovalError, match="different human"):
            service.approve_profile(
                "underwriter-packet",
                1,
                expected_revision=draft["revision"],
                actor="user:preparer",
            )
        approved = service.approve_profile(
            "underwriter-packet",
            1,
            expected_revision=draft["revision"],
            actor="user:approver",
        )
        assert approved["versions"][0]["exportable"] is True
        first = service.export_profile("underwriter-packet")
        second = service.export_profile("underwriter-packet")

    assert first == second
    digest = first.pop("packet_sha256")
    assert digest == _canonical_sha(first)
    assert all(value is False for value in first["claims"].values())
    assert first["approval"] == {
        "human_approved": True,
        "four_eyes": True,
        "authority_fresh": True,
    }
    assert "user:" not in json.dumps(first)


def test_asset_or_evidence_change_invalidates_approval_and_export():
    service, _, registry, evidence, _ = _service("stale")
    with tenant_scope(tenant="acme"):
        draft = _create(service, evidence)
        service.approve_profile(
            "underwriter-packet",
            1,
            expected_revision=draft["revision"],
            actor="user:approver",
        )
        registry.change()
        stale = service.get_profile("underwriter-packet")
        assert stale["status"] == "stale"
        assert "asset_authority_changed" in stale["versions"][0]["stale_reasons"]
        # An exact retry remains idempotent and returns the now-stale authority.
        assert _create(service, evidence)["status"] == "stale"
        with pytest.raises(assurance.AIInsurabilityStaleError, match="asset_authority"):
            service.export_profile("underwriter-packet")

        registry.revision = 1
        registry.digest = _hex("asset-v1")
        evidence.current = False
        stale = service.get_profile("underwriter-packet")
        assert stale["versions"][0]["exportable"] is False
        assert stale["versions"][0]["stale_reasons"] == [
            f"evidence_authority_changed:{EVIDENCE}"
        ]


def test_new_version_binds_new_asset_authority_without_mutating_history():
    service, _, registry, evidence, _ = _service("versions")
    with tenant_scope(tenant="acme"):
        first = _create(service, evidence)
        original = copy.deepcopy(first["versions"][0])
        registry.change()
        content = _content()
        content["measurements"]["evaluation"]["value"] = 88.0
        updated = service.add_version(
            "underwriter-packet",
            content=content,
            evidence_bindings=_citations(evidence),
            expected_revision=first["revision"],
            idempotency_key="prepare-002",
            actor="user:second-preparer",
        )

    assert updated["versions"][0]["content"] == original["content"]
    assert updated["versions"][1]["asset_binding"]["revision"] == 2
    assert updated["versions"][1]["asset_binding"]["version_digest"] == registry.digest
    assert updated["versions"][1]["content"]["measurements"]["evaluation"]["value"] == 88.0


def test_create_and_version_operations_are_idempotent_but_reuse_conflicts():
    service, _, _, evidence, clock = _service("idempotency")
    with tenant_scope(tenant="acme"):
        first = _create(service, evidence)
        clock.advance(60)
        replay = _create(service, evidence)
        assert replay == first
        changed = _content()
        changed["measurements"]["evaluation"]["value"] = 1.0
        with pytest.raises(assurance.AIInsurabilityIdempotencyConflict):
            _create(service, evidence, content=changed)

        second = service.add_version(
            "underwriter-packet",
            content=changed,
            evidence_bindings=_citations(evidence),
            expected_revision=first["revision"],
            idempotency_key="prepare-002",
            actor="user:preparer-two",
        )
        clock.advance(60)
        version_replay = service.add_version(
            "underwriter-packet",
            content=changed,
            evidence_bindings=_citations(evidence),
            expected_revision=first["revision"],
            idempotency_key="prepare-002",
            actor="user:preparer-two",
        )
        assert version_replay == second
        different = copy.deepcopy(changed)
        different["measurements"]["runtime"]["value"] = 2.0
        with pytest.raises(assurance.AIInsurabilityIdempotencyConflict):
            service.add_version(
                "underwriter-packet",
                content=different,
                evidence_bindings=_citations(evidence),
                expected_revision=second["revision"],
                idempotency_key="prepare-002",
                actor="user:preparer-two",
            )


def test_tampered_or_malformed_persisted_authority_fails_closed():
    service, store, _, evidence, _ = _service("tamper")
    with tenant_scope(tenant="acme"):
        created = _create(service, evidence)
        record_id = store.list(limit=1)[0]["id"]

        def mutate(row):
            row["versions"][0]["content"]["measurements"]["uptime"]["value"] = 1.0

        store.update(
            record_id,
            mutate,
            expected_revision=created["revision"],
            action="simulate_tamper",
            actor="system:test",
        )
        with pytest.raises(assurance.AIInsurabilityStateError, match="malformed"):
            service.get_profile("underwriter-packet")


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("limitations", 0), "Contact person@example.test for details.", "personal contact"),
        (("exclusions", 0), "Bearer abcdefghijklmnopqrstuvwxyz", "secret material"),
        (("limitations", 0), "This guarantees a lower premium.", "underwriting claim"),
    ],
)
def test_free_text_rejects_personal_data_secrets_and_forbidden_claims(path, value, message):
    service, _, _, evidence, _ = _service(f"unsafe-{message.replace(' ', '-')}")
    content = _content()
    content[path[0]][path[1]] = value
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match=message):
            _create(service, evidence, content=content)


def test_list_is_bounded_and_export_requires_approval():
    service, _, _, evidence, _ = _service("list")
    with tenant_scope(tenant="acme"):
        _create(service, evidence)
        assert service.list_profiles(limit=1)[0]["exportable"] is False
        with pytest.raises(ValueError, match="between 1 and 100"):
            service.list_profiles(limit=101)
        with pytest.raises(assurance.AIInsurabilityApprovalError, match="not human approved"):
            service.export_profile("underwriter-packet")
