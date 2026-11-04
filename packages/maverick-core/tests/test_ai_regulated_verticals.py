"""Focused contracts for closed regulated-vertical decision-support packages."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import ai_regulated_verticals as regulated
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ManualClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class AssetRegistry:
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


class EvidenceRegistry:
    def __init__(self) -> None:
        self.rows = {
            "EVD-primary": self._row("EVD-primary", "evidence-primary"),
            "EVD-secondary": self._row("EVD-secondary", "evidence-secondary"),
        }

    @staticmethod
    def _row(evidence_id: str, label: str):
        return {
            "evidence_id": evidence_id,
            "digest": _hex(label),
            "status": "approved",
            "result": "passed",
            "current": True,
            "asset_id": ASSET,
        }

    def __call__(self, evidence_id: str):
        return self.rows.get(evidence_id)

    def change(self, evidence_id: str = "EVD-primary") -> None:
        self.rows[evidence_id]["digest"] = _hex(f"changed-{evidence_id}")


class TemplateRegistry:
    def __init__(self) -> None:
        self.rows = {
            kind: {
                "package_type": kind,
                "template_id": f"lightwork.{kind}",
                "version": 1,
                "digest": _hex(f"template:{kind}:1"),
            }
            for kind in regulated.PACKAGE_TYPES
        }

    def __call__(self, package_type: str):
        row = self.rows.get(package_type)
        return None if row is None else dict(row)

    def change(self, package_type: str) -> None:
        self.rows[package_type]["version"] += 1
        self.rows[package_type]["digest"] = _hex(
            f"template:{package_type}:{self.rows[package_type]['version']}"
        )


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[ai_regulated_verticals]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _store(label: str) -> GovernedRecordStore:
    return GovernedRecordStore(
        f"test_ai_regulated_verticals_{label}",
        "RVP",
        "test_ai_regulated_vertical_package",
    )


def _service(label: str = "main"):
    store = _store(label)
    assets = AssetRegistry()
    evidence = EvidenceRegistry()
    templates = TemplateRegistry()
    clock = ManualClock()
    service = regulated.RegulatedVerticalsService(
        records=store,
        asset_lookup=assets,
        evidence_resolver=evidence,
        template_resolver=templates,
        clock=clock,
    )
    return service, assets, evidence, templates, store


def _bindings(*evidence_ids: str):
    labels = {
        "EVD-primary": "evidence-primary",
        "EVD-secondary": "evidence-secondary",
    }
    return [
        {"evidence_id": evidence_id, "digest": _hex(labels[evidence_id])}
        for evidence_id in evidence_ids
    ]


def _credit():
    return {
        "model_receipt_sha256": _hex("model-receipt"),
        "input_receipt_sha256": _hex("input-receipt-no-raw-values"),
        "explanation_receipt_sha256": _hex("explanation-receipt"),
        "reason_codes": [
            {
                "code": "RC-capacity",
                "rank": 1,
                "source_factor_code": "debt_capacity",
                "evidence_ids": ["EVD-primary"],
            },
            {
                "code": "RC-history",
                "rank": 2,
                "source_factor_code": "account_history",
                "evidence_ids": ["EVD-secondary"],
            },
        ],
    }


def _cohort(code: str, *, samples: int, favorable: int, evidence_id: str):
    return {
        "cohort_code": code,
        "definition_sha256": _hex(f"definition:{code}"),
        "sample_count": samples,
        "favorable_count": favorable,
        "missing_count": 3,
        "evidence_ids": [evidence_id],
    }


def _fair(*, zero_reference: bool = False, zero_comparison: bool = False):
    return {
        "analysis_scope_code": "credit-screening-quarterly",
        "window_start": NOW - 86_400,
        "window_end": NOW,
        "reference_cohort": _cohort(
            "reference",
            samples=0 if zero_reference else 100,
            favorable=0 if zero_reference else 80,
            evidence_id="EVD-primary",
        ),
        "comparison_cohorts": [
            _cohort(
                "comparison-a",
                samples=0 if zero_comparison else 50,
                favorable=0 if zero_comparison else 30,
                evidence_id="EVD-secondary",
            )
        ],
        "methodology_sha256": _hex("methodology"),
        "limitations_codes": ["aggregate-only", "human-interpretation-required"],
    }


def _item(
    state: str = "complete", *, evidence_id: str = "EVD-primary"
):
    if state in {"complete", "implemented"}:
        return {
            "state": state,
            "evidence_ids": [evidence_id],
            "rationale_sha256": None,
        }
    if state == "not_applicable":
        return {
            "state": state,
            "evidence_ids": [],
            "rationale_sha256": _hex("not-applicable-rationale"),
        }
    return {"state": state, "evidence_ids": [], "rationale_sha256": None}


def _nyc(*, auditor_state: str = "asserted", missing_check: str | None = None):
    auditor = (
        {
            "state": "asserted",
            "assertion_sha256": _hex("independent-auditor-assertion"),
            "asserted_at": NOW,
            "coverage_start": NOW - 86_400,
            "coverage_end": NOW,
            "evidence_ids": ["EVD-primary"],
        }
        if auditor_state == "asserted"
        else {
            "state": "missing",
            "assertion_sha256": None,
            "asserted_at": None,
            "coverage_start": None,
            "coverage_end": None,
            "evidence_ids": [],
        }
    )
    return {
        "assessment_window_start": NOW - 86_400,
        "assessment_window_end": NOW,
        "independent_auditor": auditor,
        "checklist": {
            name: _item("missing" if name == missing_check else "complete")
            for name in regulated.NYC_LL144_CHECKS
        },
    }


def _naic(*, partial_check: str | None = None):
    return {
        "bulletin_version_code": "naic-model-bulletin-2023",
        "jurisdiction_scope_codes": ["US-TN", "US-NY"],
        "applicability_assertion_sha256": _hex("human-applicability-assertion"),
        "checklist": {
            name: _item("partial" if name == partial_check else "implemented")
            for name in regulated.NAIC_CHECKS
        },
    }


def _case(package_type: str):
    if package_type == regulated.CREDIT_ADVERSE_ACTION:
        return _credit(), _bindings("EVD-primary", "EVD-secondary")
    if package_type == regulated.FAIR_LENDING_AGGREGATE:
        return _fair(), _bindings("EVD-primary", "EVD-secondary")
    if package_type == regulated.NYC_LL144:
        return _nyc(), _bindings("EVD-primary")
    return _naic(), _bindings("EVD-primary")


def _create(service, package_type: str, *, package_id: str | None = None):
    content, bindings = _case(package_type)
    return service.create_package(
        package_id or f"package-{package_type}",
        package_type=package_type,
        asset_id=ASSET,
        content=content,
        evidence_bindings=bindings,
        idempotency_key=f"create-{package_type}",
        actor="user:preparer",
    )


def test_feature_gate_is_default_off_and_explicit_tenant_is_required(_isolate):
    from maverick import config

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert regulated.enabled() is False
    service, *_ = _service("disabled")
    with tenant_scope(tenant="acme"):
        with pytest.raises(regulated.AIRegulatedVerticalsConfigError, match="disabled"):
            _create(service, regulated.CREDIT_ADVERSE_ACTION)

    (_isolate / "config.toml").write_text(
        "[ai_regulated_verticals]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    assert regulated.enabled() is True
    with pytest.raises(regulated.AIRegulatedVerticalsStateError, match="explicit tenant"):
        _create(service, regulated.CREDIT_ADVERSE_ACTION)


@pytest.mark.parametrize("package_type", sorted(regulated.PACKAGE_TYPES))
def test_all_four_package_types_require_four_eyes_then_export_safe_projection(
    package_type,
):
    service, *_ = _service(package_type)
    with tenant_scope(tenant="acme"):
        draft = _create(service, package_type)
        assert draft["status"] == "draft"
        assert draft["versions"][0]["completeness_gaps"] == []
        with pytest.raises(regulated.AIRegulatedVerticalsApprovalError, match="four-eyes"):
            service.approve_package(
                draft["package_id"], 1, expected_revision=1, actor="user:preparer"
            )
        approved = service.approve_package(
            draft["package_id"], 1, expected_revision=1, actor="user:reviewer"
        )
        assert approved["status"] == "approved"
        packet = service.export_package(draft["package_id"])

    assert packet["package_type"] == package_type
    assert packet["approval"] == {
        "human_approved": True,
        "four_eyes": True,
        "authority_fresh": True,
    }
    assert packet["privacy"]["individual_records_included"] is False
    assert all(value is False for value in packet["claims"].values())
    serialized = json.dumps(packet, sort_keys=True)
    assert "preparer" not in serialized
    assert "reviewer" not in serialized
    assert "applicant" not in serialized


def test_tenant_isolation_and_bounded_listing():
    service, *_ = _service("tenants")
    with tenant_scope(tenant="acme"):
        _create(service, regulated.CREDIT_ADVERSE_ACTION, package_id="credit-one")
        assert len(service.list_packages(limit=1)) == 1
        with pytest.raises(ValueError, match="between 1 and 250"):
            service.list_packages(limit=251)
    with tenant_scope(tenant="beta"):
        assert service.get_package("credit-one") is None
        assert service.list_packages() == []


def test_exact_bindings_and_authority_changes_make_approval_stale():
    service, assets, evidence, templates, _ = _service("stale")
    with tenant_scope(tenant="acme"):
        draft = _create(service, regulated.CREDIT_ADVERSE_ACTION)
        service.approve_package(
            draft["package_id"], 1, expected_revision=1, actor="user:reviewer"
        )
        assets.change()
        evidence.change()
        templates.change(regulated.CREDIT_ADVERSE_ACTION)
        current = service.get_package(draft["package_id"])
        latest = current["versions"][-1]
        assert latest["status"] == "stale"
        assert latest["authority_fresh"] is False
        assert "asset_authority_changed" in latest["stale_reasons"]
        assert "template_authority_changed" in latest["stale_reasons"]
        assert any(
            reason.startswith("evidence_authority_changed:")
            for reason in latest["stale_reasons"]
        )
        with pytest.raises(regulated.AIRegulatedVerticalsStaleError, match="stale"):
            service.export_package(draft["package_id"])


def test_digest_mismatch_wrong_asset_and_unused_evidence_fail_closed():
    service, *_ = _service("bindings")
    content, bindings = _case(regulated.CREDIT_ADVERSE_ACTION)
    wrong_digest = [dict(row) for row in bindings]
    wrong_digest[0]["digest"] = _hex("wrong")
    with tenant_scope(tenant="acme"):
        with pytest.raises(regulated.AIRegulatedVerticalsEvidenceError, match="changed"):
            service.create_package(
                "wrong-digest",
                package_type=regulated.CREDIT_ADVERSE_ACTION,
                asset_id=ASSET,
                content=content,
                evidence_bindings=wrong_digest,
                idempotency_key="wrong-digest",
                actor="user:preparer",
            )
        with pytest.raises(ValueError, match="exactly match"):
            service.create_package(
                "unused-evidence",
                package_type=regulated.CREDIT_ADVERSE_ACTION,
                asset_id=ASSET,
                content=content,
                evidence_bindings=[*bindings, {"evidence_id": "EVD-unused", "digest": _hex("x")}],
                idempotency_key="unused-evidence",
                actor="user:preparer",
            )
        with pytest.raises(regulated.AIRegulatedVerticalsAssetError, match="does not exist"):
            service.create_package(
                "wrong-asset",
                package_type=regulated.CREDIT_ADVERSE_ACTION,
                asset_id="MAA-fedcba9876543210fedcba9876543210",
                content=content,
                evidence_bindings=bindings,
                idempotency_key="wrong-asset",
                actor="user:preparer",
            )


def test_fair_lending_metrics_are_bounded_aggregate_counts_with_no_conclusion():
    service, *_ = _service("fair-metrics")
    with tenant_scope(tenant="acme"):
        draft = _create(service, regulated.FAIR_LENDING_AGGREGATE)
    report = draft["versions"][0]["content"]
    reference = report["reference_cohort"]
    comparison = report["comparison_cohorts"][0]
    assert reference["selection_rate"] == pytest.approx(0.8)
    assert comparison["selection_rate"] == pytest.approx(0.6)
    assert comparison["impact_ratio"] == pytest.approx(0.75)
    for cohort in (reference, comparison):
        assert 0.0 <= cohort["selection_rate"] <= 1.0
        assert 0.0 <= cohort["confidence"]["lower"] <= 1.0
        assert 0.0 <= cohort["confidence"]["upper"] <= 1.0
        assert cohort["confidence"]["lower"] <= cohort["selection_rate"]
        assert cohort["confidence"]["upper"] >= cohort["selection_rate"]
    assert report["interpretation_state"] == (
        "human_review_required_no_automated_conclusion"
    )
    assert set(reference) == {
        "cohort_code",
        "definition_sha256",
        "sample_count",
        "favorable_count",
        "missing_count",
        "selection_rate",
        "confidence",
        "evidence_ids",
    }


@pytest.mark.parametrize(("zero_reference", "zero_comparison"), [(True, False), (False, True)])
def test_fair_lending_zero_denominators_are_explicit_and_never_auto_conclusions(
    zero_reference, zero_comparison
):
    service, *_ = _service(f"zero-{zero_reference}-{zero_comparison}")
    with tenant_scope(tenant="acme"):
        draft = service.create_package(
            "fair-zero",
            package_type=regulated.FAIR_LENDING_AGGREGATE,
            asset_id=ASSET,
            content=_fair(
                zero_reference=zero_reference, zero_comparison=zero_comparison
            ),
            evidence_bindings=_bindings("EVD-primary", "EVD-secondary"),
            idempotency_key="fair-zero",
            actor="user:preparer",
        )
        content = draft["versions"][0]["content"]
        cohort = (
            content["reference_cohort"]
            if zero_reference
            else content["comparison_cohorts"][0]
        )
        assert cohort["selection_rate"] is None
        assert cohort["confidence"]["state"] == "unavailable_zero_denominator"
        if zero_reference:
            assert content["comparison_cohorts"][0]["impact_ratio"] is None
        assert content["interpretation_state"] == (
            "human_review_required_no_automated_conclusion"
        )
        assert draft["versions"][0]["completeness_gaps"]
        with pytest.raises(regulated.AIRegulatedVerticalsApprovalError, match="missing"):
            service.approve_package(
                "fair-zero", 1, expected_revision=1, actor="user:reviewer"
            )


@pytest.mark.parametrize(
    ("package_type", "content", "bindings", "expected_gap"),
    [
        (
            regulated.NYC_LL144,
            _nyc(auditor_state="missing"),
            _bindings("EVD-primary"),
            "independent_auditor",
        ),
        (
            regulated.NYC_LL144,
            _nyc(missing_check="public_summary"),
            _bindings("EVD-primary"),
            "checklist.public_summary",
        ),
        (
            regulated.NAIC_INSURANCE,
            _naic(partial_check="third_party_controls"),
            _bindings("EVD-primary"),
            "checklist.third_party_controls",
        ),
    ],
)
def test_required_completeness_states_block_approval(
    package_type, content, bindings, expected_gap
):
    service, *_ = _service(f"incomplete-{expected_gap}")
    with tenant_scope(tenant="acme"):
        draft = service.create_package(
            "incomplete",
            package_type=package_type,
            asset_id=ASSET,
            content=content,
            evidence_bindings=bindings,
            idempotency_key=f"incomplete-{expected_gap}",
            actor="user:preparer",
        )
        assert expected_gap in draft["versions"][0]["completeness_gaps"]
        with pytest.raises(regulated.AIRegulatedVerticalsApprovalError, match="missing"):
            service.approve_package(
                "incomplete", 1, expected_revision=1, actor="user:reviewer"
            )


def test_cas_versioning_rebinds_current_authorities_and_old_version_cannot_approve():
    service, assets, *_ = _service("versioning")
    with tenant_scope(tenant="acme"):
        first = _create(service, regulated.CREDIT_ADVERSE_ACTION)
        assets.change()
        with pytest.raises(RecordConflict):
            service.add_version(
                first["package_id"],
                content=_credit(),
                evidence_bindings=_bindings("EVD-primary", "EVD-secondary"),
                expected_revision=99,
                idempotency_key="version-2",
                actor="user:preparer",
            )
        second = service.add_version(
            first["package_id"],
            content=_credit(),
            evidence_bindings=_bindings("EVD-primary", "EVD-secondary"),
            expected_revision=1,
            idempotency_key="version-2",
            actor="user:preparer",
        )
        assert second["versions"][1]["asset_binding"]["revision"] == 2
        with pytest.raises(regulated.AIRegulatedVerticalsApprovalError, match="latest"):
            service.approve_package(
                first["package_id"], 1, expected_revision=2, actor="user:reviewer"
            )
        approved = service.approve_package(
            first["package_id"], 2, expected_revision=2, actor="user:reviewer"
        )
        assert approved["status"] == "approved"


def test_closed_schemas_reject_raw_or_individual_data_and_invalid_metric_bounds():
    service, *_ = _service("privacy")
    raw_credit = {**_credit(), "applicant_name": "Person Example"}
    invalid_fair = _fair()
    invalid_fair["comparison_cohorts"][0]["favorable_count"] = 51
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="closed schema"):
            service.create_package(
                "raw-credit",
                package_type=regulated.CREDIT_ADVERSE_ACTION,
                asset_id=ASSET,
                content=raw_credit,
                evidence_bindings=_bindings("EVD-primary", "EVD-secondary"),
                idempotency_key="raw-credit",
                actor="user:preparer",
            )
        with pytest.raises(ValueError, match="between 0 and 50"):
            service.create_package(
                "invalid-rate",
                package_type=regulated.FAIR_LENDING_AGGREGATE,
                asset_id=ASSET,
                content=invalid_fair,
                evidence_bindings=_bindings("EVD-primary", "EVD-secondary"),
                idempotency_key="invalid-rate",
                actor="user:preparer",
            )


def test_persisted_tampering_fails_closed_even_if_outer_state_digest_is_recomputed():
    service, *_, store = _service("tamper")
    with tenant_scope(tenant="acme"):
        _create(service, regulated.CREDIT_ADVERSE_ACTION)
        raw = store.list(limit=1)[0]

        def tamper(row):
            row["versions"][0]["content"]["model_receipt_sha256"] = _hex("tampered")
            row["state_sha256"] = regulated._sha256(regulated._record_state(row))

        store.update(
            raw["id"],
            tamper,
            expected_revision=raw["revision"],
            action="test_tamper",
            actor="user:attacker",
        )
        with pytest.raises(regulated.AIRegulatedVerticalsStateError, match="malformed"):
            service.get_package("package-credit_adverse_action")
