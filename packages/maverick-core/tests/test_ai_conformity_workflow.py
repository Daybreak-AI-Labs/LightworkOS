"""Focused contracts for the governed EU AI Act readiness workflow."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest
from maverick import ai_conformity_workflow as workflow
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

ASSET = "MAA-0123456789abcdef0123456789abcdef"
NOW = 1_800_000_000.0


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


class AssetRegistry:
    def __init__(self) -> None:
        self.revision = 7
        self.digest = _hex("model-risk-v7")

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
        self.digest = _hex(f"model-risk-v{self.revision}")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = true\n"
        "\n[ai_conformity_workflow]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _stores(label: str):
    return (
        GovernedRecordStore(
            f"test_eu_conformity_cases_{label}",
            "EUC",
            "test_eu_conformity_case",
        ),
        GovernedRecordStore(
            f"test_eu_conformity_evidence_{label}",
            "EUE",
            "test_eu_conformity_evidence",
        ),
    )


def _service(label: str = "main"):
    cases, evidence = _stores(label)
    registry = AssetRegistry()
    service = workflow.EUAIConformityWorkflow(
        cases=cases,
        evidence=evidence,
        asset_lookup=registry,
        clock=lambda: NOW,
    )
    return service, registry, cases, evidence


def _actor(label: str = "author") -> workflow.HumanActor:
    return workflow.HumanActor(f"user:{label}")


def _citation(provision: str = "Article 6 and Annex III") -> workflow.LegalCitation:
    return workflow.LegalCitation(provision, workflow.CONSOLIDATED_REGULATION_URL)


def _create(service: workflow.EUAIConformityWorkflow, operation: str = "case-001"):
    return service.create_case(
        asset_id=ASSET,
        economic_operator_role="provider",
        risk_tier="high_risk",
        act_applicability="applicable",
        legal_basis=(_citation(),),
        operation_id=operation,
        actor=_actor(),
    )


def _bind_domain(
    service: workflow.EUAIConformityWorkflow,
    case_id: str,
    domain: str,
    suffix: str = "primary",
):
    return service.bind_evidence(
        case_id,
        evidence=workflow.EvidenceReference(
            evidence_type=domain,
            source_ref=f"{domain}:{suffix}",
            sha256=_hex(f"{domain}:{suffix}:bytes"),
        ),
        operation_id=f"bind:{domain}:{suffix}",
        actor=_actor(),
    )


def _set_complete_sections(
    service: workflow.EUAIConformityWorkflow,
    projection: dict,
    *,
    domain: str,
    sections: tuple[str, ...],
    binding_id: str,
) -> dict:
    current = projection
    for index, section in enumerate(sections):
        current = service.set_checklist_entry(
            current["case_id"],
            domain=domain,
            section=section,
            entry=workflow.ChecklistEntry(
                status="complete",
                evidence_binding_ids=(binding_id,),
            ),
            expected_revision=current["revision"],
            operation_id=f"complete:{domain}:{index}:{section}",
            actor=_actor(),
        )
    return current


def _complete(service: workflow.EUAIConformityWorkflow, projection: dict) -> tuple[dict, dict]:
    current = service.set_fria_determination(
        projection["case_id"],
        outcome="required",
        rationale_sha256=_hex("fria-applicability-rationale"),
        citations=(_citation("Article 27(1)"),),
        expected_revision=projection["revision"],
        operation_id="fria-determination",
        actor=_actor(),
    )
    current = service.set_article_43_route(
        projection["case_id"],
        route="internal_control_annex_vi",
        rationale_sha256=_hex("article-43-route-rationale"),
        citations=(_citation("Article 43 and Annex VI"),),
        expected_revision=current["revision"],
        operation_id="article-43-route",
        actor=_actor(),
    )
    bindings = {
        domain: _bind_domain(service, projection["case_id"], domain)
        for domain in workflow.CHECKLIST_SECTIONS
    }
    current = _set_complete_sections(
        service,
        current,
        domain="fria",
        sections=workflow.FRIA_SECTIONS,
        binding_id=bindings["fria"]["binding_id"],
    )
    current = _set_complete_sections(
        service,
        current,
        domain="annex_iv",
        sections=workflow.ANNEX_IV_SECTIONS,
        binding_id=bindings["annex_iv"]["binding_id"],
    )
    current = _set_complete_sections(
        service,
        current,
        domain="article_43",
        sections=workflow.ARTICLE_43_ROUTE_REQUIREMENTS["internal_control_annex_vi"],
        binding_id=bindings["article_43"]["binding_id"],
    )
    current = _set_complete_sections(
        service,
        current,
        domain="post_market",
        sections=workflow.POST_MARKET_SECTIONS,
        binding_id=bindings["post_market"]["binding_id"],
    )
    current = _set_complete_sections(
        service,
        current,
        domain="declaration_draft",
        sections=workflow.DECLARATION_DRAFT_SECTIONS,
        binding_id=bindings["declaration_draft"]["binding_id"],
    )
    current = _set_complete_sections(
        service,
        current,
        domain="ce_marking",
        sections=workflow.CE_MARKING_SECTIONS,
        binding_id=bindings["ce_marking"]["binding_id"],
    )
    return current, bindings


def test_default_off_gate_configured_service_and_explicit_tenant(_isolate):
    from maverick import config

    assert workflow.enabled() is True
    assert isinstance(
        workflow.configured_ai_conformity_workflow(),
        workflow.EUAIConformityWorkflow,
    )
    service, *_ = _service("feature")
    with pytest.raises(workflow.AIConformityWorkflowStateError, match="tenant"):
        _create(service)

    (_isolate / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert workflow.enabled() is False
    with tenant_scope(tenant="alpha"):
        with pytest.raises(workflow.AIConformityWorkflowConfigError, match="disabled"):
            _create(service, "disabled-case")
        with pytest.raises(workflow.AIConformityWorkflowConfigError, match="disabled"):
            workflow.configured_service()


def test_case_is_idempotent_exact_asset_bound_and_tenant_isolated():
    service, registry, _, _ = _service("case")
    with tenant_scope(tenant="alpha"):
        created = _create(service)
        replay = _create(service)
        assert replay == created
        assert created["asset_binding"] == {
            "asset_id": ASSET,
            "asset_revision": registry.revision,
            "asset_version_digest": registry.digest,
        }
        assert created["human_declaration"]["classification_source"] == (
            "human_declaration_unverified"
        )
        assert created["human_declaration"]["legal_basis"] == [{
            "provision": "Article 6 and Annex III",
            "official_url": workflow.CONSOLIDATED_REGULATION_URL,
        }]
        with pytest.raises(
            workflow.AIConformityWorkflowIdempotencyConflict,
            match="different declarations",
        ):
            service.create_case(
                asset_id=ASSET,
                economic_operator_role="deployer",
                risk_tier="high_risk",
                act_applicability="applicable",
                legal_basis=(_citation(),),
                operation_id="case-001",
                actor=_actor(),
            )
        with pytest.raises(ValueError, match="non-PII"):
            service.create_case(
                asset_id=ASSET,
                economic_operator_role="provider",
                risk_tier="high_risk",
                act_applicability="applicable",
                legal_basis=(_citation(),),
                operation_id="bad-actor",
                actor=workflow.HumanActor("user:person@example.test"),
            )

    with tenant_scope(tenant="beta"):
        assert service.get_case(created["case_id"]) is None


def test_case_evidence_is_listed_for_its_own_case_and_workspace_only():
    service, _, _, _ = _service("listing")
    with tenant_scope(tenant="alpha"):
        first = _create(service)
        fria = _bind_domain(service, first["case_id"], "fria")
        annex = _bind_domain(service, first["case_id"], "annex_iv")
        listed = service.list_case_evidence(first["case_id"])
        assert [row["binding_id"] for row in listed] == sorted(
            [fria["binding_id"], annex["binding_id"]]
        )
        assert {row["evidence_type"] for row in listed} == {"fria", "annex_iv"}
    with tenant_scope(tenant="beta"), pytest.raises(workflow.AIConformityWorkflowStateError):
        service.list_case_evidence(first["case_id"])


def test_missing_sections_block_submission_and_evidence_digests_are_exact():
    service, registry, _, _ = _service("missing")
    with tenant_scope(tenant="alpha"):
        created = _create(service)
        assert created["strict_manifest"]["complete"] is False
        assert "annex_iv.1_general_system_description" in created["strict_manifest"][
            "gaps"
        ]
        with pytest.raises(workflow.AIConformityWorkflowIncomplete, match="Annex|annex"):
            service.submit_case(
                created["case_id"],
                expected_revision=created["revision"],
                operation_id="premature-submit",
                actor=_actor(),
            )

        evidence = _bind_domain(service, created["case_id"], "annex_iv")
        assert evidence["evidence_sha256"] == _hex("annex_iv:primary:bytes")
        assert evidence["asset_binding"] == created["asset_binding"]
        updated = service.set_annex_iv_section(
            created["case_id"],
            section=workflow.ANNEX_IV_SECTIONS[0],
            entry=workflow.ChecklistEntry(
                "complete",
                evidence_binding_ids=(evidence["binding_id"],),
            ),
            expected_revision=created["revision"],
            operation_id="one-annex-section",
            actor=_actor(),
        )
        pointer = updated["annex_iv"]["items"][workflow.ANNEX_IV_SECTIONS[0]][
            "evidence_bindings"
        ][0]
        assert pointer == {
            "binding_id": evidence["binding_id"],
            "evidence_sha256": evidence["evidence_sha256"],
            "binding_sha256": evidence["binding_sha256"],
        }
        assert updated["asset_binding"]["asset_version_digest"] == registry.digest

        with pytest.raises(ValueError, match="SHA-256"):
            service.bind_evidence(
                created["case_id"],
                evidence=workflow.EvidenceReference("annex_iv", "bad-digest", "raw"),
                operation_id="bad-digest",
                actor=_actor(),
            )
        with pytest.raises(ValueError, match="opaque non-PII"):
            service.bind_evidence(
                created["case_id"],
                evidence=workflow.EvidenceReference(
                    "annex_iv",
                    "C:/raw source documents/person name.pdf",
                    _hex("bytes"),
                ),
                operation_id="raw-path",
                actor=_actor(),
            )


def test_cas_operation_idempotency_and_capacity_bounds(monkeypatch):
    service, _, _, _ = _service("bounds")
    with tenant_scope(tenant="alpha"):
        created = _create(service)
        determined = service.set_fria_determination(
            created["case_id"],
            outcome="not_required",
            rationale_sha256=_hex("fria-not-required"),
            citations=(_citation("Article 27(1)"),),
            expected_revision=created["revision"],
            operation_id="determine-fria",
            actor=_actor(),
        )
        replay = service.set_fria_determination(
            created["case_id"],
            outcome="not_required",
            rationale_sha256=_hex("fria-not-required"),
            citations=(_citation("Article 27(1)"),),
            expected_revision=created["revision"],
            operation_id="determine-fria",
            actor=_actor(),
        )
        assert replay["revision"] == determined["revision"]
        with pytest.raises(workflow.AIConformityWorkflowIdempotencyConflict):
            service.set_fria_determination(
                created["case_id"],
                outcome="required",
                rationale_sha256=_hex("fria-required"),
                citations=(_citation("Article 27(1)"),),
                expected_revision=created["revision"],
                operation_id="determine-fria",
                actor=_actor(),
            )
        with pytest.raises(RecordConflict):
            service.set_article_43_route(
                created["case_id"],
                route="internal_control_annex_vi",
                rationale_sha256=_hex("route"),
                citations=(_citation("Article 43"),),
                expected_revision=created["revision"],
                operation_id="stale-route-cas",
                actor=_actor(),
            )
        with pytest.raises(ValueError, match="limit"):
            service.list_cases(limit=0)

        monkeypatch.setattr(workflow, "_MAX_EVIDENCE_PER_CASE", 1)
        first = _bind_domain(service, created["case_id"], "annex_iv", "capacity-1")
        assert first["binding_id"].startswith("EUE-")
        with pytest.raises(workflow.AIConformityWorkflowStateError, match="limit"):
            _bind_domain(service, created["case_id"], "annex_iv", "capacity-2")


def test_complete_package_four_eyes_staleness_and_non_certification_labels():
    service, registry, _, _ = _service("complete")
    with tenant_scope(tenant="alpha"):
        created = _create(service)
        complete, bindings = _complete(service, created)
        manifest = complete["strict_manifest"]
        assert manifest["complete"] is True
        assert manifest["gaps"] == []
        assert manifest["asset_binding"] == created["asset_binding"]
        assert manifest["evidence_binding_count"] == len(bindings)

        submitted = service.submit_case(
            created["case_id"],
            expected_revision=complete["revision"],
            operation_id="submit-complete",
            actor=_actor("submitter"),
        )
        assert submitted["current_submission"] is not None
        assert submitted["current_approval"] is None
        with pytest.raises(ValueError, match="distinct human"):
            service.approve_case(
                created["case_id"],
                expected_revision=submitted["revision"],
                operation_id="self-approval",
                actor=_actor("submitter"),
            )
        approved = service.approve_case(
            created["case_id"],
            expected_revision=submitted["revision"],
            operation_id="approve-complete",
            actor=_actor("approver"),
        )
        assert approved["current_approval"]["four_eyes_verified"] is True
        replay = service.approve_case(
            created["case_id"],
            expected_revision=submitted["revision"],
            operation_id="approve-complete",
            actor=_actor("approver"),
        )
        assert replay["revision"] == approved["revision"]

        package = service.export_package(created["case_id"])
        assert package["strict_manifest"]["manifest_sha256"] == manifest[
            "manifest_sha256"
        ]
        assert package["declaration_artifact"] == {
            "label": workflow.DRAFT_DECLARATION_LABEL,
            "signed": False,
            "final_declaration_generated": False,
        }
        assert package["ce_marking_artifact"]["mark_created"] is False
        assert package["ce_marking_artifact"]["mark_affixed"] is False
        assert set(package["legal_effects"].values()) == {False}
        assert package["package_sha256"] == _canonical_sha({
            key: value for key, value in package.items() if key != "package_sha256"
        })
        compact = json.dumps(package, sort_keys=True, separators=(",", ":")).lower()
        for forbidden in (
            '"certification":true',
            '"conformity_determination":true',
            '"ce_marking":true',
            '"regulator_acceptance":true',
            '"notified_body_acceptance":true',
            '"final_signed_declaration":true',
        ):
            assert forbidden not in compact
        assert "not an eu declaration of conformity" in compact
        assert "no ce mark is created or authorised" in compact

        old_revision = registry.revision
        old_digest = registry.digest
        registry.change()
        stale_asset = service.get_case(created["case_id"])
        assert stale_asset is not None and stale_asset["stale"] is True
        assert stale_asset["current_approval"] is None
        assert "model_risk_asset_revision_or_version_changed" in stale_asset[
            "stale_reasons"
        ]
        with pytest.raises(workflow.AIConformityWorkflowIncomplete):
            service.export_package(created["case_id"])

        registry.revision = old_revision
        registry.digest = old_digest
        current_again = service.get_case(created["case_id"])
        assert current_again is not None and current_again["current_approval"] is not None
        replacement = _bind_domain(
            service,
            created["case_id"],
            "annex_iv",
            "replacement",
        )
        changed = service.set_annex_iv_section(
            created["case_id"],
            section=workflow.ANNEX_IV_SECTIONS[0],
            entry=workflow.ChecklistEntry(
                "complete",
                evidence_binding_ids=(replacement["binding_id"],),
            ),
            expected_revision=current_again["revision"],
            operation_id="replace-annex-evidence",
            actor=_actor(),
        )
        assert changed["stale"] is True
        assert changed["current_submission"] is None
        assert "submitted_manifest_or_case_content_changed" in changed["stale_reasons"]
        with pytest.raises(workflow.AIConformityWorkflowIncomplete):
            service.export_package(created["case_id"])


def test_corrupt_case_and_evidence_binding_fail_closed(monkeypatch):
    service, _, cases, evidence_store = _service("tamper")
    with tenant_scope(tenant="alpha"):
        created = _create(service)
        evidence = _bind_domain(service, created["case_id"], "annex_iv")
        updated = service.set_annex_iv_section(
            created["case_id"],
            section=workflow.ANNEX_IV_SECTIONS[0],
            entry=workflow.ChecklistEntry(
                "complete",
                evidence_binding_ids=(evidence["binding_id"],),
            ),
            expected_revision=created["revision"],
            operation_id="tamper-target",
            actor=_actor(),
        )
        raw_case = cases.get(created["case_id"])
        assert raw_case is not None
        corrupted_case = copy.deepcopy(raw_case)
        corrupted_case["declaration"]["risk_tier"] = "minimal"
        original_case_get = cases.get
        monkeypatch.setattr(
            cases,
            "get",
            lambda identity: (
                copy.deepcopy(corrupted_case)
                if identity == created["case_id"]
                else original_case_get(identity)
            ),
        )
        with pytest.raises(workflow.AIConformityWorkflowStateError, match="malformed"):
            service.get_case(created["case_id"])

        monkeypatch.setattr(cases, "get", original_case_get)
        raw_evidence = evidence_store.get(evidence["binding_id"])
        assert raw_evidence is not None
        corrupted_evidence = copy.deepcopy(raw_evidence)
        corrupted_evidence["evidence_sha256"] = _hex("attacker-replacement")
        original_evidence_get = evidence_store.get
        monkeypatch.setattr(
            evidence_store,
            "get",
            lambda identity: (
                copy.deepcopy(corrupted_evidence)
                if identity == evidence["binding_id"]
                else original_evidence_get(identity)
            ),
        )
        with pytest.raises(workflow.AIConformityWorkflowStateError, match="evidence"):
            service.get_case(updated["case_id"])
