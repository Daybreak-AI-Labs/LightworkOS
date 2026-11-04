"""The Security/GRC suite step and its config writer.

See :mod:`._seams` for how the prompt primitives stay patchable through the
``maverick_installer.wizard`` facade.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ._common import _append_nested_product_config, _safe_float, _toml_str
from ._seams import _q_checkbox, _q_confirm, _q_text, console


def _pick_evidence_local_parsers(enabled: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ai_evidence_ocr": False,
        "ai_evidence_ocr_executable": "",
        "ai_evidence_ocr_sha256": "",
        "ai_evidence_ocr_tesseract_version": "",
        "ai_evidence_ocr_traineddata_path": "",
        "ai_evidence_ocr_traineddata_sha256": "",
        "ai_evidence_ocr_runtime_library_paths": [],
        "ai_evidence_ocr_runtime_libraries_sha256": "",
        "ai_evidence_ocr_pillow_version": "",
        "ai_evidence_ocr_pillow_manifest_sha256": "",
        "ai_evidence_legacy_xls": False,
        "ai_evidence_xlrd_manifest_sha256": "",
        "ai_evidence_olefile_manifest_sha256": "",
        "ai_evidence_parser_sandbox": False,
        "ai_evidence_parser_sandbox_launcher": "",
        "ai_evidence_parser_sandbox_sha256": "",
        "ai_evidence_parser_sandbox_version": "",
    }
    if not enabled:
        return result
    ocr_enabled = _q_confirm(
        "Configure the governed offline JPEG/PNG OCR runtime now? It remains "
        "disabled unless an absolute Tesseract path, exact reviewed binary "
        "SHA-256, exact Tesseract version, and exact Pillow version are supplied.",
        default=False,
    )
    if ocr_enabled:
        result["ai_evidence_ocr_executable"] = _q_text(
            "  Absolute Tesseract executable path", default=""
        ).strip()
        result["ai_evidence_ocr_sha256"] = _q_text(
            "  Reviewed Tesseract executable SHA-256 (64 lowercase hex)",
            default="",
        ).strip().lower()
        result["ai_evidence_ocr_tesseract_version"] = _q_text(
            "  Exact `tesseract --version` version token", default=""
        ).strip()
        result["ai_evidence_ocr_traineddata_path"] = _q_text(
            "  Absolute eng.traineddata path", default=""
        ).strip()
        result["ai_evidence_ocr_traineddata_sha256"] = _q_text(
            "  Reviewed eng.traineddata SHA-256 (64 lowercase hex)", default=""
        ).strip().lower()
        raw_runtime_paths = _q_text(
            "  Absolute Tesseract runtime library paths (comma-separated)", default=""
        )
        result["ai_evidence_ocr_runtime_library_paths"] = [
            value.strip() for value in raw_runtime_paths.split(",") if value.strip()
        ]
        result["ai_evidence_ocr_runtime_libraries_sha256"] = _q_text(
            "  Reviewed runtime-library manifest SHA-256", default=""
        ).strip().lower()
        result["ai_evidence_ocr_pillow_version"] = _q_text(
            "  Exact installed Pillow distribution version", default="13.0.0"
        ).strip()
        result["ai_evidence_ocr_pillow_manifest_sha256"] = _q_text(
            "  Reviewed Pillow package-file manifest SHA-256", default=""
        ).strip().lower()
        digests = (
            result["ai_evidence_ocr_sha256"],
            result["ai_evidence_ocr_traineddata_sha256"],
            result["ai_evidence_ocr_runtime_libraries_sha256"],
            result["ai_evidence_ocr_pillow_manifest_sha256"],
        )
        digests_valid = all(
            len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest)
            for digest in digests
        )
        versions_valid = all(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", value)
            for value in (
                result["ai_evidence_ocr_tesseract_version"],
                result["ai_evidence_ocr_pillow_version"],
            )
        )
        absolute_paths = [
            result["ai_evidence_ocr_executable"],
            result["ai_evidence_ocr_traineddata_path"],
            *result["ai_evidence_ocr_runtime_library_paths"],
        ]
        ocr_enabled = bool(
            absolute_paths
            and all(Path(path).is_absolute() for path in absolute_paths)
            and digests_valid
            and versions_valid
        )
        if not ocr_enabled:
            console.print(
                "[yellow]Governed OCR remains disabled until every exact "
                "runtime attestation is supplied.[/yellow]"
            )
    result["ai_evidence_ocr"] = ocr_enabled
    xls_enabled = _q_confirm(
        "Enable the isolated, offline legacy BIFF8 XLS subset parser? It requires "
        "the evidence-analysis extra with exact xlrd 2.0.2 and olefile 0.47, and "
        "rejects formulas, macros, external references, and unknown records.",
        default=False,
    )
    if xls_enabled:
        result["ai_evidence_xlrd_manifest_sha256"] = _q_text(
            "  Reviewed xlrd package-file manifest SHA-256", default=""
        ).strip().lower()
        result["ai_evidence_olefile_manifest_sha256"] = _q_text(
            "  Reviewed olefile package-file manifest SHA-256", default=""
        ).strip().lower()
        xls_enabled = all(
            len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest)
            for digest in (
                result["ai_evidence_xlrd_manifest_sha256"],
                result["ai_evidence_olefile_manifest_sha256"],
            )
        )
    result["ai_evidence_legacy_xls"] = xls_enabled
    if ocr_enabled or xls_enabled:
        if os.name != "posix":
            console.print(
                "[yellow]Governed OCR/XLS remains disabled on this platform: "
                "the stock runtime requires a POSIX Bubblewrap network namespace.[/yellow]"
            )
            result["ai_evidence_ocr"] = False
            result["ai_evidence_legacy_xls"] = False
            return result
        result["ai_evidence_parser_sandbox_launcher"] = _q_text(
            "  Absolute Bubblewrap launcher path", default="/usr/bin/bwrap"
        ).strip()
        result["ai_evidence_parser_sandbox_sha256"] = _q_text(
            "  Reviewed Bubblewrap launcher SHA-256", default=""
        ).strip().lower()
        result["ai_evidence_parser_sandbox_version"] = _q_text(
            "  Exact `bwrap --version` version token", default=""
        ).strip()
        sandbox_digest = result["ai_evidence_parser_sandbox_sha256"]
        result["ai_evidence_parser_sandbox"] = bool(
            Path(result["ai_evidence_parser_sandbox_launcher"]).is_absolute()
            and len(sandbox_digest) == 64
            and all(character in "0123456789abcdef" for character in sandbox_digest)
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}",
                result["ai_evidence_parser_sandbox_version"],
            )
        )
        if not result["ai_evidence_parser_sandbox"]:
            result["ai_evidence_ocr"] = False
            result["ai_evidence_legacy_xls"] = False
            console.print(
                "[yellow]Governed OCR/XLS remains disabled until the exact "
                "Bubblewrap sandbox attestation is supplied.[/yellow]"
            )
    return result


def _vendor_setup_guidance(enabled: bool) -> None:
    """Defer new ownership to the app's current-workspace membership checks."""
    if enabled:
        console.print(
            "[dim]Finish vendor setup in the app: select a workspace, choose an "
            "active workspace member to own vendor reviews, and select your "
            "named Jira connection. Google Drive is optional when using reviewed "
            "uploads. Enabling this workflow does not assign ownership or verify "
            "provider access.[/dim]"
        )


def pick_security_suite() -> dict[str, Any]:
    """Configure the Security/GRC suite and both defensive hunters.

    The record-only GRC workspace follows Privacy's default-on posture.  The
    hunters are explicit opt-ins because they consume operational telemetry.
    Environment response execution is a second, independent opt-in and still
    requires a human-approved playbook at runtime.
    """
    console.print()
    console.print(
        "[dim]Security & GRC maintains control, evidence, risk, POA&M, policy, "
        "vendor, incident, and audit records locally. The platform hunter "
        "defensively scans Lightwork's signed telemetry; the environment "
        "hunter reads configured customer telemetry. Hunters are OFF until "
        "enabled. Approved response execution is a separate opt-in.[/dim]"
    )
    customer_sandbox_lifecycle = _q_confirm(
        "Enable the global-admin managed customer sandbox tenant-copy control "
        "plane? It copies only a closed safe configuration projection into a "
        "separate isolated local sandbox workspace; production data and credentials are "
        "never copied.",
        default=False,
    )
    security_ops = _q_confirm(
        "Enable Security & GRC records and readiness workspace?", default=True
    )
    evidence_graph = _q_confirm(
        "Enable the review-gated evidence graph? It stores bounded evidence "
        "metadata and hashes, never raw telemetry.",
        default=False,
    )
    model_risk_assurance = _q_confirm(
        "Enable the Model Risk & AI Assurance Officer? Legal applicability, "
        "risk acceptance, and deployment decisions remain human-owned.",
        default=False,
    )
    if model_risk_assurance:
        evidence_graph = True
    evidence_gateway = _q_confirm(
        "Enable the AI Evidence-Ready Gateway? It stores signed hash-only "
        "interaction receipts and cited regulatory-impact records, never raw "
        "prompts or generated text.",
        default=False,
    )
    if evidence_gateway:
        evidence_graph = True
        model_risk_assurance = True
    model_improvement = _q_confirm(
        "Enable governed specialist-model improvement plumbing? Training and "
        "weight promotion remain separately approval-gated.",
        default=False,
    )
    allow_hosted_training = False
    if model_improvement:
        evidence_graph = True
        model_risk_assurance = True
        allow_hosted_training = _q_confirm(
            "Allow hosted training only for cases with an exact hosted-training "
            "consent scope? Cross-tenant training remains refused.",
            default=False,
        )
    ai_inventory = _q_confirm(
        "Enable read-only discovery of customer-owned AI assets across cloud AI, "
        "model registries, data platforms, agent builders, and model hubs such as "
        "Bedrock, SageMaker, Azure AI Foundry, Vertex AI, Databricks, Copilot "
        "Studio, MLflow, Hugging Face, OpenAI, Replicate, Snowflake, or "
        "Salesforce Agentforce? "
        "Credentials are configured separately and are never stored in the "
        "inventory ledger.",
        default=False,
    )
    ai_entity_tasks = _q_confirm(
        "Enable governed task management for AI inventory entities? Tasks are "
        "tenant-bound, revision-pinned, approval-audited, and require the AI "
        "inventory authority.",
        default=False,
    )
    ai_inventory = ai_inventory or ai_entity_tasks
    inventory_connectors: list[str] = []
    if ai_inventory:
        evidence_graph = True
        model_risk_assurance = True
        connector_labels = {
            "AWS Bedrock": "bedrock",
            "AWS SageMaker (stock contract)": "aws_sagemaker",
            "Amazon SageMaker account registry": "sagemaker",
            "Azure AI Foundry": "azure_ai_foundry",
            "Google Vertex AI": "vertex_ai",
            "Databricks Unity Catalog": "databricks_unity_catalog",
            "Microsoft Copilot Studio": "copilot_studio",
            "MLflow Model Registry": "mlflow",
            "Snowflake Cortex": "snowflake_cortex",
            "Snowflake Model Registry": "snowflake",
            "Salesforce Agentforce (stock contract)": "salesforce_agentforce",
            "Salesforce Agentforce account": "agentforce",
            "Hugging Face Hub (stock contract)": "hugging_face",
            "Hugging Face Hub organization": "huggingface",
            "OpenAI platform (org models + fine-tunes)": "openai",
            "Replicate (account deployments)": "replicate",
        }
        selected = _q_checkbox(
            "Prepare which read-only AI inventory connectors?",
            list(connector_labels),
            default=[],
        )
        inventory_connectors = [
            connector_labels[label] for label in selected if label in connector_labels
        ]
    ai_vendor_risk = _q_confirm(
        "Enable governed AI-specific vendor assessments with cited document "
        "drafting and independent review before model-risk projection?",
        default=False,
    )
    ai_vendor_risk_portal = False
    if ai_vendor_risk:
        evidence_graph = True
        model_risk_assurance = True
        ai_vendor_risk_portal = _q_confirm(
            "Enable the external AI-vendor questionnaire portal? Invitation "
            "tokens and vendor submissions remain bounded, tenant-scoped, and "
            "separately governed.",
            default=False,
        )
    portfolio_risk = _q_confirm(
        "Enable transparent AI portfolio-risk rollups and immutable quarterly "
        "snapshots? Scores remain decision support, not compliance verdicts.",
        default=False,
    )
    policy_packs = _q_confirm(
        "Enable signed, versioned AI policy packs with human activation and "
        "evidence-staleness tracking? Packs do not certify compliance.",
        default=False,
    )
    grc_studio = _q_confirm(
        "Enable the tenant-private no-code GRC configuration studio for closed "
        "objects, fields, forms, rules, collector bindings and reports? "
        "Publishing requires independent review and approval; runtime writes "
        "remain deployment-owned.",
        default=False,
    )
    policy_publication_links = _q_confirm(
        "Enable Tech Risk & Compliance evergreen public/private policy links? "
        "Publication remains review-gated; private capabilities, expiry, "
        "revocation, and scheduled changes fail closed.",
        default=False,
    )
    compliance_scoping = _q_confirm(
        "Enable local Tech Risk & Compliance questionnaire scoping? Closed "
        "rules use opaque references and independent review; no licensed "
        "framework text, legal advice, discovery, or certification is included.",
        default=False,
    )
    compliance_scope_actions = compliance_scoping and _q_confirm(
        "Enable deterministic control and evidence-task plans from independently "
        "finalized compliance scopes? Plans use reviewed opaque mapping catalogs, "
        "four-eyes approval, and a separately injected local apply callback; no "
        "licensed framework text or provider write is included.",
        default=False,
    )
    continuous_evidence = _q_confirm(
        "Enable Tech Risk & Compliance continuous evidence collection? The "
        "built-in local collector and seven read-only stock provider adapters are "
        "digest-only; external estates still require exact approved definitions, "
        "enrollments, credentials, and acceptance.",
        default=False,
    )
    stock_collector_labels = {
        "AWS Security Hub": "aws_security_hub_v1",
        "AWS Config posture": "aws_config_posture_v1",
        "Azure Defender": "azure_defender_v1",
        "Azure Policy posture": "azure_policy_posture_v1",
        "Google Cloud Security Command Center": "gcp_security_command_center_v1",
        "GitHub security streams": "github_security_v1",
        "Okta policy posture": "okta_posture_v1",
    }
    selected_stock_collector_labels = (
        _q_checkbox(
            "Prepare which read-only Tech Risk stock evidence adapters? Exact "
            "tenant source manifests are added separately after independent approval.",
            list(stock_collector_labels),
            default=[],
        )
        if continuous_evidence
        else []
    )
    stock_collector_ids = [
        stock_collector_labels[label]
        for label in selected_stock_collector_labels
        if label in stock_collector_labels
    ]
    continuous_evidence_scheduler = continuous_evidence and _q_confirm(
        "Enable the continuous-evidence scheduler with leased retries, recovery, "
        "and bounded tenant processing?",
        default=False,
    )
    ai_evidence_analysis = _q_confirm(
        "Enable bounded multimodal AI Evidence Analysis for PDF, JPEG/PNG, "
        "Excel, and text evidence? Results remain evidence-pinned drafts with "
        "transparent scoring and mandatory human review, never compliance or "
        "legal conclusions.",
        default=False,
    )
    if ai_evidence_analysis:
        evidence_gateway = True
    evidence_local_parsers = _pick_evidence_local_parsers(ai_evidence_analysis)
    assessment_evidence_autopopulation = ai_evidence_analysis and _q_confirm(
        "Enable evidence-assisted assessment answer proposals from released AI "
        "Evidence Analysis results? Proposals remain cited drafts and require a "
        "different human reviewer.",
        default=False,
    )
    assessment_evidence_apply = assessment_evidence_autopopulation and _q_confirm(
        "Allow a separately approved proposal to fill only unanswered assessment "
        "questions under revision-CAS? Existing answers are never overwritten and "
        "final assessment review remains required.",
        default=False,
    )
    third_party_intelligence = _q_confirm(
        "Enable the provider-neutral Third-Party Management intelligence, "
        "screening, continuous-monitoring, EDD, exchange, and bounded "
        "low-risk workflow plane? Commercial feeds remain inert until "
        "separately licensed and enrolled.",
        default=False,
    )
    third_party_intelligence_providers = third_party_intelligence and _q_confirm(
        "Enable the bounded third-party intelligence provider runtime for "
        "RiskRecon, SecurityScorecard, HackNotice, SupplyWisdom, and ISS Corporate "
        "Solutions? Licensed credentials and live provider acceptance remain "
        "separate deployment requirements.",
        default=False,
    )
    third_party_supplywisdom = third_party_intelligence_providers and _q_confirm(
        "Enable the SupplyWisdom normalized reference contract? This requires the "
        "exact licensed HTTPS gateway hostname for this deployment.",
        default=False,
    )
    third_party_supplywisdom_host = (
        _q_text(
            "  Exact SupplyWisdom gateway hostname (no scheme, port, path, or query)",
            default="",
        )
        .strip()
        .lower()
        if third_party_supplywisdom
        else ""
    )
    third_party_iss_corporate_solutions = (
        third_party_intelligence_providers
        and _q_confirm(
            "Enable the ISS Corporate Solutions normalized reference contract? This "
            "requires the exact licensed HTTPS gateway hostname for this deployment.",
            default=False,
        )
    )
    third_party_iss_corporate_solutions_host = (
        _q_text(
            "  Exact ISS Corporate Solutions gateway hostname "
            "(no scheme, port, path, or query)",
            default="",
        )
        .strip()
        .lower()
        if third_party_iss_corporate_solutions
        else ""
    )
    third_party_intelligence_scheduler = third_party_intelligence_providers and _q_confirm(
        "Enable scheduled third-party provider collection with retries, "
        "revocation handling, and tenant-bounded processing?",
        default=False,
    )
    third_party_lifecycle = _q_confirm(
        "Enable provider-neutral conditional third-party assessments, lifecycle "
        "transitions, and governed offboarding? Callbacks remain local intent; "
        "no transport worker or provider write is included.",
        default=False,
    )
    third_party_contracts = _q_confirm(
        "Enable first-class third-party Contract and Engagement records with "
        "revisioned schema metadata, redaction state, and governed tombstones? "
        "External contract systems and legal acceptance remain separate.",
        default=False,
    )
    third_party_executive_reports = _q_confirm(
        "Enable role-aware, brandable third-party executive PDF reports from "
        "exact revision-pinned local records? PDFs use closed branding and "
        "one-time downloads; live portfolio completeness remains separate.",
        default=False,
    )
    # The stock composition resolves exact vendor authority through the local
    # intelligence registry; commercial provider transports stay independent.
    third_party_intelligence = third_party_intelligence or third_party_contracts
    third_party_collaboration_portal = third_party_lifecycle and _q_confirm(
        "Enable the external third-party collaboration portal for invitation-"
        "bound assessments, attestations, evidence manifests, and follow-up? "
        "No email transport, raw document ingestion, or model-authored answer "
        "is enabled by this setting.",
        default=False,
    )
    governance_agents = _q_confirm(
        "Enable the packaged Breach Response, Privacy Risk Assessment, Program "
        "Copilot, Knowledgebase Governance, and Third-Party Risk agents? Agent "
        "outputs remain evidence-bound recommendations and all mutations require "
        "separate human approval.",
        default=False,
    )
    if governance_agents:
        evidence_gateway = True
    ai_regulatory_feed = _q_confirm(
        "Enable the governed AI regulatory-change bridge? It maps cited alerts "
        "to reviewed policy/evidence impacts and requires Finance Operations plus "
        "the AI evidence gateway.",
        default=False,
    )
    red_team_assurance = _q_confirm(
        "Enable governed red-team campaigns for enrolled external agents? "
        "Raw target output stays transient; only keyed commitments and bounded metrics "
        "enter review-pending evidence.",
        default=False,
    )
    eu_ai_incidents = _q_confirm(
        "Enable the human-routed EU AI Act Article 73 incident clock and report "
        "workflow? Lightwork records decisions and receipts but does not file or "
        "make legal determinations.",
        default=False,
    )
    grc_outbound_sync = _q_confirm(
        "Enable governed semantic writeback of findings, risk acceptances, and AI "
        "incidents to allowlisted ServiceNow IRM or Archer targets? Credentials "
        "remain separately configured.",
        default=False,
    )
    ai_literacy = _q_confirm(
        "Enable privacy-minimising AI-literacy requirements, completion receipts, "
        "reviewed waivers, and evidence exports?",
        default=False,
    )
    ai_business_intake = _q_confirm(
        "Enable the bounded AI business-intake workflow that creates or links an "
        "inventory asset and routes a proposed declaration and risk assessment "
        "for human review?",
        default=False,
    )
    ai_cost_roi = _q_confirm(
        "Enable governed multi-provider AI cost allocation and assumption-labelled "
        "ROI reporting? Provider billing collectors and credentials are configured "
        "separately.",
        default=False,
    )
    ai_dynamic_risk = _q_confirm(
        "Enable explainable dynamic AI risk scoring from normalized telemetry, "
        "policy, privacy, security, and evidence signals? Scores remain human-"
        "reviewed decision support and never certify compliance.",
        default=False,
    )
    ai_policy_management = _q_confirm(
        "Enable governed operational AI policies with human activation, exact "
        "applicability, strictest-wins decisions, four-eyes expiring exceptions, "
        "and revalidation-aware attestations?",
        default=False,
    )
    ai_runtime_guardrails = _q_confirm(
        "Enable transient prompt, output, and action guardrails that compose "
        "Shield, secret/PII redaction, operational policy, and digest-only "
        "runtime receipts? Raw runtime content is never persisted by this plane.",
        default=False,
    )
    ai_governance_loop = (
        ai_inventory
        and ai_dynamic_risk
        and ai_policy_management
        and ai_runtime_guardrails
        and _q_confirm(
            "Enable the durable AI governance closed loop that correlates "
            "inventory, risk, policy, control, monitoring, escalation, and "
            "evidence? It remains digest-only and performs no provider mutation.",
            default=False,
        )
    )
    ai_explainability = _q_confirm(
        "Enable governed, digest-only native/SHAP/LIME/Captum/Alibi and "
        "counterfactual explanation receipts with exact model binding and "
        "independent human review? Raw feature values are never admitted.",
        default=False,
    )
    ai_conformity_workflow = _q_confirm(
        "Enable the EU AI Act conformity-readiness workflow for FRIA, Annex IV, "
        "Article 43, post-market, draft declaration, and CE-readiness evidence? "
        "It does not make legal determinations, certify, sign, or affix a CE mark.",
        default=False,
    )
    ai_insurability = _q_confirm(
        "Enable exact-evidence insurance-assurance profiles with measurements, "
        "limitations, verifier instructions, and four-eyes export? Profiles do "
        "not establish coverage, pricing impact, or insurer acceptance.",
        default=False,
    )
    ai_regulated_verticals = _q_confirm(
        "Enable aggregate credit, fair-lending, NYC Local Law 144, and NAIC "
        "decision-support evidence packages? Packages do not make individual "
        "decisions, legal conclusions, filings, audits, or certifications.",
        default=False,
    )
    ai_bank_mrm = _q_confirm(
        "Enable governed bank model-risk evidence packages with nine closed "
        "review sections and four-eyes package-integrity approval? This does not "
        "approve a model or establish regulatory acceptance.",
        default=False,
    )
    ai_benchmark_exchange = _q_confirm(
        "Enable voluntary, aggregate-only benchmark contribution packages and "
        "externally signed cohort-report admission? This does not pool tenant "
        "records, prove anonymity, or independently verify differential privacy.",
        default=False,
    )
    ai_discovery_sensors = _q_confirm(
        "Enable the privacy-safe discovery-sensor control plane for approved, "
        "digest-bound normalized observations? This does not deploy sensors or "
        "establish complete AI discovery.",
        default=False,
    )
    ai_media_provenance = _q_confirm(
        "Enable governed digest-only C2PA adapter receipts and four-eyes media "
        "release review? A real verifier or signer remains separately required; "
        "Lightwork does not simulate cryptography or certify media.",
        default=False,
    )
    ai_media_provenance_c2patool = False
    ai_media_provenance_c2patool_sha256 = ""
    if ai_media_provenance:
        ai_media_provenance_c2patool = _q_confirm(
            "Select the separately installed c2patool verification adapter? "
            "This enables verification only; signing credentials and trust "
            "material are never generated by the installer.",
            default=False,
        )
        if ai_media_provenance_c2patool:
            candidate = (
                _q_text(
                    "  Independently approved c2patool executable SHA-256 "
                    "(64 lowercase hex; blank leaves the adapter unselected)",
                    default="",
                )
                .strip()
                .lower()
            )
            if len(candidate) == 64 and all(
                character in "0123456789abcdef" for character in candidate
            ):
                ai_media_provenance_c2patool_sha256 = candidate
            else:
                ai_media_provenance_c2patool = False
                console.print(
                    "[yellow]c2patool verification remains unselected until an "
                    "exact reviewed executable SHA-256 is supplied.[/yellow]"
                )
    ai_identity_governance_connectors = _q_confirm(
        "Enable bounded read-only Entra, Okta, and Purview identity/data-governance "
        "snapshots? Provider tenant IDs, secret references, and endpoints remain "
        "separately configured, and this does not claim complete discovery.",
        default=False,
    )
    ai_identity_governance_scheduler = False
    ai_identity_governance_controls = False
    ai_identity_change_coupling = False
    ai_identity_federation = False
    ai_identity_conditional_access = False
    ai_identity_purview_writeback = False
    ai_identity_production_composition = False
    if ai_identity_governance_connectors:
        ai_identity_governance_scheduler = _q_confirm(
            "Enable the bounded identity-governance scheduler supervisor? "
            "Every provider connector and provider schedule remains disabled "
            "until separately configured.",
            default=False,
        )
        ai_identity_governance_controls = _q_confirm(
            "Prepare the separately gated identity control plane? Every "
            "control remains independently disabled until selected, configured, "
            "and accepted against test tenants.",
            default=False,
        )
        if ai_identity_governance_controls:
            ai_identity_change_coupling = _q_confirm(
                "Enable digest-only identity-change coupling to dynamic risk and "
                "alerts? Sink wiring and replay acceptance remain required.",
                default=False,
            )
            ai_identity_federation = _q_confirm(
                "Enable pseudonymous Entra/Okta agent-principal federation? "
                "Provider trust and test-tenant acceptance remain required.",
                default=False,
            )
            if ai_identity_federation:
                ai_identity_conditional_access = _q_confirm(
                    "Enable fresh conditional-access enforcement for federated "
                    "agent principals? Provider policy acceptance remains required.",
                    default=False,
                )
                ai_identity_purview_writeback = _q_confirm(
                    "Enable default-deny Purview classification writeback for "
                    "federated agent principals? This is a mutating control and "
                    "requires separate test-tenant consent.",
                    default=False,
                )
            ai_identity_production_composition = _q_confirm(
                "Enable the lazy per-tenant identity-governance production "
                "composition? Provider transports and enrolled pseudonymous "
                "authorities remain separately required; local readiness does "
                "not claim live provider acceptance.",
                default=False,
            )
    if (
        portfolio_risk
        or policy_packs
        or red_team_assurance
        or ai_regulatory_feed
        or eu_ai_incidents
        or grc_outbound_sync
        or ai_literacy
        or ai_business_intake
        or ai_cost_roi
        or ai_dynamic_risk
        or ai_policy_management
        or ai_runtime_guardrails
        or ai_explainability
        or ai_conformity_workflow
        or ai_insurability
        or ai_regulated_verticals
        or ai_bank_mrm
        or ai_benchmark_exchange
        or ai_discovery_sensors
        or ai_media_provenance
    ):
        evidence_graph = True
        model_risk_assurance = True
    if ai_regulatory_feed:
        evidence_gateway = True
    threat_hunt = _q_confirm(
        "Enable the defensive Lightwork platform threat hunter?", default=False
    )
    env_hunt = _q_confirm("Enable the defensive customer-environment threat hunter?", default=False)
    response_execution = False
    connectors: dict[str, dict[str, bool]] = {}
    enrichment_sources: list[str] = []
    poll_seconds = 300
    if env_hunt:
        response_execution = _q_confirm(
            "Allow execution of human-approved response playbooks?",
            default=False,
        )
        connector_labels = {
            "AWS CloudTrail": "cloudtrail",
            "AWS GuardDuty": "guardduty",
            "Syslog": "syslog",
            "Endpoint detection and response (EDR)": "edr",
            "Splunk": "splunk",
            "Elastic": "elastic",
            "Microsoft Sentinel": "sentinel",
            "Kubernetes audit logs": "kubernetes_audit",
            "Okta": "okta",
            "Microsoft Entra ID": "entra",
        }
        console.print(
            "[dim]Choose the read-only telemetry connector types to prepare. "
            "Credentials and vendor-specific transports are configured after "
            "installation; selecting a type here does not grant access.[/dim]"
        )
        selected_labels = _q_checkbox(
            "Prepare which read-only environment connectors?",
            list(connector_labels),
            default=[],
        )
        push_labels = (
            _q_checkbox(
                "Allow API push ingestion for which selected connector types?",
                selected_labels,
                default=[],
            )
            if selected_labels
            else []
        )
        pivot_labels = (
            _q_checkbox(
                "Allow bounded read-only investigation pivots for which selected connectors?",
                selected_labels,
                default=[],
            )
            if selected_labels
            else []
        )
        connectors = {
            name: {
                "enable": label in selected_labels,
                "push_enable": label in push_labels,
                "pivot_enable": label in pivot_labels,
            }
            for label, name in connector_labels.items()
        }
        enrichment_sources = [
            value.strip().lower()
            for value in _q_text(
                "Allowlisted enrichment adapter names (comma-separated; optional)",
                default="",
            ).split(",")
            if value.strip()
        ]
        poll_seconds = max(
            30,
            min(
                3600,
                int(
                    _safe_float(
                        _q_text("Hunter poll interval (seconds)", default="300"),
                        default=300.0,
                    )
                ),
            ),
        )
    # Keep these additive administration prompts at the end of the established
    # security-suite questionnaire so scripted/resumed answers for existing
    # controls retain their historical ordering.
    administration_document_access = _q_confirm(
        "Enable governed short-lived document and attachment access tokens? "
        "Document authority, object storage, and delivery grants remain deployment-owned.",
        default=False,
    )
    governed_document_vault = administration_document_access and _q_confirm(
        "Enable the stock tenant-private encrypted document vault as the local "
        "document authority and one-time delivery backend? External object-store, "
        "backup, HSM/KMS, and live workflow acceptance remain separate.",
        default=False,
    )
    incident_attachment_metadata = administration_document_access and _q_confirm(
        "Enable governed metadata-only attachments on privacy and security incidents? "
        "No document bytes, filenames, paths, or object-store credentials are stored.",
        default=False,
    )
    vendor_onboarding = _q_confirm(
        "Enable AI vendor onboarding and evidence renewal with Google Drive "
        "evidence, named human review, and approved Jira Task creation?",
        default=False,
    )
    # Fresh setup cannot validate workspace membership here. The app chooses
    # initial ownership; explicit configured/resumed owners remain unchanged.
    vendor_onboarding_owner = ""
    _vendor_setup_guidance(vendor_onboarding)
    vendor_reviewed_uploads = (
        _q_confirm("  Allow reviewed local Word, Excel, PDF and text evidence uploads, including explicit PDF transcription?", default=True)
        if vendor_onboarding else False
    )
    result = {
        "vendor_onboarding": vendor_onboarding,
        "vendor_onboarding_owner": vendor_onboarding_owner,
        "vendor_reviewed_uploads": vendor_reviewed_uploads,
        "customer_sandbox_lifecycle": customer_sandbox_lifecycle,
        "security_ops": security_ops,
        "administration_document_access": administration_document_access,
        "governed_document_vault": governed_document_vault,
        "incident_attachment_metadata": incident_attachment_metadata,
        "evidence_graph": evidence_graph,
        "model_risk_assurance": model_risk_assurance,
        "evidence_gateway": evidence_gateway,
        "model_improvement": model_improvement,
        "allow_hosted_training": allow_hosted_training,
        "ai_inventory": ai_inventory,
        "ai_entity_tasks": ai_entity_tasks,
        "inventory_connectors": inventory_connectors,
        "ai_vendor_risk": ai_vendor_risk,
        "ai_vendor_risk_portal": ai_vendor_risk_portal,
        "portfolio_risk": portfolio_risk,
        "policy_packs": policy_packs,
        "governance_agents": governance_agents,
        "ai_evidence_analysis": ai_evidence_analysis,
        **evidence_local_parsers,
        "assessment_evidence_autopopulation": assessment_evidence_autopopulation,
        "assessment_evidence_apply": assessment_evidence_apply,
        "tech_risk_compliance": {
            "enable": (
                policy_publication_links
                or compliance_scoping
                or compliance_scope_actions
                or continuous_evidence
                or grc_studio
            ),
            "grc_studio": {
                "enable": grc_studio,
                "max_studios": 10_000,
                "retention_seconds": 31_536_000,
                "max_import_bytes": 2_097_152,
            },
            "policy_publication_links": {"enable": policy_publication_links},
            "scoping": {"enable": compliance_scoping},
            "scope_actions": {"enable": compliance_scope_actions},
            "continuous_evidence": {
                "enable": continuous_evidence,
                "enabled_collectors": (
                    ["local_soc2_v1", *stock_collector_ids]
                    if continuous_evidence
                    else []
                ),
                "stock_collectors": {
                    "enable": bool(stock_collector_ids),
                    "sources": [],
                },
                "scheduler": {
                    "enable": continuous_evidence_scheduler,
                    "poll_seconds": 60,
                    "enqueue_limit": 50,
                    "claim_limit": 10,
                    "tenant_limit": 1_000,
                    "lease_seconds": 120,
                    "retry_backoff_seconds": 30,
                },
            },
        },
        "third_party_management": {
            "enable": (
                third_party_intelligence
                or third_party_lifecycle
                or third_party_contracts
                or third_party_executive_reports
            ),
            "contracts": {
                "enable": third_party_contracts,
                "max_records": 100_000,
                "retention_seconds": 31_536_000,
                "authority_max_age_seconds": 604_800,
            },
            "executive_reports": {
                "enable": third_party_executive_reports,
                "max_reports": 10_000,
                "max_sources": 100,
                "max_pdf_bytes": 524_288,
                "retention_seconds": 31_536_000,
                "download_token_seconds": 300,
            },
            "intelligence": {
                "enable": third_party_intelligence,
                "providers": {
                    "enable": third_party_intelligence_providers,
                    "enabled_providers": (
                        [
                            "riskrecon",
                            "securityscorecard",
                            "hacknotice",
                            *(
                                ["supplywisdom"]
                                if third_party_supplywisdom
                                else []
                            ),
                            *(
                                ["iss_corporate_solutions"]
                                if third_party_iss_corporate_solutions
                                else []
                            ),
                        ]
                        if third_party_intelligence_providers
                        else []
                    ),
                    **(
                        {"supplywisdom_host": third_party_supplywisdom_host}
                        if third_party_supplywisdom
                        else {}
                    ),
                    **(
                        {
                            "iss_corporate_solutions_host": (
                                third_party_iss_corporate_solutions_host
                            )
                        }
                        if third_party_iss_corporate_solutions
                        else {}
                    ),
                    "timeout_seconds": 20,
                    "scheduler": {
                        "enable": third_party_intelligence_scheduler,
                        "poll_seconds": 900,
                    },
                },
            },
            "lifecycle": {
                "enable": third_party_lifecycle,
                "portal": {
                    "enable": third_party_collaboration_portal,
                    "invitation_ttl_seconds": 86_400,
                    "retention_seconds": 31_536_000,
                    "max_messages": 100,
                    "max_artifacts": 20,
                    "max_artifact_bytes": 10_485_760,
                },
            },
        },
        "ai_regulatory_feed": ai_regulatory_feed,
        "red_team_assurance": red_team_assurance,
        "eu_ai_incidents": eu_ai_incidents,
        "grc_outbound_sync": grc_outbound_sync,
        "ai_literacy": ai_literacy,
        "ai_business_intake": ai_business_intake,
        "ai_cost_roi": ai_cost_roi,
        "ai_dynamic_risk": ai_dynamic_risk,
        "ai_policy_management": ai_policy_management,
        "ai_runtime_guardrails": ai_runtime_guardrails,
        "ai_governance_loop": ai_governance_loop,
        "ai_explainability": ai_explainability,
        "ai_conformity_workflow": ai_conformity_workflow,
        "ai_insurability": ai_insurability,
        "ai_regulated_verticals": ai_regulated_verticals,
        "ai_bank_mrm": ai_bank_mrm,
        "ai_benchmark_exchange": ai_benchmark_exchange,
        "ai_discovery_sensors": ai_discovery_sensors,
        "ai_media_provenance": ai_media_provenance,
        "ai_media_provenance_c2patool": ai_media_provenance_c2patool,
        "ai_media_provenance_c2patool_sha256": (ai_media_provenance_c2patool_sha256),
        "ai_identity_governance_connectors": ai_identity_governance_connectors,
        "ai_identity_governance_scheduler": ai_identity_governance_scheduler,
        "ai_identity_governance_controls": ai_identity_governance_controls,
        "ai_identity_change_coupling": ai_identity_change_coupling,
        "ai_identity_federation": ai_identity_federation,
        "ai_identity_conditional_access": ai_identity_conditional_access,
        "ai_identity_purview_writeback": ai_identity_purview_writeback,
        "ai_identity_production_composition": ai_identity_production_composition,
        "threat_hunt": threat_hunt,
        "env_hunt": env_hunt,
        "response_execution": response_execution,
    }
    if env_hunt:
        result["connectors"] = connectors
        result["enrichment_sources"] = list(dict.fromkeys(enrichment_sources))
        result["poll_seconds"] = poll_seconds
    return result


def _cfg_governed_records(enable_pool: bool = False) -> list[str]:
    return [
        "", "[governed_records]", 'backend = "auto"',
        f"pool_size = {1 if enable_pool else 0}", "pool_timeout_seconds = 5",
    ]


def _cfg_security_suite(
    security_suite: dict[str, Any] | None, *, governed_pg_pool: bool = False,
) -> list[str]:
    if security_suite is None:
        return _cfg_governed_records(True) if governed_pg_pool else []
    allowed_inventory_connectors = {
        "agentforce",
        "azure_ai_foundry",
        "aws_sagemaker",
        "bedrock",
        "copilot_studio",
        "databricks_unity_catalog",
        "hugging_face",
        "huggingface",
        "mlflow",
        "openai",
        "replicate",
        "salesforce_agentforce",
        "sagemaker",
        "snowflake",
        "snowflake_cortex",
        "vertex_ai",
    }
    inventory_connectors = list(
        dict.fromkeys(
            str(value).strip().lower()
            for value in (security_suite.get("inventory_connectors") or [])
            if str(value).strip().lower() in allowed_inventory_connectors
        )
    )
    ai_entity_tasks_enabled = bool(security_suite.get("ai_entity_tasks", False))
    governance_agents_enabled = bool(security_suite.get("governance_agents", False))
    evidence_analysis_enabled = bool(security_suite.get("ai_evidence_analysis", False))
    evidence_ocr_enabled = bool(
        evidence_analysis_enabled and security_suite.get("ai_evidence_ocr", False)
    )
    evidence_legacy_xls_enabled = bool(
        evidence_analysis_enabled and security_suite.get("ai_evidence_legacy_xls", False)
    )
    evidence_parser_sandbox_enabled = bool(
        (evidence_ocr_enabled or evidence_legacy_xls_enabled)
        and security_suite.get("ai_evidence_parser_sandbox", False)
    )
    evidence_media_types = ["pdf", "jpeg", "png", "xlsx", "text"]
    if evidence_legacy_xls_enabled:
        evidence_media_types.insert(3, "xls")
    rendered_evidence_media_types = ", ".join(
        _toml_str(value) for value in evidence_media_types
    )
    assessment_evidence_enabled = bool(
        security_suite.get("assessment_evidence_autopopulation", False)
        and evidence_analysis_enabled
    )
    assessment_evidence_apply_enabled = bool(
        assessment_evidence_enabled and security_suite.get("assessment_evidence_apply", False)
    )
    rendered_inventory_connectors = ", ".join(_toml_str(value) for value in inventory_connectors)
    vendor_portal_enabled = bool(
        security_suite.get("ai_vendor_risk", False)
        and security_suite.get("ai_vendor_risk_portal", False)
    )
    c2patool_executable_sha256 = (
        str(security_suite.get("ai_media_provenance_c2patool_sha256", "")).strip().lower()
    )
    c2patool_digest_valid = len(c2patool_executable_sha256) == 64 and all(
        character in "0123456789abcdef" for character in c2patool_executable_sha256
    )
    c2patool_verification_enabled = bool(
        security_suite.get("ai_media_provenance", False)
        and security_suite.get("ai_media_provenance_c2patool", False)
        and c2patool_digest_valid
    )
    identity_scheduler_enabled = bool(
        security_suite.get("ai_identity_governance_connectors", False)
        and security_suite.get("ai_identity_governance_scheduler", False)
    )
    identity_controls_enabled = bool(
        security_suite.get("ai_identity_governance_connectors", False)
        and security_suite.get("ai_identity_governance_controls", False)
    )
    identity_federation_enabled = bool(
        identity_controls_enabled and security_suite.get("ai_identity_federation", False)
    )
    identity_production_enabled = bool(
        identity_controls_enabled
        and security_suite.get("ai_identity_production_composition", False)
    )
    lines = [
        "",
        "[customer_sandbox_lifecycle]",
        "enable = "
        f"{'true' if security_suite.get('customer_sandbox_lifecycle', False) else 'false'}",
        "source_revision = 1",
        "",
        "[security_ops]",
        f"enable = {'true' if security_suite.get('security_ops', True) else 'false'}",
        "",
        "[administration_document_access]",
        "enable = "
        f"{'true' if security_suite.get('administration_document_access', False) else 'false'}",
        "default_ttl_seconds = 300",
        "max_ttl_seconds = 900",
        "max_uses = 1",
        "delivery_grant_ttl_seconds = 60",
        "retention_seconds = 31536000",
        "",
        "[governed_document_vault]",
        f"enable = {'true' if security_suite.get('governed_document_vault', False) else 'false'}",
        "max_document_bytes = 26214400",
        "max_documents = 100000",
        "retention_seconds = 31536000",
        "grant_ttl_seconds = 60",
        "claim_lease_seconds = 30",
        "stream_chunk_bytes = 65536",
        'allowed_media_types = ["application/json", "application/pdf", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/jpeg", "image/png", "image/webp", "text/csv", "text/plain"]',
        "",
        "[incident_attachment_metadata]",
        "enable = "
        f"{'true' if security_suite.get('incident_attachment_metadata', False) else 'false'}",
        "retention_seconds = 31536000",
        "attachment_ttl_seconds = 604800",
        "max_attachments = 100000",
        'allowed_media_types = ["application/json", "application/pdf", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/jpeg", "image/png", "image/webp", "text/csv", "text/plain"]',
        *_cfg_governed_records(governed_pg_pool or bool(security_suite.get("governed_pg_pool"))),
        "",
        "[evidence_graph]",
        f"enable = {'true' if security_suite.get('evidence_graph', False) or security_suite.get('vendor_onboarding', False) else 'false'}",
        "",
        "[model_risk_assurance]",
        f"enable = {'true' if security_suite.get('model_risk_assurance', False) or security_suite.get('vendor_onboarding', False) else 'false'}",
        "gate_promotions = "
        f"{'true' if security_suite.get('model_risk_assurance', False) else 'false'}",
        "",
        "[evidence_gateway]",
        "enable = "
        f"{'true' if security_suite.get('evidence_gateway', False) or governance_agents_enabled or evidence_analysis_enabled else 'false'}",
        "",
        "[ai_inventory]",
        "enable = "
        f"{'true' if security_suite.get('ai_inventory', False) or ai_entity_tasks_enabled else 'false'}",
        f"connectors = [{rendered_inventory_connectors}]",
        "page_cap = 100",
        "record_cap = 5000",
        "retry_attempts = 3",
        "timeout_seconds = 30",
        "missing_grace_runs = 2",
        "poll_seconds = 900",
        "",
        "[ai_entity_tasks]",
        f"enable = {'true' if ai_entity_tasks_enabled else 'false'}",
        "max_tasks = 100000",
        "retention_seconds = 31536000",
        "authority_max_age_seconds = 604800",
        "",
        "[ai_vendor_risk]",
        f"enable = {'true' if security_suite.get('ai_vendor_risk', False) or security_suite.get('vendor_onboarding', False) else 'false'}",
        f"portal_enable = {'true' if vendor_portal_enabled else 'false'}",
        "",
        "[portfolio_risk]",
        f"enable = {'true' if security_suite.get('portfolio_risk', False) else 'false'}",
        "",
        "[policy_packs]",
        "enable = "
        f"{'true' if security_suite.get('policy_packs', False) else 'false'}",
        "",
        "[governance_agents]",
        f"enable = {'true' if governance_agents_enabled else 'false'}",
        'enabled_agents = ["breach_response", "privacy_risk_assessment", "program_copilot", "knowledgebase_governance", "third_party_risk"]',
        f"context_projection_enable = {'true' if governance_agents_enabled else 'false'}",
        "context_projection_max_records_per_source = 100",
        "context_projection_max_context_items = 32",
        "context_projection_max_total_bytes = 2097152",
        "context_projection_max_record_bytes = 16384",
        "max_context_items = 100",
        "max_context_bytes = 1048576",
        "max_output_bytes = 262144",
        "retention_seconds = 31536000",
        "",
        "[ai_evidence_analysis]",
        f"enable = {'true' if evidence_analysis_enabled else 'false'}",
        f"enabled_media_types = [{rendered_evidence_media_types}]",
        "max_artifact_bytes = 52428800",
        "max_artifacts_per_case = 20",
        "max_authority_records = 100000",
        "max_extracted_text_bytes = 1048576",
        "retention_seconds = 31536000",
        "",
        "[ai_evidence_analysis.parser_sandbox]",
        f"enable = {'true' if evidence_parser_sandbox_enabled else 'false'}",
        'mode = "bubblewrap"',
        "launcher = "
        f"{_toml_str(str(security_suite.get('ai_evidence_parser_sandbox_launcher', '')))}",
        "launcher_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_parser_sandbox_sha256', '')).lower())}",
        "launcher_version = "
        f"{_toml_str(str(security_suite.get('ai_evidence_parser_sandbox_version', '')))}",
        "",
        "[ai_evidence_analysis.ocr]",
        f"enable = {'true' if evidence_ocr_enabled else 'false'}",
        "executable = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_executable', '')))}",
        "executable_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_sha256', '')).lower())}",
        "tesseract_version = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_tesseract_version', '')))}",
        "traineddata_path = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_traineddata_path', '')))}",
        "traineddata_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_traineddata_sha256', '')).lower())}",
        "runtime_library_paths = ["
        + ", ".join(
            _toml_str(str(value))
            for value in security_suite.get("ai_evidence_ocr_runtime_library_paths", [])
        )
        + "]",
        "runtime_libraries_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_runtime_libraries_sha256', '')).lower())}",
        "pillow_version = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_pillow_version', '')))}",
        "pillow_manifest_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_ocr_pillow_manifest_sha256', '')).lower())}",
        "timeout_seconds = 30",
        "max_pixels = 40000000",
        "max_output_bytes = 1048576",
        "max_memory_bytes = 536870912",
        "",
        "[ai_evidence_analysis.legacy_xls]",
        f"enable = {'true' if evidence_legacy_xls_enabled else 'false'}",
        'xlrd_version = "2.0.2"',
        "xlrd_manifest_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_xlrd_manifest_sha256', '')).lower())}",
        'olefile_version = "0.47"',
        "olefile_manifest_sha256 = "
        f"{_toml_str(str(security_suite.get('ai_evidence_olefile_manifest_sha256', '')).lower())}",
        "timeout_seconds = 15",
        "max_workbook_stream_bytes = 33554432",
        "max_record_bytes = 8388608",
        "max_records = 500000",
        "max_sheets = 200",
        "max_rows_per_sheet = 200000",
        "max_columns_per_sheet = 256",
        "max_cells = 200000",
        "max_output_bytes = 1048576",
        "max_memory_bytes = 536870912",
        "",
        "[assessment_evidence_autopopulation]",
        f"enable = {'true' if assessment_evidence_enabled else 'false'}",
        f"apply_enabled = {'true' if assessment_evidence_apply_enabled else 'false'}",
        "retention_seconds = 31536000",
        "max_records = 10000",
        "max_evidence_records_per_proposal = 32",
        "max_citations_per_answer = 32",
        "min_confidence_bps = 7000",
        "",
        "[ai_regulatory_feed]",
        f"enable = {'true' if security_suite.get('ai_regulatory_feed', False) else 'false'}",
        "",
        "[red_team_assurance]",
        f"enable = {'true' if security_suite.get('red_team_assurance', False) else 'false'}",
        'commitment_secret_ref = "MAVERICK_RED_TEAM_COMMITMENT_KEY"',
        "max_cases = 12",
        "max_response_bytes = 65536",
        "campaign_ttl_seconds = 604800",
        "evidence_validity_seconds = 7776000",
        "scheduler_poll_seconds = 30",
        "",
        "[eu_ai_incidents]",
        f"enable = {'true' if security_suite.get('eu_ai_incidents', False) else 'false'}",
        "authorities = []",
        "",
        "[grc_outbound_sync]",
        f"enable = {'true' if security_suite.get('grc_outbound_sync', False) else 'false'}",
        'targets = ["servicenow_irm", "archer"]',
        "max_attempts_per_revision = 8",
        "",
        "[grc_outbound_sync.servicenow_irm]",
        'credential_secret_ref = "SERVICENOW_TOKEN"',
        "timeout_seconds = 15",
        "max_response_bytes = 262144",
        "",
        "[grc_outbound_sync.archer]",
        'credential_secret_ref = "ARCHER_GRC_TOKEN"',
        "timeout_seconds = 15",
        "max_response_bytes = 262144",
        "",
        "[ai_literacy]",
        f"enable = {'true' if security_suite.get('ai_literacy', False) else 'false'}",
        "",
        "[ai_business_intake]",
        f"enable = {'true' if security_suite.get('ai_business_intake', False) else 'false'}",
        "",
        "[ai_cost_roi]",
        f"enable = {'true' if security_suite.get('ai_cost_roi', False) else 'false'}",
        "collector_poll_seconds = 86400",
        "collector_lookback_days = 1",
        "",
        "[ai_cost_roi.collector_limits]",
        "timeout_seconds = 20",
        "page_cap = 20",
        "record_cap = 1000",
        "max_period_days = 93",
        "page_size = 200",
        "max_bytes_billed = 1000000000",
        "",
        "[ai_cost_roi.aws]",
        "enable = false",
        "",
        "[ai_cost_roi.azure]",
        "enable = false",
        "",
        "[ai_cost_roi.gcp]",
        "enable = false",
        "",
        "[ai_cost_roi.openai]",
        "enable = false",
        "",
        "[ai_dynamic_risk]",
        f"enable = {'true' if security_suite.get('ai_dynamic_risk', False) else 'false'}",
        "",
        "[ai_policy_management]",
        "enable = "
        f"{'true' if security_suite.get('ai_policy_management', False) else 'false'}",
        "",
        "[ai_runtime_guardrails]",
        "enable = "
        f"{'true' if security_suite.get('ai_runtime_guardrails', False) else 'false'}",
        "",
        "[ai_governance_loop]",
        f"enable = {'true' if security_suite.get('ai_governance_loop', False) else 'false'}",
        "poll_seconds = 300",
        "batch_size = 100",
        "lease_seconds = 120",
        "max_attempts = 5",
        "retry_base_seconds = 30",
        "max_lag_seconds = 900",
        "",
        "[ai_explainability]",
        f"enable = {'true' if security_suite.get('ai_explainability', False) else 'false'}",
        "",
        "[ai_conformity_workflow]",
        f"enable = {'true' if security_suite.get('ai_conformity_workflow', False) else 'false'}",
        "",
        "[ai_insurability]",
        f"enable = {'true' if security_suite.get('ai_insurability', False) else 'false'}",
        "",
        "[ai_regulated_verticals]",
        f"enable = {'true' if security_suite.get('ai_regulated_verticals', False) else 'false'}",
        "",
        "[ai_bank_mrm]",
        f"enable = {'true' if security_suite.get('ai_bank_mrm', False) else 'false'}",
        "",
        "[ai_benchmark_exchange]",
        f"enable = {'true' if security_suite.get('ai_benchmark_exchange', False) else 'false'}",
        "",
        "[ai_discovery_sensors]",
        f"enable = {'true' if security_suite.get('ai_discovery_sensors', False) else 'false'}",
        "",
        "[ai_media_provenance]",
        f"enable = {'true' if security_suite.get('ai_media_provenance', False) else 'false'}",
        *(
            [
                'verification_adapter = "c2patool"',
                f"c2patool_executable_sha256 = {_toml_str(c2patool_executable_sha256)}",
            ]
            if c2patool_verification_enabled
            else []
        ),
        "",
        "[ai_identity_governance_connectors]",
        "enable = "
        f"{'true' if security_suite.get('ai_identity_governance_connectors', False) else 'false'}",
        "",
        "[ai_identity_governance_connectors.entra]",
        "enable = false",
        'tenant_id = ""',
        'base_url = "https://graph.microsoft.com"',
        'credential_secret_ref = "ENTRA_IDENTITY_GOVERNANCE_TOKEN"',
        "",
        "[ai_identity_governance_connectors.okta]",
        "enable = false",
        'tenant_id = ""',
        'base_url = "https://replace-me.okta.com"',
        'credential_secret_ref = "OKTA_IDENTITY_GOVERNANCE_TOKEN"',
        "",
        "[ai_identity_governance_connectors.purview]",
        "enable = false",
        'tenant_id = ""',
        'base_url = "https://replace-me.purview.azure.com"',
        'credential_secret_ref = "PURVIEW_IDENTITY_GOVERNANCE_TOKEN"',
        "",
        "[ai_identity_governance_connectors.scheduler]",
        f"enable = {'true' if identity_scheduler_enabled else 'false'}",
        "poll_seconds = 60",
        "",
        "[ai_identity_governance_connectors.scheduler.providers.entra]",
        "enable = false",
        "interval_seconds = 3600",
        "retry_base_seconds = 30",
        "retry_max_seconds = 900",
        "max_attempts_per_slot = 3",
        "lease_seconds = 3600",
        "history_limit = 8",
        "max_snapshot_items = 5000",
        "max_delta_digests = 256",
        "",
        "[ai_identity_governance_connectors.scheduler.providers.okta]",
        "enable = false",
        "interval_seconds = 3600",
        "retry_base_seconds = 30",
        "retry_max_seconds = 900",
        "max_attempts_per_slot = 3",
        "lease_seconds = 3600",
        "history_limit = 8",
        "max_snapshot_items = 5000",
        "max_delta_digests = 256",
        "",
        "[ai_identity_governance_connectors.scheduler.providers.purview]",
        "enable = false",
        "interval_seconds = 3600",
        "retry_base_seconds = 30",
        "retry_max_seconds = 900",
        "max_attempts_per_slot = 3",
        "lease_seconds = 3600",
        "history_limit = 8",
        "max_snapshot_items = 5000",
        "max_delta_digests = 256",
        "",
        "[ai_identity_governance_connectors.controls]",
        f"enable = {'true' if identity_controls_enabled else 'false'}",
        "",
        "[ai_identity_governance_connectors.controls.change_coupling]",
        "enable = "
        f"{'true' if identity_controls_enabled and security_suite.get('ai_identity_change_coupling', False) else 'false'}",
        "dynamic_risk = "
        f"{'true' if identity_controls_enabled and security_suite.get('ai_identity_change_coupling', False) else 'false'}",
        "alerts = "
        f"{'true' if identity_controls_enabled and security_suite.get('ai_identity_change_coupling', False) else 'false'}",
        "",
        "[ai_identity_governance_connectors.controls.federation]",
        f"enable = {'true' if identity_federation_enabled else 'false'}",
        "",
        "[ai_identity_governance_connectors.controls.conditional_access]",
        "enable = "
        f"{'true' if identity_federation_enabled and security_suite.get('ai_identity_conditional_access', False) else 'false'}",
        "",
        "[ai_identity_governance_connectors.controls.purview_writeback]",
        "enable = "
        f"{'true' if identity_federation_enabled and security_suite.get('ai_identity_purview_writeback', False) else 'false'}",
        "",
        "[ai_identity_governance_connectors.controls.production]",
        f"enable = {'true' if identity_production_enabled else 'false'}",
        "mapping_revision = 1",
        "mapping_retention_seconds = 86400",
        "max_authority_records = 10000",
        "max_observation_age_seconds = 300",
        "max_future_skew_seconds = 30",
        "outcome_max_attempts = 5",
        "outcome_retry_base_seconds = 30",
        "outcome_retry_max_seconds = 3600",
        "outcome_lease_seconds = 60",
        "outcome_signal_validity_seconds = 86400",
        "purview_max_attempts = 3",
        "purview_operation_lease_seconds = 60",
        "",
        "[model_improvement]",
        f"enable = {'true' if security_suite.get('model_improvement', False) else 'false'}",
        "allow_hosted = "
        f"{'true' if security_suite.get('allow_hosted_training', False) else 'false'}",
        "allow_cross_tenant = false",
        "require_signed_receipt = true",
        "minimum_train_families = 20",
        "minimum_holdout_families = 20",
        "",
        "[threat_hunt]",
        f"enable = {'true' if security_suite.get('threat_hunt', False) else 'false'}",
        "",
        "[env_hunt]",
        f"enable = {'true' if security_suite.get('env_hunt', False) else 'false'}",
        "response_execution = "
        f"{'true' if security_suite.get('response_execution', False) else 'false'}",
        f"poll_seconds = {max(30, min(3600, int(security_suite.get('poll_seconds', 300))))}",
    ]
    enrichment_sources = security_suite.get("enrichment_sources") or []
    enrichment_sources = list(
        dict.fromkeys(
            str(value).strip().lower() for value in enrichment_sources if str(value).strip()
        )
    )
    for name in enrichment_sources:
        lines += [
            "",
            f"[env_hunt.enrichment_sources.{name}]",
            "enable = true",
        ]
    try:
        from maverick.env_hunt import CONNECTOR_NAMES
    except ImportError:  # installer can render before maverick-core is installed
        CONNECTOR_NAMES = (
            "cloudtrail",
            "guardduty",
            "syslog",
            "edr",
            "splunk",
            "elastic",
            "sentinel",
            "kubernetes_audit",
            "okta",
            "entra",
        )
    configured = security_suite.get("connectors") or {}
    configured = configured if isinstance(configured, dict) else {}
    for name in CONNECTOR_NAMES:
        value = configured.get(name, False)
        enabled = value.get("enable", False) if isinstance(value, dict) else value
        push_enabled = value.get("push_enable", False) if isinstance(value, dict) else False
        pivot_enabled = value.get("pivot_enable", False) if isinstance(value, dict) else False
        lines += [
            "",
            f"[env_hunt.connectors.{name}]",
            f"enable = {'true' if enabled is True else 'false'}",
            f"push_enable = {'true' if push_enabled is True else 'false'}",
            f"pivot_enable = {'true' if pivot_enabled is True else 'false'}",
        ]
    tech_risk_compliance = security_suite.get("tech_risk_compliance")
    if isinstance(tech_risk_compliance, dict):
        _append_nested_product_config(lines, "tech_risk_compliance", tech_risk_compliance)
    third_party_management = security_suite.get("third_party_management")
    if isinstance(third_party_management, dict):
        _append_nested_product_config(lines, "third_party_management", third_party_management)
    return lines
