"""The assessments step (consent & preferences, privacy automation, data-use
governance, vendor-paper review) and its config writer.

See :mod:`._seams` for how the prompt primitives stay patchable through the
``maverick_installer.wizard`` facade.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from ._common import _append_nested_product_config, _emit_kv, _safe_int
from ._seams import _q_checkbox, _q_confirm, _q_select, _q_text, console


@dataclass
class _ConsentChoices:
    """What the Consent & Preferences questions decided.

    The privacy-automation questions that follow depend on these answers and
    may extend ``product`` (shared storage, the Global Opt-Out experience).
    """

    product: dict[str, Any] | None = None
    publishing: bool = False
    public_api: bool = False
    identity: bool = False
    trust_center: bool = False
    native_sdk: dict[str, Any] | None = None


def pick_assessments() -> dict[str, Any]:
    """Assessment-flow assists (doc discovery + learning), both default ON.

    Doc discovery searches connected sources (Microsoft Graph / Slack /
    Google Drive) for the SOW/contract/DPA related to an assessment subject;
    it only activates when a source has credentials. Learning suggests
    answers from the org's OWN past assessments -- advisory only. Returns a
    dict written under ``[assessments]`` only on divergence from defaults.

    The product families are asked in this order: consent & preferences,
    privacy automation, data-use governance, then vendor-paper review and
    the entity graph.
    """
    console.print()
    console.print(
        "[dim]Assessment assists: doc discovery finds the SOW/contract/DPA in "
        "your connected Microsoft 365 / Slack / Google Drive when someone "
        "fills an assessment; learning suggests answers from your own past "
        "assessments (a human still reviews everything). Both ON by default; "
        "discovery stays inert until a source is connected.[/dim]"
    )
    discovery = _q_confirm("Enable assessment doc discovery?", default=True)
    learn = _q_confirm("Enable assessment learning (suggest from past assessments)?", default=True)
    ops = _q_confirm(
        "Enable the privacy ops record types (DPA review, AI registry, RoPA, DSAR tracker)?",
        default=True,
    )
    consent = _pick_consent_preferences()
    privacy_automation = _pick_privacy_automation(consent)
    data_use_governance = _pick_data_use_governance()
    draft, org_name, graph = _pick_paper_review_and_graph()
    out: dict[str, Any] = {}
    if not discovery:
        out["doc_discovery"] = False
    if not learn:
        out["learn"] = False
    if not ops:
        out["privacy_ops"] = False
    if consent.product is not None:
        out["consent_preferences"] = consent.product
    if privacy_automation is not None:
        out["privacy_automation"] = privacy_automation
    if data_use_governance is not None:
        out["data_use_governance"] = data_use_governance
    if not draft:
        out["paper_review_use_model"] = False
    if org_name:
        out["paper_review_org"] = org_name
    if not graph:
        out["entity_graph"] = False
    return out


def _pick_consent_preferences() -> _ConsentChoices:
    """Consumer Consent & Preferences: publishing, the public API, scanners,
    signals, the native SDK, delivery, analytics and the Trust Center."""
    consent = _ConsentChoices()
    if not _q_confirm(
        "Enable consumer Consent & Preferences records, receipts, tracker "
        "governance, and fail-closed enforcement?",
        default=False,
    ):
        return consent
    consent.publishing = _q_confirm(
        "Enable versioned property, policy, notice, translation, and publication governance?",
        default=True,
    )
    consent_web_publish_settings = consent.publishing and _q_confirm(
        "Enable governed website publish settings for SDK version, "
        "geolocation reconsent, analytics, cookie scope, SPA reload, CSP "
        "nonce requirements, and automatic refresh?",
        default=False,
    )
    consent.public_api = consent.publishing and _q_confirm(
        "Enable the external consumer consent API? Property/origin "
        "bindings are still required before it serves traffic.",
        default=False,
    )
    consent.identity = consent.public_api and _q_confirm(
        "Enable verified consumer identity federation and one-time "
        "cross-domain/device pairing? OIDC keys and subject-digest custody "
        "must still be injected by the deployment.",
        default=False,
    )
    consent_identity_config: dict[str, Any] | None = None
    if consent.identity:
        consent_identity_config = {
            "enable": True,
            "issuer": _q_text(
                "  Consumer OIDC issuer (exact signed iss value)",
                default="",
            ).strip(),
            "audience": _q_text(
                "  Consumer OIDC audience (exact app/API audience)",
                default="",
            ).strip(),
            "jwks_origin": _q_text(
                "  Pinned HTTPS JWKS origin (origin only; keys are injected at runtime)",
                default="",
            ).strip(),
            "token_ttl_seconds": 600,
            "link_lifecycle_retention_seconds": 31_536_000,
        }
    consent_scanner = _q_confirm(
        "Enable scheduled website tracker scanning? Only properties "
        "explicitly enrolled by the privacy owner are eligible.",
        default=False,
    )
    consent_scan_scheduler = consent_scanner and _q_confirm(
        "Run the bounded consent scan scheduler automatically with the "
        "dashboard? Enrolled schedules remain the only work authority.",
        default=False,
    )
    consent_scan_notice_proposals = consent_scanner and _q_confirm(
        "Enable independently reviewed scan-to-cookie/privacy disclosure "
        "metadata proposals? This creates structured local proposals only; "
        "it does not generate legal copy or publish a notice or site change.",
        default=False,
    )
    consent_application_scanner = _q_confirm(
        "Enable bounded mobile and OTT/CTV application manifest analysis? "
        "Operators must supply already-extracted manifests; this does not "
        "execute APKs/IPAs, inspect devices, or classify trackers or law.",
        default=False,
    )
    consent_signals = _q_confirm(
        "Enable GPC and DNT signal interpretation?",
        default=True,
    )
    consent_adtech_standards = _q_confirm(
        "Enable advertising interoperability (GPP, TCF, and Google "
        "Consent Mode) after its conformance vectors are installed?",
        default=False,
    )
    consent_native_enabled = (
        consent.publishing
        and consent.public_api
        and _q_confirm(
            "Enable the native mobile and OTT/CTV consent SDK runtime? "
            "Production readiness requires an injected platform attestation "
            "verifier; GPP/TCF also requires an injected standards-wire verifier.",
            default=False,
        )
    )
    if consent_native_enabled:
        consent.native_sdk = _pick_consent_native_sdk(consent.identity)
    consent_delivery = _q_confirm(
        "Enable downstream preference delivery? Destinations remain "
        "disabled until separately enrolled.",
        default=False,
    )
    consent_delivery_worker = consent_delivery and _q_confirm(
        "Run automatic consent delivery for subscriptions separately reviewed in Lightwork? "
        "No destination is authorized by this installation choice.", default=False,
    )
    consent_destination_config: dict[str, Any] | None = None
    if consent_delivery and _q_confirm(
        "Configure named Salesforce, Marketo, Adobe Experience Platform, "
        "or Snowflake consent destinations? Exact destination enrollment, "
        "signing keys, deployment-held credentials, and an independent "
        "reconciliation authority are still required.",
        default=False,
    ):
        consent_destination_config = _pick_consent_destinations()
    consent_analytics = _q_confirm(
        "Enable privacy-safe aggregate consent analytics?",
        default=False,
    )
    consent_experiments = _q_confirm(
        "Enable privacy-preserving consent A/B experiments? Legal signals, "
        "required purposes, accessibility, and symmetry of choice remain "
        "non-experimental safety floors.",
        default=False,
    )
    consent_profile_data = _q_confirm(
        "Enable governed volunteered profile data and progressive consent "
        "journeys? Values remain closed-schema and purpose-bound; raw free "
        "text and protected-trait inference are not supported.",
        default=False,
    )
    consent_custom_index = consent_profile_data and _q_confirm(
        "Enable governed custom data-element indexes and exact profile search? "
        "Search values are HMAC-tokenized under a deployment-custody key; "
        "indexes fail closed when their source changes.",
        default=False,
    )
    consent_bulk_jobs = _q_confirm(
        "Enable governed bulk consent exports and lifecycle jobs? Jobs are "
        "tenant-scoped, credit-limited, cancellable, and retain bounded "
        "artifacts; operators must still hold the matching consent authority.",
        default=False,
    )
    consent.trust_center = consent.public_api and _q_confirm(
        "Enable the unified consumer Trust Center? It requires separately "
        "approved capability grants before consumer data is shown.",
        default=False,
    )
    consent_trust_center_branding = consent.trust_center and _q_confirm(
        "Enable governed Trust Center logos and exact custom-domain claims? "
        "PNG/JPEG assets require independent review; DNS/TLS/CDN deployment "
        "authority and the encryption key must still be injected.",
        default=False,
    )
    consent.product = {
        "enable": True,
        "publishing": {
            "enable": consent.publishing,
            **(
                {
                    "web_settings": {
                        "enable": True,
                        "retention_seconds": 31_536_000,
                        "max_history": 250,
                    }
                }
                if consent_web_publish_settings
                else {}
            ),
        },
        "public_api": {"enable": consent.public_api},
        **(
            {"identity": consent_identity_config} if consent_identity_config is not None else {}
        ),
        "scanner": {
            "enable": consent_scanner,
            "notice_proposals": {"enable": consent_scan_notice_proposals},
            "scheduler": {
                "enable": consent_scan_scheduler,
                "poll_seconds": 60,
                "enqueue_limit": 100,
                "claim_limit": 4,
                "tenant_limit": 1_000,
            },
        },
        **(
            {
                "application_scanner": {
                    "enable": True,
                    "max_records": 25_000,
                    "retention_seconds": 31_536_000,
                }
            }
            if consent_application_scanner
            else {}
        ),
        "standards": {
            "gpc": consent_signals,
            "dnt": consent_signals,
            "gpp": consent_adtech_standards,
            "tcf": consent_adtech_standards,
            "google_consent_mode": consent_adtech_standards,
        },
        **({"native_sdk": consent.native_sdk} if consent.native_sdk is not None else {}),
        "delivery": {
            "enable": consent_delivery,
            "worker": {"enable": bool(consent_delivery_worker)},
            **(
                {"destinations": consent_destination_config}
                if consent_destination_config is not None
                else {}
            ),
        },
        "analytics": {"enable": consent_analytics},
        "experiments": {"enable": consent_experiments},
        "profile_data": {
            "enable": consent_profile_data,
            "custom_index": {
                "enable": consent_custom_index,
                "key_secret_ref": "MAVERICK_CONSENT_CUSTOM_INDEX_KEY",
                "key_version": 1,
                "max_indexes": 256,
                "max_page_size": 100,
                "retention_seconds": 31_536_000,
            },
        },
        **(
            {
                "bulk_jobs": {
                    "enable": True,
                    "initial_credits": 10_000,
                    "max_jobs": 10_000,
                    "max_items_per_job": 10_000,
                    "max_artifact_bytes": 16_777_216,
                    "lease_seconds": 60,
                    "retention_seconds": 31_536_000,
                    "worker_batch_size": 100,
                }
            }
            if consent_bulk_jobs
            else {}
        ),
        "trust_center": {
            "enable": consent.trust_center,
            **(
                {
                    "branding": {
                        "enable": True,
                        "max_asset_bytes": 2_097_152,
                        "max_assets": 1_000,
                        "max_width": 4_096,
                        "max_height": 4_096,
                        "max_pixels": 8_388_608,
                        "max_domains": 100,
                        "challenge_ttl_seconds": 3_600,
                        "verification_ttl_seconds": 604_800,
                        "retention_seconds": 7_776_000,
                        "key_ref": "env:MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY",
                        "key_revision": 1,
                    }
                }
                if consent_trust_center_branding
                else {}
            ),
        },
    }
    return consent


def _pick_consent_native_sdk(identity: bool) -> dict[str, Any]:
    """Receipt signing and profile linking for the native mobile / OTT-CTV consent SDK."""
    receipt_key_id = (
        _q_text(
            "  Native receipt signing key id",
            default="native-consent-receipt",
        ).strip()
        or "native-consent-receipt"
    )
    receipt_key_secret_ref = (
        _q_text(
            "  Environment variable holding the native receipt root secret",
            default="MAVERICK_NATIVE_CONSENT_RECEIPT_KEY",
        ).strip()
        or "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY"
    )
    require_profile_linking = identity and _q_confirm(
        "Require each native consent request to link to a verified consumer profile? "
        "The deployment must inject the profile-linking callback.",
        default=False,
    )
    return {
        "enable": True,
        "receipt_key_id": receipt_key_id,
        "receipt_key_revision": 1,
        "receipt_key_secret_ref": receipt_key_secret_ref,
        "max_applications": 1_000,
        "max_devices": 100_000,
        "max_requests": 1_000_000,
        "requests_per_minute": 120,
        "require_profile_linking": require_profile_linking,
        "require_rights_requests": False,
    }


def _pick_consent_destinations() -> dict[str, Any] | None:
    """Named consent delivery destinations; None when no destination was chosen."""
    destination_providers = _q_checkbox(
        "Select named consent delivery destinations",
        [
            "salesforce",
            "marketo",
            "adobe_experience_platform",
            "snowflake",
        ],
        default=[],
    )
    destination_tables: dict[str, dict[str, Any]] = {}

    def destination_text(label: str, default: str) -> str:
        return _q_text(f"  {label}", default=default).strip() or default

    def credential_reference(label: str, default: str) -> str:
        name = destination_text(label, default)
        if name.startswith("$"):
            return name
        return "${" + name + "}"

    if "salesforce" in destination_providers:
        destination_tables["salesforce"] = {
            "destination_id": destination_text(
                "Salesforce destination id", "salesforce"
            ),
            "origin": destination_text(
                "Salesforce exact HTTPS origin",
                "https://tenant.my.salesforce.com",
            ),
            "credential_secret_ref": credential_reference(
                "Environment variable holding the Salesforce OAuth token",
                "MAVERICK_SALESFORCE_CONSENT_TOKEN",
            ),
            "credential_revision": 1,
            "api_version": destination_text(
                "Salesforce REST API version", "v65.0"
            ),
            "object_api_name": destination_text(
                "Salesforce consent-event object API name",
                "Lightwork_Consent_Event__c",
            ),
            "external_id_field": destination_text(
                "Salesforce external-id field",
                "Lightwork_Message_Id__c",
            ),
            "payload_digest_field": destination_text(
                "Salesforce payload-digest field",
                "Lightwork_Payload_SHA256__c",
            ),
        }
    if "marketo" in destination_providers:
        destination_tables["marketo"] = {
            "destination_id": destination_text(
                "Marketo destination id", "marketo"
            ),
            "origin": destination_text(
                "Marketo exact HTTPS origin",
                "https://123-ABC-456.mktorest.com",
            ),
            "credential_secret_ref": credential_reference(
                "Environment variable holding the Marketo OAuth token",
                "MAVERICK_MARKETO_CONSENT_TOKEN",
            ),
            "credential_revision": 1,
            "custom_object_name": destination_text(
                "Marketo consent custom-object API name",
                "lightworkConsentEvent",
            ),
            "dedupe_field": destination_text(
                "Marketo dedupe field", "lightworkMessageId"
            ),
            "message_id_field": destination_text(
                "Marketo standalone searchable message-id field",
                "lightworkMessageId",
            ),
            "payload_digest_field": destination_text(
                "Marketo payload-digest field", "payloadSha256"
            ),
        }
    if "adobe_experience_platform" in destination_providers:
        destination_tables["adobe_experience_platform"] = {
            "destination_id": destination_text(
                "Adobe Experience Platform destination id", "aep"
            ),
            "origin": destination_text(
                "Adobe Experience Platform exact streaming origin",
                "https://dcs.adobedc.net",
            ),
            "credential_secret_ref": credential_reference(
                "Environment variable holding the AEP credential JSON bundle",
                "MAVERICK_AEP_CONSENT_CREDENTIAL",
            ),
            "credential_revision": 1,
            "connection_id": destination_text(
                "AEP streaming connection id", "replace_connection_id"
            ),
            "flow_id": destination_text(
                "AEP dataflow id", "replace_flow_id"
            ),
            "dataset_id": destination_text(
                "AEP dataset id", "replace_dataset_id"
            ),
            "schema_id": destination_text(
                "AEP XDM schema id", "replace_schema_id"
            ),
            "ims_org_id": destination_text(
                "AEP IMS organization id", "replace@AdobeOrg"
            ),
        }
    if "snowflake" in destination_providers:
        destination_tables["snowflake"] = {
            "destination_id": destination_text(
                "Snowflake destination id", "snowflake"
            ),
            "origin": destination_text(
                "Snowflake exact SQL API origin",
                "https://account.region.snowflakecomputing.com",
            ),
            "credential_secret_ref": credential_reference(
                "Environment variable holding the Snowflake OAuth token",
                "MAVERICK_SNOWFLAKE_CONSENT_TOKEN",
            ),
            "credential_revision": 1,
            "database": destination_text(
                "Snowflake database", "LIGHTWORK"
            ),
            "schema": destination_text(
                "Snowflake schema", "CONSENT"
            ),
            "table": destination_text(
                "Snowflake consent-event table", "PREFERENCE_EVENTS"
            ),
            "warehouse": destination_text(
                "Snowflake warehouse", "LIGHTWORK_WH"
            ),
            "role": destination_text(
                "Snowflake least-privilege role", "LIGHTWORK_CONSENT_WRITER"
            ),
        }
    if not destination_tables:
        return None
    return {
        "enable": True,
        "enabled_providers": list(destination_tables),
        "timeout_seconds": 10.0,
        "max_response_bytes": 65_536,
        **destination_tables,
    }


def _pick_privacy_discovery() -> dict[str, Any]:
    """Personal-data discovery and its bounded built-in source adapters.

    Returns the ``data_discovery`` table (``enable`` is False when declined).
    """
    privacy_data_discovery = _q_confirm(
        "Enable Privacy Automation structured and unstructured personal-data "
        "discovery? Sources remain inert until separately enrolled and provider "
        "adapters are attached.",
        default=False,
    )
    config: dict[str, Any] = {"enable": privacy_data_discovery}
    if not (privacy_data_discovery and _q_confirm(
        "Enable the bounded built-in privacy discovery source adapters? "
        "Each source requires an exact tenant enrollment and a saved connection or "
        "deployment-managed credential; evidence keys can be generated in the app.",
        default=False,
    )):
        return config
    adapter_providers = _q_checkbox(
        "Select built-in privacy discovery adapters",
        [
            "aws_s3",
            "azure_blob",
            "google_cloud_storage",
            "snowflake_metadata",
            "servicenow_cmdb",
            "entra_assets",
        ],
        default=[],
    )
    if not adapter_providers:
        return config
    remediation = _q_confirm(
        "Enable independently approved discovery-remediation outbox jobs and "
        "the digest-only governed data-map target? Provider writes remain "
        "disabled until a separate tenant authority is enrolled.",
        default=False,
    )
    scheduler = (
        remediation
        and _q_confirm(
            "Enable the managed privacy discovery remediation scheduler? "
            "It runs bounded tenant-local digest-only retry and ambiguity "
            "reconciliation; it never runs provider discovery or proves completeness.",
            default=False,
        )
    )
    config["adapters"] = {
        "enable": True,
        "enabled_providers": adapter_providers,
        "timeout_seconds": 15.0,
        "max_response_bytes": 8_388_608,
        "page_size": 250,
        "max_pages": 500,
        "max_attempts": 3,
        "max_polls": 8,
    }
    config["remediation"] = {
        "enable": remediation,
        "max_attempts": 5,
        "retention_seconds": 2_592_000,
        "data_map": {
            "enable": remediation,
            "retention_seconds": 31_536_000,
        },
        "scheduler": {
            "enable": scheduler,
            "interval_seconds": 60,
            "jitter_seconds": 10,
            "retry_max_seconds": 300,
            "tenant_limit": 1_000,
            "worker_limit": 10,
            "reconcile_limit": 10,
            "lease_seconds": 60,
        },
    }
    return config


def _pick_privacy_rights_source_adapters() -> dict[str, Any]:
    """Stock privacy-rights source adapters (directory, CRM and ITSM providers)."""
    source_choices = _q_checkbox(
        "Select privacy-rights source providers",
        [
            "Microsoft Graph users",
            "Google Workspace users",
            "Salesforce contacts",
            "ServiceNow users",
        ],
        default=[],
    )
    provider_specs = {
        "Microsoft Graph users": (
            "microsoft_graph_users",
            "directory-graph",
            "https://graph.microsoft.com",
            "env:GRAPH_RIGHTS_TOKEN",
        ),
        "Google Workspace users": (
            "google_workspace_users",
            "directory-google",
            "https://admin.googleapis.com",
            "env:GOOGLE_WORKSPACE_RIGHTS_TOKEN",
        ),
        "Salesforce contacts": (
            "salesforce_contacts",
            "crm-salesforce",
            "https://tenant.salesforce.com",
            "env:SALESFORCE_RIGHTS_TOKEN",
        ),
        "ServiceNow users": (
            "servicenow_users",
            "itsm-servicenow",
            "https://tenant.service-now.com",
            "env:SERVICENOW_RIGHTS_TOKEN",
        ),
    }
    selected_providers: dict[str, Any] = {}
    for choice in source_choices:
        provider, source_id, origin, credential_ref = provider_specs[choice]
        selected_providers[provider] = {
            "enable": True,
            "source_id": source_id,
            "origin": origin,
            "credential_ref": credential_ref,
            "capabilities": [
                "discover",
                "retrieve",
                "delete",
                "verify_delete",
            ],
        }
    return {
        "enable": bool(selected_providers),
        "timeout_seconds": 15,
        "max_response_bytes": 1_048_576,
        "max_retrieval_bytes": 8_388_608,
        "max_records": 200,
        "batch_size": 10,
        "lease_seconds": 60,
        "retry_delay_seconds": 30,
        "claim_history_retention_seconds": 86_400,
        "target_custody_retention_seconds": 2_592_000,
        "providers": selected_providers,
    }


def _pick_notice_publication_binding() -> dict[str, Any]:
    """The first privacy-notice publication binding (exact tenant and release IDs)."""
    binding_tenant = (
        _q_text(
            "  Exact active tenant ID for the first publication binding",
            default=os.environ.get("MAVERICK_TENANT", "default"),
        ).strip()
        or "default"
    )
    binding_id = (
        _q_text("  Publication binding name", default="primary").strip()
        or "primary"
    )
    return {
        "binding_id": binding_id,
        "tenant_id": binding_tenant,
        "notice_id": (
            _q_text("  Exact notice release ID", default="privacy-main").strip()
            or "privacy-main"
        ),
        "consent_publication_ref": (
            _q_text(
                "  Exact notice release consent-publication reference",
                default="consent-binding:1",
            ).strip()
            or "consent-binding:1"
        ),
        "property_id": (
            _q_text("  Exact Consent Publishing property ID", default="property-main").strip()
            or "property-main"
        ),
        "rule_group_id": (
            _q_text("  Exact consent rule-group ID", default="production-rules").strip()
            or "production-rules"
        ),
        "rule_group_version": max(
            1,
            _safe_int(
                _q_text("  Exact consent rule-group version", default="1"),
                default=1,
            ),
        ),
        "notice_resource_id": (
            _q_text("  Exact consent notice-resource ID", default="privacy-notice").strip()
            or "privacy-notice"
        ),
        "notice_resource_version": max(
            1,
            _safe_int(
                _q_text("  Exact consent notice-resource version", default="1"),
                default=1,
            ),
        ),
    }


def _pick_privacy_automation(consent: _ConsentChoices) -> dict[str, Any] | None:
    """Privacy Automation: discovery, regulatory research, rights orchestration,
    DROP management, the public request form and notice governance.

    Two answers extend the consent product (shared PostgreSQL storage and the
    Global Opt-Out experience), so the consent choices are passed in. Returns
    the ``privacy_automation`` table, or None when nothing was enabled.
    """
    data_discovery = _pick_privacy_discovery()
    privacy_regulatory_intelligence = _q_confirm(
        "Enable Privacy Automation regulatory research, collections, alerts, "
        "comparisons, and cited reports? No proprietary corpus is bundled; "
        "sources remain unavailable until separately licensed and enrolled.",
        default=False,
    )
    privacy_rights_orchestration = _q_confirm(
        "Enable provider-neutral Privacy Automation rights-request orchestration? "
        "Raw subject references are HMACed; callbacks remain worker intent with "
        "no provider transport or response delivery.",
        default=False,
    )
    privacy_rights_source_adapters: dict[str, Any] | None = None
    if privacy_rights_orchestration and _q_confirm(
        "Enable production stock privacy-rights source adapters with encrypted "
        "immutable-target custody and reconciliation-only deletes? Provider "
        "credentials and raw subjects remain server-owned.",
        default=False,
    ):
        privacy_rights_source_adapters = _pick_privacy_rights_source_adapters()
    privacy_rights_consumer_delivery = privacy_rights_orchestration and _q_confirm(
        "Enable one-time consumer delivery for closed, redacted rights-response "
        "packages? Production use still requires the governed document vault, "
        "pinned key references, independent public reauthentication, and an "
        "IdP-backed operator-to-consumer mapping for operator minting.",
        default=False,
    )
    privacy_rights_consumer_intake = (
        privacy_rights_orchestration
        and consent.publishing
        and consent.public_api
        and consent.trust_center
        and _q_confirm(
            "Enable authenticated consumer privacy-rights intake in the Trust "
            "Center? Requests remain profile-bound, identity evidence is "
            "independently resolved, and provider retrieval/deletion stays "
            "disabled until separately authorized.",
            default=False,
        )
    )
    if consent.native_sdk is not None and privacy_rights_consumer_intake:
        consent.native_sdk["require_rights_requests"] = _q_confirm(
            "Require native SDK privacy-rights requests? The deployment must inject "
            "the tenant-bound rights-request callback.",
            default=False,
        )
    consent_global_opt_out = privacy_rights_consumer_intake and _q_confirm(
        "Enable the governed Global Opt-Out mobile and email experience? "
        "Public submissions create a real profile-bound opt-out rights request; "
        "live device, service, customer-estate, and legal acceptance remain separate.",
        default=False,
    )
    if consent.product is not None and _q_confirm(
        "Keep consent records in a shared PostgreSQL database instead of files on "
        "this server? The connection is read from MAVERICK_CONSENT_PG_DSN on the server.",
        default=False,
    ):
        consent.product["storage"] = {
            "backend": "postgres",
            "dsn_secret_ref": "$MAVERICK_CONSENT_PG_DSN",
        }
    if consent_global_opt_out and consent.product is not None:
        consent.product["global_opt_out"] = {
            "enable": True,
            "retention_seconds": 31_536_000,
            "submission_ttl_seconds": 900,
            "max_records": 10_000,
        }
    privacy_ott_ctv_rights = (
        privacy_rights_orchestration
        and consent.identity
        and consent.trust_center
        and _q_confirm(
            "Enable the selector-free OTT/CTV service-client rights bridge? "
            "This is a local access/deletion control path only; it provides no "
            "native provider SDK, live deletion, or estate-completeness proof.",
            default=False,
        )
    )
    privacy_drop_management = privacy_rights_orchestration and _q_confirm(
        "Enable California DROP deletion and permanent opt-out management? "
        "DROP records, subject bindings, DSAR submission and terminal outcome "
        "evidence must be independently enrolled; this does not enable a live "
        "California provider connection or make a legal-compliance claim.",
        default=False,
    )
    privacy_drop_key_ref = "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY"
    privacy_drop_scheduler = False
    if privacy_drop_management:
        privacy_drop_key_ref = (
            _q_text(
                "DROP principal-binding secret-provider reference (never key material)",
                default=privacy_drop_key_ref,
            ).strip()
            or privacy_drop_key_ref
        )
        privacy_drop_scheduler = _q_confirm(
            "Enable the managed DROP reconciliation and retention scheduler? "
            "This runs bounded tenant-local maintenance; California delivery and "
            "registered-broker interoperability remain separately operated.",
            default=False,
        )
    privacy_public_rights_form = _q_confirm(
        "Let people submit privacy requests from your website? Publishes a "
        "public request form per site or app; requesters confirm their email "
        "address before a request opens, and deadlines follow the law they "
        "choose (needs the platform email account for the confirmation link).",
        default=False,
    )
    privacy_notice_governance = _q_confirm(
        "Enable governed Privacy Automation notice approvals and publication "
        "intents? Notice content stays external and publication remains local "
        "worker intent with no site, app, or consent-provider write.",
        default=False,
    )
    privacy_notice_publication_runtime = False
    privacy_notice_publication_scheduler = False
    privacy_notice_publication_binding: dict[str, Any] | None = None
    if privacy_notice_governance and consent.publishing:
        privacy_notice_publication_runtime = _q_confirm(
            "Enable the local privacy-notice publication runtime? This consumes "
            "approved intents into the tenant-private Consent Publishing store "
            "only; it does not update a website, SDK, tag manager, or provider.",
            default=False,
        )
    if privacy_notice_publication_runtime:
        privacy_notice_publication_binding = _pick_notice_publication_binding()
        privacy_notice_publication_scheduler = _q_confirm(
            "Run the bounded local notice-publication scheduler with the dashboard? "
            "Only the exact active tenant and target binding above are eligible.",
            default=False,
        )
    if not (
        data_discovery["enable"]
        or privacy_regulatory_intelligence
        or privacy_rights_orchestration
        or privacy_rights_consumer_delivery
        or privacy_rights_consumer_intake
        or privacy_ott_ctv_rights
        or privacy_drop_management
        or privacy_notice_governance
        or privacy_public_rights_form
    ):
        return None
    return {
        "enable": True,
        "data_discovery": data_discovery,
        "regulatory_intelligence": {
            "enable": privacy_regulatory_intelligence,
        },
        "rights_orchestration": {
            "enable": privacy_rights_orchestration,
            **(
                {"source_adapters": privacy_rights_source_adapters}
                if privacy_rights_source_adapters is not None
                else {}
            ),
        },
        "rights_consumer_delivery": {
            "enable": privacy_rights_consumer_delivery,
            "digest_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY",
            "export_signing_key_ref": (
                "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_EXPORT_KEY"
            ),
            "package_encryption_key_ref": "env:MAVERICK_ENCRYPTION_KEY",
            "server_grant_ttl_seconds": 30,
            "max_package_bytes": 16_777_216,
        },
        "rights_consumer_intake": {
            "enable": privacy_rights_consumer_intake,
            "request_ttl_seconds": 86_400,
            "retention_seconds": 31_536_000,
            "max_active_requests": 1_000,
            "max_active_requests_per_subject": 25,
        },
        "ott_ctv_rights": {
            "enable": privacy_ott_ctv_rights,
        },
        "drop_management": {
            "enable": privacy_drop_management,
            "principal_binding_key_ref": privacy_drop_key_ref,
            "retention_seconds": 31_536_000,
            "scheduler_enable": privacy_drop_scheduler,
            "scheduler_interval_seconds": 3_600,
            "scheduler_jitter_seconds": 60,
            "scheduler_retry_max_seconds": 900,
        },
        **(
            {
                "public_rights_form": {
                    "enable": True,
                    "verification_ttl_hours": 24,
                    "status_ttl_days": 90,
                    "requests_per_ip_per_hour": 5,
                    "requests_per_email_per_day": 3,
                    "internal_target_days": 30,
                    "max_message_chars": 4000,
                }
            }
            if privacy_public_rights_form
            else {}
        ),
        "notice_governance": {
            "enable": privacy_notice_governance,
            **(
                {
                    "publication_runtime": {
                        "enable": True,
                        "scheduler_enable": privacy_notice_publication_scheduler,
                        "active_tenants": [
                            str(privacy_notice_publication_binding["tenant_id"])
                        ],
                        "poll_seconds": 30,
                        "retry_max_seconds": 300,
                        "tenant_limit": 100,
                        "lease_seconds": 60,
                        "retry_delay_seconds": 60,
                        "bindings": {
                            str(privacy_notice_publication_binding["binding_id"]): {
                                key: value
                                for key, value in privacy_notice_publication_binding.items()
                                if key != "binding_id"
                            }
                        },
                    }
                }
                if privacy_notice_publication_binding is not None
                else {}
            ),
        },
    }


def _pick_data_use_governance() -> dict[str, Any] | None:
    """Data Use Governance: the policy compiler, background checks and an optional
    native Snowflake/Databricks enforcement runtime. None when declined."""
    data_use_governance = _q_confirm(
        "Enable the Data Use Governance authority and policy compiler? "
        "Provider writes remain disabled until a native provider is enrolled.",
        default=False,
    )
    data_use_checks = data_use_governance and _q_confirm(
        "Run the data-use checks in the background (the change record, decisions that "
        "no longer match current facts, ended exceptions)? Nothing is changed or sent.",
        default=False,
    )
    data_use_native: dict[str, Any] | None = None
    data_use_provider_audit = False
    data_use_provider_audit_scheduler = False
    if data_use_governance and _q_confirm(
        "Configure a native Snowflake or Databricks enforcement runtime? "
        "This enables external writes only after a binding is enrolled and an "
        "authorized decision is explicitly applied.",
        default=False,
    ):
        native_provider = _q_select(
            "Native data provider",
            ["snowflake", "databricks"],
            default="snowflake",
        )
        native_origin = _q_text(
            f"Exact HTTPS {native_provider} account/workspace origin",
            default=(
                "https://account.snowflakecomputing.com"
                if native_provider == "snowflake"
                else "https://workspace.cloud.databricks.com"
            ),
        ).strip()
        native_secret_ref = _q_text(
            "Secret-provider reference containing the bearer token (for example "
            "$LIGHTWORK_DATA_USE_PROVIDER_TOKEN)",
            default="$LIGHTWORK_DATA_USE_PROVIDER_TOKEN",
        ).strip()
        native_revision = _safe_int(
            _q_text(
                "Credential authority revision (increment on rotation)",
                default="1",
            ),
            default=1,
        )
        data_use_native = {
            "provider": native_provider,
            "section": {
                "enable": True,
                "origin": native_origin,
                "credential_secret_ref": native_secret_ref,
                "credential_revision": max(1, native_revision),
                "timeout_seconds": 10,
                "max_response_bytes": 65_536,
            },
        }
        data_use_provider_audit = _q_confirm(
            "Enable native provider audit-log ingestion and last-mile "
            "reconciliation? Provider writes will then require a current, "
            "independently enrolled read capability and use the built-in typed "
            "audit transport; audit-log completeness and live provider acceptance "
            "remain separate.",
            default=False,
        )
        if data_use_provider_audit:
            data_use_provider_audit_scheduler = _q_confirm(
                "Run the bounded cross-tenant provider-audit recovery and "
                "reconciliation scheduler in this dashboard process?",
                default=False,
            )
    if not data_use_governance:
        return None
    data_use_product: dict[str, Any] = {
        "enable": True,
        "compiler": {"enable": True},
    }
    if data_use_checks:
        data_use_product["scheduler"] = {
            "enable": True,
            "poll_seconds": 3_600,
            "lease_seconds": 900,
            "history_limit": 50,
        }
    if data_use_native is not None:
        data_use_product["enforcement"] = {
            "enable": True,
            "require_four_eyes": True,
            "max_attempts": 3,
        }
        data_use_product[str(data_use_native["provider"])] = data_use_native["section"]
        provider_audit_config: dict[str, Any] = {
            "enable": data_use_provider_audit,
            "audit_window_seconds": (
                14_400
                if data_use_provider_audit and data_use_native["provider"] == "snowflake"
                else 3_600
            ),
            "retention_seconds": 31_536_000,
            "max_attempts": 5,
            "cursor_overlap_seconds": 300,
            "max_pages_per_read": 20,
            "scheduler": {
                "enable": data_use_provider_audit_scheduler,
                "poll_seconds": 60,
                "claim_limit": 10,
                "tenant_limit": 1_000,
                "lease_seconds": 120,
                "event_limit": 100,
                "retry_backoff_seconds": 30,
                "purge_limit": 100,
            },
        }
        if data_use_provider_audit and data_use_native["provider"] == "snowflake":
            provider_audit_config["snowflake_latency_watermark_seconds"] = 10_800
        data_use_product["provider_audit"] = provider_audit_config
    return data_use_product


def _pick_paper_review_and_graph() -> tuple[bool, str, bool]:
    """Vendor-paper review model use, the drafting entity name and the entity graph."""
    console.print()
    console.print(
        "[dim]Vendor-paper review compares a vendor's own DPA or privacy "
        "addendum against your standard positions and produces a Word "
        "tracked-changes redline. Which clauses fall short is always decided "
        "deterministically from the clause checklists; a model is used only to "
        "re-word YOUR required clause to match the vendor's drafting, and any "
        "draft that weakens your position is discarded. Say no and the redline "
        "uses your template language verbatim -- no model sees the "
        "contract.[/dim]"
    )
    draft = _q_confirm(
        "Let a model re-word your standard clauses to match vendor drafting?", default=True
    )
    console.print()
    console.print(
        "[dim]When a vendor signs YOUR paper, Lightwork drafts your template "
        "DPA/addendum as a Word document with the vendor-specific values "
        "filled in red for counsel to verify. Your legal entity name goes on "
        "the party line; leave blank to keep a red placeholder.[/dim]"
    )
    org_name = _q_text(
        "Legal entity name for drafted agreements (blank = placeholder)", default=""
    ).strip()
    console.print()
    console.print(
        "[dim]The entity graph links your records into one lineage: every "
        "vendor, reviewer, document, and clause becomes one identity, and "
        "every review/decision becomes a dated, citable edge — so you can ask "
        "'why did we approve this vendor?', 'what did we know on the day we "
        "signed?', and 'this clause turned out bad — what relied on it?'. "
        "Derived and read-only: it is rebuilt from your records and never "
        "stores anything they don't say.[/dim]"
    )
    graph = _q_confirm("Enable the entity graph (lineage & dossier queries)?", default=True)
    return draft, org_name, graph


def _cfg_assessments(assessments: dict[str, Any] | None) -> list[str]:
    if not assessments:
        return []
    # Assessment assists + privacy ops are default-on; write tables only when
    # the operator opted OUT of something (write-only-on-divergence).
    body = {
        k: v
        for k, v in assessments.items()
        if k
        not in (
            "privacy_ops",
            "privacy_automation",
            "consent_preferences",
            "data_use_governance",
            "paper_review_use_model",
            "paper_review_org",
            "entity_graph",
        )
    }
    lines: list[str] = []
    if body:
        lines += ["", "[assessments]"]
        for k, v in body.items():
            _emit_kv(lines, k, v)
    if "privacy_ops" in assessments:
        lines += ["", "[privacy_ops]"]
        _emit_kv(lines, "enable", assessments["privacy_ops"])
    consent = assessments.get("consent_preferences")
    if consent is True:
        lines += ["", "[consent_preferences]"]
        _emit_kv(lines, "enable", True)
    elif isinstance(consent, dict):
        _append_nested_product_config(lines, "consent_preferences", consent)
    data_use = assessments.get("data_use_governance")
    if isinstance(data_use, dict):
        _append_nested_product_config(lines, "data_use_governance", data_use)
    privacy_automation = assessments.get("privacy_automation")
    if isinstance(privacy_automation, dict):
        _append_nested_product_config(lines, "privacy_automation", privacy_automation)
    if "paper_review_use_model" in assessments or "paper_review_org" in assessments:
        lines += ["", "[paper_review]"]
        if "paper_review_use_model" in assessments:
            _emit_kv(lines, "use_model", assessments["paper_review_use_model"])
        if "paper_review_org" in assessments:
            _emit_kv(lines, "org_name", assessments["paper_review_org"])
    if "entity_graph" in assessments:
        lines += ["", "[entity_graph]"]
        _emit_kv(lines, "enable", assessments["entity_graph"])
    return lines
