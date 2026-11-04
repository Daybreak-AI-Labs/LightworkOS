"""Disposable real-dashboard browser fixture. Local fake providers only.

This executable is never imported by the product. It owns a new temporary home,
binds loopback, pins an explicit synthetic principal, and blocks outbound sockets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

CONFIG = '''
[features]
employee_content_access_requests = true
draft_recovery = true
record_search = true
action_center = true
guided_onboarding = true
project_reviews = true
outcome_measurement = true
workspace_recovery = true
[copilot]
operation_families = ["learning", "commitments"]
[vendor_onboarding]
enable = true
resource_owner = "procurement"
[vendor_management]
enable = true
[ai_vendor_risk]
enable = true
[model_risk_assurance]
enable = true
[ai_business_intake]
enable = true
[evidence_graph]
enable = true
[flows]
enable = true
action_episode_capture = true
action_recipes = true
action_recipe_transforms = true
action_recipe_lineage = true
require_action_recipe_lineage = false
action_evidence_issuer = "synthetic-browser-learning"
[event_triggers]
enable = true
[connections]
enable = true
[ai_cost_roi]
enable = true
[grc_sync]
enable = true
connector = "servicenow"
findings_path = "/api/now/table/sn_grc_issue"
acceptances_path = "/api/now/table/sn_risk_acknowledgement"
incidents_path = "/api/now/table/incident"
backlink_base = "https://lightwork.example.test"
[privacy_automation]
enable = true
[privacy_automation.data_discovery]
enable = true
[privacy_automation.data_discovery.adapters]
enable = true
enabled_providers = ["servicenow_cmdb"]
[consent_preferences]
enable = true
[consent_preferences.publishing]
enable = true
require_signed_publications = true
[consent_preferences.public_api]
enable = true
[enterprise]
enable = false
[voice]
auto_fetch_model = false
[budget.provider_caps]
browser-spend = 20.0
[security.tool_risk]
browser_learning_lookup = "low"
browser_learning_create = "high"
[dashboard.themes.browser-white]
bg = "#ffffff"
panel = "#ffffff"
text = "#111111"
accent = "#111111"
'''


def environment(directory):
    # Never inherit a real account/provider credential or a user's external
    # database, queue, tenant key, or configured home into acceptance tests.
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")) or name.endswith("_API_KEY"):
            os.environ.pop(name)
    config_path = directory / "config.toml"
    config_path.write_text(CONFIG, encoding="utf-8")
    os.environ.update({"MAVERICK_HOME":str(directory), "MAVERICK_CONFIG":str(config_path),
        "MAVERICK_TENANT":"browser-workspace", "MAVERICK_CLIENT_ID":"browser-client",
        "MAVERICK_PROFILE":"standard", "MAVERICK_ENTERPRISE":"0",
        "MAVERICK_ENCRYPT_AT_REST":"1", "MAVERICK_ENCRYPTION_KEY":secrets.token_hex(32),
        "MAVERICK_DESKTOP_OAUTH_TICKET_KEY":secrets.token_hex(32),
        # require_signed_publications is on above: publishing needs a signing key.
        "MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY":"hex:" + secrets.token_hex(32),
        "MAVERICK_CONNECTIONS":"1",
        "MAVERICK_DASHBOARD_ADMINS":"user:browser-reviewer,user:browser-learning-reviewer"})


def fake_connection_authorization(module):
    calls = []

    def local_connection_token(provider, form):
        if provider != "google":
            raise AssertionError("Synthetic account fixture permits only Google authorization")
        calls.append(form.get("grant_type"))
        return {"access_token":"synthetic-browser-access", "refresh_token":"synthetic-browser-refresh",
                "expires_in":3600, "token_type":"Bearer"}

    module._post_token = local_connection_token
    module._provider_identity = lambda provider, token, **_identity_inputs: {
        "provider": provider, "subject": "browser-fixture-account",
        "display_name": "Browser Fixture Account", "email": "browser@example.test",
        "email_verified": True, "hosted_domain": "example.test",
    }
    return calls


def build_app(directory):
    from fastapi import Request
    from maverick import ai_cost_roi as billing
    from maverick import (
        config,
        connection_oauth,
        connections,
        crypto_at_rest,
        grc_sync,
        model_risk_assurance,
        privacy_data_discovery,
        voice_models,
        world_model,
    )
    from maverick.file_lock import atomic_create_text, ensure_private_directory
    from maverick.governed_operations import ServiceContext
    from maverick.oidc import VerifiedPrincipal
    from maverick.paths import tenant_scope
    from maverick.vendor_onboarding import VendorOnboardingService
    from maverick.vendor_onboarding_adapters import (
        EvidenceDocument,
        FakeGoogleDriveEvidence,
        FakeJiraTickets,
    )
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import privacy_data_discovery_adapters_composition, rbac
    from maverick_dashboard.vendor_onboarding_composition import WorkflowBinding

    config.reset_config_cache()
    # Exercise the real setup worker/hash/publication logic with an explicitly
    # synthetic local byte stream. These bytes are never used for inference.
    voice_bytes = b"Synthetic browser voice model fixture; not speech weights.\n" * 1200
    voice_filename = voice_models.KNOWN_MODELS["base"][0]
    voice_models.KNOWN_MODELS["base"] = (voice_filename, hashlib.sha256(voice_bytes).hexdigest(), len(voice_bytes))
    voice_downloads = []

    class SyntheticVoiceDownload:
        def __init__(self, attempt):
            self.attempt = attempt
            self.offset = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, _maximum):
            if self.attempt == 2 and self.offset >= 2048:
                raise OSError("Synthetic voice download interruption")
            time.sleep(0.07 if self.attempt == 1 else 0.001)
            chunk = voice_bytes[self.offset:self.offset + 1024]
            self.offset += len(chunk)
            return chunk

    def synthetic_voice_open(url, *, timeout):
        if url != voice_models._BASE_URL + voice_filename or timeout > 2.0:
            raise RuntimeError("Unexpected synthetic voice download request")
        voice_downloads.append(url)
        return SyntheticVoiceDownload(len(voice_downloads))

    voice_models._open_model_url = synthetic_voice_open
    # A separately downloadable local custody copy for the synthetic rehearsal.
    # Tenant KEKs use the ordinary local derivation from this same fixture key.
    # The fresh rehearsal child cannot inherit this environment or key path.
    key_path = crypto_at_rest._key_path()
    if directory.resolve() not in key_path.resolve().parents:
        raise RuntimeError("Browser fixture key path escaped its temporary home")
    ensure_private_directory(key_path.parent)
    atomic_create_text(key_path, os.environ["MAVERICK_ENCRYPTION_KEY"])
    tenant, principal = "browser-workspace", "user:browser-reviewer"
    # Keep the real fixture database inside the named workspace's snapshot
    # scope so ordinary domain mutations exercise database recovery guards.
    world_model.DEFAULT_DB = directory / "tenants" / tenant / "world.db"
    world_model.DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
    dashboard._world_cache.clear()
    context = ServiceContext(tenant, principal, "procurement", principal, "jira", human=True)
    documents = FakeGoogleDriveEvidence({(tenant, "browser-policy"): EvidenceDocument(
        "browser-policy", "v1", time.time() - 86400,
        b"Synthetic acceptance material. We do not train on customer data. Data is encrypted at rest and in transit.")})
    tickets = FakeJiraTickets()
    grc_writes = []
    connection_exchanges = fake_connection_authorization(connection_oauth)

    def local_grc_writer(operation, path, payload):
        del operation, path
        grc_writes.append(dict(payload))
        return "ERROR: post request failed (Timeout)"

    def local_grc_reader(path, params):
        remote = [{**body, "sys_id":format(index, "032x")} for index, body in enumerate(grc_writes, 1)]
        exact = next((body for body in remote if path.endswith("/" + body["sys_id"])), None)
        if exact:
            return json.dumps({"result":exact})
        identity = params.get("sysparm_query", "").removeprefix("correlation_id=")
        matches = [body for body in remote if body.get("correlation_id") == identity]
        return json.dumps({"result":matches})

    grc_sync._default_reader = lambda settings: local_grc_reader
    service = VendorOnboardingService(documents, tickets, lambda ctx, cap, ref: ctx.binding() == context.binding())
    with tenant_scope(tenant=tenant):
        row = service.intake(context, vendor_name="Browser Northstar", document_id="browser-policy", project="TEST", purpose="Synthetic browser review")
        world = dashboard._world()
        goal_id = world.create_goal("Browser search task", "Synthetic task body excluded from cross-module search", owner=principal)
        project_id = world.create_project("Browser review project", owner=principal)
        review_goal = world.create_goal("Browser captured result", "Synthetic review task", owner=principal, project_id=project_id)
        world.set_goal_status(review_goal, "done", result="Synthetic captured deliverable. Evidence limitations remain explicit.")
        for member in (principal, "user:browser-colleague", "user:browser-outcome-owner",
                       "user:browser-outcome-readiness-owner"):
            rbac.set_tenant_role(tenant, member, "operator", actor=principal)
        with connections.bind_principal(principal):
            connections.set_connection("browser-discovery", connector="servicenow_cmdb", base_url="https://data.example.com", token="synthetic-local-test-token", owner=principal)
        def citation(label):
            return billing.SourceCitation(uri="s3://synthetic-browser-billing/" + label, sha256=hashlib.sha256(label.encode()).hexdigest(), row_ref=label)

        provider_line = billing.NormalizedBillingRecord(provider=billing.BillingProvider.OPENAI,
            source_account_id="synthetic-browser-account", source_record_id="browser-original-line",
            period_start="2026-08-01T00:00:00Z", period_end="2026-09-01T00:00:00Z", currency="USD", cost="10.000000001",
            usage=(billing.UsageQuantity("tokens", "1", "tokens"),), service="synthetic-browser-service",
            resource_id="synthetic-browser-resource", citation=citation("browser-original-line"))
        billing.default_service.ingest(billing.BillingCollection(provider=provider_line.provider, collector_id="synthetic_fixture",
            source_account_id=provider_line.source_account_id, batch_id="browser-fixture-batch", period_start=provider_line.period_start,
            period_end=provider_line.period_end, collected_at=time.time(), manifest_citation=citation("browser-manifest"), records=(provider_line,)), actor=principal)
        officer = model_risk_assurance.ModelRiskAssuranceOfficer()
        observed = officer.observe_asset(asset_type="model", source="synthetic_browser_fixture", source_id="browser-triage",
            display_name="Synthetic browser triage", version_digest=hashlib.sha256(b"synthetic-browser-model").hexdigest(),
            actor=principal, observed_at=time.time(), metadata={}, dependencies=[])
        officer.record_incident(observed["asset_id"], source_id="browser-grc-incident", severity="high",
            summary="Synthetic browser incident for held-delivery reconciliation.", actor=principal, occurred_at=time.time()-60, evidence_ids=[])
        grc_sync.run_sync(actor=principal, writer=local_grc_writer)
        held_delivery = grc_sync.list_outbound()[0]["id"]

    class LocalRows:
        def iter_rows(self, **kwargs):
            del kwargs
            yield privacy_data_discovery.StructuredRecord("synthetic-row", {"email":"never-return-this-value@example.test"})

    local_rows = LocalRows()
    stock_snapshot = privacy_data_discovery_adapters_composition.snapshot_for_tenant

    def local_snapshot(*args, **kwargs):
        snapshot = stock_snapshot(*args, **kwargs)
        return replace(snapshot, registry=replace(snapshot.registry, structured={"servicenow_cmdb":local_rows}, unstructured={}))

    privacy_data_discovery_adapters_composition.snapshot_for_tenant = local_snapshot
    dashboard.app.state.privacy_data_discovery_structured_sources = {"servicenow_cmdb":local_rows}
    dashboard.app.state.vendor_onboarding_binding_factory = lambda request: WorkflowBinding(service, context)
    dashboard.app.state.vendor_onboarding_demo = True

    @dashboard.app.middleware("http")
    async def fixture_principal(request: Request, call_next):
        subject = request.headers.get("X-Browser-Principal", "browser-reviewer")
        if subject not in {"browser-reviewer", "browser-colleague", "browser-learning-reviewer",
                           "browser-outcome-owner", "browser-outcome-readiness-owner"}:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail":"Unknown synthetic browser principal"}, status_code=403)
        request.state.principal = VerifiedPrincipal(
            sub=subject,
            issuer="https://synthetic-browser-identity.example.test",
            audience="lightwork-browser-fixture",
            claims={"fixture": True},
        )
        return await call_next(request)

    @dashboard.app.get("/__browser_fixture", include_in_schema=False)
    async def fixture_state():
        return {"synthetic":True, "case_id":row["id"], "goal_id":goal_id,
                "project_id":project_id, "review_goal":review_goal,
                "grc_delivery":held_delivery, "grc_writes":len(grc_writes),
                "review_signoff":world.signoff_for(review_goal),
                "ticket_creates":tickets.creates, "outbound_calls":"blocked",
                "voice_download_attempts":len(voice_downloads), "voice_fixture":"synthetic bytes; no inference",
                "connection_exchanges":len(connection_exchanges), "connection_fixture":"synthetic token exchange; no provider consent"}

    @dashboard.app.post("/__browser_fixture/spending", include_in_schema=False)
    async def fixture_spending():
        from maverick import provider_cost_cap
        with tenant_scope(tenant=tenant):
            hold = provider_cost_cap.reserve("browser-spend", 3, request_id="browser-cost-review")
            provider_cost_cap.reserve("browser-spend", 2, request_id="browser-other-running-call")
            provider_cost_cap.settle(hold, None)
        return {"synthetic": True, "provider_calls": 0}

    from fixture_chat_actions import install as install_chat_actions_fixture
    install_chat_actions_fixture(dashboard.app, world, tenant, principal)
    from fixture_pilot_learning import install as install_pilot_learning_fixture
    install_pilot_learning_fixture(dashboard.app, world, tenant, principal)
    from fixture_outcome_value import install as install_outcome_value_fixture
    install_outcome_value_fixture(dashboard.app, world, tenant, principal)
    from fixture_knowledge_access import install as install_knowledge_access_fixture
    install_knowledge_access_fixture(dashboard.app, tenant, principal)
    from fixture_task_files import install as install_task_file_fixture
    install_task_file_fixture(dashboard.app, world, tenant, principal)
    from fixture_approvals import install as install_approvals_fixture
    install_approvals_fixture(dashboard.app, world, tenant, principal)
    from fixture_flow_approval import install as install_flow_approval_fixture
    install_flow_approval_fixture(dashboard.app, tenant, principal)
    from fixture_signed_learning import install as install_signed_learning_fixture
    install_signed_learning_fixture(dashboard.app, tenant, principal)
    from fixture_learned_skill import install as install_learned_skill_fixture
    install_learned_skill_fixture(dashboard.app, world, tenant)
    return dashboard.app


# Longer than any idle gap between a spec's API calls. With uvicorn's 5-second
# default, the server could close a pooled keep-alive connection just as
# Playwright's request context reused it, failing the call with ECONNRESET.
KEEP_ALIVE_SECONDS = 75


def block_outbound():
    original = socket.socket.connect

    def local_connect(self, address):
        if isinstance(address, tuple) and str(address[0]) not in {"127.0.0.1", "::1", "localhost"}:
            raise OSError("Outbound connections are blocked by the synthetic browser fixture")
        return original(self, address)

    socket.socket.connect = local_connect


def exit_cleanly_on_sigterm():
    """Turn SIGTERM into an ordinary exit so the temporary home is removed.

    Playwright stops a fixture server with SIGTERM. uvicorn then shuts down and
    raises the signal again under the previous handler; with the default one the
    process ends there, before any TemporaryDirectory can delete its folder.
    """
    def stop(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)


def main():
    import uvicorn

    exit_cleanly_on_sigterm()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument(
        "--show-vendor-setup",
        action="store_true",
        help="Show setup controls with synthetic browser identity and provider fixtures only",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lightwork-browser-") as temporary:
        directory = Path(temporary)
        environment(directory)
        block_outbound()
        app = build_app(directory)
        if args.show_vendor_setup:
            app.state.vendor_onboarding_demo = False
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning", timeout_keep_alive=KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
