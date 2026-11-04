"""Rendered contracts for the additive AI-governance operator panels."""

from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _intake_controller(page):
    script = '/static/lightwork-ai-business-intake.js'
    # Static tags carry a content-hash cache key (static_asset_versioning).
    tag = re.compile(rf'<script src="{re.escape(script)}(?:\?v=[0-9a-f]{{8}})?" defer></script>')
    assert len(tag.findall(page)) == 1
    response = client.get(script)
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    return response.text


@pytest.fixture(autouse=True)
def _isolated_page(tmp_path, monkeypatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "governance-operator-test")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_assurance_page_renders_all_governance_operator_contracts():
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    for panel_id in (
        "governance-operations-panel",
        "ai-literacy-panel",
        "article-73-panel",
        "ai-business-intake-panel",
        "ai-cost-roi-panel",
        "ai-policy-management-panel",
        "dynamic-risk-panel",
        "runtime-guardrails-panel",
        "ai-explainability-panel",
        "ai-insurability-panel",
        "ai-conformity-panel",
        "ai-regulated-package-workbench",
        "ai-benchmark-panel",
        "ai-discovery-sensors-panel",
        "ai-identity-governance-panel",
        "ai-media-provenance-panel",
        "grc-outbound-panel",
    ):
        assert f'id="{panel_id}"' in page

    for api_contract in (
        '"/ai-literacy/requirements"',
        '"/ai-literacy/evidence-export"',
        '"/eu-ai-incidents?limit=100"',
        '"/ai-cost-roi/collectors"',
        '"/ai-cost-roi/portfolio"',
        '"/ai-policy-management/policies"',
        '"/ai-policy-management/exceptions"',
        '"/ai-policy-management/evaluations"',
        '"/ai-policy-management/preview"',
        '"/dynamic-risk/signals"',
        '"/runtime-guardrails/evaluate"',
        '"/ai-explainability/explanations"',
        '"/ai-insurability/profiles"',
        '"/ai-conformity/cases"',
        '"/ai-bank-mrm/packages"',
        '"/ai-regulated-verticals/packages"',
        '"/ai-benchmark/contributions"',
        '"/ai-benchmark/cohort-reports"',
        '"/ai-discovery-sensors/sensors"',
        '"/ai-discovery-sensors/findings"',
        '"/identity-governance/connectors"',
        '"/identity-governance/scheduler/status"',
        '"/identity-governance/scheduler/run"',
        '"/identity-governance/controls/status"',
        '"/identity-governance/controls/purview/writebacks/prepare"',
        '"/ai-media-provenance/capabilities"',
        '"/ai-media-provenance/verify"',
        '"/grc-outbound/events?limit=100"',
    ):
        assert api_contract in page

    intake = _intake_controller(page)
    assert "base='/api/v1/security/assurance/ai-business-intake'" in intake
    for api_contract in (
        "api('/form')",
        "api('/drafts?'",
        "api('/drafts'+(current?",
        "api('/drafts/'+encodeURIComponent(current.id)+'/submit','POST'",
    ):
        assert api_contract in intake
    assert "X-Lightwork-Intake-Context" in intake

    assert "not a legal conclusion" in page
    assert "does not file reports" in page
    assert "Preview never transmits" in page
    assert "calculated ROI is" in page
    assert "not a verified financial outcome" in page
    assert "live, read-only billing" in page
    assert "Passwords and keys are never shown here" in page
    assert "OpenAI organization costs" in page
    assert "OpenAI (unsupported)" not in page
    assert "not a legal conclusion" in page
    assert "compliance certification" in page
    assert "does not discover, poll, or stream live telemetry" in page
    assert "This was not a live check of the system" in page
    # The precise safeguard wording is kept for auditors under "Technical details".
    assert "versioned Ed25519 report trust roots and an HTTPS coordinator" in page
    assert "transmission remains a separate human action" in page
    assert "independently verified differential privacy" in page
    assert "control plane only" in page
    assert "deploys no live browser, network, OAuth, SaaS" in page
    assert "makes no completeness" in page
    assert "one-shot or opt-in scheduled" in page
    assert "Scheduler history retains bounded digests" in page
    assert "provider writes and makes no live-acceptance" in page
    assert "not raw provider rows" in page
    assert "complete-inventory" in page
    assert "automatic-risk claim" in page
    assert "tenant-bound runtime attached by server startup" in page
    assert "A Purview prepare creates no provider write" in page
    assert "cannot supply raw" in page
    assert "selected local <code>c2patool</code> verifier" in page
    assert "signing still requires" in page
    assert "default verification and signing" in page
    assert "persisted. Adapter-reported validation" in page
    assert "Lightwork certification, proof of authorship or truth" in page
    assert "not a certification or a regulator's approval" in page
    # Failures are plain sentences: no status codes or server wording.
    assert "(HTTP ${response.status})" not in page
    assert "This was changed since you opened it" in page


def test_governance_panels_render_api_values_as_text_only():
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    fragment = page[
        page.index('<section class="panel" id="governance-operations-panel"'):
        page.index('<p><a class="back-link" href="/security">')
    ]
    assert "td.textContent = asText(value)" in fragment
    assert "target.textContent = JSON.stringify(value" in fragment
    assert ".innerHTML" not in fragment
    assert ".outerHTML" not in fragment
    assert "insertAdjacentHTML" not in fragment
    assert "document.write" not in fragment
    assert "eval(" not in fragment
    assert "No coverage conclusion is shown" in page
    assert "No deadline conclusion is shown" in page
    assert "No financial conclusion is shown" in page
    assert "No delivery conclusion is shown" in page
    assert "No policy-coverage conclusion is shown" in page
    assert "No monitoring-coverage conclusion is shown" in page
    assert "No network, cohort, or coverage conclusion is shown" in page
    assert "No discovery-completeness conclusion is shown" in page
    assert "No identity-completeness conclusion is shown" in page
    assert "No grant-completeness conclusion is shown" in page
    assert "No classification-completeness conclusion is shown" in page
    assert "No provenance-coverage conclusion is shown" in page


def test_identity_control_workbench_is_pseudonymous_explicit_and_default_off():
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    fragment = page[
        page.index('<section id="ai-identity-governance-panel"'):
        page.index('<section id="ai-media-provenance-panel"')
    ]
    for element_id in (
        "ai-identity-control-workbench",
        "ai-identity-control-status",
        "ai-identity-control-evaluate",
        "ai-identity-federation-observe",
        "ai-identity-capability-map",
        "ai-identity-capability-decision",
        "ai-identity-conditional-decision",
        "ai-identity-purview-prepare",
        "ai-identity-purview-resume",
        "ai-identity-purview-get",
        "ai-identity-purview-execute",
        "ai-identity-purview-compensate",
        "ai-identity-control-result",
    ):
        assert f'id="{element_id}"' in fragment
    assert 'name="principal_ref"' in fragment
    assert 'name="provider_subject_id"' in fragment
    assert 'name="principal"' not in fragment
    assert 'name="credential"' not in fragment
    assert "it cannot supply raw" in fragment
    assert "A Purview prepare creates no provider write" in fragment
    script = page[page.index("const identityControlStatus"):]
    prepare_handler = script[
        script.index('const identityPurviewPrepare ='):
        script.index('const identityPurviewResume =')
    ]
    assert '"/identity-governance/controls/purview/writebacks/prepare"' in prepare_handler
    assert "/execute" not in prepare_handler
    assert "/compensate" not in prepare_handler
    assert 'showProjection("ai-identity-control-result"' in script


def test_policy_and_dynamic_risk_forms_cover_exact_bounded_api_contracts():
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    for form_id in (
        "ai-policy-record-query",
        "ai-policy-preview",
        "ai-policy-create",
        "ai-policy-version",
        "ai-policy-activate",
        "ai-policy-exception-request",
        "ai-policy-exception-approve",
        "ai-policy-exception-close",
        "ai-policy-evaluate",
        "ai-policy-attest",
        "dynamic-risk-asset-query",
        "dynamic-risk-signal-query",
        "dynamic-risk-signal-ingest",
        "dynamic-risk-score",
        "dynamic-risk-resolve",
        "dynamic-risk-supersede",
        "runtime-guardrails-evaluate",
        "ai-explainability-list",
        "ai-explainability-detail",
        "ai-explainability-ingest",
        "ai-insurability-list",
        "ai-insurability-detail",
        "ai-insurability-create",
        "ai-insurability-version",
        "ai-conformity-list",
        "ai-conformity-detail",
        "ai-conformity-create",
        "ai-conformity-evidence",
        "ai-conformity-fria",
        "ai-conformity-route",
        "ai-conformity-checklist",
        "ai-conformity-submit",
        "ai-regulated-package-list",
        "ai-regulated-package-detail",
        "ai-regulated-package-prepare",
        "ai-benchmark-list",
        "ai-benchmark-detail",
        "ai-benchmark-prepare",
        "ai-benchmark-report-list",
        "ai-benchmark-report-detail",
        "ai-benchmark-report-ingest",
        "ai-discovery-sensor-list",
        "ai-discovery-sensor-detail",
        "ai-discovery-sensor-register",
        "ai-discovery-sensor-configure",
        "ai-discovery-sensor-revoke",
        "ai-discovery-observation-ingest",
        "ai-discovery-observation-list",
        "ai-discovery-observation-detail",
        "ai-discovery-findings",
        "ai-identity-governance-status",
        "ai-identity-governance-collect",
        "ai-identity-control-status",
        "ai-identity-control-evaluate",
        "ai-identity-purview-prepare",
        "ai-identity-purview-resume",
        "ai-media-provenance-capabilities",
        "ai-media-provenance-list",
        "ai-media-provenance-detail",
        "ai-media-provenance-receipt",
        "ai-media-provenance-verify",
        "ai-media-provenance-sign",
        "ai-media-provenance-release",
        "ai-media-provenance-review",
    ):
        assert f'id="{form_id}"' in page

    for path_contract in (
        "/policies/${encodeURIComponent(policyId)}/versions",
        "/policies/${encodeURIComponent(policyId)}/activate",
        "/evaluations/${encodeURIComponent(key)}/attest",
        "/dynamic-risk/assets/${encodeURIComponent(assetId)}",
        "/dynamic-risk/assets/${encodeURIComponent(assetId)}/signals",
        "/dynamic-risk/assets/${encodeURIComponent(assetId)}/score",
        "/dynamic-risk/signals/${encodeURIComponent(signalId)}/resolve",
        "/dynamic-risk/signals/${encodeURIComponent(signalId)}/supersede",
        "/ai-explainability/explanations/${encodeURIComponent(id)}",
        "/ai-insurability/profiles/${encodeURIComponent(profileId)}",
        "/ai-conformity/cases/${encodeURIComponent(caseId)}",
        "${regulatedPackageBase(plane)}/${encodeURIComponent(packageId)}",
        "/ai-benchmark/contributions/${encodeURIComponent(contributionId)}",
        "/ai-benchmark/cohort-reports/${encodeURIComponent(reportId)}",
        "/ai-discovery-sensors/sensors/${encodeURIComponent(sensorId)}",
        "/ai-discovery-sensors/observations/${encodeURIComponent(observationId)}",
        "/identity-governance/connectors/${encodeURIComponent(provider)}/collect",
        "/identity-governance/controls/federation/${encodeURIComponent(provider)}/observe",
        "/identity-governance/controls/capabilities/${encodeURIComponent(provider)}/map",
        "/identity-governance/controls/capabilities/${encodeURIComponent(provider)}/decision",
        "/identity-governance/controls/conditional-access/${encodeURIComponent(provider)}/decision",
        "/identity-governance/controls/purview/writebacks/${encodeURIComponent(intentId)}/get",
        "/identity-governance/controls/purview/writebacks/${encodeURIComponent(intentId)}/execute",
        "/identity-governance/controls/purview/writebacks/${encodeURIComponent(intentId)}/compensate",
        "/ai-media-provenance/records/${encodeURIComponent(provenanceId)}",
        "/ai-media-provenance/receipts/${encodeURIComponent(operation)}",
    ):
        assert path_contract in page
    # Exception request/approve/close moved to their reviewed controller
    # (b0ffccbb); it still writes only through the native exception routes.
    exceptions = client.get("/static/lightwork-policy-exceptions.js")
    assert exceptions.status_code == 200
    assert "'/ai-policy-management/exceptions/' + encodeURIComponent(previous.exception_key) + '/' + kind" in exceptions.text
    assert "kind === 'approve'" in exceptions.text and "kind === 'close'" in exceptions.text
    assert '<script src="/static/lightwork-policy-exceptions.js' in page

    # AI systems are picked from the inventory, never typed as MAA- IDs.
    assert 'pattern="MAA-[0-9a-f]{32}"' not in page
    assert '<select class="select" name="asset_id" required><option value="">Choose an AI system</option>' in page
    # Fingerprints, references and version numbers are never typed.
    assert 'pattern="[0-9a-f]{64}"' not in page
    assert 'pattern="prn_[0-9a-f]{32}"' not in page
    assert 'pattern="(?:sub|idn)_[0-9a-f]{32}"' not in page
    assert 'pattern="IGPW-[0-9a-f]{32}"' not in page
    assert "JSON exceeds" not in page
    assert "parseObject(" not in page
    assert "encodeURIComponent(key)" in page
    assert "encodeURIComponent(policyId)" in page
    assert "encodeURIComponent(assetId)" in page
    assert "encodeURIComponent(signalId)" in page
    assert "The text you entered was not saved" in page
    assert "Raw feature values" in page
    assert "policy facts come from its current" in page
    assert "voluntary_opt_in: true" in page
    assert "It does not claim that every AI tool in your organisation was found" in page
    assert "Array.isArray(item.classification_codes)" in page
    assert '"/pickers/identity-controls"' in page
    assert "The service's sign-in rules were only read, not changed" in page
    assert 'enctype="multipart/form-data"' in page
    assert 'prefix + "/ai-media-provenance/sign"' in page
    assert 'mediaProvenanceReceipt.elements.receipt_file' in page
    assert "mediaProvenanceVerify.elements.file.value = \"\"" in page


def test_governance_operations_inline_javascript_has_valid_syntax(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for the optional JavaScript syntax check")
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    start = page.index('<section class="panel" id="governance-operations-panel"')
    end = page.index('<p><a class="back-link" href="/security">', start)
    fragment = page[start:end]
    match = re.search(r'<script nonce="[^"]*">(.*?)</script>', fragment, flags=re.DOTALL)
    assert match is not None
    script_path = tmp_path / "governance-operations.js"
    script_path.write_text(match.group(1), encoding="utf-8")
    result = subprocess.run(
        [node, "--check", str(script_path)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_assurance_modules_lazy_load_each_read_group_once():
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert '"IntersectionObserver" in window' in page
    assert 'rootMargin: "240px 0px"' in page
    assert 'id="governance-operations-load-all"' in page
    assert "const loadedPanels = new Set();" in page
    assert "loadedPanels.has(item[0])" in page
    assert 'panel.addEventListener("focusin"' in page
    assert "panelObserver.unobserve(panel)" in page
    assert "Promise.all(panelLoaders.map(loadPanel))" in page
    for panel_id in (
        "ai-literacy-panel",
        "article-73-panel",
        "ai-cost-roi-panel",
        "ai-policy-management-panel",
        "ai-explainability-panel",
        "ai-insurability-panel",
        "ai-conformity-panel",
        "ai-regulated-package-workbench",
        "ai-benchmark-panel",
        "ai-discovery-sensors-panel",
        "ai-identity-governance-panel",
        "ai-media-provenance-panel",
        "grc-outbound-panel",
    ):
        assert f'["{panel_id}",' in page

    # The guided intake initializes from its deferred controller; registering it
    # in the generic summary loader too would issue duplicate draft reads.
    assert '["ai-business-intake-panel",' not in page
    intake = _intake_controller(page)
    assert intake.count("run(initialize);") == 1
    assert "await api('/form')" in intake
    assert "await list();" in intake


def test_non_admin_page_withholds_admin_governance_mutations(monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)

    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert 'data-governance-admin="false"' in page
    assert 'id="ai-literacy-requirement-upsert"' not in page
    assert 'id="ai-literacy-assignment-set"' not in page
    assert 'id="article-73-route"' not in page
    assert 'id="article-73-report-draft"' not in page
    assert 'id="grc-outbound-sync"' not in page
    assert 'id="ai-cost-collector-run"' not in page
    assert 'id="ai-policy-create"' not in page
    assert 'id="ai-policy-version"' not in page
    assert 'id="ai-policy-activate"' not in page
    assert 'id="ai-policy-exception-request"' not in page
    assert 'id="ai-policy-exception-approve"' not in page
    assert 'id="ai-policy-exception-close"' not in page
    assert 'id="ai-policy-evaluate"' not in page
    assert 'id="ai-policy-attest"' not in page
    assert 'id="dynamic-risk-signal-ingest"' not in page
    assert 'id="dynamic-risk-score"' not in page
    assert 'id="dynamic-risk-resolve"' not in page
    assert 'id="dynamic-risk-supersede"' not in page
    assert 'id="ai-explainability-review"' not in page
    assert 'id="ai-insurability-approve"' not in page
    assert 'id="ai-conformity-approve"' not in page
    assert 'id="ai-regulated-package-approve"' not in page
    assert 'id="ai-benchmark-approve"' not in page
    assert 'id="ai-discovery-sensor-approve"' not in page
    assert 'id="ai-discovery-revocation-approve"' not in page
    assert 'id="ai-media-provenance-sign"' not in page
    assert 'id="ai-media-provenance-review"' not in page
    assert 'id="ai-identity-control-status"' not in page
    assert 'id="ai-identity-control-evaluate"' not in page
    assert 'id="ai-identity-purview-prepare"' not in page
    assert 'id="ai-identity-purview-resume"' not in page
    assert "/requirements/${encodeURIComponent(key)}" not in page
    assert "/routing`" not in page
    assert "/reports/${report}/approve" not in page
    assert "/policies/${encodeURIComponent(policyId)}/versions" not in page
    assert "/policies/${encodeURIComponent(policyId)}/activate" not in page
    assert "/exceptions/${encodeURIComponent(key)}/approve" not in page
    assert "/evaluations/${encodeURIComponent(key)}/attest" not in page
    assert "/dynamic-risk/signals/${encodeURIComponent(signalId)}/resolve" not in page
    assert "/dynamic-risk/signals/${encodeURIComponent(signalId)}/supersede" not in page
    assert "/ai-explainability/explanations/${encodeURIComponent(id)}/review" not in page
    assert "/ai-benchmark/contributions/${encodeURIComponent(contributionId)}/approve" not in page
    assert "/ai-discovery-sensors/sensors/${encodeURIComponent(sensorId)}/approve" not in page
    assert "/ai-discovery-sensors/sensors/${encodeURIComponent(sensorId)}/revocation/approve" not in page
    assert 'prefix + "/ai-media-provenance/sign"' not in page
    assert "/ai-media-provenance/records/${encodeURIComponent(provenanceId)}/review" not in page
    assert "/identity-governance/controls/status" not in page
    assert "/identity-governance/controls/purview/writebacks/prepare" not in page
    assert 'sendJson("/ai-policy-management/policies"' not in page
    assert 'sendJson("/ai-policy-management/exceptions"' not in page
    assert 'sendJson("/ai-policy-management/evaluations"' not in page
    assert 'sendJson("/dynamic-risk/signals"' not in page
    # Tenant operators retain the non-admin intake, preview, and evidence tools.
    assert 'id="abi-answers"' in page
    assert 'id="abi-fields"' in page
    assert 'id="abi-save" type="submit"' in page
    assert 'id="abi-submit" type="button" class="btn btn--primary" disabled' in page
    assert 'id="abi-open"' in page
    intake = _intake_controller(page)
    assert "!contract.can_edit" in intake
    assert "if(!contract.can_edit||conflicted" in intake
    assert 'id="grc-outbound-preview"' in page
    assert 'id="ai-literacy-export"' in page
    assert 'id="ai-policy-record-query"' in page
    assert 'id="ai-policy-preview"' in page
    assert 'id="dynamic-risk-asset-query"' in page
    assert 'id="dynamic-risk-signal-query"' in page
    assert 'id="ai-explainability-ingest"' in page
    assert 'id="ai-insurability-create"' in page
    assert 'id="ai-conformity-create"' in page
    assert 'id="ai-regulated-package-prepare"' in page
    assert 'id="ai-benchmark-prepare"' in page
    assert 'id="ai-benchmark-report-ingest"' in page
    assert 'id="ai-discovery-sensor-register"' in page
    assert 'id="ai-discovery-sensor-configure"' in page
    assert 'id="ai-discovery-sensor-revoke"' in page
    assert 'id="ai-discovery-observation-ingest"' in page
    assert 'id="ai-identity-governance-collect"' in page
    assert 'id="ai-media-provenance-receipt"' in page
    assert 'id="ai-media-provenance-verify"' in page
    assert 'id="ai-media-provenance-release"' in page


def test_admin_page_explains_trusted_article_73_authority_boundary():
    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert 'data-governance-admin="true"' in page
    assert "administrator-configured trusted" in page
    assert "directory" in page
    assert "cannot supply or override them" in page
    assert 'id="article-73-route"' in page
    assert 'id="grc-outbound-sync"' in page
    assert 'id="ai-cost-collector-run"' in page
    assert 'id="ai-policy-activate"' in page
    assert 'id="ai-policy-exception-approve"' in page
    assert 'id="ai-policy-attest"' in page
    assert 'id="dynamic-risk-signal-ingest"' in page
    assert 'id="dynamic-risk-resolve"' in page
    assert 'id="ai-explainability-review"' in page
    assert 'id="ai-insurability-approve"' in page
    assert 'id="ai-conformity-approve"' in page
    assert 'id="ai-regulated-package-approve"' in page
    assert 'id="ai-benchmark-approve"' in page
    assert 'id="ai-discovery-sensor-approve"' in page
    assert 'id="ai-discovery-revocation-approve"' in page
    assert 'id="ai-identity-governance-collect"' in page
    assert 'id="ai-identity-control-status"' in page
    assert 'id="ai-identity-control-evaluate"' in page
    assert 'id="ai-identity-purview-prepare"' in page
    assert 'id="ai-identity-purview-resume"' in page
    assert 'id="ai-media-provenance-sign"' in page
    assert 'id="ai-media-provenance-review"' in page
    assert 'sendJson("/ai-policy-management/policies"' in page
    # A new exception is requested through the reviewed controller.
    assert "kind === 'request' ? '/ai-policy-management/exceptions'" in client.get(
        "/static/lightwork-policy-exceptions.js").text
    assert 'sendJson("/ai-policy-management/evaluations"' in page
    assert 'sendJson("/dynamic-risk/signals"' in page
    assert "/collect`" in page
    assert "/sync`" in page
    assert "authority_role:" not in page
    assert "authority_refs:" not in page


class _VisibleText(HTMLParser):
    """Collect what a person sees: text and prompts, not scripts, styles or
    the collapsed "Technical details" kept for auditors."""

    _VOID = {"input", "br", "meta", "link", "img", "hr", "option", "source"}

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.stack: list[list] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag not in self._VOID:
            skip = tag in {"script", "style"}
            self.stack.append([tag, skip])
            self.hidden += skip
        if not self.hidden:
            for name in ("placeholder", "title", "aria-label", "alt"):
                if values.get(name):
                    self.parts.append(values[name])

    def handle_endtag(self, tag):
        while self.stack:
            name, skip = self.stack.pop()
            self.hidden -= skip
            if name == tag:
                break

    def handle_data(self, data):
        text = data.strip()
        if text == "Technical details":
            for entry in reversed(self.stack):
                if entry[0] == "details":
                    if not entry[1]:
                        entry[1] = True
                        self.hidden += 1
                    break
            return
        if text and not self.hidden:
            self.parts.append(text)


_BANNED = re.compile(
    r"json|sha-?256|digest|principal|revision|idempotency|tenant|endpoint|schema|uuid|ed25519",
    re.IGNORECASE,
)


def _governance_fragment(page: str) -> str:
    return page[
        page.index('<section class="panel" id="governance-operations-panel"'):
        page.index('<p><a class="back-link" href="/security">')
    ]


def _visible(fragment: str) -> str:
    parser = _VisibleText()
    parser.feed(fragment)
    return "\n".join(parser.parts)


@pytest.mark.parametrize("admin", [True, False])
def test_governance_tools_offer_forms_and_pickers_in_plain_words(monkeypatch, admin):
    from maverick_dashboard import auth

    if not admin:
        monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)
    response = client.get("/security/assurance")

    assert response.status_code == 200
    fragment = _governance_fragment(response.text)
    hits = [line for line in _visible(fragment).splitlines() if _BANNED.search(line)]
    assert hits == []
    # No data-format text boxes remain; structured requests are guided forms.
    assert re.search(
        r'<textarea[^>]*name="(statements|context|scope|details|receipt|'
        r'evidence_bindings|report|observation|source|action_arguments)"',
        fragment,
    ) is None
    for slot in (
        "policy-context",
        "insurability-create",
        "insurability-version",
        "regulated-content",
        "benchmark-evidence",
        "discovery-observation",
        "action-details",
    ):
        assert f'data-structured="{slot}"' in fragment
    assert re.search(
        r'<script src="/static/lightwork-assurance-forms\.js(?:\?v=[0-9a-f]{8})?"></script>',
        fragment,
    )
    # Records, versions and outside results are chosen, never typed.
    assert 'name="source_choice" required data-grc-source' in fragment
    assert 'data-version-options="profile"' in fragment
    assert 'name="section" required data-conformity-sections' in fragment
    assert 'name="deployment_id" required data-deployment-choice' in fragment
    assert 'name="receipt_file"' in fragment and 'name="report_file"' in fragment
    assert 'name="purpose_code" required><option' in fragment
    assert 'name="incident_member_states" value="DE"' in fragment
    # Values that come from other systems are picked from what Lightwork
    # already has, with typing only as a clearly secondary fallback.
    assert fragment.count('<fieldset class="assurance-form__wide" data-provision-picker') == 4
    assert fragment.count("<select class=\"select\" data-provision-choice") == 4
    assert re.search(r'<input[^>]*name="provision"', fragment) is None
    assert re.search(r'<input[^>]*name="context_id"', fragment) is None
    assert fragment.count('<div class="assurance-form__wide" data-release-picker>') == (2 if admin else 1)
    assert fragment.count('<select class="select" required data-release-choice>') == (2 if admin else 1)
    assert '"/pickers/media-release-references"' in fragment
    assert '"/pickers/legal-provisions"' in fragment
    assert "Employee number from your HR system" in fragment
    if admin:
        assert '<fieldset class="assurance-form__wide" data-purview-labels>' in fragment
        assert re.search(r'<input[^>]*name="classification_codes"', fragment) is None
        assert 'list="ai-literacy-edition-choices"' in fragment
        assert "Filing reference the authority gave you" in fragment
        assert 'name="submission_reference" required maxlength="128"' in fragment
    else:
        assert '<fieldset class="assurance-form__wide" data-purview-labels>' not in fragment
    if admin:
        assert 'name="resolution_code" required><option value="fixed">' in fragment
        assert 'data-structured="report-details"' in fragment
        assert 'data-structured="policy-create-statements"' in fragment
        assert 'data-structured="exception-scope"' in fragment
        assert 'name="identity_choice" required data-identity-choice' in fragment
        assert 'name="intent_choice" required data-purview-intent-choice' in fragment
        assert 'select class="select" name="version" required data-policy-versions' in fragment
    else:
        assert 'data-identity-choice' not in fragment


def test_assurance_forms_script_is_served():
    response = client.get("/static/lightwork-assurance-forms.js")

    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "window.LWAssuranceForms" in response.text


def test_governance_record_fields_are_labelled_in_plain_words():
    from pathlib import Path

    from maverick_dashboard import app as app_module

    source = (Path(app_module.__file__).parent / "templates" / "_governance_operations.html").read_text(encoding="utf-8")
    block = source[source.index("const FIELD_LABELS = {"):source.index("const fieldLabel = key =>")]
    labels = dict(re.findall(r'(\w+): "([^"]+)"', block))
    # Every record list shows the plain label, not the raw key.
    assert 'dt.textContent = fieldLabel(key);' in source
    assert "dt.textContent = words(key);" not in source
    for key, plain in {"sysparm_query": "ServiceNow search", "four_eyes_approved": "Approved by a second person",
                       "projection": "Summary", "asset_binding": "Linked AI system",
                       "media_bytes_persisted": "Media file stored"}.items():
        assert labels[key] == plain
    developer = re.compile(r"\b(projection|binding|sysparm|cursor|idempotent|payload|schema|manifest|"
                           r"canonical|plane|seam|adapter|sink|dispatch|params|uri|hex|arn|"
                           r"determination|supersession|persisted|truncated|lease)\b", re.IGNORECASE)
    assert not [label for label in labels.values() if developer.search(label)]
