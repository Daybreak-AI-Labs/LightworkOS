"""Source-level guardrails for fail-closed governance workbench responses."""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATES = Path(__file__).parents[1] / "maverick_dashboard" / "templates"
STATIC = Path(__file__).parents[1] / "maverick_dashboard" / "static"

FAIL_CLOSED_TEMPLATES = (
    "agents.html",
    "compliance_scope_actions.html",
    "compliance_scoping.html",
    "consent_delivery.html",
    "consent_experiments.html",
    "consent_preferences.html",
    "consent_profile_data.html",
    "consent_public_clients.html",
    "consent_publishing.html",
    "consent_scan_inventory.html",
    "consent_scan_notice_proposals.html",
    "consumer_trust_center_authority.html",
    "data_use_governance.html",
    "data_use_providers.html",
    "ekko.html",
    "policy_publication_links.html",
    "privacy_data_discovery.html",
    "privacy_notice_governance.html",
    "privacy_regulatory_intelligence.html",
    "privacy_rights_consumer_delivery.html",
    "privacy_rights_orchestration.html",
    "redact.html",
    "third_party_collaboration.html",
    "third_party_intelligence.html",
    "third_party_lifecycle.html",
)


# Pages whose requests live in static scripts rather than inline.
PAGE_SCRIPTS = {
    "privacy_data_discovery.html": (
        "lightwork-privacy-data-discovery.js",
        "lightwork-record-workflows.js",
    ),
    "privacy_regulatory_intelligence.html": (
        "lightwork-privacy-regulatory-intelligence.js",
        "lightwork-record-workflows.js",
    ),
}


# Pages rebuilt for non-technical readers fail closed with plain wording.
PLAIN_INVALID_JSON = {
    "ekko.html": "Lightwork sent back a reply this page could not read. Try again.",
}


def test_governance_workbenches_fail_closed_on_invalid_json() -> None:
    swallowed_json = re.compile(
        r"catch\s*\([^)]*\)\s*\{\s*(?:body|payload|result)\s*=\s*\{\s*\}",
        re.DOTALL,
    )
    raw_body_fallback = re.compile(r"\{\s*detail\s*:\s*(?:text|responseText)\s*\}")
    # The shell's mvFetchJSON rejects a success it cannot read (the JS tests
    # in lightwork_ui_shared_helpers cover the behaviour), so a page that
    # reads every reply through it, and never reads one itself, fails closed.
    shared = (STATIC / "lightwork-ui.js").read_text(encoding="utf-8")
    assert "Malformed success never counts as success" in shared
    assert "bad.unreadable = true" in shared

    for name in FAIL_CLOSED_TEMPLATES:
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        # A page's own client may live in a static script it loads.
        loaded = re.findall(r'src="/static/(lightwork-[a-z-]+\.js)"', source)
        for script in dict.fromkeys([*loaded, *PAGE_SCRIPTS.get(name, ())]):
            source += (STATIC / script).read_text(encoding="utf-8")
        # Every client fails closed on an unreadable response; the plain
        # wordings keep code words off the page.
        assert (PLAIN_INVALID_JSON.get(
            name, "The reply from the server could not be read. Try again."
        ) in source
                or "could not be confirmed" in source
                or "Could not read the result." in source
                or ("mvFetchJSON(" in source and ".json()" not in source)), name
        assert swallowed_json.search(source) is None, name
        assert raw_body_fallback.search(source) is None, name


def test_automation_run_queue_requires_a_json_response_before_success() -> None:
    source = (TEMPLATES / "automations.html").read_text(encoding="utf-8")
    # mvFetchJSON reads the reply and rejects one it cannot read (unreadable);
    # only a readable reply counts as started.
    parse = source.index("var j = await window.mvFetchJSON('/api/v1/flows/' + encodeURIComponent(id) + '/run'")
    success = source.index("flowsMsg.textContent = j ? 'Run started.", parse)
    unreadable = source.index("if (e.unreadable) { flowsMsg.textContent = 'The run could not be confirmed.", success)
    assert parse < success < unreadable
    assert "The run could not be confirmed." in source[success:unreadable]


def test_agent_department_deploy_does_not_turn_invalid_json_into_success() -> None:
    source = (TEMPLATES / "agents.html").read_text(encoding="utf-8")
    assert ".json().catch(function () { return {}; })" not in source
    # Both team buttons save through the shared reviewed-team client.
    assert source.count("await window.LWDepartmentTeamUpdates.open(") == 2
    client = (STATIC / "lightwork-department-team-updates.js").read_text(encoding="utf-8")
    # An unreadable reply is never a success: mvFetchJSON rejects it with the page's own sentence.
    assert "U='The result could not be confirmed. Refresh the page to check whether the team was set up.'" in client
    assert "window.mvFetchJSON(API+path," in client and "messages:{unreadable:U}" in client
    assert "return {}" not in client
