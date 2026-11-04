"""Focused regressions for truthful UI authority and recoverable async actions."""
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

PACKAGE = Path(__file__).parents[1] / "maverick_dashboard"
STATIC = PACKAGE / "static"
TEMPLATES = PACKAGE / "templates"


def _button(markup: str, element_id: str) -> str:
    match = re.search(
        rf"<button\b[^>]*\bid=[\"']{re.escape(element_id)}[\"'][^>]*>",
        markup,
    )
    assert match, f"missing button {element_id}"
    return match.group(0)


def test_tenant_operator_controls_do_not_leak_global_authority(monkeypatch, tmp_path):
    from maverick import config, runtime_overrides, world_model
    from maverick_dashboard import api, auth
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "overrides.toml")
    monkeypatch.setattr(dashboard_app, "has_global_permission", lambda _r, _p: False)
    monkeypatch.setattr(auth, "has_global_permission", lambda _r, _p: False)
    monkeypatch.setattr(dashboard_app, "has_permission", lambda _r, _p: True)
    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    config.reset_config_cache()

    client = TestClient(
        dashboard_app.app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )
    learning = client.get("/learning")
    permissions = client.get("/permissions")

    assert learning.status_code == 200
    assert permissions.status_code == 200
    assert 'data-can-halt="false"' in learning.text
    assert "only an administrator can change learning settings" in learning.text
    assert "Run learning now" not in learning.text
    assert "disabled" in _button(learning.text, "lrn-enable")
    # Global learning-policy summaries are unavailable to a tenant operator;
    # the privileged section is omitted rather than populated with fake zeros.
    assert 'id="lrn-auto-evolve"' not in learning.text
    assert "only a global administrator can change where work runs" in permissions.text
    assert "var canManageSandbox = false" in permissions.text
    # Tenant operate authority remains truthful and independently enables the
    # tenant-scoped tool overlay; it must not be collapsed into global admin.
    assert "changing tool admission requires" not in permissions.text
    assert "perm-toggle" in permissions.text


def test_destructive_clients_confirm_exact_targets_and_recover_single_flight():
    bulk = (STATIC / "lightwork-consent-bulk-jobs.js").read_text(encoding="utf-8")
    reports = (STATIC / "lightwork-third-party-executive-reports.js").read_text(
        encoding="utf-8"
    )

    assert "var operationInFlight = false" in bulk
    assert "Another operation is already running" in bulk
    assert "operationInFlight = false" in bulk
    assert "delete shell.dataset.operationInFlight" in bulk
    assert "Run the next bulk change that is due now? It may change or delete people’s consent records." in bulk
    assert "Allow \" + answers.amount + \" more consent records to be processed in this workspace?" in bulk
    assert "Permanently delete \" + count + \" finished bulk changes" in bulk

    assert "var destructiveInFlight = false" in reports
    assert "Another report change is already running" in reports
    assert "destructiveInFlight = false" in reports
    assert "delete root.dataset.destructiveInFlight" in reports
    assert "Withdraw the report “" in reports
    assert "Permanently purge up to " in reports

    # The focused opener must remain enabled until the shared confirmation
    # dialog captures it; disable only after the operator confirms.
    assert "function handle(button, work)" in bulk
    assert "return work(disableControls)" in bulk
    # Every destructive handler confirms before it disables its opener.
    assert bulk.count("disableControls();") == 10
    for confirm_then_disable in bulk.split("await CW.confirm(")[1:]:
        head = confirm_then_disable.split("\n", 2)
        assert "disableControls();" in "\n".join(head[:2]) or "return;" not in head[0]
    report_destructive = reports[
        reports.index("async function runDestructive") :
        reports.index("function setMutationReady")
    ]
    assert report_destructive.index("await confirmDestructive") < report_destructive.index(
        "control.disabled = true"
    )


def test_async_drafts_and_assessment_failures_stay_with_visible_context():
    workflow = (TEMPLATES / "workflow_builder.html").read_text(encoding="utf-8")
    assessments = (TEMPLATES / "assessments.html").read_text(encoding="utf-8")

    draft = workflow[workflow.index("async function draft()") : workflow.index("// ---- refine:")]
    assert "var draftMode = mode" in draft
    assert "var draftStillVisible = mode === draftMode" in draft
    assert "renderPlaybook(data, draftStillVisible)" in draft
    assert "renderDraft(data, draftStillVisible)" in draft
    assert "if (mode !== draftMode)" in draft
    assert "setForm(mode)" in draft
    assert "Switch back to review it" in draft

    assert 'id="as-page-msg"' in assessments
    assert "document.getElementById('as-detail-msg') || pageMsg" in assessments
    assert "Could not load the assessment register. Reload to try again." in assessments
    assert "(HTTP " not in assessments and "Request failed (" not in assessments
    assert "The assessment register is temporarily unavailable" in assessments

    assert workflow.count("if (shouldScroll !== false)") == 2
