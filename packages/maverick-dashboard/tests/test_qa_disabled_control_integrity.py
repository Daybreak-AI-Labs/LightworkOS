"""Rendered control-integrity contracts across disabled workbenches."""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


class _ControlMarkup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.by_id: dict[str, dict[str, str | None]] = {}
        self._disabled_fieldsets: list[bool] = []
        self.activation_buttons: list[tuple[dict[str, str | None], bool]] = []
        self.external_mutation_buttons: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "fieldset":
            ancestor_disabled = any(self._disabled_fieldsets)
            self._disabled_fieldsets.append(ancestor_disabled or "disabled" in values)
        element_id = values.get("id")
        if element_id:
            self.by_id[element_id] = values
        if tag == "button" and "mg-on" in (values.get("class") or "").split():
            self.activation_buttons.append((values, any(self._disabled_fieldsets)))
        if tag == "button" and any(
            name.startswith("data-xa-") for name in values
        ):
            self.external_mutation_buttons.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag == "fieldset":
            self._disabled_fieldsets.pop()


def _render(template_name: str, **context: Any) -> _ControlMarkup:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    from maverick_dashboard.app import templates as app_templates

    templates.env.filters.update(app_templates.env.filters)
    # The app's own template helpers (comments_enabled, static_url, ...), as
    # every real page render has them.
    templates.env.globals.update(app_templates.env.globals)
    templates.env.globals.update(
        nav_groups=[],
        show_settings_link=False,
        can_create_goal=False,
    )
    app = FastAPI()

    @app.get("/")
    async def page(request: Request):
        return templates.TemplateResponse(request, template_name, context)

    response = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    ).get("/")
    assert response.status_code == 200
    markup = _ControlMarkup()
    markup.feed(response.text)
    return markup


def _assert_disabled(markup: _ControlMarkup, *element_ids: str) -> None:
    for element_id in element_ids:
        attrs = markup.by_id[element_id]
        assert "disabled" in attrs, element_id
        assert attrs.get("aria-disabled") == "true", element_id


def _assert_activation_outside_disabled_controls(markup: _ControlMarkup) -> None:
    assert markup.activation_buttons
    for attrs, inside_disabled_fieldset in markup.activation_buttons:
        assert "disabled" not in attrs
        assert inside_disabled_fieldset is False


def test_data_use_core_and_compiler_controls_are_natively_disabled() -> None:
    disabled = _render(
        "data_use_governance.html",
        data_use_enabled=False,
        data_use_compiler_enabled=False,
    )
    _assert_disabled(
        disabled,
        "dug-catalog-controls",
        "dug-context-controls",
        "dug-policy-controls",
        "dug-request-controls",
        "dug-compile",
    )
    _assert_activation_outside_disabled_controls(disabled)

    compiler_off = _render(
        "data_use_governance.html",
        data_use_enabled=True,
        data_use_compiler_enabled=False,
    )
    for element_id in (
        "dug-catalog-controls",
        "dug-context-controls",
        "dug-policy-controls",
        "dug-request-controls",
    ):
        assert "disabled" not in compiler_off.by_id[element_id]
    _assert_disabled(compiler_off, "dug-compile")
    _assert_activation_outside_disabled_controls(compiler_off)


def test_consent_core_and_analytics_controls_are_natively_disabled() -> None:
    disabled = _render(
        "consent_preferences.html",
        consent_preferences_enabled=False,
        consent_analytics_enabled=False,
    )
    _assert_disabled(
        disabled,
        "cp-policy-controls",
        "cp-preference-controls",
        "cp-identity-controls",
        "cp-profile-controls",
        "cp-decision-controls",
        "cp-tracker-controls",
        "cp-analytics-controls",
    )
    _assert_activation_outside_disabled_controls(disabled)

    analytics_off = _render(
        "consent_preferences.html",
        consent_preferences_enabled=True,
        consent_analytics_enabled=False,
    )
    for element_id in (
        "cp-policy-controls",
        "cp-preference-controls",
        "cp-identity-controls",
        "cp-profile-controls",
        "cp-decision-controls",
        "cp-tracker-controls",
    ):
        assert "disabled" not in analytics_off.by_id[element_id]
    _assert_disabled(analytics_off, "cp-analytics-controls")
    _assert_activation_outside_disabled_controls(analytics_off)


def test_composition_workbenches_start_mutations_disabled_until_ready() -> None:
    proposals = _render(
        "assessment_evidence_autopopulation.html",
        api_base="/api/v1/assessment-evidence-autopopulation",
        page_path="/assess/evidence-autopopulation",
        script_path="/static/lightwork-assessment-evidence-autopopulation.js",
        style_path="/static/lightwork-assessment-evidence-autopopulation.css",
        csp_style_nonce="test-nonce",
        proposal_can_operate=True,
        proposal_can_audit=True,
        proposal_can_admin=True,
        proposal_module_enabled=True,
    )
    _assert_disabled(
        proposals,
        "aep-create-controls",
        "aep-review-controls",
    )
    # Adding approved answers is a per-row button the script only creates
    # once the service reports ready, so there is no static apply form.
    assert "aep-apply-controls" not in proposals.by_id

    reports = _render(
        "third_party_executive_reports.html",
        api_base="/api/v1/third-party/executive-reports",
        page_path="/third-party/executive-reports",
        csp_style_nonce="test-nonce",
        reports_can_create=True,
        reports_can_download=True,
        reports_can_audit=True,
        reports_can_admin=True,
        reports_can_activate=True,
        reports_module_enabled=True,
    )
    _assert_disabled(
        reports,
        "tper-create-controls",
        "tper-download-controls",
        "tper-revoke-controls",
        "tper-purge-controls",
    )


def test_disabled_composition_gates_stay_operable_outside_fieldsets() -> None:
    proposals = _render(
        "assessment_evidence_autopopulation.html",
        api_base="/api/v1/assessment-evidence-autopopulation",
        page_path="/assess/evidence-autopopulation",
        script_path="/static/lightwork-assessment-evidence-autopopulation.js",
        style_path="/static/lightwork-assessment-evidence-autopopulation.css",
        csp_style_nonce="test-nonce",
        proposal_can_operate=True,
        proposal_can_audit=True,
        proposal_can_admin=True,
        proposal_module_enabled=False,
    )
    _assert_activation_outside_disabled_controls(proposals)
    _assert_disabled(
        proposals,
        "aep-create-controls",
        "aep-review-controls",
    )
    # Adding approved answers is a per-row button the script only creates
    # once the service reports ready, so there is no static apply form.
    assert "aep-apply-controls" not in proposals.by_id

    reports = _render(
        "third_party_executive_reports.html",
        api_base="/api/v1/third-party/executive-reports",
        page_path="/third-party/executive-reports",
        csp_style_nonce="test-nonce",
        reports_can_create=True,
        reports_can_download=True,
        reports_can_audit=True,
        reports_can_admin=True,
        reports_can_activate=True,
        reports_module_enabled=False,
    )
    _assert_activation_outside_disabled_controls(reports)
    _assert_disabled(
        reports,
        "tper-create-controls",
        "tper-download-controls",
        "tper-revoke-controls",
        "tper-purge-controls",
    )


def test_continuous_evidence_and_external_enrollment_fail_closed() -> None:
    evidence = _render(
        "trc_continuous_evidence.html",
        trc_continuous_evidence_enabled=False,
    )
    _assert_disabled(evidence, "trc-refresh", "trc-run-cycle")
    # Turned off, the page keeps only a way to read an earlier setup result:
    # its root says it is off (the script then loads nothing) and none of the
    # live source or collection controls render.
    assert evidence.by_id["trc-root"].get("data-enabled") == "false"
    for live in ("trc-source-new", "trc-source-save", "trc-composition", "trc-scheduler"):
        assert live not in evidence.by_id, live
    _assert_activation_outside_disabled_controls(evidence)

    evidence_unready = _render(
        "trc_continuous_evidence.html",
        trc_continuous_evidence_enabled=True,
    )
    _assert_disabled(evidence_unready, "trc-run-cycle")
    assert "disabled" not in evidence_unready.by_id["trc-refresh"]

    external = _render(
        "external_agents.html",
        enabled=False,
        external_agents_can_manage=False,
        external_agents_can_activate=True,
        status={
            "enrolled": 0,
            "runs": 0,
            "reported_dollars": 0,
            "memory_contributions": 0,
            "over_budget": 0,
            "contained": 0,
        },
        agents=[
            {
                "id": "existing-agent",
                "description": "Existing governed agent",
                "platform_label": "Custom",
                "owner": "owner@example.test",
                "department": "risk",
                "max_risk": "medium",
                "period_spent": 0,
                "max_dollars": 10,
                "period": "monthly",
                "over_budget": True,
                "runs": 0,
                "wall_violations": 0,
                "credentials": ["rest"],
                "contained": True,
                "active": False,
                "lifecycle": "contained",
            }
        ],
        platforms={},
        surfaces=(),
    )
    _assert_disabled(external, "xa-add-controls")
    assert len(external.external_mutation_buttons) == 5
    for button in external.external_mutation_buttons:
        assert "disabled" in button
        assert button.get("aria-disabled") == "true"
    _assert_activation_outside_disabled_controls(external)


def test_readiness_clients_only_unlock_after_positive_runtime_proof() -> None:
    assessment_source = (
        PACKAGE / "static" / "lightwork-assessment-evidence-autopopulation.js"
    ).read_text(encoding="utf-8")
    reports_source = (
        PACKAGE / "static" / "lightwork-third-party-executive-reports.js"
    ).read_text(encoding="utf-8")
    evidence_template = (
        PACKAGE / "static" / "lightwork-trc-continuous-evidence.js"
    ).read_text(encoding="utf-8")

    assert "setMutationReady(ready);" in assessment_source
    assert "setMutationReady(false);" in assessment_source
    assert "setMutationReady(state.ready === true);" in reports_source
    assert "setMutationReady(false);" in reports_source
    assert (
        "setCycleReady(Boolean(result.scheduler && result.scheduler.running === true));"
        in evidence_template
    )
    assert "setCycleReady(false);" in evidence_template
