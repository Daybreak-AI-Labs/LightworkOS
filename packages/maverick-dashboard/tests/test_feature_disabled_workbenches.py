from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.templating import Jinja2Templates

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"

FEATURE_WORKBENCHES = (
    ("consent_delivery.html", "consent_delivery_enabled"),
    ("consent_experiments.html", "consent_experiments_enabled"),
    ("consent_public_clients.html", "consent_public_clients_enabled"),
    ("consent_publishing.html", "consent_publishing_enabled"),
    ("policy_publication_links.html", "policy_publication_links_enabled"),
)


class _FeatureFieldset(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attrs: dict[str, str | None] | None = None
        self.depth = 0
        self.controls = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        selected = dict(attrs)
        classes = set((selected.get("class") or "").split())
        if tag == "fieldset" and "feature-gated-workbench" in classes:
            assert self.attrs is None
            self.attrs = selected
            self.depth = 1
            return
        if self.depth:
            if tag in {"button", "input", "select", "textarea"}:
                self.controls += 1
            if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
                self.depth += 1

    def handle_endtag(self, _tag: str) -> None:
        if self.depth:
            self.depth -= 1


def _render_body(template_name: str, **context) -> str:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    request = Request({
        "type": "http", "method": "GET", "scheme": "http", "path": "/feature",
        "query_string": b"", "headers": [], "server": ("127.0.0.1", 80),
        "client": ("127.0.0.1", 50000),
    })
    response = templates.TemplateResponse(request, template_name, context)
    return response.body.decode("utf-8")


def _render(template_name: str, enabled_name: str, enabled: bool) -> _FeatureFieldset:
    body = _render_body(
        template_name, **{enabled_name: enabled},
    )
    parsed = _FeatureFieldset()
    parsed.feed(body)
    return parsed


@pytest.mark.parametrize(("template_name", "enabled_name"), FEATURE_WORKBENCHES)
def test_disabled_feature_workbenches_fail_closed_without_javascript(
    template_name: str,
    enabled_name: str,
) -> None:
    disabled = _render(template_name, enabled_name, False)
    enabled = _render(template_name, enabled_name, True)

    assert disabled.attrs is not None
    assert disabled.attrs["data-feature-enabled"] == "false"
    assert "disabled" in disabled.attrs
    assert disabled.attrs["aria-disabled"] == "true"
    assert disabled.controls > 0

    assert enabled.attrs is not None
    assert enabled.attrs["data-feature-enabled"] == "true"
    assert "disabled" not in enabled.attrs
    assert "aria-disabled" not in enabled.attrs


# Pages that replace the whole workbench with the module gate when the
# feature is off: no workbench controls are rendered at all.
MODULE_GATED_WORKBENCHES = (
    ("third_party_intelligence.html", "third_party_intelligence_enabled", "tpi-root"),
    ("privacy_data_discovery.html", "privacy_data_discovery_enabled", "pdd-sources"),
    (
        "privacy_regulatory_intelligence.html",
        "privacy_regulatory_intelligence_enabled",
        "pri-app",
    ),
)


@pytest.mark.parametrize(("template_name", "enabled_name", "marker"), MODULE_GATED_WORKBENCHES)
def test_module_gated_workbenches_render_no_controls_when_disabled(
    template_name: str,
    enabled_name: str,
    marker: str,
) -> None:
    disabled = _render_body(template_name, **{enabled_name: False})
    enabled = _render_body(template_name, **{enabled_name: True})
    assert "data-module-gate=" in disabled
    assert f'id="{marker}"' not in disabled
    assert f'id="{marker}"' in enabled


def test_glass_styles_exclude_destructive_buttons() -> None:
    css = (PACKAGE / "static" / "lightwork.css").read_text(encoding="utf-8")

    safe_selector = ".btn:not(.btn--primary):not(.btn--danger)"
    assert css.count(safe_selector) >= 2
    assert ".btn:not(.btn--primary), .ctl" not in css
