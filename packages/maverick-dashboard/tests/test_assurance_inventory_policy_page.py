"""Rendered contracts for assurance-dashboard extension panels."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_assurance_page(tmp_path, monkeypatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
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


def test_assurance_off_states_offer_working_controls():
    page = client.get("/security/assurance")
    assert page.status_code == 200, page.text
    for section in (
        "drift_monitoring", "evidence_gateway", "policy_packs",
        "portfolio_risk",
    ):
        assert f'data-module-gate="{section}"' in page.text
    assert 'href="/settings/all?id=red_team_assurance.enable"' in page.text
    assert "setup wizard" not in page.text.lower()

    setting = client.get("/settings/all?id=red_team_assurance.enable")
    assert setting.status_code == 200, setting.text
    assert 'data-setting-id="red_team_assurance.enable"' in setting.text


def test_assurance_turn_on_controls_open_their_sections():
    sections = (
        "drift_monitoring", "evidence_gateway", "policy_packs",
        "portfolio_risk",
    )
    for section in sections:
        enabled = client.post("/api/v1/features/modules", json={
            "section": section, "enabled": True,
        })
        assert enabled.status_code == 200, (section, enabled.text)
    page = client.get("/security/assurance")
    assert page.status_code == 200, page.text
    for section in sections:
        assert f'data-module-gate="{section}"' not in page.text
    assert 'id="drift-baseline-create"' in page.text
    assert 'id="policy-packs-panel"' in page.text
    assert 'aria-label="AI portfolio risk totals"' in page.text


def _policy_catalog_row(
    entry_id: str,
    pack_id: str,
    version: str,
    revision: int,
) -> dict:
    return {
        "id": entry_id,
        "pack_id": pack_id,
        "pack_version": version,
        "content_sha256": "a" * 64,
        "framework": {
            "name": "Example AI Controls",
            "version": "1.0",
            "as_of": "2026-08-23",
        },
        "coverage": "starter_subset",
        "control_count": 3,
        "runtime_check_count": 1,
        "provenance_kind": "bundled",
        "revision": revision,
    }


def _patch_enabled_surfaces(monkeypatch) -> None:
    from maverick import ai_inventory, policy_packs

    monkeypatch.setattr(ai_inventory, "enabled", lambda: True)
    monkeypatch.setattr(
        ai_inventory,
        "get_ai_inventory_config",
        lambda: {"connectors": ["bedrock"]},
    )
    monkeypatch.setattr(
        ai_inventory,
        "list_discovered_assets",
        lambda: [
            {
                "asset_id": "MAA-" + ("a" * 32),
                "display_name": "Provider model",
                "asset_type": "model",
                "platform": "AWS Bedrock",
                "model": "customer-model-v1",
                "owner": "AI Platform",
                "binding_strength": "immutable_provider_revision",
                "discovery_status": "present",
                "status": "present",
                "source_url": "https://console.aws.amazon.com/bedrock/home",
                "provider_last_seen_at": 1_724_435_200.0,
                "last_run_id": "AIR-complete",
                "missing_count": 0,
            }
        ],
    )
    monkeypatch.setattr(
        ai_inventory,
        "list_discovery_runs",
        lambda *, limit: [
            {
                "id": "AIR-complete",
                "connector": "bedrock",
                "status": "complete",
                "pages": 2,
                "asset_count": 1,
                "started_at": 1_724_435_100.0,
                "error_type": "",
            }
        ][:limit],
    )
    monkeypatch.setattr(
        ai_inventory,
        "connector_status",
        lambda connector: {
            "connector": connector,
            "state": "complete",
            "last_completed_at": 1_724_435_200.0,
            "last_completed_id": "AIR-complete",
            "last_asset_count": 1,
            "last_error_type": "",
        },
    )

    pack_one = "example-controls"
    pack_two = "second-controls"
    monkeypatch.setattr(policy_packs, "enabled", lambda: True)
    monkeypatch.setattr(
        policy_packs,
        "bundled_summaries",
        lambda: {
            pack_one: {
                "pack_id": pack_one,
                "version": "1.1.0",
                "framework": {"name": "Example AI Controls"},
                "coverage": "starter_subset",
                "control_count": 3,
            }
        },
    )
    monkeypatch.setattr(
        policy_packs,
        "list_catalog",
        lambda: {
            "items": [
                _policy_catalog_row("ppk-old", pack_one, "1.0.0", 1),
                _policy_catalog_row("ppk-next", pack_one, "1.1.0", 1),
                _policy_catalog_row("ppk-second", pack_two, "1.0.0", 1),
            ],
            "count": 3,
            "truncated": False,
            "limit": 100,
        },
    )
    monkeypatch.setattr(
        policy_packs,
        "list_channels",
        lambda: {
            "items": [
                {
                    "id": "ppc-one",
                    "pack_id": pack_one,
                    "pack_version": "1.0.0",
                    "catalog_entry_id": "ppk-old",
                    "control_count": 3,
                    "revision": 3,
                },
                {
                    "id": "ppc-two",
                    "pack_id": pack_two,
                    "pack_version": "1.0.0",
                    "catalog_entry_id": "ppk-second",
                    "control_count": 2,
                    "revision": 1,
                },
            ],
            "count": 2,
            "truncated": False,
            "limit": 100,
        },
    )
    monkeypatch.setattr(
        policy_packs,
        "list_subscriptions",
        lambda: {
            "items": [
                {
                    "id": "pps-one",
                    "pack_id": pack_one,
                    "pack_version": "1.0.0",
                    "active_pack_version": "1.1.0",
                    "needs_refresh": True,
                    "control_count": 3,
                    "current_count": 1,
                    "stale_count": 1,
                    "missing_count": 1,
                    "revision": 4,
                }
            ],
            "count": 1,
            "truncated": False,
            "limit": 100,
        },
    )


def test_assurance_page_renders_inventory_policy_state_and_bounded_admin_actions(
    monkeypatch,
):
    _patch_enabled_surfaces(monkeypatch)

    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert 'id="ai-inventory-panel"' in page
    assert "AWS Bedrock" in page
    assert "Pinned to one provider version" in page
    assert "immutable_provider_revision" not in page
    assert 'data-inventory-connector="bedrock"' in page
    assert '"/api/v1/security/assurance/ai-inventory/connectors/"' in page

    assert 'id="policy-packs-panel"' in page
    assert "Example AI Controls" in page
    assert 'data-policy-action="stage"' in page
    assert 'data-policy-id="example-controls"' in page
    assert 'data-policy-action="activate"' in page
    assert 'data-policy-id="ppk-next"' in page
    assert 'data-policy-revision="3"' in page
    assert 'data-policy-action="subscribe"' in page
    assert 'data-policy-id="second-controls"' in page
    assert 'data-policy-action="refresh"' in page
    assert 'data-policy-id="pps-one"' in page
    assert 'data-policy-revision="4"' in page
    assert '"/api/v1/security/assurance/policy-packs/catalog/"' in page
    assert "compliance certification" in page


def test_assurance_page_keeps_inventory_and_policy_mutations_admin_only(
    monkeypatch,
):
    from maverick_dashboard import auth

    _patch_enabled_surfaces(monkeypatch)
    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)

    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert "Connected accounts" in page
    assert "Provider model" in page
    assert "Prepared packs" in page
    assert "Example controls" in page  # pack names are shown as words
    assert "data-inventory-connector" not in page
    assert "data-policy-action" not in page
    assert "/ai-inventory/connectors/" not in page
    assert "/policy-packs/catalog/" not in page


def test_policy_partial_read_keeps_available_state_and_withholds_mutations(
    monkeypatch,
):
    from maverick import policy_packs

    _patch_enabled_surfaces(monkeypatch)

    def unavailable_subscriptions():
        raise RuntimeError("tenant store unavailable")

    monkeypatch.setattr(
        policy_packs,
        "list_subscriptions",
        unavailable_subscriptions,
    )

    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert "Select a workspace to view policy-pack subscriptions." in page
    assert "What could be loaded is shown below" in page
    assert "Example controls" in page  # pack names are shown as words
    assert "data-policy-action" not in page
    assert "/policy-packs/catalog/" not in page


def test_policy_truncated_read_window_withholds_revision_based_actions(
    monkeypatch,
):
    from maverick import policy_packs

    _patch_enabled_surfaces(monkeypatch)
    catalog = policy_packs.list_catalog()
    catalog["truncated"] = True
    monkeypatch.setattr(policy_packs, "list_catalog", lambda: catalog)

    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert "Changes are paused because one of the lists is too long" in page
    assert "data-policy-action" not in page
    assert "/policy-packs/catalog/" not in page


def test_red_team_form_handler_renders_when_evidence_gateway_is_off(monkeypatch):
    from maverick import ai_evidence_gateway, external_agents, red_team_assurance

    monkeypatch.setattr(ai_evidence_gateway, "enabled", lambda: False)
    monkeypatch.setattr(red_team_assurance, "enabled", lambda: True)
    monkeypatch.setattr(
        red_team_assurance,
        "list_campaigns",
        lambda **_kwargs: {
            "items": [
                {
                    "id": "RTC-" + ("a" * 24),
                    "revision": 3,
                    "status": "running",
                    "target_binding": {"asset_id": "MAA-" + ("b" * 32)},
                    "submitted_case_count": 1,
                    "case_count": 6,
                    "summary": None,
                }
            ],
            "count": 1,
            "truncated": False,
            "limit": 20,
        },
    )
    monkeypatch.setattr(
        external_agents,
        "roster",
        lambda: [
            {
                "id": "runner-one",
                "active": True,
                "platform_label": "Isolated test runner",
            }
        ],
    )

    response = client.get("/security/assurance")

    assert response.status_code == 200
    page = response.text
    assert 'id="red-team-create"' in page
    assert 'value="runner-one"' in page
    assert 'const campaignForm = document.getElementById("red-team-create")' in page
    assert 'campaignForm.addEventListener("submit"' in page
    assert '"/api/v1/security/assurance/red-team/campaigns"' in page
    assert "safe_target_environment: fields.has" in page
    assert 'data-red-team-action="finalize"' in page
    assert 'data-red-team-action="force-finalize"' in page
    assert 'data-red-team-action="cancel"' in page
    assert "/finalize`" in page
    assert "/cancel`" in page
    assert "force_incomplete" in page
    assert "expected_revision" in page
    assert "/api/v1/security/assurance/gateway/demo-seed" not in page
    assert "/api/v1/security/assurance/gateway/assurance-packet" not in page


def test_assurance_page_sections_speak_plainly(monkeypatch):
    import re

    _patch_enabled_surfaces(monkeypatch)
    page = client.get("/security/assurance").text
    main = page.split('<main id="content"', 1)[1].split("</main>", 1)[0]
    own = main.split('id="governance-operations-panel"', 1)[0]
    visible = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", own)
    assert not re.search(
        r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
        r"idempoten\w*)\b|/api/v1|HTTP \d{3}|\[ai_inventory\]|\[policy_packs\]",
        visible,
        re.IGNORECASE,
    ), visible
    scripts = "".join(re.findall(r"<script>([\s\S]*?)</script>", page.split('id="governance-operations-panel"', 1)[0]))
    assert "window.prompt" not in scripts and "window.confirm(" not in scripts
    # Pickers replace typed identifiers and JSON.
    assert 'name="asset_id" required pattern="MAA-' not in page
    assert "Aggregate samples JSON" not in page
    assert "source:id" not in page
