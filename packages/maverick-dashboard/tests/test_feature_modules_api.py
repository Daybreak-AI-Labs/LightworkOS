"""In-app governance-module switches (/api/v1/features/modules).

Every tenant-facing module fails closed behind a [section] enable flag. These
endpoints make the gates switchable from the module's own page instead of
config.toml: admin-gated, allowlisted, persisted through the settings overlay.
Turning a module ON applies its full requirement chain in one atomic write
(one click must open a WORKING workbench, never a child under a dead
parent); turning it OFF disables only the module itself.
"""
from __future__ import annotations

import hashlib
import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config
    from maverick.audit import signing

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", raising=False)
    config.reset_config_cache()
    signing._reset_injected_keypair_cache()
    app.state.module_readiness_evidence = {}
    yield
    app.state.module_readiness_evidence = {}
    config.reset_config_cache()
    signing._reset_injected_keypair_cache()


def _module(section):
    rows = client.get("/api/v1/features/modules").json()["modules"]
    return next(m for m in rows if m["section"] == section)


def test_modules_list_defaults_off_with_labels():
    rows = client.get("/api/v1/features/modules").json()["modules"]
    assert rows, "registry must not be empty"
    by_section = {m["section"]: m for m in rows}
    assert "consent_preferences" in by_section
    assert "privacy_automation.data_discovery" in by_section
    for m in rows:
        assert m["label"]
        assert m["enabled"] is False  # fail-closed defaults
        assert m["activation"]["status"] == "disabled"
        assert m["readiness"]["status"] == "blocked"
        assert m["readiness"]["ready"] is False


def test_enable_applies_the_full_requirement_chain_atomically():
    r = client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences.analytics", "enabled": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["section"] == "consent_preferences.analytics"
    assert r.json()["enabled"] is True
    assert r.json()["activation"]["status"] == "enabled"
    assert r.json()["readiness"]["status"] == "unverified"
    # The parent gate came on with it -- the one click opened a working module.
    assert _module("consent_preferences")["enabled"] is True
    assert _module("consent_preferences.analytics")["enabled"] is True


def test_disable_turns_off_only_the_module_itself():
    client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences.analytics", "enabled": True},
    )
    r = client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences.analytics", "enabled": False},
    )
    assert r.json()["enabled"] is False
    # Siblings/parents keep running.
    assert _module("consent_preferences")["enabled"] is True


def test_a_child_under_a_disabled_parent_reads_as_off():
    client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences.analytics", "enabled": True},
    )
    client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences", "enabled": False},
    )
    # The child's own flag is still true in the overlay, but its effective
    # state honors the whole chain.
    assert _module("consent_preferences.analytics")["enabled"] is False


def test_unknown_module_is_400():
    r = client.post(
        "/api/v1/features/modules",
        json={"section": "totally_made_up", "enabled": True},
    )
    assert r.status_code == 400


def test_switching_requires_global_admin(monkeypatch):
    import maverick_dashboard.auth as auth
    from maverick_dashboard import settings_store

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:viewer")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(
        settings_store,
        "set_module_enables",
        lambda *_args, **_kwargs: pytest.fail("viewer reached module mutation"),
    )
    r = client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences", "enabled": True},
    )
    assert r.status_code == 403
    # Reading module state stays open to any signed-in user.
    assert client.get("/api/v1/features/modules").status_code == 200


def test_viewer_sees_module_recovery_without_an_activation_button(monkeypatch):
    from maverick import external_agents
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:module-reader", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:module-reader")
    monkeypatch.setattr(external_agents, "enabled", lambda: False)
    monkeypatch.setattr(
        external_agents,
        "status",
        lambda: {
            "enrolled": 0,
            "runs": 0,
            "reported_dollars": 0,
            "memory_contributions": 0,
            "over_budget": 0,
            "contained": 0,
        },
    )
    monkeypatch.setattr(external_agents, "roster", list)

    response = client.get("/external-agents")
    assert response.status_code == 200
    assert 'data-module-gate="external_agents"' in response.text
    assert "Ask an administrator to turn this on." in response.text
    assert "mg-on" not in response.text
    # The shell marks the viewer, so shared gates hide their Turn on button.
    assert 'data-global-admin="0"' in response.text


def test_switch_survives_other_overlay_writes():
    """_dump is an allowlist serializer; a module table it didn't know would
    be silently dropped by the NEXT save (the active_tenant bug class)."""
    from maverick_dashboard import settings_store

    client.post(
        "/api/v1/features/modules",
        json={"section": "third_party_management.lifecycle", "enabled": True},
    )
    settings_store.set_section_enable("dreaming", True)  # unrelated overlay write
    assert _module("third_party_management.lifecycle")["enabled"] is True


def test_enabling_in_app_unlocks_the_workbench_page():
    """The user-visible promise end to end: the /consent page loses its gate
    banner (and its in-page Turn on control) once the module is switched on."""
    page = client.get("/consent").text
    assert 'data-module-gate="consent_preferences"' in page

    r = client.post(
        "/api/v1/features/modules",
        json={"section": "consent_preferences", "enabled": True},
    )
    assert r.status_code == 200
    page = client.get("/consent").text
    assert 'data-module-gate="consent_preferences"' not in page
    # Analytics is independently switched and still off.
    assert 'data-module-gate="consent_preferences.analytics"' in page


def test_registry_matches_store_allowlist():
    import maverick_dashboard.api as api
    from maverick_dashboard import settings_store

    used: set[str] = set()
    for section, meta in api._MODULE_SWITCHES.items():
        used.add(section)
        used.update(meta["requires"])
        # Every requirement is itself a switchable row, so the UI can also
        # show/flip parents individually.
        for req in meta["requires"]:
            assert req in api._MODULE_SWITCHES
    assert used == set(settings_store.MODULE_ENABLE_PATHS)


def test_new_workbench_gates_are_registered_and_configuration_is_separate(
    monkeypatch,
):
    from maverick import config

    expected = {
        "ai_evidence_analysis",
        "assessment_evidence_autopopulation",
        "consent_preferences.native_sdk",
        "external_agents",
        "third_party_management.executive_reports",
    }
    rows = client.get("/api/v1/features/modules").json()["modules"]
    assert expected <= {row["section"] for row in rows}

    # Both gates can be on while the closed configuration contract is still
    # incomplete. A flag transition must not be promoted to runtime readiness.
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "ai_evidence_analysis": {"enable": True},
            "assessment_evidence_autopopulation": {"enable": True},
        },
    )
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: {})
    state = _module("assessment_evidence_autopopulation")
    assert state["activation"]["status"] == "enabled"
    assert state["readiness"]["status"] == "incomplete"
    assert state["readiness"]["configured"] is False
    assert state["readiness"]["ready"] is False


def test_runtime_failure_receipt_requires_exact_activation_fingerprint():
    enabled = client.post(
        "/api/v1/features/modules",
        json={"section": "external_agents", "enabled": True},
    ).json()
    fingerprint = enabled["activation"]["fingerprint"]
    assert enabled["readiness"]["status"] == "configured"
    assert enabled["readiness"]["ready"] is None

    app.state.module_readiness_evidence = {
        "external_agents": {
            "activation_fingerprint": fingerprint,
            "checked_at": time.time(),
            "status": "failed",
            "detail": "The consenting sandbox gateway rejected its bounded probe.",
        }
    }
    failed = _module("external_agents")
    assert failed["readiness"]["status"] == "failed"
    assert failed["readiness"]["ready"] is False
    assert failed["readiness"]["evidence"]["kind"] == "runtime_receipt"

    # A changed effective configuration invalidates the receipt rather than
    # carrying a stale failure or success badge forward.
    client.post(
        "/api/v1/features/modules",
        json={"section": "external_agents", "enabled": False},
    )
    blocked = _module("external_agents")
    assert blocked["readiness"]["status"] == "blocked"


def test_module_state_and_mutation_fail_closed_on_unreadable_sources(
    monkeypatch, request,
):
    from maverick import config
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "module-state-test-token")
    # Keep the authenticated audit tenant valid while corrupting the module's
    # configuration source; otherwise token admission fails before this API.
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "module-state-test")
    monkeypatch.setenv(
        "MAVERICK_AUDIT_SIGNING_KEY",
        hashlib.sha256(request.node.nodeid.encode()).hexdigest(),
    )
    authorization = {"Authorization": "Bearer module-state-test-token"}
    # The token's hourly use record is written while the configuration is
    # readable, whichever test ran first in this process; otherwise that write
    # is what fails closed below, not the module state under test.
    monkeypatch.setattr(auth, "_break_glass_last_audit", [None])
    assert client.get("/api/v1/features/modules", headers=authorization).status_code == 200
    original_source_errors = config.config_source_errors
    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda **_kwargs: {"base": "invalid"},
    )
    response = client.get("/api/v1/features/modules", headers=authorization)
    assert response.status_code == 503
    assert "no state was inferred" in response.json()["detail"]

    overlay = config.dashboard_overrides_path()
    assert not overlay.exists()
    response = client.post(
        "/api/v1/features/modules",
        json={"section": "external_agents", "enabled": True},
        headers=authorization,
    )
    assert response.status_code == 503
    assert not overlay.exists()

    monkeypatch.setattr(config, "config_source_errors", original_source_errors)
    overlay.parent.mkdir(parents=True, exist_ok=True)
    overlay.write_text("this is not = valid = toml", encoding="utf-8")
    original = overlay.read_text(encoding="utf-8")
    response = client.post(
        "/api/v1/features/modules",
        json={"section": "external_agents", "enabled": True},
        headers=authorization,
    )
    assert response.status_code == 503
    assert overlay.read_text(encoding="utf-8") == original


def test_previously_switchless_workbenches_carry_turn_on_banners(monkeypatch):
    """AI entity tasks, the document vault, the GRC studio and contracts used
    to report 'disabled' with no in-app way to turn them on. Each page now
    renders the shared banner for its switch while off, and the switch
    applies the module's requirement chain."""
    monkeypatch.setenv("MAVERICK_TENANT", "gate-test")
    pages = {
        "/ai-entity-tasks": "ai_entity_tasks",
        "/administration/document-vault": "governed_document_vault",
        "/compliance/grc-studio": "tech_risk_compliance.grc_studio",
        "/third-party/contracts": "third_party_management.contracts",
    }
    for path, section in pages.items():
        page = client.get(path)
        assert page.status_code == 200, (path, page.status_code)
        assert f'data-module-gate="{section}"' in page.text, path
        assert "mg-on" in page.text, path

    flipped = client.post(
        "/api/v1/features/modules",
        json={"section": "ai_entity_tasks", "enabled": True},
    )
    assert flipped.status_code == 200, flipped.text
    assert _module("ai_inventory")["activation"]["status"] == "enabled"
    assert _module("ai_entity_tasks")["activation"]["status"] == "enabled"
    assert 'data-module-gate="ai_entity_tasks"' not in client.get("/ai-entity-tasks").text
    # The others stay off and keep their own banner.
    assert 'data-module-gate="governed_document_vault"' in client.get("/administration/document-vault").text


# Governance modules the terminal installer can also turn on. Each flips a
# boolean ``enable`` gate, and turning it on must make
# the kernel module's OWN enabled() check pass (its parent chain included).
_KERNEL_GATES = {
    "control_plane": lambda: __import__("maverick.config", fromlist=["x"]).get_control_plane()["enable"],
    "eu_conformity": lambda: __import__("maverick.eu_conformity", fromlist=["x"]).enabled(),
    "ai_literacy": lambda: __import__("maverick.ai_literacy", fromlist=["x"]).enabled(),
    "policy_packs": lambda: __import__("maverick.policy_packs", fromlist=["x"]).enabled(),
    "evidence_gateway": lambda: __import__("maverick.ai_evidence_gateway", fromlist=["x"]).enabled(),
    "drift_monitoring": lambda: __import__("maverick.drift_monitoring", fromlist=["x"]).enabled(),
    "ai_incident_reporting": lambda: __import__("maverick.ai_incident_reporting", fromlist=["x"]).enabled(),
    "explainability": lambda: __import__("maverick.explainability", fromlist=["x"]).enabled(),
    "content_provenance": lambda: __import__("maverick.content_provenance", fromlist=["x"]).enabled(),
    "breach_notification": lambda: __import__("maverick.breach_notification", fromlist=["x"]).enabled(),
    "privacy_automation.drop_management": lambda: __import__(
        "maverick.privacy_drop_management", fromlist=["x"]).enabled(),
}


@pytest.mark.parametrize("section", sorted(_KERNEL_GATES))
def test_new_module_switches_turn_the_kernel_gate_on_and_off(section, monkeypatch):
    from maverick import config

    for name in ("MAVERICK_CONTROL_PLANE", "MAVERICK_EVIDENCE_GATEWAY"):
        monkeypatch.delenv(name, raising=False)
    assert _module(section)["enabled"] is False
    config.reset_config_cache()
    assert _KERNEL_GATES[section]() is False

    r = client.post("/api/v1/features/modules", json={"section": section, "enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    config.reset_config_cache()
    assert _KERNEL_GATES[section]() is True

    r = client.post("/api/v1/features/modules", json={"section": section, "enabled": False})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
    config.reset_config_cache()
    assert _KERNEL_GATES[section]() is False


def test_new_module_switches_are_admin_only(monkeypatch):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:olive", "operator")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:olive")
    r = client.post("/api/v1/features/modules", json={"section": "policy_packs", "enabled": True})
    assert r.status_code == 403
