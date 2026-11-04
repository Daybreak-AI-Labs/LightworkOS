"""Settings > All settings: the guided forms added for installer-only settings.

Chat channels and their allow lists, trusted skill publishers (key upload with
fingerprints), the protected work area, document search, connected business
systems, finance limits, the security suite's event sources, AI governance
module policies, the AI gateway, GRC sync, the tool gateway for outside AI
clients, local models, plugin permissions and usage limits for any tool.

Each form is checked end to end: the value lands in the overlay, the kernel
reads it back through its own getter, options come from live data, anything
that loosens a protection needs confirmation on the server, secrets stay
sealed, and the values the page accepts at its limits are values the kernel
accepts.
"""
from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"

# A real Ed25519 public key (32 bytes) in the forms publishers hand out.
_KEY = bytes(range(1, 33))
_HEX = _KEY.hex()
_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    + base64.b64encode(bytes.fromhex("302a300506032b6570032100") + _KEY).decode()
    + "\n-----END PUBLIC KEY-----\n"
)
_SSH_BLOB = (len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519"
             + len(_KEY).to_bytes(4, "big") + _KEY)
_SSH = "ssh-ed25519 " + base64.b64encode(_SSH_BLOB).decode() + " publisher@example"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import settings_all_page

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_GOVERNED_APPROVER", "MAVERICK_LOCAL_FIRST",
                 "MAVERICK_PLUGINS_ENFORCE", "MAVERICK_REQUIRE_SIGNED_CATALOG"):
        monkeypatch.delenv(name, raising=False)
    # Building the real tool list is slow; the page's picker only needs names.
    monkeypatch.setattr(settings_all_page, "_tool_names",
                        lambda: ["http_fetch", "shell", "web_search", "wiki_search"])
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _loaded():
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False, http=client):
    return save_catalog(http, API, json={"changes": changes, "confirm": confirm})


def _row(setting_id):
    for group in client.get(API).json()["groups"]:
        for row in group["settings"]:
            if row["id"] == setting_id:
                return row
    raise AssertionError(setting_id)


def _installer(text: str) -> None:
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text, encoding="utf-8")
    config.reset_config_cache()


# ------------------------------------------------------ catalog vs kernel data
def test_channel_forms_cover_the_channel_adapter_registry():
    from maverick.server import _WIRES

    assert set(catalog.CHANNEL_ALLOWLISTS) == set(_WIRES)
    for name, (_label, _on_page, key, *_rest) in catalog.CHANNEL_ALLOWLISTS.items():
        assert f"channels.{name}.{key}" in catalog.BY_ID
    # The six channels with their own page keep their sign-in fields there.
    from maverick_dashboard.settings_store import CHANNELS

    for channel in CHANNELS:
        assert f"channels.{channel['name']}.enabled" not in catalog.BY_ID
        assert catalog.CHANNEL_ALLOWLISTS[channel["name"]][1] is True


def test_fixed_option_lists_match_the_kernel():
    from maverick import governance_agents, grc_outbound_sync, local_runtime, plugins
    from maverick.ai_inventory import _CONNECTORS
    from maverick.env_hunt.tooling import CONNECTOR_NAMES
    from maverick.finance.regimes import REGIMES
    from maverick.sandbox.ssh import _VALID_HOST_KEY_POLICIES

    def values(setting_id):
        return {v for v, _ in catalog.BY_ID[setting_id].choices}

    assert set(catalog.ENV_HUNT_SOURCES) == set(CONNECTOR_NAMES)
    assert values("finance.regimes") == set(REGIMES)
    assert values("ai_inventory.connectors") <= set(_CONNECTORS)
    assert values("governance_agents.enabled_agents") == set(governance_agents.AGENT_KINDS)
    assert values("grc_outbound_sync.targets") == {t.value for t in grc_outbound_sync.GRCSystem}
    assert values("local_runtime.engine") == set(local_runtime.ENGINES)
    assert values("local_runtime.precision") == set(local_runtime.PRECISIONS)
    assert values("sandbox.host_key_checking") == _VALID_HOST_KEY_POLICIES
    assert values("plugins.grant") <= set(plugins._KNOWN_PERMISSIONS)


def test_new_defaults_match_the_kernel():
    from maverick import config, drift_monitoring, local_runtime

    for key, value in drift_monitoring._DEFAULTS.items():
        if f"drift_monitoring.{key}" in catalog.BY_ID:
            assert catalog.BY_ID[f"drift_monitoring.{key}"].default == value, key
    for key in ("engine", "precision", "max_concurrent", "min_replicas", "max_replicas"):
        assert catalog.BY_ID[f"local_runtime.{key}"].default == local_runtime.DEFAULTS[key]
    knowledge = config.get_knowledge()
    for key in ("embedder", "store", "model", "base_url", "dim"):
        assert catalog.BY_ID[f"knowledge.{key}"].default == knowledge[key], key
    improvement = config.get_model_improvement()
    for key in ("allow_hosted", "require_signed_receipt", "minimum_train_families"):
        assert catalog.BY_ID[f"model_improvement.{key}"].default == improvement[key], key


# Values at both ends of each form's range must be accepted by the kernel's
# own strict validator, so the page can never save a configuration that
# switches a module off as "invalid".
def _extremes(prefix: str) -> list[list[dict]]:
    low, high = [], []
    for s in catalog.SETTINGS:
        if not s.id.startswith(prefix + ".") or s.control != "number":
            continue
        low.append({"id": s.id, "value": s.minimum})
        high.append({"id": s.id, "value": s.maximum})
    return [low, high]


def _check_bounds(prefix, validate, audit_rows, *, fixed=()):
    for changes in _extremes(prefix):
        r = _save([*fixed, *changes], confirm=True)
        assert r.status_code == 200, r.text
        validate()


def test_drift_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick.drift_monitoring import get_drift_config

    _check_bounds("drift_monitoring", get_drift_config, audit_rows)


def test_gateway_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick.llm_gateway import get_llm_gateway_config

    _check_bounds("llm_gateway", get_llm_gateway_config, audit_rows)
    cfg = get_llm_gateway_config()
    assert cfg["team_budgets"][0][0] == "default"


def test_tool_gateway_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick_mcp.sidecar import SidecarConfig

    _check_bounds("mcp_sidecar",
                  lambda: SidecarConfig.from_mapping(_loaded().get("mcp_sidecar")), audit_rows)


def test_local_runtime_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick.local_runtime import load_local_runtime

    for changes in _extremes("local_runtime"):
        values = {c["id"]: c["value"] for c in changes}
        # The kernel requires fewest <= most copies; the page checks it too.
        values["local_runtime.max_replicas"] = 64
        r = _save([{"id": k, "value": v} for k, v in values.items()], confirm=True)
        assert r.status_code == 200, r.text
        load_local_runtime()


def test_inventory_and_document_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick.administration_document_access import DocumentAccessConfig
    from maverick.governed_document_vault import GovernedDocumentVaultConfig
    from maverick_dashboard.shared_governance_inventory_composition import inventory_settings

    _check_bounds("governance_inventory", lambda: inventory_settings(_loaded()), audit_rows)
    _check_bounds("governed_document_vault",
                  lambda: GovernedDocumentVaultConfig(**_loaded()["governed_document_vault"]),
                  audit_rows)
    for changes in _extremes("administration_document_access"):
        values = {c["id"]: c["value"] for c in changes}
        values["administration_document_access.max_ttl_seconds"] = 3600
        assert _save([{"id": k, "value": v} for k, v in values.items()],
                     confirm=True).status_code == 200
        DocumentAccessConfig(**_loaded()["administration_document_access"])


def test_finance_limits_are_accepted_by_the_kernel(audit_rows):
    from maverick.finance.control_testing import schedule_config
    from maverick.governance import Policy
    from maverick_dashboard.finance_scheduler import _poll_seconds

    _check_bounds("finance_operations", schedule_config, audit_rows)
    _poll_seconds(_loaded()["finance_operations"])
    _check_bounds("governance", Policy.from_config, audit_rows)


def test_grc_sync_form_is_accepted_by_the_kernel(audit_rows):
    from maverick.grc_sync import enabled, get_grc_sync_config

    r = _save([{"id": "grc_sync.enable", "value": True}], confirm=True)
    assert r.status_code == 400 and "at least one" in r.json()["message"]
    r = _save([{"id": "grc_sync.enable", "value": True},
               {"id": "grc_sync.connector", "value": "servicenow"},
               {"id": "grc_sync.findings_path", "value": "/records/findings"},
               {"id": "grc_sync.backlink_base", "value": "https://lightwork.example"}],
              confirm=True)
    assert r.status_code == 200, r.text
    cfg = get_grc_sync_config()
    assert cfg["paths"]["finding"] == "/records/findings" and enabled()
    assert _save([{"id": "grc_sync.findings_path", "value": "no-slash"}]).status_code == 400
    assert _save([{"id": "grc_sync.connector", "value": "unknown_system"}]).status_code == 400


# ----------------------------------------------------------------- the page
def test_page_shows_the_guided_forms_in_plain_language():
    from test_support.plain_language import developer_terms

    page = every_group(client)
    for text in ("Chat channels", "Protected work area", "Finance", "Security suite",
                 "AI governance", "Who may use Matrix", "Trusted skill publishers",
                 "Upload a publisher", "Usage limits for other tools",
                 "Find a tool", "Reviewed tools", "Standing approver for changes",
                 "Pause payments above", "Save AI gateway", "data-subgroup-pick",
                 "Everything in Chat channels"):
        assert text in page, text
    assert developer_terms(page) == []


def test_choices_come_from_live_data(monkeypatch):
    from maverick_dashboard import rbac

    rbac.set_role("user:dana@example.com", "admin")
    approver = _row("governed_connectors.approver")
    values = [c["value"] for c in approver["choices"]]
    assert values[0] == "" and "user:dana@example.com" in values
    assert "empty_hint" not in approver
    systems = [c["value"] for c in _row("governed_connectors.connectors")["choices"]]
    from maverick.governed_rest import available_rest_connectors

    assert systems == available_rest_connectors()
    models = [c["value"] for c in _row("llm_gateway.allowed_models")["choices"]]
    from maverick.llm import MODEL_CATALOG

    assert set(models) == {m for ids in MODEL_CATALOG.values() for m in ids}
    local = [c["value"] for c in _row("local_first.model")["choices"]]
    assert local[0] == "" and all(v.startswith(("ollama:", "vllm:", "lmstudio:", "llamacpp:",
                                                "llama_cpp:", "tgi:", "local:")) for v in local[1:])
    tools = client.get(API + "/choices/rate_limits.other").json()["choices"]
    names = [c["value"] for c in tools]
    assert "mcp_*" in names and "wiki_search" in names
    assert "shell" not in names  # it has its own setting
    assert all("_" not in c["label"] for c in tools)


def test_approver_picker_says_what_to_do_when_nobody_exists():
    row = _row("governed_connectors.approver")
    assert "People page" in row["empty_hint"]


def test_choices_route_is_admin_only(monkeypatch):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get(API + "/choices/rate_limits.other").status_code == 403
    monkeypatch.undo()
    assert client.get(API + "/choices/safety.profile").status_code == 404


# ------------------------------------------------------------ chat channels
def test_allow_lists_round_trip_and_widening_needs_confirmation(audit_rows):
    r = _save([{"id": "channels.telegram.allowed_user_ids", "value": ["12345", " ", "12345"]}])
    assert r.status_code == 409
    assert r.json()["confirm"][0]["id"] == "channels.telegram.allowed_user_ids"
    r = _save([{"id": "channels.telegram.allowed_user_ids", "value": ["12345"]}], confirm=True)
    assert r.status_code == 200, r.text
    cfg = _loaded()["channels"]["telegram"]
    assert cfg == {"allowed_user_ids": ["12345"]}  # on/off is not touched
    # Narrowing needs no confirmation; emptying is still confirmed. A blank
    # list saved here denies everyone; it does not hand back to the server's list.
    assert _save([{"id": "channels.telegram.allowed_user_ids",
                   "value": ["12345", "678"]}], confirm=True).status_code == 200
    assert _save([{"id": "channels.telegram.allowed_user_ids",
                   "value": ["12345"]}]).status_code == 200
    assert _save([{"id": "channels.telegram.allowed_user_ids", "value": []}]).status_code == 409
    assert _save([{"id": "channels.telegram.allowed_user_ids", "value": []}],
                 confirm=True).status_code == 200
    assert _loaded()["channels"]["telegram"] == {"allowed_user_ids": []}
    bad = _save([{"id": "channels.sms.allowed_user_ids", "value": ["4155551234"]}], confirm=True)
    assert bad.status_code == 400
    assert "a phone number starting with +" in bad.json()["message"]


def test_channels_page_settings_survive_an_allow_list_save(audit_rows):
    from maverick_dashboard import settings_store

    settings_store.set_channel("telegram", True, {"bot_token": "123:secret-token"})  # pragma: allowlist secret
    assert _save([{"id": "channels.telegram.allowed_user_ids", "value": ["42"]}],
                 confirm=True).status_code == 200
    cfg = _loaded()["channels"]["telegram"]
    assert cfg["enabled"] is True and cfg["bot_token"] == "123:secret-token"  # pragma: allowlist secret
    assert cfg["allowed_user_ids"] == ["42"]


def test_a_new_channel_is_set_up_with_sealed_sign_in(audit_rows):
    from maverick import config

    token = "matrix-access-token-do-not-show"  # pragma: allowlist secret
    changes = [
        {"id": "channels.matrix.enabled", "value": True},
        {"id": "channels.matrix.homeserver", "value": "https://matrix.example"},
        {"id": "channels.matrix.user_id", "value": "@lightwork:matrix.example"},
        {"id": "channels.matrix.access_token", "value": token},
        {"id": "channels.matrix.allowed_user_ids", "value": ["@ada:matrix.example"]},
    ]
    r = _save(changes)
    assert r.status_code == 409
    assert {c["id"] for c in r.json()["confirm"]} == {
        "channels.matrix.enabled", "channels.matrix.allowed_user_ids"}
    r = _save(changes, confirm=True)
    assert r.status_code == 200 and token not in r.text
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert token not in stored and "MVKAR1:" in stored
    matrix = _loaded()["channels"]["matrix"]
    assert matrix["access_token"] == token and matrix["enabled"] is True
    assert token not in every_group(client)
    assert token not in repr(audit_rows)
    assert _row("channels.matrix.access_token")["value_text"] == "Set"
    assert _row("channels.matrix.enabled")["restart"] is True


# ------------------------------------------------------- publisher keys
@pytest.mark.parametrize("text", [_HEX, _HEX.upper(), _PEM, _SSH, base64.b64encode(_KEY).decode()])
def test_publisher_key_files_in_every_common_form_are_read(text):
    assert catalog.parse_public_key(text) == _HEX


@pytest.mark.parametrize("text", ["", "not a key", "ssh-rsa AAAAB3NzaC1yc2E=", "00" * 31,
                                  "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"])
def test_unreadable_publisher_keys_are_refused_plainly(text):
    with pytest.raises(catalog.SettingError, match="public key file"):
        catalog.parse_public_key(text)


def test_trusting_a_publisher_needs_confirmation_and_shows_a_fingerprint(audit_rows):
    from maverick import config

    r = _save([{"id": "skills.trusted_pubkeys", "value": [_PEM]}])
    assert r.status_code == 409
    r = _save([{"id": "skills.trusted_pubkeys", "value": [_PEM]}], confirm=True)
    assert r.status_code == 200, r.text
    assert config.get_skills()["trusted_pubkeys"] == [_HEX]
    row = _row("skills.trusted_pubkeys")
    fingerprint = hashlib.sha256(_KEY).hexdigest().upper()[:16]
    assert row["key_items"][0]["fingerprint"].replace(" ", "") == fingerprint
    assert row["value_text"] == "1 trusted key"
    page = every_group(client)
    assert row["key_items"][0]["fingerprint"] in page
    # The activity record names the key by fingerprint only.
    assert audit_rows[-1]["new"] == [row["key_items"][0]["fingerprint"]]
    assert _HEX not in repr(audit_rows)
    # Keeping the same key (sent back as stored) is not a change.
    assert _save([{"id": "skills.trusted_pubkeys", "value": [_HEX]}]).json()["changed"] == []
    # Removing the last trusted publisher accepts any signature again: confirm.
    assert _save([{"id": "skills.trusted_pubkeys", "value": []}]).status_code == 409


# ------------------------------------------------------ protected work area
def test_loosening_the_work_area_needs_confirmation(audit_rows):
    for change in ({"id": "sandbox.allow_network", "value": True},
                   {"id": "sandbox.image", "value": "python:3.12"},
                   {"id": "sandbox.host", "value": "builder@build-server"},
                   {"id": "sandbox.namespace", "value": "agents"},
                   {"id": "sandbox.host_key_checking", "value": "no"}):
        r = _save([change])
        assert r.status_code == 409, change
        assert _save([change], confirm=True).status_code == 200, change
    cfg = _loaded()["sandbox"]
    assert cfg["allow_network"] is True and cfg["image"] == "python:3.12"
    assert cfg["host"] == "builder@build-server" and cfg["namespace"] == "agents"
    # Tightening again is not confirmed.
    assert _save([{"id": "sandbox.allow_network", "value": False},
                  {"id": "sandbox.host_key_checking", "value": "yes"}]).status_code == 200
    for bad in ({"id": "sandbox.host", "value": "-oProxyCommand=evil"},
                {"id": "sandbox.namespace", "value": "Not A Namespace"},
                {"id": "sandbox.memory", "value": "999g"}):
        assert _save([bad], confirm=True).status_code == 400, bad


def test_work_area_keeps_the_backend_chosen_on_permissions(audit_rows):
    from maverick_dashboard import settings_store

    settings_store.set_sandbox_backend("docker")
    assert _save([{"id": "sandbox.memory", "value": "8g"},
                  {"id": "sandbox.language", "value": "go"}]).status_code == 200
    from maverick.sandbox import _IMAGE_BY_LANGUAGE, _resolve_image

    cfg = _loaded()["sandbox"]
    assert cfg["backend"] == "docker" and cfg["memory"] == "8g"
    assert _resolve_image(cfg) == _IMAGE_BY_LANGUAGE["go"]


# ---------------------------------------------------------- document search
def test_document_search_settings_reach_the_kernel(audit_rows):
    from maverick import config

    r = _save([{"id": "knowledge.store", "value": "pgvector"},
               {"id": "knowledge.dim", "value": 512}])
    assert r.status_code == 200
    assert config.get_knowledge()["store"] == "pgvector" and config.get_knowledge()["dim"] == 512
    assert _save([{"id": "knowledge.base_url", "value": "https://embed.example"}]).status_code == 409


# ------------------------------------------------ connected business systems
def test_standing_approver_is_a_person_from_the_people_list(audit_rows):
    from maverick import governed_tools
    from maverick_dashboard import rbac

    assert _save([{"id": "governed_connectors.approver", "value": "user:mallory"}],
                 confirm=True).status_code == 400
    rbac.set_role("user:dana@example.com", "admin")
    r = _save([{"id": "governed_connectors.approver", "value": "user:dana@example.com"}])
    assert r.status_code == 409
    assert _save([{"id": "governed_connectors.approver", "value": "user:dana@example.com"}],
                 confirm=True).status_code == 200
    assert governed_tools._approver() == "user:dana@example.com"
    assert _row("governed_connectors.approver")["value_text"].startswith("dana@example.com")


def test_removing_a_governed_system_needs_confirmation(audit_rows):
    from maverick import config

    assert _save([{"id": "governed_connectors.connectors",
                   "value": ["salesforce", "servicenow"]}]).status_code == 200
    assert config.get_governed_connectors()["connectors"] == ["salesforce", "servicenow"]
    assert _save([{"id": "governed_connectors.connectors",
                   "value": ["servicenow"]}]).status_code == 409


# ------------------------------------------------------------------ finance
def test_payment_limits_reach_the_governance_policy(audit_rows):
    from maverick.governance import Policy

    r = _save([{"id": "governance.require_human_above.*", "value": 5000},
               {"id": "governance.deny_above.*", "value": 50000},
               {"id": "finance.regimes", "value": ["sox", "gaap"]}])
    assert r.status_code == 200, r.text
    policy = Policy.from_config()
    assert policy.require_human_above.get("*") in (5000, 5000.0)
    assert policy.deny_above.get("*") in (50000, 50000.0)
    # Raising the pause limit, or dropping a rule, loosens: confirm first.
    assert _save([{"id": "governance.require_human_above.*", "value": 9000}]).status_code == 409
    assert _save([{"id": "finance.regimes", "value": ["sox"]}]).status_code == 409
    assert _save([{"id": "governance.require_human_above.*", "value": 1000}]).status_code == 200
    page = every_group(client)
    assert 'id="sa-governance-require_human_above-all"' in page


def test_finance_schedule_is_shown_in_friendly_units(audit_rows):
    r = _save([{"id": "finance_operations.regulatory_poll_seconds", "value": 30},
               {"id": "finance_operations.control_test_interval_seconds", "value": 12}])
    assert r.status_code == 200
    cfg = _loaded()["finance_operations"]
    assert cfg["regulatory_poll_seconds"] == 1800
    assert cfg["control_test_interval_seconds"] == 43200
    row = _row("finance_operations.regulatory_poll_seconds")
    assert row["value"] == 30 and row["value_text"] == "30 minutes"
    assert _save([{"id": "finance_operations.regulatory_poll_seconds",
                   "value": 1}]).status_code == 400


# ------------------------------------------------------------ security suite
def test_event_sources_reach_the_hunter_and_push_needs_confirmation(audit_rows):
    from maverick.env_hunt.tooling import connector_enablement, connector_push_enablement

    assert _save([{"id": "env_hunt.connectors.splunk.enable", "value": True}]).status_code == 200
    assert _save([{"id": "env_hunt.connectors.splunk.push_enable", "value": True}]
                 ).status_code == 409
    assert _save([{"id": "env_hunt.connectors.splunk.push_enable", "value": True}],
                 confirm=True).status_code == 200
    cfg = _loaded()
    cfg["env_hunt"]["enable"] = True
    assert connector_enablement(cfg)["splunk"] is True
    assert connector_push_enablement(cfg)["splunk"] is True


def test_security_suite_switches_keep_their_own_control(audit_rows):
    from maverick_dashboard import settings_store

    revision = settings_store.security_suite_revision()
    # Hunting less often finds threats later: confirmed like any loosening.
    assert _save([{"id": "env_hunt.poll_seconds", "value": 10}]).status_code == 409
    assert _save([{"id": "env_hunt.poll_seconds", "value": 10}], confirm=True).status_code == 200
    assert settings_store.security_suite_revision() == revision
    assert "env_hunt.enable" not in catalog.BY_ID
    assert "env_hunt.response_execution" not in catalog.BY_ID
    assert _loaded()["env_hunt"]["poll_seconds"] == 600


# ------------------------------------------------------------- AI governance
def test_gateway_needs_somewhere_to_forward_to(audit_rows):
    r = _save([{"id": "llm_gateway.enable", "value": True}], confirm=True)
    assert r.status_code == 400 and "AI service the gateway forwards to" in r.json()["message"]
    r = _save([{"id": "llm_gateway.enable", "value": True},
               {"id": "llm_gateway.upstream_url", "value": "https://api.openai.com"},
               {"id": "llm_gateway.allowed_models", "value": ["gpt-5.5"]}], confirm=True)
    assert r.status_code == 200, r.text
    from maverick.llm_gateway import get_llm_gateway_config

    cfg = get_llm_gateway_config()
    assert cfg["enable"] is True and cfg["allowed_models"] == ["gpt-5.5"]
    # Clearing the model list allows every model again: confirmed.
    assert _save([{"id": "llm_gateway.allowed_models", "value": []}]).status_code == 409
    assert _save([{"id": "llm_gateway.redact_prompts", "value": True}]).status_code == 200
    assert _save([{"id": "llm_gateway.redact_prompts", "value": False}]).status_code == 409


def test_agent_dependency_map_switch_turns_on_its_chain(audit_rows):
    from maverick_dashboard import api

    assert api._MODULE_SWITCHES["agent_topology"]["requires"] == (
        "evidence_graph", "model_risk_assurance")
    r = client.post("/api/v1/features/modules",
                    json={"section": "agent_topology", "enabled": True})
    assert r.status_code == 200, r.text
    cfg = _loaded()
    assert cfg["agent_topology"]["enable"] is True
    assert cfg["model_risk_assurance"]["enable"] is True
    assert "Agent dependency map" in every_group(client)


# ------------------------------------------------ tool gateway (sidecar)
def test_reviewed_tools_table_is_saved_for_the_tool_gateway(audit_rows):
    from maverick_mcp.sidecar import SidecarConfig

    rows = [{"name": "search.docs", "risk": "low"}, {"name": "tickets", "risk": "high"}]
    r = _save([{"id": "mcp_sidecar.tools", "value": rows}])
    assert r.status_code == 409  # new tools are offered: confirm first
    r = _save([{"id": "mcp_sidecar.tools", "value": rows},
               {"id": "mcp_sidecar.upstream_url", "value": "https://tools.example/mcp"},
               {"id": "mcp_sidecar.enable", "value": True}], confirm=True)
    assert r.status_code == 200, r.text
    config = SidecarConfig.from_mapping(_loaded()["mcp_sidecar"])
    assert {t.name for t in config.tools} == {"search.docs", "tickets"}
    table = _row("mcp_sidecar.tools")
    assert [(t["name"], t["risk"]) for t in table["rows"]] == [
        ("search.docs", "low"), ("tickets", "high")]
    # Raising a risk level is not a loosening; lowering one is.
    raised = [{"name": "search.docs", "risk": "medium"}, {"name": "tickets", "risk": "high"}]
    assert _save([{"id": "mcp_sidecar.tools", "value": raised}]).status_code == 200
    lowered = [{"name": "search.docs", "risk": "medium"}, {"name": "tickets", "risk": "low"}]
    assert _save([{"id": "mcp_sidecar.tools", "value": lowered}]).status_code == 409
    bad = [{"name": "bad__name", "risk": "low"}]
    assert _save([{"id": "mcp_sidecar.tools", "value": bad}], confirm=True).status_code == 400
    assert _save([{"id": "mcp_sidecar.enable", "value": True},
                  {"id": "mcp_sidecar.tools", "value": []}], confirm=True).status_code == 400


# ----------------------------------------------------- usage limits table
def test_usage_limits_for_any_tool(audit_rows):
    from maverick.safety.rate_limiter import _load_limits

    rows = [{"name": "mcp_*", "count": 60, "seconds": 60},
            {"name": "wiki_search", "count": 5, "seconds": 3600}]
    r = _save([{"id": "rate_limits.other", "value": rows}])
    assert r.status_code == 200, r.text
    limits = _load_limits()
    assert limits["mcp_*"] == (60, 60.0) and limits["wiki_search"] == (5, 3600.0)
    # A family name such as mcp_* is written as a quoted key: the overlay file
    # stays readable, so no other saved setting is lost.
    from maverick import config

    assert config.config_source_errors() == {}
    assert '"mcp_*" = "60/60"' in config.dashboard_overrides_path().read_text(encoding="utf-8")
    table = _row("rate_limits.other")
    assert {t["label"] for t in table["rows"]} == {
        "Every tool from outside tool servers", "Wiki search"}
    # Removing a limit, or allowing more calls, loosens: confirm first.
    assert _save([{"id": "rate_limits.other", "value": rows[:1]}]).status_code == 409
    faster = [{"name": "mcp_*", "count": 120, "seconds": 60}, rows[1]]
    assert _save([{"id": "rate_limits.other", "value": faster}]).status_code == 409
    slower = [{"name": "mcp_*", "count": 30, "seconds": 60}, rows[1]]
    assert _save([{"id": "rate_limits.other", "value": slower}]).status_code == 200
    # The three common tools keep their own settings; unknown tools are refused.
    assert _save([{"id": "rate_limits.other",
                   "value": [{"name": "shell", "count": 1, "seconds": 60}]}]).status_code == 400
    assert _save([{"id": "rate_limits.other",
                   "value": [{"name": "no_such_tool", "count": 1, "seconds": 60}]}]
                 ).status_code == 400
    # The shell limit set on its own row is untouched by the table.
    assert _save([{"id": "rate_limits.shell", "value": {"count": 3, "seconds": 60}}]
                 ).status_code == 200
    assert _save([{"id": "rate_limits.other", "reset": True}], confirm=True).status_code == 200
    cfg = _loaded()["rate_limits"]
    assert cfg == {"shell": "3/60"}


def test_installer_limits_can_change_but_not_be_removed_here(audit_rows):
    _installer('[rate_limits]\n"mcp_*" = "60/60"\n')
    row = _row("rate_limits.other")
    assert row["source"] == "installer" and row["rows"][0]["name"] == "mcp_*"
    r = _save([{"id": "rate_limits.other", "value": []}], confirm=True)
    assert r.status_code == 400 and "set by your installer" in r.json()["message"]
    assert _save([{"id": "rate_limits.other",
                   "value": [{"name": "mcp_*", "count": 10, "seconds": 60}]}]).status_code == 200
    assert _loaded()["rate_limits"]["mcp_*"] == "10/60"


# ------------------------------------------------ plugins and local models
def test_plugin_permissions_survive_next_to_the_install_list(audit_rows):
    from maverick import plugins
    from maverick_dashboard import settings_store

    settings_store.set_plugin_install_allowed(True)
    r = _save([{"id": "plugins.grant", "value": ["network"]}])
    assert r.status_code == 409
    assert _save([{"id": "plugins.grant", "value": ["network"]}], confirm=True).status_code == 200
    cfg = _loaded()["plugins"]
    assert cfg["grant"] == ["network"] and cfg["allow_install"] is True
    assert _save([{"id": "plugins.enforce_permissions", "value": False}]).status_code == 409
    assert plugins._KNOWN_PERMISSIONS  # the module the setting feeds


def test_local_model_preference_uses_the_model_catalog(audit_rows):
    from maverick import provider_local_first

    r = _save([{"id": "system.local_first", "value": True},
               {"id": "local_first.model", "value": "ollama:qwen3-32b"}])
    assert r.status_code == 200, r.text
    assert provider_local_first.enabled() is True
    assert provider_local_first.local_model_for_role("orchestrator") == "ollama:qwen3-32b"
    assert _save([{"id": "local_first.model", "value": "openai:gpt-5.5"}]).status_code == 400
    assert _save([{"id": "local_runtime.enabled", "value": True}]).status_code == 400
    assert _save([{"id": "local_runtime.min_replicas", "value": 4},
                  {"id": "local_runtime.max_replicas", "value": 2}]).status_code == 400


# Module switches added for governance modules that only had an installer
# question: turning one on (with its requirement chain) is exactly what the
# kernel module's own gate checks.
_NEW_SWITCHES = {
    "ai_regulatory_feed": "maverick.ai_regulatory_feed",
    "ai_business_intake": "maverick.ai_business_intake",
    "ai_dynamic_risk": "maverick.ai_dynamic_risk",
    "ai_policy_management": "maverick.ai_policy_management",
    "ai_runtime_guardrails": "maverick.ai_runtime_guardrails",
    "ai_explainability": "maverick.ai_explainability",
    "ai_conformity_workflow": "maverick.ai_conformity_workflow",
    "ai_insurability": "maverick.ai_insurability",
    "ai_regulated_verticals": "maverick.ai_regulated_verticals",
    "ai_bank_mrm": "maverick.ai_bank_mrm",
    "ai_discovery_sensors": "maverick.ai_discovery_sensors",
    "portfolio_risk": "maverick.portfolio_risk",
    "ai_cost_roi": "maverick.ai_cost_roi",
    "eu_ai_incidents": "maverick.eu_ai_incidents",
    "grc_outbound_sync": "maverick.grc_outbound_sync",
    "incident_attachment_metadata": "maverick.incident_attachment_metadata",
    "agent_topology": "maverick.agent_topology",
}


@pytest.mark.parametrize("section", sorted(_NEW_SWITCHES))
def test_new_module_switches_open_the_kernel_gate(section):
    import importlib

    module = importlib.import_module(_NEW_SWITCHES[section])
    assert module.enabled() is False
    r = client.post("/api/v1/features/modules", json={"section": section, "enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    _loaded()
    assert module.enabled() is True
    r = client.post("/api/v1/features/modules", json={"section": section, "enabled": False})
    assert r.status_code == 200
    _loaded()
    assert module.enabled() is False


def test_page_does_not_build_the_long_tool_list(monkeypatch):
    from maverick_dashboard import settings_all_page

    def slow():
        raise AssertionError("the page must load the tool list only when asked")

    monkeypatch.setattr(settings_all_page, "_tool_names", slow)
    assert client.get("/settings/all").status_code == 200
    for group in ("safety", "security", "performance"):  # the groups with tool lists
        assert client.get("/settings/all", params={"group": group}).status_code == 200
        assert client.get("/settings/all/rows", params={"group": group}).status_code == 200
    assert client.get(API).status_code == 200


def test_page_script_and_styles_are_served():
    script = client.get("/static/lightwork-settings-all.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"]
    assert "settings-all-groups" in script.text
    styles = client.get("/static/lightwork-settings-all.css")
    assert styles.status_code == 200 and styles.headers["content-type"].startswith("text/css")


# ------------------------------------------------- task-start risk check
def test_asking_a_person_before_risky_tasks_is_off_by_default_and_loosening_confirms(audit_rows):
    from maverick.safety.goal_risk import config_floor, require_human_for
    assert require_human_for("high") is False and config_floor() == "low"
    turn_on = {"id": "safety.goal_risk_require_human", "value": "medium"}
    assert _save([turn_on]).status_code == 200  # tightening needs no confirmation
    assert require_human_for("medium") is True
    for change in ({"id": "safety.goal_risk_require_human", "value": "never"},):
        assert _save([change]).status_code == 409, change
        assert _save([change], confirm=True).status_code == 200, change
    assert require_human_for("high") is False
    assert _save([{"id": "safety.goal_risk_floor", "value": "high"}]).status_code == 200
    assert config_floor() == "high"
    assert _save([{"id": "safety.goal_risk_floor", "value": "low"}]).status_code == 409
    assert _save([{"id": "safety.goal_risk_require_human", "value": "sometimes"}],
                 confirm=True).status_code == 400
