"""Settings > All settings: page, save/reset round-trips, permissions, audit.

Values saved here land in the dashboard overlay and must be what the kernel's
``load_config`` returns; reset must give the default back; only a global admin
on the same origin may write; each change leaves one audit row without any
secret value; and a change that lowers a protection is refused by the server
unless the request confirms it.
"""
from __future__ import annotations

import json
import threading

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_AUDIT_SIGN", "MAVERICK_IFC_MODE", "MAVERICK_APPROVALS_REQUIRED"):
        monkeypatch.delenv(name, raising=False)
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


def test_locked_down_mode_row_says_it_is_on_when_its_source_is_unreadable(monkeypatch):
    from maverick import containment

    assert _row("containment.enabled")["value"] is False
    message = "Locked-down mode is on because config.toml could not be read."
    monkeypatch.setattr(containment, "status", lambda: {
        "enabled": True, "reason": "unreadable_configuration",
        "sources": ["config.toml"], "message": message})
    row = _row("containment.enabled")
    assert row["value"] is None and row["locked"] is True
    assert row["value_text"] == message


def test_work_value_controls_round_trip_into_live_report_authority():
    from maverick.intent_value.settings import policy

    report = "/api/v1/intent-value"
    assert policy()["enabled"] is True
    saved = _save([{"id": "intent_value.enabled", "value": False}])
    assert saved.status_code == 200, saved.text
    assert _loaded()["intent_value"]["enabled"] is False
    assert client.get(report).status_code == 403
    saved = _save([{"id": "intent_value.enabled", "value": True},
                   {"id": "intent_value.recommendations", "value": False}])
    assert saved.status_code == 200, saved.text
    assert policy() == {"enabled": True, "recommendations": False, "completion_confirmation": False}
    assert client.get(report).status_code == 200
    assert client.get(report + "/settings").json()["completion_confirmation"] is False
    assert client.get(report + "/opportunities").json()["opportunities"] == []


# ------------------------------------------------------------------ page
def test_page_lists_groups_controls_and_speaks_plain_language():
    from test_support.plain_language import developer_terms

    r = client.get("/settings/all")
    assert r.status_code == 200
    page = r.text
    for group in ("Safety", "Security", "AI models", "Spending &amp; limits",
                  "Memory &amp; learning", "Privacy", "Data retention", "Integrations",
                  "Performance", "Modules"):
        assert group in page
    assert "Save changes in Safety" in page
    assert 'id="settings-all-search"' in page
    assert "/static/lightwork-settings-all.js" in page
    assert 'id="settings-signin-guide"' in page
    for setting in ("auth.oidc.redirect_uri", "auth.saml.acs_url", "auth.saml.sp_entity_id"):
        assert f"/settings/all?id={setting}" in page
    assert 'data-signin-check="oidc"' in page and 'data-signin-check="saml"' in page
    assert "What can&#39;t be changed here" in page or "What can't be changed here" in page
    assert developer_terms(page) == []
    group = client.get("/settings/all?group=safety").text
    assert 'role="switch"' in group and "<select" in group and 'type="number"' in group
    assert "Reset to product default" in group and "Use inherited value" in group and "Save changes in Safety" in group
    assert developer_terms(group) == []


# ------------------------------------------------- loading a group at a time
def _row_ids(html: str) -> list[str]:
    import re

    return re.findall(r'data-setting-id="([^"]+)"', html)


def _available_settings(catalog):
    return list(catalog.SETTINGS)


def test_first_load_is_the_list_of_groups_without_their_settings():
    from maverick_dashboard import settings_catalog as catalog

    r = client.get("/settings/all")
    assert r.status_code == 200 and len(r.content) < 300_000
    assert _row_ids(r.text) == []
    for name in catalog.GROUPS:
        count = sum(1 for s in _available_settings(catalog) if s.group == name)
        slug = name.lower().replace(" & ", "-").replace(" ", "-")
        assert f'data-group="{slug}" data-loaded="0"' in r.text, name
        # Works without the page's script too: a plain link to the group.
        assert f'href="/settings/all?group={slug}#group-{slug}"' in r.text, name
        assert f"Show the {count} settings in" in r.text, name
    assert f"0 of {len(_available_settings(catalog))} settings" in r.text
    assert 'data-module="' in r.text  # the module switches are always there


def test_each_group_lists_all_its_settings_and_every_setting_has_a_group():
    from maverick_dashboard import settings_catalog as catalog

    seen: list[str] = []
    for name in catalog.GROUPS:
        slug = name.lower().replace(" & ", "-").replace(" ", "-")
        page = client.get("/settings/all", params={"group": slug}).text
        rows = client.get("/settings/all/rows", params={"group": slug})
        assert rows.status_code == 200 and rows.headers["cache-control"] == "no-store"
        assert f'data-complete="{slug}"' in rows.text
        ids = [s.id for s in _available_settings(catalog) if s.group == name]
        assert sorted(_row_ids(page)) == sorted(ids) == sorted(_row_ids(rows.text)), name
        assert f'data-group="{slug}" data-loaded="1"' in page
        assert f'<option value="{slug}" selected>' in page
        listed = client.get(API, params={"group": slug}).json()["groups"]
        assert [g["name"] for g in listed] == [name]
        assert [s["id"] for s in listed[0]["settings"]] == _row_ids(rows.text)
        seen += ids
    assert sorted(seen) == sorted(s.id for s in _available_settings(catalog))
    assert client.get(API, params={"group": "nothing-here"}).status_code == 404


def test_rows_keep_their_place_in_page_order():
    whole = [s["id"] for g in client.get(API).json()["groups"] for s in g["settings"]]
    orders = {s["id"]: s["order"] for g in client.get(API).json()["groups"]
              for s in g["settings"]}
    assert [orders[i] for i in whole] == list(range(len(whole)))
    part = client.get(API, params={"group": "safety"}).json()["groups"][0]
    assert all(orders[s["id"]] == s["order"] for s in part["settings"])
    assert [p["order"] for p in part["subgroups"]] == sorted(p["order"] for p in part["subgroups"])


def test_search_finds_matching_settings_in_every_group_without_the_rest():
    import html
    import re

    from maverick_dashboard import settings_catalog as catalog

    words = ("records", "keep")
    expected = [s.id for s in _available_settings(catalog)
                if all(w in " ".join((s.label, s.help, s.aliases, s.group, s.subgroup)).lower()
                       for w in words)]
    assert 1 < len(expected) < len(catalog.SETTINGS) // 10
    assert len({catalog.BY_ID[i].group for i in expected}) > 1
    found = client.get("/settings/all/rows", params={"q": "Records  KEEP"})
    assert found.status_code == 200 and 'data-complete=""' in found.text
    assert sorted(_row_ids(found.text)) == sorted(expected)
    # The page's own filter matches the same words on the rows it gets.
    for text in re.findall(r'data-search="([^"]*)"', found.text):
        assert all(w in html.unescape(text) for w in words)
    listed = client.get(API, params={"q": "records keep"}).json()["groups"]
    assert sorted(s["id"] for g in listed for s in g["settings"]) == sorted(expected)
    # Without the script: the search box sends the same words to the page.
    page = client.get("/settings/all", params={"q": "records keep"}).text
    assert sorted(_row_ids(page)) == sorted(expected) and 'value="records keep"' in page
    assert 'data-served="1"' in page
    assert _row_ids(client.get("/settings/all/rows", params={"q": "zzzz-nothing"}).text) == []
    assert client.get("/settings/all/rows").status_code == 400


def test_only_changed_settings_and_a_link_to_one_setting(audit_rows):
    from maverick_dashboard import settings_catalog as catalog

    assert _save([{"id": "ifc.mode", "value": "block"}]).status_code == 200
    changed = client.get("/settings/all/rows", params={"changed": "1"})
    assert _row_ids(changed.text) == ["ifc.mode"]
    assert [s["id"] for g in client.get(API, params={"changed": "1"}).json()["groups"]
            for s in g["settings"]] == ["ifc.mode"]
    page = client.get("/settings/all", params={"changed": "1"}).text
    assert _row_ids(page) == ["ifc.mode"] and "1 changed here" in page
    assert f"1 of {len(_available_settings(catalog))} settings" in page
    # ?id= opens the setting's group and points the page at the setting.
    group = catalog.BY_ID["ifc.mode"].group
    linked = client.get("/settings/all", params={"id": "ifc.mode"}).text
    assert 'data-focus="ifc.mode"' in linked
    assert sorted(_row_ids(linked)) == sorted(s.id for s in catalog.SETTINGS if s.group == group)
    assert _row_ids(client.get("/settings/all", params={"id": "no.such"}).text) == []


def test_loading_rows_is_for_administrators_only(monkeypatch):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get("/settings/all/rows", params={"group": "safety"}).status_code == 403
    assert client.get("/settings/all", params={"group": "safety"}).status_code == 403
    assert client.get(API, params={"q": "retention"}).status_code == 403


def test_a_save_replies_with_the_rows_it_touched_not_every_row(audit_rows):
    from maverick_dashboard import settings_catalog as catalog

    r = _save([{"id": "ifc.mode", "value": "block"}])
    assert r.status_code == 200 and r.json()["changed"] == ["ifc.mode"]
    rows = [s for g in r.json()["groups"] for s in g["settings"]]
    assert [s["id"] for s in rows] == ["ifc.mode"]
    assert rows[0]["source"] == "here" and rows[0]["value"] == "block"
    assert len(r.content) < 10_000
    # Nothing changed: the named row still comes back, so the page shows it.
    again = _save([{"id": "ifc.mode", "value": "block"}])
    assert again.json()["changed"] == []
    assert [s["id"] for g in again.json()["groups"] for s in g["settings"]] == ["ifc.mode"]
    # ?full=1 keeps the whole listing for a caller that wants it.
    whole = save_catalog(client, API + "?full=1", json={"changes": [{"id": "ifc.mode", "reset": True}],
                                                "confirm": True})
    assert whole.status_code == 200
    assert sum(len(g["settings"]) for g in whole.json()["groups"]) == len(_available_settings(catalog))


def test_rows_changed_by_a_save_come_back_even_when_not_named():
    from maverick_dashboard import settings_all_page

    before = settings_all_page.catalog_state()
    target = before["groups"][2]["settings"][0]
    target["value_text"] = "something older"  # as if the save changed this row too
    state = settings_all_page._saved_state(before, {"ifc.mode"})
    ids = [s["id"] for g in state["groups"] for s in g["settings"]]
    assert sorted(ids) == sorted({"ifc.mode", target["id"]})
    for group in state["groups"]:
        parts = {s["subgroup"] for s in group["settings"] if s["subgroup"]}
        assert {p["name"] for p in group["subgroups"]} == parts
    assert settings_all_page._saved_state(None, set())["groups"] == \
        settings_all_page.catalog_state()["groups"]


def test_one_listing_builds_each_live_list_once(monkeypatch):
    from maverick_dashboard import settings_all_page

    calls: list[str] = []
    real = settings_all_page._build_source_choices

    def counted(source):
        calls.append(source)
        return real(source)

    monkeypatch.setattr(settings_all_page, "_build_source_choices", counted)
    settings_all_page.catalog_state()
    assert calls and len(calls) == len(set(calls))


def test_settings_page_links_to_all_settings():
    assert 'href="/settings/all"' in client.get("/settings").text


def test_page_shows_where_each_value_comes_from(tmp_path):
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text('[safety]\nprofile = "strict"\n', encoding="utf-8")
    config.reset_config_cache()
    assert _row("safety.profile")["source_text"] == "Set by your installer"
    assert _row("safety.profile")["value"] == "strict"
    assert _row("ifc.mode")["source_text"] == "Default"
    assert _save([{"id": "ifc.mode", "value": "block"}]).status_code == 200
    assert _row("ifc.mode")["source_text"] == "Set here"
    assert "Set by your installer" in client.get("/settings/all?group=safety").text


# ------------------------------------------------------------ round trip
def test_save_and_reset_round_trip_through_load_config(audit_rows):
    changes = [
        {"id": "ifc.mode", "value": "block"},
        {"id": "budget.max_tool_calls", "value": 40},
        {"id": "routing.allowed_providers", "value": ["openai", "anthropic"]},
        {"id": "webhooks.outbound", "value": ["https://hooks.example/run"]},
        {"id": "rate_limits.shell", "value": {"count": 5, "seconds": 60}},
        {"id": "billing.stripe.currency", "value": "EUR"},
        {"id": "sandbox.timeout", "value": 120},
        {"id": "memory_guard.min_recall_trust", "value": "2"},
    ]
    # Adding an address that receives task events is confirmed.
    assert _save(changes).status_code == 409
    r = _save(changes, confirm=True)
    assert r.status_code == 200, r.text
    cfg = _loaded()
    assert cfg["ifc"]["mode"] == "block"
    assert cfg["budget"]["max_tool_calls"] == 40
    assert cfg["routing"]["allowed_providers"] == ["anthropic", "openai"]
    assert cfg["webhooks"]["outbound"] == ["https://hooks.example/run"]
    assert cfg["rate_limits"]["shell"] == "5/60"
    assert cfg["billing"]["stripe"]["currency"] == "EUR"
    assert cfg["sandbox"]["timeout"] == 120
    assert cfg["memory_guard"]["min_recall_trust"] == 2
    from maverick import config

    assert config.get_ifc()["mode"] == "block"
    assert config.get_memory_guard()["min_recall_trust"] == 2

    resets = [{"id": c["id"], "reset": True} for c in changes]
    # Going back to the default loosens some of these, so it is confirmed too.
    assert _save(resets).status_code == 409
    r = _save(resets, confirm=True)
    assert r.status_code == 200, r.text
    cfg = _loaded()
    assert "ifc" not in cfg and "rate_limits" not in cfg and "budget" not in cfg
    assert config.get_ifc()["mode"] == "audit"
    assert _row("ifc.mode")["source"] == "default"


def test_reset_returns_to_the_default_even_over_an_installer_value(audit_rows):
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text("[swarm]\nmax_total_spawns = 8\n", encoding="utf-8")
    config.reset_config_cache()
    assert _save([{"id": "swarm.max_total_spawns", "reset": True}]).status_code == 200
    assert config.get_swarm()["max_total_spawns"] == 64
    assert "max_total_spawns = 8" in config.config_path().read_text(encoding="utf-8")


def test_existing_overlay_settings_survive_a_catalog_save(audit_rows):
    from maverick import config
    from maverick_dashboard import settings_store

    # The signing secret is saved through its reviewed change, like the Settings card.
    reviewed = client.get("/settings/webhooks").json()["expected_generation"]
    assert client.post("/settings/webhooks", data={
        "secret": "keep-me-secret", "expected_generation": reviewed,  # pragma: allowlist secret
    }).status_code == 200
    settings_store.set_sandbox_backend("docker")
    settings_store.set_toggle("features", "skills", False)
    assert _save([{"id": "sandbox.timeout", "value": 90},
                  {"id": "webhooks.outbound", "value": ["https://a.example/b"]}],
                 confirm=True).status_code == 200
    cfg = _loaded()
    assert cfg["sandbox"] == {"backend": "docker", "timeout": 90}
    assert cfg["features"]["skills"] is False
    from maverick.webhooks import _load_config_outbound
    assert _load_config_outbound()[1] == "keep-me-secret"  # pragma: allowlist secret
    assert config.config_source_errors() == {}


def test_invalid_values_are_refused_with_a_plain_message(audit_rows):
    r = _save([{"id": "budget.max_tool_calls", "value": -3}])
    assert r.status_code == 400
    assert r.json()["message"].startswith("Actions per task:")
    assert _save([{"id": "no.such_setting", "value": 1}]).status_code == 400
    assert audit_rows == []


def test_deployment_controlled_settings_are_locked(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_IFC_MODE", "block")
    row = _row("ifc.mode")
    assert row["locked"] is True and row["source"] == "deployment"
    r = _save([{"id": "ifc.mode", "value": "off"}], confirm=True)
    assert r.status_code == 409
    assert "ifc" not in _loaded()


# ---------------------------------------------------------- permissions
def test_cross_origin_writes_are_refused(audit_rows):
    bare = TestClient(app, base_url="http://127.0.0.1")
    r = _save([{"id": "ifc.mode", "value": "block"}], http=bare)
    assert r.status_code == 403
    assert "ifc" not in _loaded()


def test_non_admins_are_refused(monkeypatch, audit_rows):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:vera", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vera")
    assert client.get("/settings/all").status_code == 403
    assert client.get(API).status_code == 403
    assert _save([{"id": "ifc.mode", "value": "block"}]).status_code == 403
    assert "ifc" not in _loaded()


def test_workspace_admins_cannot_change_installation_settings(monkeypatch, audit_rows):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    token = set_tenant("acme")
    try:
        r = _save([{"id": "ifc.mode", "value": "block"}])
    finally:
        reset_tenant(token)
    assert r.status_code == 403


# ------------------------------------------------------------- safety
def test_weakening_needs_confirmation_on_the_server(audit_rows):
    r = _save([{"id": "audit.sign", "value": False}])
    assert r.status_code == 409
    assert r.json()["confirm"][0]["id"] == "audit.sign"
    assert "audit" not in _loaded()
    assert audit_rows == []
    r = _save([{"id": "audit.sign", "value": False}], confirm=True)
    assert r.status_code == 200
    assert _loaded()["audit"]["sign"] is False
    assert audit_rows[-1]["confirmed"] is True
    # Strengthening again needs no confirmation.
    assert _save([{"id": "audit.sign", "value": True}]).status_code == 200


def test_resetting_to_a_weaker_default_also_needs_confirmation(audit_rows):
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text("[security]\nallow_self_approval = false\n"
                                    "approvals_required = 2\n", encoding="utf-8")
    config.reset_config_cache()
    r = _save([{"id": "security.approvals_required", "reset": True}])
    assert r.status_code == 409
    assert _save([{"id": "security.approvals_required", "reset": True}],
                 confirm=True).status_code == 200


def test_shortening_retention_needs_confirmation(audit_rows):
    assert _save([{"id": "retention.audit_days", "value": 30}]).status_code == 409
    assert _save([{"id": "retention.audit_days", "value": 30}], confirm=True).status_code == 200
    assert _save([{"id": "retention.audit_days", "value": 90}]).status_code == 200


# ----------------------------------------------------------------- audit
def test_one_audit_row_per_change(audit_rows):
    r = _save([{"id": "ifc.mode", "value": "block"},
               {"id": "persona.name", "value": "Ada"}])
    assert r.status_code == 200
    kinds = [row["kind"] for row in audit_rows]
    assert kinds == ["setting_changed", "setting_changed"]
    by_key = {(row["section"], row["key"]): row for row in audit_rows}
    assert by_key[("ifc", "mode")]["old"] == "audit"
    assert by_key[("ifc", "mode")]["new"] == "block"
    assert by_key[("persona", "name")]["new"] == "Ada"
    assert all(row["_global"] is True and row["actor"] for row in audit_rows)
    # Saving the same value again is not a change.
    _save([{"id": "ifc.mode", "value": "block"}])
    assert len(audit_rows) == 2


def test_secrets_are_sealed_never_shown_and_never_audited(audit_rows):
    from maverick import config

    secret = "ntfy-topic-do-not-show"  # pragma: allowlist secret
    r = _save([{"id": "notifications.ntfy_topic", "value": secret}])
    assert r.status_code == 200
    assert secret not in r.text
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert secret not in stored and "MVKAR1:" in stored
    assert _loaded()["notifications"]["ntfy_topic"] == secret
    row = _row("notifications.ntfy_topic")
    assert row["is_set"] is True and row["value"] is None
    assert secret not in every_group(client)
    assert secret not in client.get(API).text
    assert audit_rows[-1]["old"] == "not set" and audit_rows[-1]["new"] == "set"
    assert secret not in repr(audit_rows)
    assert _save([{"id": "notifications.ntfy_topic", "reset": True}]).status_code == 200
    assert "ntfy_topic" not in (_loaded().get("notifications") or {})


def test_refused_audit_undoes_the_change(monkeypatch):
    import maverick.audit as audit

    def refuse(kind, **payload):
        raise audit.AuditRefused("custody refused")

    monkeypatch.setattr(audit, "audit_event", refuse)
    r = _save([{"id": "ifc.mode", "value": "block"}])
    assert r.status_code == 503
    assert "ifc" not in _loaded()


# ------------------------------------------------- settings file integrity
@pytest.mark.parametrize("bad", ["\ud800", "name\x7fhere", "name\x00here", "line\nbreak"])
def test_values_that_would_break_the_settings_file_are_refused(audit_rows, bad):
    from maverick_dashboard import settings_store

    assert _save([{"id": "sandbox.timeout", "value": 30}]).status_code == 200
    # Sent as escaped JSON, the way any script can send it.
    body = json.dumps({"expected_revision": client.get(API, params={"q":"__revision__"}).json()["revision"], "changes": [{"id": "persona.name", "value": bad}]})
    r = client.post(API, content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    message = r.json()["message"]
    assert message.startswith("Name") or ":" in message
    assert "surrogate" not in message.lower() and "toml" not in message.lower()
    # The overlay still reads, so every other dashboard setting still applies.
    assert settings_store.load_overlay()["sandbox"]["timeout"] == 30
    assert "persona" not in settings_store.load_overlay()
    assert _save([{"id": "sandbox.timeout", "value": 31}]).status_code == 200


def test_list_entries_that_would_break_the_settings_file_are_refused(audit_rows):
    import dataclasses

    from maverick_dashboard import settings_catalog as catalog

    # A text list: the percentage lists have their own number check in coerce().
    numeric = {"spending_limits.alert_at", "budget.warning_thresholds"}
    listed = next(s for s in catalog.SETTINGS if s.control == "list" and s.id not in numeric)
    free_text = dataclasses.replace(listed, pattern="")
    assert catalog.coerce(free_text, ["ok"]) == ["ok"]
    for bad in ("bad\ud800", "bad\x7f", "bad\x1b"):
        with pytest.raises(catalog.SettingError) as exc:
            catalog.coerce(free_text, ["ok", bad])
        assert str(exc.value).startswith(listed.label)


# ------------------------------------------- loosening spend, rate, egress
@pytest.mark.parametrize("change,setup", [
    ({"id": "quotas.enforce", "value": False}, {"id": "quotas.enforce", "value": True}),
    ({"id": "rate_limits.shell", "reset": True},
     {"id": "rate_limits.shell", "value": {"count": 5, "seconds": 60}}),
    ({"id": "rate_limits.shell", "value": {"count": 500, "seconds": 60}},
     {"id": "rate_limits.shell", "value": {"count": 5, "seconds": 60}}),
    ({"id": "budget.max_tool_calls", "value": None},
     {"id": "budget.max_tool_calls", "value": 50}),
    ({"id": "webhooks.outbound", "value": ["https://collector.example.net/x"]}, None),
    ({"id": "knowledge.url", "value": "http://10.0.0.5:6333"}, None),
])
def test_loosening_spending_rate_and_outbound_controls_needs_confirmation(
    audit_rows, change, setup,
):
    if setup is not None:
        assert _save([setup]).status_code == 200
    r = _save([change])
    assert r.status_code == 409, r.text
    assert r.json()["confirm"][0]["id"] == change["id"]
    assert r.json()["confirm"][0]["warning"]
    r = _save([change], confirm=True)
    assert r.status_code == 200, r.text
    assert audit_rows[-1]["confirmed"] is True


def test_tightening_spending_rate_and_outbound_controls_needs_no_confirmation(audit_rows):
    assert _save([{"id": "quotas.enforce", "value": True}]).status_code == 200
    assert _save([{"id": "rate_limits.shell",
                   "value": {"count": 5, "seconds": 60}}]).status_code == 200
    assert _save([{"id": "rate_limits.shell",
                   "value": {"count": 2, "seconds": 60}}]).status_code == 200
    assert _save([{"id": "budget.max_tool_calls", "value": 50}]).status_code == 200
    assert _save([{"id": "budget.max_tool_calls", "value": 20}]).status_code == 200
    assert _save([{"id": "knowledge.url", "value": "https://qdrant.example.net"}]).status_code == 200
    assert _save([{"id": "webhooks.outbound", "value": ["https://a.example.net/x"]}],
                 confirm=True).status_code == 200
    # Removing an address only sends less, so it needs no confirmation.
    assert _save([{"id": "webhooks.outbound", "value": []}]).status_code == 200


def test_saving_the_contact_centre_token_sends_a_waiting_handoff_without_a_restart(monkeypatch, audit_rows):
    from maverick import contact_centre

    token = "tok-SECRET-98765"  # pragma: allowlist secret
    handoff = "handoff-settings-0123456789ab"
    calls: list[tuple[str, bytes, dict]] = []

    def fake_transport(url, body, headers):
        # Fake receiving system: one accepted ticket per request.
        calls.append((url, body, dict(headers)))
        return (201, 9, '{"ticket":{"url":"https://acme-support.zendesk.com/api/v2/tickets/4242.json","id":4242}}', "")

    assert _save([{"id": "contact_centre.provider", "value": "zendesk"},
                  {"id": "contact_centre.zendesk_subdomain", "value": "acme-support"},
                  {"id": "contact_centre.zendesk_email", "value": "agent@acme.example"}]).status_code == 200
    # Queued without a token: the handoff waits for Settings and is not sent.
    monkeypatch.setattr(contact_centre, "_start", lambda key: None)
    assert contact_centre.enqueue_handoff(
        handoff_id=handoff, title="Card declined", reason="Customer asked for a person",
        requester_name="Ana Ruiz", requester_email="ana@example.com",
        messages=[("user", "My card was declined")], link="https://lightwork.acme.example/conversations?goal=7",
    ) is not None
    assert contact_centre.status_for(handoff)["state"] == "waiting"

    monkeypatch.setattr(contact_centre, "_post", fake_transport)
    monkeypatch.setattr(contact_centre, "_start", lambda key: contact_centre.run_delivery(key))
    # An unrelated save starts nothing.
    assert _save([{"id": "sandbox.timeout", "value": 30}]).status_code == 200
    assert calls == [] and contact_centre.status_for(handoff)["state"] == "waiting"

    # Saving the token is a contact-centre save: the waiting handoff is sent now, with no restart.
    assert _save([{"id": "contact_centre.zendesk_api_token", "value": token}]).status_code == 200
    status = contact_centre.status_for(handoff)
    assert status["state"] == "sent" and status["ticket_id"] == "4242"
    assert len(calls) == 1
    assert token not in repr(audit_rows)


def test_the_contact_centre_resume_runs_after_the_settings_writer_lock_is_released(monkeypatch, audit_rows):
    from maverick import contact_centre
    from maverick_dashboard import settings_store

    def writer_lock_is_free() -> bool:
        # Another thread can take the settings writer lock only once the save has released it.
        taken = []

        def probe():
            if settings_store._SETTINGS_LOCK.acquire(timeout=2):
                taken.append(True)
                settings_store._SETTINGS_LOCK.release()

        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        return bool(taken)

    seen = []
    monkeypatch.setattr(contact_centre, "resume_all_workspaces",
                        lambda *, restarted=True: seen.append(writer_lock_is_free()) or 0)
    assert _save([{"id": "contact_centre.provider", "value": "zendesk"},
                  {"id": "contact_centre.zendesk_subdomain", "value": "acme-support"},
                  {"id": "contact_centre.zendesk_email", "value": "agent@acme.example"}]).status_code == 200
    assert seen == [True]
    # A save that touches no contact-centre setting resumes nothing.
    assert _save([{"id": "sandbox.timeout", "value": 30}]).status_code == 200
    assert seen == [True]

