"""The privacy-estate API surfaces: vendors, consent, and the data map.

Mutating /api/v1 requests carry a same-origin Origin (the CSRF contract).
Each surface is opt-in: the API answers 403 until its section is enabled.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_dsar_response_rate_is_separate_per_client(monkeypatch):
    import importlib
    from types import SimpleNamespace

    from fastapi import HTTPException
    from maverick_dashboard import ip_allowlist

    app_module = importlib.import_module("maverick_dashboard.app")
    app_module._dsar_response_times.clear()
    monkeypatch.setattr(ip_allowlist, "client_ip", lambda request: request.client.host)
    first = SimpleNamespace(client=SimpleNamespace(host="192.0.2.1"))
    second = SimpleNamespace(client=SimpleNamespace(host="192.0.2.2"))
    for _ in range(30):
        app_module._check_dsar_response_rate(first)
    with pytest.raises(HTTPException) as denied:
        app_module._check_dsar_response_rate(first)
    assert denied.value.status_code == 429
    app_module._check_dsar_response_rate(second)
    app_module._dsar_response_times.clear()

_CONFIG = (
    "[vendor_management]\nenable = true\n\n"
    "[consent_registry]\nenable = true\n"
    'subject_salt = "dashboard-test-salt-0123456789"\n\n'
    "[data_map]\nenable = true\n\n"
    "[privacy_ops]\nenable = true\n"
)


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in (
        "MAVERICK_CONNECTIONS", "MAVERICK_ENTERPRISE",
        "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH",
        "MAVERICK_GRAPH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text(_CONFIG, encoding="utf-8")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def test_every_surface_is_403_until_enabled(tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert client.get("/api/v1/vendors").status_code == 403
    assert client.get("/api/v1/consent/posture").status_code == 403
    assert client.get("/api/v1/data-map/assets").status_code == 403


def test_vendor_register_round_trip_and_conflict():
    resp = client.post("/api/v1/vendors", json={
        "name": "Acme Analytics", "category": "analytics",
        "criticality": "high", "owner": "procurement"})
    assert resp.status_code == 201, resp.text
    vendor = resp.json()
    assert vendor["id"].startswith("VMR-")

    dup = client.post("/api/v1/vendors", json={
        "name": "Acme Analytics", "category": "analytics",
        "criticality": "low", "owner": "procurement"})
    assert dup.status_code == 409

    single = client.get(f"/api/v1/vendors/{vendor['id']}")
    assert single.status_code == 200
    assert single.json()["criticality"] == "high"
    assert client.get("/api/v1/vendors/VMR-missing").status_code == 404

    listing = client.get("/api/v1/vendors")
    assert [v["name"] for v in listing.json()["vendors"]] == ["Acme Analytics"]

    posture = client.get("/api/v1/vendors/posture")
    assert posture.status_code == 200
    assert posture.json()["vendors"] == 1


def test_vendor_questionnaire_lifecycle_over_the_api():
    vendor = client.post("/api/v1/vendors", json={
        "name": "Globex", "category": "hosting",
        "criticality": "medium", "owner": "it"}).json()
    sent = client.post(
        f"/api/v1/vendors/{vendor['id']}/questionnaires",
        json={"assessment_type": "vendor_risk",
              "revision": vendor["revision"]})
    assert sent.status_code == 201, sent.text
    assert sent.json()["form_path"].startswith("/form/")
    token = sent.json()["form_path"].removeprefix("/form/")
    assert "token" not in sent.json()["questionnaires"][0]

    # The creation response is the only place the public bearer link is shown.
    listed = client.get("/api/v1/vendors").json()
    detail = client.get(f"/api/v1/vendors/{vendor['id']}").json()
    for projection in (listed, detail):
        assert token not in str(projection)
    assert detail["questionnaires"][0]["request_id"]

    bad = client.post(
        f"/api/v1/vendors/{vendor['id']}/questionnaires",
        json={"assessment_type": "not-a-template",
              "revision": sent.json()["revision"]})
    assert bad.status_code == 422

    back = client.get(f"/api/v1/vendors/{vendor['id']}/questionnaires")
    assert back.status_code == 200
    assert back.json()["questionnaires"][0]["status"] == "sent"
    assert token not in back.text
    assert "form_path" not in back.json()["questionnaires"][0]


def test_admin_can_replace_vendor_link_without_losing_replies(monkeypatch):
    import maverick_dashboard.api as api
    from maverick import form_store

    vendor = client.post("/api/v1/vendors", json={
        "name": "Link rotation", "category": "hosting",
        "criticality": "high", "owner": "it",
    }).json()
    sent = client.post(
        f"/api/v1/vendors/{vendor['id']}/questionnaires",
        json={"assessment_type": "vendor_risk", "revision": vendor["revision"]},
    ).json()
    old_path = sent["form_path"]
    assert client.post(old_path, json={"vr_q1": "yes"}).status_code == 201
    rows = client.get(f"/api/v1/vendors/{vendor['id']}/questionnaires").json()["questionnaires"]
    request_id = rows[0]["request_id"]
    url = f"/api/v1/vendors/{vendor['id']}/questionnaires/{request_id}/replace"

    original_permission = api.require_permission

    def operator_only(request, permission):
        if permission == "admin":
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Administrator access required.")
        return original_permission(request, permission)

    with monkeypatch.context() as patch:
        patch.setattr(api, "require_permission", operator_only)
        assert client.post(url, json={"revision": sent["revision"]}).status_code == 403
    assert client.get(old_path).status_code == 200

    stale = client.post(url, json={"revision": vendor["revision"]})
    assert stale.status_code == 409
    assert client.post(old_path, json={"vr_q1": "no"}).status_code == 201

    replaced = client.post(url, json={"revision": sent["revision"]})
    assert replaced.status_code == 200, replaced.text
    assert replaced.headers["cache-control"] == "no-store"
    new_path = replaced.json()["form_path"]
    assert new_path != old_path
    for route in ("/api/v1/vendors", f"/api/v1/vendors/{vendor['id']}",
                  f"/api/v1/vendors/{vendor['id']}/questionnaires"):
        projection = client.get(route)
        assert projection.status_code == 200
        assert old_path.rsplit("/", 1)[-1] not in projection.text
        assert new_path.rsplit("/", 1)[-1] not in projection.text
    assert client.get(old_path).status_code == 404
    assert client.post(old_path, json={"vr_q1": "no"}).status_code == 404
    assert client.get(new_path).status_code == 200
    assert client.post(new_path, json={"vr_q1": "no"}).status_code == 201
    readback = client.get(f"/api/v1/vendors/{vendor['id']}/questionnaires")
    assert readback.headers["cache-control"] == "no-store"
    history = readback.json()["questionnaires"][0]
    assert history["previous_links"][0]["reply_count"] == 2
    assert history["previous_links"][0]["submissions"][0]["vr_q1"] == "yes"
    assert history["submissions"][0]["vr_q1"] == "no"
    assert client.post(url, json={"revision": replaced.json()["revision"]}).status_code == 404
    assert form_store.is_closed(old_path.rsplit("/", 1)[-1])


def test_vendor_questionnaire_read_failure_returns_unavailable(monkeypatch):
    from maverick import form_store

    vendor = client.post("/api/v1/vendors", json={
        "name": "Globex", "category": "hosting",
        "criticality": "medium", "owner": "it",
    }).json()
    sent = client.post(
        f"/api/v1/vendors/{vendor['id']}/questionnaires",
        json={"assessment_type": "vendor_risk", "revision": vendor["revision"]},
    ).json()

    def fail_read(_token, _cursor):
        raise OSError("private storage detail")

    monkeypatch.setattr(form_store, "since", fail_read)
    response = client.get(f"/api/v1/vendors/{vendor['id']}/questionnaires")
    assert response.status_code == 503
    assert "couldn't check questionnaire replies" in response.json()["detail"]
    assert "questionnaires" not in response.json()
    assert "private storage detail" not in response.text
    assert sent["form_path"] not in response.text


def test_vendor_status_note_and_onetrust_import():
    vendor = client.post("/api/v1/vendors", json={
        "name": "Initech", "category": "billing",
        "criticality": "low", "owner": "finance"}).json()
    # A new vendor starts under review; activating it needs a completed
    # assessment, so a bare status move to active is refused.
    assert vendor["status"] == "under_review"
    gated = client.post(
        f"/api/v1/vendors/{vendor['id']}/status",
        json={"status": "active", "revision": vendor["revision"]})
    assert gated.status_code == 422, gated.text
    moved = client.post(
        f"/api/v1/vendors/{vendor['id']}/status",
        json={"status": "offboarded", "revision": vendor["revision"]})
    assert moved.status_code == 200, moved.text
    assert moved.json()["status"] == "offboarded"
    stale = client.post(
        f"/api/v1/vendors/{vendor['id']}/status",
        json={"status": "under_review", "revision": vendor["revision"]})
    assert stale.status_code == 409

    noted = client.post(
        f"/api/v1/vendors/{vendor['id']}/notes",
        json={"note": "sanctions screen hit", "severity": "critical",
              "revision": moved.json()["revision"]})
    assert noted.status_code == 201

    imported = client.post("/api/v1/vendors/import-onetrust", json={
        "csv_text": "Vendor Name,Vendor Type,Tier\nUmbrella,security,Tier 1\n"})
    assert imported.status_code == 201
    assert imported.json()["imported"] == 1
    assert imported.json()["skipped"] == []
    # Re-importing the same export reports the vendor as a duplicate (left
    # untouched) instead of silently dropping the row.
    again = client.post("/api/v1/vendors/import-onetrust", json={
        "csv_text": "Vendor Name,Vendor Type,Tier\nUmbrella,security,Tier 1\n"})
    assert again.status_code == 201
    assert again.json()["imported"] == 0
    assert [(s["row"], s["name"], s["reason"]) for s in again.json()["skipped"]] == [
        (1, "Umbrella", "duplicate"),
    ]


def test_consent_round_trip_and_digest_only_export():
    resp = client.post("/api/v1/consent/records", json={
        "subject_ref": "alice@example.com", "purpose": "marketing emails",
        "status": "granted", "policy_version": "2026-01", "channel": "web"})
    assert resp.status_code == 201, resp.text
    assert "alice" not in resp.text

    prefs = client.post("/api/v1/consent/preferences",
                        json={"subject_ref": "alice@example.com"})
    assert prefs.status_code == 200
    assert prefs.json()["purposes"]["marketing_emails"]["status"] == "granted"

    posture = client.get("/api/v1/consent/posture")
    assert posture.json()["records"] == 1

    export = client.get("/api/v1/consent/export")
    assert export.status_code == 200
    assert "alice" not in export.text
    assert export.json()["receipts"][0]["purpose"] == "marketing_emails"

    imported = client.post("/api/v1/consent/import-onetrust", json={
        "csv_text": ("Identifier,Purpose,Status,Version\n"
                     "bob@example.com,Newsletters,Opt-Out,2\n")})
    assert imported.status_code == 201
    assert imported.json() == {"imported": 1, "skipped": 0}


def test_data_map_register_classify_and_schema_import():
    resp = client.post("/api/v1/data-map/assets", json={
        "name": "crm.contacts", "system": "snowflake", "kind": "table",
        "owner": "data-team", "columns": ["id", "email", "diagnosis"]})
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    assert asset["special_category"] is True
    assert "email" in asset["categories"]

    single = client.get(f"/api/v1/data-map/assets/{asset['id']}")
    assert single.status_code == 200
    assert client.get("/api/v1/data-map/assets/DMA-none").status_code == 404

    linked = client.post(
        f"/api/v1/data-map/assets/{asset['id']}/links",
        json={"kind": "ropa", "reference": "ROPA-1",
              "revision": asset["revision"]})
    assert linked.status_code == 201

    flagged = client.post("/api/v1/data-map/classify", json={
        "columns": ["order_total", "customer_email"]})
    assert flagged.status_code == 200
    assert set(flagged.json()["flagged"]) == {"customer_email"}

    imported = client.post("/api/v1/data-map/import-schema", json={
        "csv_text": ("table_name,column_name\n"
                     "payments,iban\npayments,amount\n"),
        "system": "postgres", "owner": "data-team"})
    assert imported.status_code == 201
    assert imported.json() == {"imported": 1, "skipped": 0}

    posture = client.get("/api/v1/data-map/posture")
    assert posture.json()["assets"] == 2
    assert posture.json()["by_category"]["financial"] == 1


def test_privacy_page_renders_the_estate_tabs():
    client.post("/api/v1/vendors", json={
        "name": "Acme Analytics", "category": "analytics",
        "criticality": "high", "owner": "procurement"})
    page = client.get("/privacy")
    assert page.status_code == 200
    assert "Privacy estate" in page.text
    assert "Acme Analytics" in page.text
    assert "List SharePoint sites" in page.text
    assert "Record their choice" in page.text


def test_privacy_page_explains_what_is_off(tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    page = client.get("/privacy")
    assert page.status_code == 200
    assert 'data-module-gate="vendor_management"' in page.text
    assert 'data-module-gate="consent_registry"' in page.text
    assert 'data-module-gate="data_map"' in page.text
    assert "[vendor_management] enable = true" not in page.text
    assert "[consent_registry] enable = true" not in page.text
    assert "[data_map] enable = true" not in page.text


def test_sharepoint_sync_without_a_token_is_503():
    resp = client.post("/api/v1/data-map/sync-sharepoint",
                       json={"owner": "it"})
    assert resp.status_code == 503
    assert "Sites.Read.All" in resp.json()["detail"]


def test_vendor_contracts_and_renewals_over_the_api():
    import time as time_module

    vendor = client.post("/api/v1/vendors", json={
        "name": "Hooli", "category": "cloud",
        "criticality": "high", "owner": "it"}).json()
    recorded = client.post(
        f"/api/v1/vendors/{vendor['id']}/contracts",
        json={"kind": "dpa", "reference": "doc://dpa",
              "renews_at": time_module.time() + 5 * 86400,
              "revision": vendor["revision"]})
    assert recorded.status_code == 201, recorded.text
    renewals = client.get("/api/v1/vendors/contracts/renewals")
    assert renewals.status_code == 200
    assert [entry["kind"] for entry in renewals.json()["due_soon"]] == ["dpa"]
    assert renewals.json()["overdue"] == []


def test_privacy_notices_and_site_scan_validation():
    published = client.post("/api/v1/consent/notices", json={
        "version": "2026-01", "text": "We process personal data to ..."})
    assert published.status_code == 201, published.text
    dup = client.post("/api/v1/consent/notices", json={
        "version": "2026-01", "text": "Other wording"})
    assert dup.status_code == 409

    listing = client.get("/api/v1/consent/notices")
    assert listing.json()["notices"][0]["version"] == "2026-01"
    single = client.get("/api/v1/consent/notices/2026-01")
    assert single.status_code == 200
    assert single.json()["text"].startswith("We process")
    assert client.get("/api/v1/consent/notices/nope").status_code == 404

    coverage = client.get("/api/v1/consent/notices/coverage")
    assert coverage.status_code == 200
    assert coverage.json()["covered"] is True

    scan = client.post("/api/v1/consent/site-scan",
                       json={"url": "http://insecure.example/"})
    assert scan.status_code == 422
    assert "https" in scan.json()["detail"]


def test_questionnaire_page_and_submission_without_automation_events():
    vendor = client.post("/api/v1/vendors", json={
        "name": "Pied Piper", "category": "compression",
        "criticality": "medium", "owner": "it"}).json()
    sent = client.post(
        f"/api/v1/vendors/{vendor['id']}/questionnaires",
        json={"assessment_type": "vendor_risk",
              "revision": vendor["revision"]}).json()
    form_path = sent["form_path"]

    # The vendor's link renders the questionnaire -- no account, no auth.
    page = client.get(form_path)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert "Pied Piper" in page.text
    assert "Submit answers" in page.text
    assert 'class="public-shell ' in page.text
    assert 'class="panel fq-wrap"' in page.text
    for internal_control in (
        'id="sidebar"',
        'id="halt-pill"',
        'id="mv-copilot"',
        'id="mv-copilot-fab"',
        "/static/lightwork-copilot.js",
        "/static/lightwork-ui.js",
        "/static/lightwork-voice.js",
    ):
        assert internal_control not in page.text
    assert client.get("/form/not-a-real-token").status_code == 404

    # Submissions land even though automation events are disabled: the
    # questionnaire token itself authorizes the POST.
    posted = client.post(form_path, json={"vr_q1": "yes"})
    assert posted.status_code == 201, posted.text
    back = client.get(f"/api/v1/vendors/{vendor['id']}/questionnaires")
    assert back.json()["questionnaires"][0]["status"] == "answered"
    assert back.json()["questionnaires"][0]["score"] is not None

    # A non-questionnaire token stays gated on automation events.
    assert client.post("/form/other-token", json={"x": "1"}).status_code == 404


def test_dsar_estate_worksheet_over_the_api():
    opened = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "alice@example.com", "kind": "access"})
    assert opened.status_code == 201, opened.text
    request_id = opened.json()["id"]

    client.post("/api/v1/data-map/assets", json={
        "name": "crm.contacts", "system": "snowflake", "kind": "table",
        "owner": "data-team", "columns": ["id", "email"]})

    plan = client.get(f"/api/v1/privacy/dsar/{request_id}/estate-worksheet")
    assert plan.status_code == 200, plan.text
    body = plan.json()
    assert body["platform_holdings"]["enabled"] is True
    assert [asset["name"] for asset in body["data_map"]["assets"]] == [
        "crm.contacts"]
    assert client.get(
        "/api/v1/privacy/dsar/DSAR-none/estate-worksheet"
    ).status_code == 404


def test_privacy_page_renders_contracts_notices_and_scan():
    import time as time_module

    vendor = client.post("/api/v1/vendors", json={
        "name": "Vandelay", "category": "import-export",
        "criticality": "low", "owner": "ops"}).json()
    client.post(
        f"/api/v1/vendors/{vendor['id']}/contracts",
        json={"kind": "dpa", "reference": "doc://dpa",
              "renews_at": time_module.time() + 3 * 86400,
              "revision": vendor["revision"]})
    client.post("/api/v1/consent/notices", json={
        "version": "2026-01", "text": "We process personal data to ..."})

    page = client.get("/privacy")
    assert page.status_code == 200
    assert "Contracts &amp; renewals" in page.text
    assert "renewing within 30 days" in page.text
    assert "Privacy notices" in page.text
    assert "2026-01" in page.text
    assert "Check a web page" in page.text
    assert 'id="pe-scan-go"' in page.text


def test_consent_write_races_map_to_409_not_500(monkeypatch):
    # A CAS retry that exhausts (concurrent writers) is a retryable
    # conflict for the client, never an operator-paging 500.
    from maverick import consent_registry
    from maverick.governed_records import RecordConflict

    def racing(*_args, **_kwargs):
        raise RecordConflict("the consent record changed during save")

    monkeypatch.setattr(consent_registry, "record_consent", racing)
    response = client.post("/api/v1/consent/records", json={
        "subject_ref": "alice@example.com", "purpose": "marketing",
        "status": "granted", "policy_version": "2026-01", "channel": "web",
    })
    assert response.status_code == 409

    def exhausted(*_args, **_kwargs):
        raise consent_registry.ConsentRegistryError(
            "the consent record changed during save")

    monkeypatch.setattr(consent_registry, "record_consent", exhausted)
    response = client.post("/api/v1/consent/records", json={
        "subject_ref": "alice@example.com", "purpose": "marketing",
        "status": "granted", "policy_version": "2026-01", "channel": "web",
    })
    assert response.status_code == 409


def test_privacy_page_dropdowns_come_from_module_vocab():
    # The contract panel renders once at least one vendor exists.
    created = client.post("/api/v1/vendors", json={
        "name": "Acme Analytics", "category": "analytics",
        "criticality": "high", "owner": "procurement",
    })
    assert created.status_code == 201, created.text
    page = client.get("/privacy").text
    # Contract kinds, consent statuses, and channels render from the
    # modules that enforce them -- including every CONTRACT_KINDS entry.
    for kind in ("dpa", "msa", "sla", "addendum", "other"):
        assert f'value="{kind}"' in page
    for status in ("granted", "withdrawn"):
        assert f'value="{status}"' in page
    # The importer-only channel never shows as a manual-entry choice.
    assert 'value="import"' not in page


def test_breach_plan_endpoints(tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text(
        _CONFIG + "\n[breach_notification]\nenable = true\n",
        encoding="utf-8")
    config.reset_config_cache()
    regimes = client.get("/api/v1/breach/regimes")
    assert regimes.status_code == 200
    # Pinned to the module's own vocabulary, not a copied literal: a
    # verified regime added there must not require a dashboard-test edit.
    from maverick import breach_notification

    assert len(regimes.json()["regimes"]) == len(breach_notification.REGIMES)
    assert "ca_quebec" in {r["regime"] for r in regimes.json()["regimes"]}
    plan = client.post("/api/v1/breach/plan", json={
        "jurisdictions": ["eu_gdpr", "us_tx"], "subjects_affected": 900,
    })
    assert plan.status_code == 200, plan.text
    rows = {row["regime"]: row for row in plan.json()["obligations"]}
    assert rows["eu_gdpr"]["authority_due_at"] is not None
    unknown = client.post("/api/v1/breach/plan", json={
        "jurisdictions": ["us_ca"],
    })
    assert unknown.json()["obligations"][0]["authority_below_threshold"] is None
    bad = client.post("/api/v1/breach/plan",
                      json={"jurisdictions": ["narnia"]})
    assert bad.status_code == 422
    # Anchored to a real incident's discovery time.
    opened = client.post("/api/v1/privacy/incidents", json={
        "title": "Laptop lost", "severity": "high",
        "affected_estimate": "1.2k customers", "affected_people": "1200",
    })
    assert opened.status_code == 201, opened.text
    incident = opened.json()
    anchored = client.get(
        "/api/v1/privacy/incidents/" + incident["id"]
        + "/notification-plan?jurisdictions=eu_gdpr,us_co")
    assert anchored.status_code == 200, anchored.text
    body = anchored.json()
    assert body["subjects_affected"] == 1200
    assert body["discovered_at"] == incident["created_at"]
    revised = client.post(
        f"/api/v1/privacy/incidents/{incident['id']}/affected-people",
        json={"affected_people": None},
    )
    assert revised.status_code == 200, revised.text
    assert revised.json()["affected_estimate"] == "1.2k customers"
    unknown_plan = client.get(
        f"/api/v1/privacy/incidents/{incident['id']}/notification-plan"
        "?jurisdictions=us_ca,jp_appi"
    ).json()
    assert unknown_plan["subjects_affected"] is None
    assert all(row["authority_below_threshold"] is None
               for row in unknown_plan["obligations"])
    assert all("count not provided" in row["threshold_note"]
               for row in unknown_plan["obligations"])


def test_legacy_incident_counts_are_used_only_when_unambiguous(tmp_path):
    from maverick import config, privacy_ops

    (tmp_path / "config.toml").write_text(
        _CONFIG + "\n[breach_notification]\nenable = true\n",
        encoding="utf-8")
    config.reset_config_cache()
    for estimate, expected in (
        ("1,200", 1200),
        ("1.2k customers", None),
        ("1,000-5,000", None),
        ("~300 (0.5% of base)", None),
    ):
        opened = client.post("/api/v1/privacy/incidents", json={
            "title": "Legacy count", "affected_estimate": estimate,
        }).json()
        privacy_ops._INCIDENT.update(
            opened["id"], lambda row: row.pop("affected_people", None))
        plan = client.get(
            f"/api/v1/privacy/incidents/{opened['id']}/notification-plan"
            "?jurisdictions=us_ca,jp_appi"
        )
        assert plan.status_code == 200, plan.text
        assert plan.json()["subjects_affected"] == expected
        assert all(row["authority_below_threshold"] is not True
                   for row in plan.json()["obligations"])
        if estimate == "1.2k customers":
            corrected = client.post(
                f"/api/v1/privacy/incidents/{opened['id']}/affected-people",
                json={"affected_people": 1200},
            )
            assert corrected.status_code == 200, corrected.text
            assert corrected.json()["affected_estimate"] == estimate
            updated_plan = client.get(
                f"/api/v1/privacy/incidents/{opened['id']}/notification-plan"
                "?jurisdictions=us_ca,jp_appi"
            ).json()
            assert updated_plan["subjects_affected"] == 1200
            assert all(row["authority_below_threshold"] is False
                       for row in updated_plan["obligations"])


def test_dsar_fulfillment_flow_over_the_api(tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text(
        _CONFIG + "\n[dsar_fulfillment]\nenable = true\n",
        encoding="utf-8")
    config.reset_config_cache()
    opened = client.post("/api/v1/privacy/dsar", json={
        "subject_id": "alice@example.com", "kind": "access",
    })
    assert opened.status_code == 201, opened.text
    request_id = opened.json()["id"]
    fulfillment = client.post(
        "/api/v1/privacy/dsar/" + request_id + "/fulfillment")
    assert fulfillment.status_code == 201, fulfillment.text
    record = fulfillment.json()
    # The response link refuses before identity verification.
    early = client.post(
        "/api/v1/privacy/dsar/fulfillment/" + record["id"] + "/response",
        json={"revision": record["revision"]})
    assert early.status_code == 422
    verified = client.post(
        "/api/v1/privacy/dsar/fulfillment/" + record["id"] + "/identity",
        json={"method": "email_challenge", "reference": "challenge-1",
              "revision": record["revision"]})
    assert verified.status_code == 200, verified.text
    minted = client.post(
        "/api/v1/privacy/dsar/fulfillment/" + record["id"] + "/response",
        json={"revision": verified.json()["revision"]})
    assert minted.status_code == 201, minted.text
    path = minted.json()["response_path"]
    assert path.startswith("/dsar/response/")
    # The public link works without any dashboard credential or origin.
    from fastapi.testclient import TestClient as _TC
    from maverick_dashboard.app import app as _app
    anon = _TC(_app)
    delivered = anon.get(path)
    assert delivered.status_code == 200, delivered.text
    assert delivered.json()["request_id"] == request_id
    assert anon.get("/dsar/response/wrong-token").status_code == 404
    status = client.get("/api/v1/privacy/dsar/" + request_id + "/fulfillment")
    assert status.status_code == 200
    assert "token_sha256" not in (status.json()["response"] or {})


def test_consent_webhook_over_http(tmp_path, monkeypatch):
    import hashlib as _hashlib
    import hmac as _hmac
    import json as _json

    from maverick import config
    (tmp_path / "config.toml").write_text(
        _CONFIG.replace(
            "[consent_registry]\nenable = true\n",
            "[consent_registry]\nenable = true\nwebhook_enable = true\n",
        ),
        encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setenv("MAVERICK_CONSENT_WEBHOOK_SECRET",
                       "whsec-0123456789abcdef")
    import time as _time
    ts = int(_time.time())
    body = _json.dumps({"subject": "alice@example.com",
                        "purpose": "marketing",
                        "status": "granted"}).encode()
    signature = _hmac.new(b"whsec-0123456789abcdef",
                          f"{ts}.".encode() + body,
                          _hashlib.sha256).hexdigest()
    from fastapi.testclient import TestClient as _TC
    from maverick_dashboard.app import app as _app
    anon = _TC(_app)  # no Origin, no bearer: the HMAC is the auth
    accepted = anon.post("/consent/webhook", content=body,
                         headers={"X-Lightwork-Signature": signature,
                                  "X-Lightwork-Timestamp": str(ts)})
    assert accepted.status_code == 202, accepted.text
    assert accepted.json() == {"imported": 1, "skipped": 0}
    assert anon.post("/consent/webhook", content=body,
                     headers={"X-Lightwork-Signature": "0" * 64,
                              "X-Lightwork-Timestamp": str(ts)}
                     ).status_code == 401
    # Stale signed timestamp -> replay guard, same 401.
    old_ts = ts - 3600
    old_sig = _hmac.new(b"whsec-0123456789abcdef",
                        f"{old_ts}.".encode() + body,
                        _hashlib.sha256).hexdigest()
    assert anon.post("/consent/webhook", content=body,
                     headers={"X-Lightwork-Signature": old_sig,
                              "X-Lightwork-Timestamp": str(old_ts)}
                     ).status_code == 401


def test_consent_webhook_off_is_403():
    assert client.post("/consent/webhook", content=b"{}").status_code == 403


def test_content_classify_and_masking_sql_over_the_api():
    created = client.post("/api/v1/data-map/assets", json={
        "name": "crm.contacts", "system": "snowflake", "kind": "table",
        "owner": "data-team", "columns": ["id", "email"],
    })
    assert created.status_code == 201, created.text
    asset = created.json()
    verified = client.post(
        "/api/v1/data-map/assets/" + asset["id"] + "/classify-content",
        json={"text_sample": "reach carol@example.com",
              "revision": asset["revision"]})
    assert verified.status_code == 200, verified.text
    assert verified.json()["content_categories"] == ["email"]
    sql = client.get("/api/v1/data-map/masking-sql")
    assert sql.status_code == 200
    assert "MASKING POLICY" in sql.text
