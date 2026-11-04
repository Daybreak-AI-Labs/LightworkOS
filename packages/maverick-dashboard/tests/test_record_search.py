"""Record discovery does not weaken source permissions or retain source bodies."""
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick.paths import tenant_scope
from maverick_dashboard import record_search as search
from maverick_dashboard import record_search_api as api
from maverick_dashboard import record_search_sources as sources
from maverick_dashboard.app import app


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(api.config, "get_features", lambda: {"record_search": True})
    monkeypatch.setattr(api.config, "config_source_errors", lambda **kwargs: [])
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def record(identifier, title="Acme", kind="vendor"):
    return search.item(kind, identifier, title, href="/privacy/vendors/" + str(identifier), revision=2)


def test_matching_metadata_pagination_and_newer_index_guard():
    rows = [record(str(i), "Acme " + str(i)) for i in range(6)]
    loader = {"vendors": lambda: search.Source(rows)}
    first = search.search(loader, query="acme 5", limit=2)
    assert [row["id"] for row in first["items"]] == ["5"]
    first = search.search(loader, query="acme", limit=2)
    second = search.search(loader, query="acme", offset=first["next_offset"], limit=2, expected_snapshot=first["snapshot"])
    assert first["total"] == 6 and second["items"][0]["id"] == "2"
    rows[0]["revision"] = "3"
    with pytest.raises(ValueError, match="changed while paging"):
        search.search(loader, query="acme", offset=2, expected_snapshot=first["snapshot"])


def test_partial_and_failed_sources_never_imply_exhaustive_results():
    def denied():
        raise PermissionError("secret record exists: Acme hidden")
    model = search.search({"vendors": lambda: search.Source([record(str(i)) for i in range(1001)]),
                           "restricted": denied}, query="Acme")
    assert model["total"] == 1000 and model["complete"] is False
    assert model["coverage"] == [{"source":"vendors", "state":"partial", "indexed":1000},
                                 {"source":"restricted", "state":"unavailable", "indexed":None}]
    assert "secret record" not in json.dumps(model)


def test_task_owner_and_department_filter_before_search_counts(monkeypatch):
    from maverick_dashboard import app as app_module
    calls = []
    goals = [SimpleNamespace(id=1, title="Visible", status="done", domain="privacy_report", description="NEVER_SEARCH_BODY", result="NEVER_RETURN_RESULT"),
             SimpleNamespace(id=2, title="Restricted", status="done", domain="sec_report")]
    monkeypatch.setattr(app_module, "_world", lambda: SimpleNamespace(list_goals=lambda **kw: calls.append(kw) or goals))
    monkeypatch.setattr(app_module, "_deliverable_specs", lambda: [{"domain":"privacy_report"}])
    monkeypatch.setattr(sources, "goal_owner_filter", lambda request: "user:alice")
    monkeypatch.setattr(sources, "require_permission", lambda *args: None)
    monkeypatch.setattr(sources, "domain_suites_allowed", lambda request, domain: domain != "sec_report")
    projection = sources._tasks(object())
    assert calls[0]["owner"] == "user:alice" and calls[0]["limit"] == 1001
    assert [(row["title"], row["kind"]) for row in projection.items] == [("Visible", "report")]
    value = search.search({"tasks":lambda:projection}, query="NEVER_SEARCH_BODY")
    assert value["total"] == 0 and "NEVER_RETURN_RESULT" not in json.dumps(value)


def test_inherited_suite_fork_is_hidden_from_task_search(monkeypatch, tmp_path):
    from maverick_dashboard import app as app_module

    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "_world", lambda: SimpleNamespace(list_goals=lambda **kw: [
        SimpleNamespace(id=1, title="Private inherited task", status="done", domain="client_fork"),
    ]))
    monkeypatch.setattr(app_module, "_deliverable_specs", list)
    monkeypatch.setattr(sources, "goal_owner_filter", lambda request: "user:alice")
    monkeypatch.setattr(sources, "require_permission", lambda *args: None)
    monkeypatch.setattr("maverick_dashboard.auth.caller_suites", lambda request: frozenset({"finance"}))

    assert sources._tasks(object()).items == []


def test_assessment_suite_filter_precedes_matches_and_counts(monkeypatch):
    from maverick import assessment
    monkeypatch.setattr(sources, "require_permission", lambda *args: None)
    monkeypatch.setattr(sources, "suite_allowed", lambda request, suite: suite == "privacy")
    monkeypatch.setattr(assessment, "custom_template_records", dict)
    monkeypatch.setattr(assessment, "list_saved_heads", lambda **kw: ((
        {"id":"visible", "type":"pia", "subject":"Acme", "status":"approved", "revision":4, "answers":{"secret":"body"}},  # pragma: allowlist secret -- synthetic excluded search body
        {"id":"hidden", "type":"soc2", "subject":"Acme hidden", "status":"approved", "revision":1}), 2))
    projection = sources._assessments(object())
    model = search.search({"questionnaires":lambda:projection}, query="Acme", kind="decision")
    assert model["total"] == 1 and model["coverage"][0]["indexed"] == 1
    assert model["items"][0]["href"] == "/privacy?assessment=visible"
    assert "hidden" not in json.dumps(model) and "secret" not in json.dumps(model)


def test_denied_source_does_not_open_its_store(monkeypatch):
    from maverick import vendor_management
    monkeypatch.setattr(sources, "require_permission", lambda *args: (_ for _ in ()).throw(HTTPException(403)))
    monkeypatch.setattr(vendor_management, "list_vendors", lambda: pytest.fail("denied source was opened"))
    model = search.search({"vendors":lambda:sources._vendors(object())}, query="anything")
    assert model["items"] == [] and model["coverage"][0]["indexed"] is None


def test_api_binds_account_and_workspace_before_collection(monkeypatch):
    context = "a" * 64
    monkeypatch.setattr(api, "context_for", lambda request: context)
    calls = []
    monkeypatch.setattr(api, "sources_for", lambda request, kind: calls.append(kind) or {"vendors":lambda:search.Source([record("v1")])})
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin":"http://127.0.0.1"}) as client:
        rejected = client.post("/api/v1/records/search", headers={"X-Lightwork-Search-Context":"b" * 64}, json={"query":"Acme"})
        assert rejected.status_code == 409 and calls == []
        found = client.post("/api/v1/records/search", headers={"X-Lightwork-Search-Context":context}, json={"query":"Acme", "kind":"vendor"})
        assert found.status_code == 200, found.text
        assert found.json()["total"] == 1 and found.headers["cache-control"] == "private, no-store"
        context = "b" * 64
        assert client.post("/api/v1/records/search", headers={"X-Lightwork-Search-Context":"a" * 64}, json={"query":"Acme"}).status_code == 409
        monkeypatch.setattr(api.config, "get_features", lambda: {"record_search":False})
        assert client.post("/api/v1/records/search", headers={"X-Lightwork-Search-Context":context}, json={}).status_code == 403
    assert calls == ["vendor"]


def test_non_ascii_search_context_header_is_refused_before_collection(monkeypatch):
    monkeypatch.setattr(api, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(api, "sources_for", lambda request, kind: pytest.fail("non-ASCII context reached the sources"))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.post("/api/v1/records/search", headers={"X-Lightwork-Search-Context": "contéxt".encode()},
                           json={"query": "Acme"})
    assert response.status_code == 409


def test_actual_vendor_store_tenant_isolation(monkeypatch):
    from maverick import vendor_management
    monkeypatch.setattr(vendor_management, "_require_enabled", lambda: None)
    monkeypatch.setattr(sources, "require_permission", lambda *args: None)
    monkeypatch.setattr(sources, "require_suite", lambda *args: None)
    with tenant_scope(tenant="workspace-a"):
        vendor_management.register_vendor("Alpha unique", category="AI", criticality="high", owner="alice", actor="user:alice")
    with tenant_scope(tenant="workspace-b"):
        vendor_management.register_vendor("Beta unique", category="AI", criticality="high", owner="bob", actor="user:bob")
        model = search.search({"vendors":lambda:sources._vendors(object())}, query="Alpha")
        assert model["items"] == [] and model["total"] == 0
        assert model["coverage"][0]["indexed"] == 1


def test_source_selection_does_not_open_unrelated_modules():
    assert set(sources.sources_for(object(), "task")) == {"tasks"}
    assert set(sources.sources_for(object(), "decision")) == {"questionnaires", "vendor onboarding", "project reviews"}


def test_vault_and_report_use_request_bound_factories_and_project_only_metadata(monkeypatch):
    from maverick_dashboard import governed_document_vault_api as vault_api
    from maverick_dashboard import third_party_executive_reports_api as reports_api
    calls = []
    monkeypatch.setattr(sources, "require_permission", lambda request, permission: calls.append(("permission", permission)))
    monkeypatch.setattr(reports_api, "_require_report_permission", lambda request, permission: calls.append(("report-permission", permission)))
    monkeypatch.setattr(vault_api, "_tenant_id", lambda: "workspace-a")
    monkeypatch.setattr(reports_api, "_tenant_id", lambda: "workspace-a")
    document = SimpleNamespace(document_ref="doc1", safe_display_name="Evidence", state="active", content_revision=2,
                               plaintext="DO_NOT_INDEX_BODY", storage_locator="DO_NOT_RETURN_LOCATOR")
    report = SimpleNamespace(report_id="report1", brand=SimpleNamespace(report_title="Board report"), state="active", control_revision=3,
                             snapshot="DO_NOT_RETURN_SNAPSHOT", created_by_ref="PRIVATE_PRINCIPAL")
    vault = SimpleNamespace(list_documents=lambda **kw: calls.append(("vault-list", kw)) or [document])
    store = SimpleNamespace(list_reports=lambda **kw: calls.append(("report-list", kw)) or [report])
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        governed_document_vault_enabled_probe=lambda tenant: tenant == "workspace-a",
        governed_document_vault_store_factory=lambda tenant, req: calls.append((tenant, req is request)) or vault,
        third_party_executive_reports_runtime_factory=lambda **kw: calls.append((kw["tenant_id"], kw["request"] is request)) or SimpleNamespace(store=store, role_view="operator"))))
    model = search.search({"vault":lambda:sources._vault(request), "reports":lambda:sources._reports(request)}, query="")
    assert model["total"] == 2
    assert ("report-list", {"caller_role":"operator", "limit":500}) in calls
    assert calls.index(("permission", "view")) < calls.index(("vault-list", {"limit":500}))
    assert "DO_NOT" not in json.dumps(model) and "PRIVATE_PRINCIPAL" not in json.dumps(model)
    assert {row["href"] for row in model["items"]} == {"/administration/document-vault?document=doc1", "/third-party/executive-reports?report=report1"}


def test_shell_renders_search_context_and_serves_new_assets():
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin":"http://127.0.0.1"}) as client:
        page = client.get("/goals")
        assert page.status_code == 200, page.text
        assert 'name="lightwork-search-context"' in page.text and 'id="navfinder-kind"' in page.text
        for asset in ("lightwork-record-search.js", "lightwork-record-search.css"):
            response = client.get("/static/" + asset)
            assert response.status_code == 200
            assert "html" not in response.headers["content-type"]


def test_chat_shell_emits_search_context_so_record_search_can_run():
    """The chat pages show the finder's record controls, so they must also carry
    the context the record-search script needs; without it the script returns
    early and 'Search records' silently does nothing."""
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = world.create_goal("find the vendor", "")
    world.close()
    marker = 'name="lightwork-search-context" content="'
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        for path in ("/chat", f"/chat/goal/{gid}"):
            page = client.get(path)
            assert page.status_code == 200, (path, page.text)
            assert 'id="navfinder-search"' in page.text, path
            assert "lightwork-record-search.js" in page.text, path
            assert marker in page.text, path
        # Same context value as the product shell, so the API accepts it.
        shell = client.get("/goals").text
        chat = client.get("/chat").text
        assert shell.split(marker)[1].split('"')[0] == chat.split(marker)[1].split('"')[0]


def test_review_links_reach_registered_pages_with_bounded_references(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "workspace-a")
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin":"http://127.0.0.1"}) as client:
        for path, key in (("/third-party/vendor-onboarding", "case"),
                          ("/administration/document-vault", "document"),
                          ("/third-party/executive-reports", "report")):
            response = client.get(path, params={key:"ref-123"})
            assert response.status_code == 200, (path, response.text)
        assert client.get("/administration/document-vault?document=../secret").status_code == 404
        assert client.get("/third-party/executive-reports?report=../secret").status_code == 404


def test_finder_knowledge_mode_delegates_current_native_acl_and_metadata_never_calls_it(monkeypatch):
    from urllib.parse import unquote

    from maverick_dashboard import knowledge_access_api as knowledge
    context = "a" * 64
    monkeypatch.setattr(api, "context_for", lambda request: context)
    monkeypatch.setattr(api, "sources_for", lambda request, kind: {"vendors": lambda: search.Source([])})
    calls = []
    async def native(payload, request, response):
        calls.append(payload)
        return {"items": [{"reference": {"kind": "dataset", "asset_id": "source", "version": "v1", "manifest_sha256": "b" * 64}, "title": "Current source", "summary": "Approved passage", "eligibility": {"fresh_until": 2000000000}}], "complete": True, "next_cursor": None}
    monkeypatch.setattr(knowledge, "search", native)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Lightwork-Search-Context": context}) as client:
        assert client.post("/api/v1/records/search", json={"query": "name"}).status_code == 200
        assert calls == []
        approved = client.post("/api/v1/records/search", json={"query": "name", "mode": "knowledge", "purpose": "business"})
        assert approved.status_code == 200
        assert calls[0].purpose == "business" and calls[0].context == context
        row = approved.json()["items"][0]
        assert json.loads(unquote(row["href"].split("#source=", 1)[1]))["reference"]["version"] == "v1"
        async def revoked(*args):
            raise HTTPException(409, "Current source access unavailable")
        monkeypatch.setattr(knowledge, "search", revoked)
        assert client.post("/api/v1/records/search", json={"query": "name", "mode": "knowledge", "purpose": "business"}).status_code == 409


def test_ordinary_task_metadata_does_not_scan_unrelated_domain_packs(monkeypatch):
    from maverick_dashboard import app as app_module
    goals = [SimpleNamespace(id=1, title="Plain task", status="done", domain="")]
    monkeypatch.setattr(app_module, "_world", lambda: SimpleNamespace(list_goals=lambda **kw: goals))
    monkeypatch.setattr(app_module, "_deliverable_specs", lambda: pytest.fail("unrelated packs scanned"))
    monkeypatch.setattr(sources, "require_permission", lambda *args: None)
    monkeypatch.setattr(sources, "goal_owner_filter", lambda request: "user:alice")
    assert sources._tasks(object()).items[0]["kind"] == "task"


def test_switched_off_or_closed_sources_do_not_mark_the_search_partial():
    def off():
        raise search.SourceOff("no workspace selected")

    def closed():
        raise HTTPException(403, "disabled")

    def broken():
        raise OSError("store unreadable")

    calm = search.search({"tasks": lambda: search.Source([record("1")]), "vault": off, "reviews": closed}, query="acme")
    assert calm["complete"] is True and calm["total"] == 1
    assert [row["state"] for row in calm["coverage"]] == ["current", "not available", "not available"]
    assert all(row["indexed"] is None for row in calm["coverage"][1:])
    # A source that actually failed still says the results may be incomplete.
    failed = search.search({"tasks": lambda: search.Source([record("1")]), "vault": broken}, query="acme")
    assert failed["complete"] is False and failed["coverage"][1]["state"] == "unavailable"
    assert "unreadable" not in json.dumps(failed)


def test_turned_off_sources_report_off_before_opening_a_store(monkeypatch):
    from maverick import vendor_management
    from maverick_dashboard import governed_document_vault_api as vault_api

    monkeypatch.setattr(sources, "require_permission", lambda *args: None)
    monkeypatch.setattr(sources, "require_suite", lambda *args: None)
    model = search.search({"vendors": lambda: sources._vendors(object()),
                           "onboarding": lambda: sources._onboarding(object())}, query="")
    assert [row["state"] for row in model["coverage"]] == ["not available", "not available"]
    assert model["complete"] is True
    monkeypatch.setattr(vendor_management, "list_vendors", lambda: (_ for _ in ()).throw(OSError("disk")))
    monkeypatch.setattr(vault_api, "_tenant_id", lambda: (_ for _ in ()).throw(HTTPException(409, "select a workspace")))
    model = search.search({"vendors": lambda: sources._vendors(object()),
                           "vault": lambda: sources._vault(object())}, query="")
    assert [row["state"] for row in model["coverage"]] == ["unavailable", "not available"]


def test_best_matching_titles_come_first():
    rows = [record("1", "Quarterly report for Acme"), record("2", "Acme quarterly"),
            record("3", "Report"), record("4", "Annual report"), record("5", "Reporting acme")]
    rows[0]["state"] = "report pending"
    model = search.search({"vendors": lambda: search.Source(rows)}, query="report")
    assert [row["id"] for row in model["items"]] == ["3", "5", "4", "1"]
    by_reference = search.search({"vendors": lambda: search.Source(rows)}, query="2")
    assert by_reference["items"][0]["id"] == "2"


def test_task_templates_show_readable_blanks_in_results(tmp_path, monkeypatch):
    from maverick import flow, templates
    from maverick_dashboard import record_history as history
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    monkeypatch.setattr(history, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(flow, "enabled", lambda: False)
    body = tmp_path / "weekly.md"
    body.write_text("metadata", encoding="utf-8")
    weekly = templates.Template("weekly-update", "Weekly update for {{ team }}", "Body", owner="user:alice", path=body)
    monkeypatch.setattr(templates, "list_templates", lambda: ["weekly-update"])
    monkeypatch.setattr(templates, "load_template", lambda name: weekly)
    rows = history._workflows(object())
    assert [row["title"] for row in rows] == ["Weekly update for [Team]"]
    assert "{{" not in json.dumps(rows)


def test_switched_off_workspace_modules_are_not_available_not_failed(monkeypatch):
    from maverick.third_party_executive_reports import ThirdPartyExecutiveReportConfigError
    from maverick_dashboard import third_party_executive_reports_api as reports_api
    from maverick_dashboard import vendor_onboarding_composition as onboarding

    monkeypatch.setattr(reports_api, "_require_report_permission", lambda request, permission: None)
    monkeypatch.setattr(reports_api, "_tenant_id", lambda: "workspace-a")
    monkeypatch.setattr(onboarding, "settings", lambda: SimpleNamespace(enable=False))

    def reports_request(code):
        def factory(**kwargs):
            raise ThirdPartyExecutiveReportConfigError(code)
        return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(third_party_executive_reports_runtime_factory=factory)))

    with tenant_scope(tenant="workspace-a"):
        model = search.search({"reports": lambda: sources._reports(reports_request("executive_report_disabled")),
                               "onboarding": lambda: sources._onboarding(object())}, query="")
    assert [row["state"] for row in model["coverage"]] == ["not available", "not available"]
    assert model["complete"] is True
    broken = search.search({"reports": lambda: sources._reports(reports_request("executive_report_configuration_unavailable"))}, query="")
    assert broken["coverage"][0]["state"] == "unavailable" and broken["complete"] is False
