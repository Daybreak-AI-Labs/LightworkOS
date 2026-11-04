"""Oldest matching metadata, cursors and scope cannot fall through recent caps."""
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick.metadata_history import HistoryChanged, Window, digest
from maverick_dashboard import _shared, auth
from maverick_dashboard import record_history as history
from maverick_dashboard import record_search_api as search_api
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
    monkeypatch.setattr(search_api.config, "get_features", lambda: {"record_search": True})
    monkeypatch.setattr(search_api.config, "config_source_errors", lambda **kwargs: [])
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def record(index, title="Needle"):
    return history.dated(history.item("task", index, title, href=f"/chat/goal/{index}", source="tasks"), index)


def test_empty_windows_continue_until_oldest_match_without_larger_caps(monkeypatch):
    monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    rows = [record(index, "Needle" if index == 1 else "Recent task") for index in range(1, 1102)]
    monkeypatch.setattr(history, "load_window", lambda request, source, **options: history.projected_window(rows, **options))
    found, cursor, pages = [], None, 0
    while True:
        value = history.search_history(object(), source="tasks", query="Needle", cursor=cursor)
        found.extend(value["items"])
        pages += 1
        cursor = value["next_cursor"]
        if not cursor:
            break
        assert value["total"] == 0 and value["complete"] is False
        assert pages < 10
    assert pages == 5 and [row["id"] for row in found] == ["1"]
    assert value["complete"] and value["total"] == 1


def test_paging_within_window_has_no_duplicates_and_rejects_changes(monkeypatch):
    monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    rows = [record(index) for index in range(30)]
    monkeypatch.setattr(history, "load_window", lambda request, source, **options: history.projected_window(rows, **options))
    first = history.search_history(object(), source="tasks", query="Needle", oldest=True)
    second = history.search_history(object(), source="tasks", query="Needle", oldest=True, cursor=first["next_cursor"])
    assert len(first["items"]) == 20 and len(second["items"]) == 10
    assert set(row["id"] for row in first["items"]).isdisjoint(row["id"] for row in second["items"])
    with pytest.raises(HistoryChanged):
        history.search_history(object(), source="tasks", query="Other", oldest=True, cursor=first["next_cursor"])
    rows[0]["revision"] = "new"
    with pytest.raises(HistoryChanged):
        history.search_history(object(), source="tasks", query="Needle", oldest=True, cursor=first["next_cursor"])


def test_unavailable_is_distinct_and_never_returns_exception_private_identity(monkeypatch):
    monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    monkeypatch.setattr(history, "load_window", lambda *args, **kw: (_ for _ in ()).throw(PermissionError("secret source name")))
    value = history.search_history(object(), source="tasks", query="")
    assert value["coverage"][0]["state"] == "unavailable"
    assert value["coverage"][0]["href"] == "/goals"
    assert value["total"] == 0 and value["complete"] is False and value["next_cursor"] is None
    assert "secret source name" not in json.dumps(value)


def test_exact_auth_task_source_and_api_history_dates(monkeypatch):
    with world_model.WorldModel() as world:
        mine = world.create_goal("Alice oldest", owner="user:alice")
        world.create_goal("Bob hidden", owner="user:bob")
        monkeypatch.setattr(_shared, "_world", lambda: world)
        monkeypatch.setattr(history, "caller_principal", lambda request: "user:alice")
        monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:alice")
        # Bind the same exact test principal at both projection and authorization seams.
        monkeypatch.setattr(auth, "caller_role", lambda request: "admin")
        monkeypatch.setattr(search_api, "context_for", lambda request: "a" * 64)
        monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
        with TestClient(app, base_url="http://127.0.0.1", headers={"Origin":"http://127.0.0.1", "X-Lightwork-Search-Context":"a" * 64}) as client:
            value = client.post("/api/v1/records/search", json={"mode":"history", "source":"tasks", "query":"", "oldest":True})
            assert value.status_code == 200, value.text
            assert [row["id"] for row in value.json()["items"]] == [str(mine)]
            assert "Bob hidden" not in value.text
            assert value.headers["cache-control"] == "private, no-store"
            assert client.post("/api/v1/records/search", json={"mode":"history", "source":"tasks", "after":"2026-02-31"}).status_code == 422
            assert client.post("/api/v1/records/search", json={"mode":"history", "source":"tasks", "after":"2026-09-30", "before":"2020-01-01"}).status_code == 422


def test_assessment_mapping_filters_before_matched_counts(monkeypatch):
    from maverick import assessment
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    monkeypatch.setattr(history, "suite_allowed", lambda request, suite: suite == "privacy")
    monkeypatch.setattr(assessment, "custom_template_records", dict)
    rows = [{"id":"private", "type":"soc2", "subject":"Secret", "status":"draft", "revision":1, "date":1},
            {"id":"visible", "type":"pia", "subject":"Visible", "status":"draft", "revision":1, "date":1}]
    monkeypatch.setattr(assessment, "history_heads", lambda **options: Window(rows, digest(rows), None))
    value = history._assessments(object())
    assert [row["id"] for row in value.rows] == ["visible"]
    assert "Secret" not in json.dumps(value.rows)


def test_native_vault_report_factories_and_no_content_projection(monkeypatch):
    from maverick_dashboard import governed_document_vault_api as vault_api
    from maverick_dashboard import third_party_executive_reports_api as report_api
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    monkeypatch.setattr(vault_api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(report_api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(report_api, "_require_report_permission", lambda *args: None)
    document = SimpleNamespace(document_ref="doc-old", safe_display_name="Old evidence", state="active", content_revision=3, created_at=1, content="DO NOT RETURN")
    report = SimpleNamespace(report_id="report-old", brand=SimpleNamespace(report_title="Old report"), state="active", control_revision=1, created_at=1, snapshot="DO NOT RETURN")
    calls=[]
    vault=SimpleNamespace(history_window=lambda **options: calls.append(options) or Window([document], "a"*64,None))
    reports=SimpleNamespace(history_window=lambda **options: calls.append(options) or Window([report], "b"*64,None))
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(governed_document_vault_enabled_probe=lambda tenant: True,
        governed_document_vault_store_factory=lambda tenant, req: vault,
        third_party_executive_reports_runtime_factory=lambda **kw: SimpleNamespace(store=reports,role_view="viewer"))))
    assert "DO NOT RETURN" not in json.dumps(history._vault(request,offset=500).rows)
    assert "DO NOT RETURN" not in json.dumps(history._reports(request,offset=500).rows)
    assert calls == [{"offset":500}, {"offset":500,"caller_role":"viewer"}]


def test_typed_copilot_uses_same_native_search_gate(monkeypatch):
    from maverick_dashboard import product_operations_record_history as operations
    monkeypatch.setattr(operations, "page_context", lambda request: {"record_search_context":"a"*64})
    calls=[]
    monkeypatch.setattr(operations, "search_history", lambda request, **args: calls.append(args) or {"items":[],"next_cursor":None})
    arguments={"source":"tasks","query":"Old record","oldest":True}
    preview=operations.prepare(object(),{},arguments)
    outcome=operations.execute(object(),{},arguments,preview.native,"b"*32)
    assert outcome.status == "confirmed" and calls == [arguments]
    monkeypatch.setattr(operations,"page_context",lambda request: {})
    with pytest.raises(HTTPException):
        operations.execute(object(),{},arguments,preview.native,"c"*32)


def test_budget_stop_remains_partial_with_date_remedy(monkeypatch):
    from maverick.metadata_history import HistoryNarrowing
    monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    monkeypatch.setattr(history, "load_window", lambda *args, **kw: (_ for _ in ()).throw(HistoryNarrowing()))
    value = history.search_history(object(), source="tasks")
    assert value["coverage"][0]["state"] == "partial" and value["complete"] is False
    assert "narrower UTC date range" in value["notice"] and value["next_cursor"] is None


def test_current_source_denial_invalidates_a_cursor(monkeypatch):
    monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    rows = [record(index) for index in range(30)]
    monkeypatch.setattr(history, "load_window", lambda request, source, **options: history.projected_window(rows, **options))
    first = history.search_history(object(), source="tasks")
    monkeypatch.setattr(history, "load_window", lambda *args, **kw: (_ for _ in ()).throw(HTTPException(403)))
    with pytest.raises(HTTPException) as refused:
        history.search_history(object(), source="tasks", cursor=first["next_cursor"])
    assert refused.value.status_code == 409


def test_current_workflow_visibility_reuses_canonical_template_authority(tmp_path, monkeypatch):
    from maverick import flow, templates
    from maverick.flow import store
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    monkeypatch.setattr(history, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(flow, "enabled", lambda: True)
    seen=[]
    monkeypatch.setattr(store, "list_flow_summaries", lambda **kw: seen.append(kw) or [{"id":"own", "name":"My process", "revision":"r1", "version":1, "updated_at":1}])
    mine=tmp_path / "mine.md"
    mine.write_text("metadata",encoding="utf-8")
    hidden=tmp_path / "hidden.md"
    hidden.write_text("private",encoding="utf-8")
    values={"mine":templates.Template("mine","My template","Private body",owner="user:alice",path=mine),
            "hidden":templates.Template("hidden","Hidden template","Other body",owner="user:bob",path=hidden)}
    monkeypatch.setattr(templates,"list_templates",lambda:list(values))
    monkeypatch.setattr(templates,"load_template",lambda name:values[name])
    rows=history._workflows(object())
    assert seen[0]["owner"] == "user:alice"
    assert {row["title"] for row in rows} == {"My process","My template"}
    assert "Private body" not in json.dumps(rows) and "Other body" not in json.dumps(rows)


def test_history_cursor_is_tenant_bound_and_contains_no_plain_scan_position(monkeypatch):
    import base64

    from maverick.paths import tenant_scope
    monkeypatch.setattr(history, "context_for", lambda request: "a" * 64)
    monkeypatch.setattr(history, "require_permission", lambda *args: None)
    rows = [record(index) for index in range(30)]
    monkeypatch.setattr(history, "load_window", lambda request, source, **options: history.projected_window(rows, **options))
    with tenant_scope(tenant="tenant-a"):
        first = history.search_history(object(), source="tasks")
        raw = base64.urlsafe_b64decode(first["next_cursor"] + "=" * (-len(first["next_cursor"]) % 4))
        assert b"offset" not in raw and b"binding" not in raw
    with tenant_scope(tenant="tenant-b"):
        with pytest.raises(HistoryChanged):
            history.search_history(object(), source="tasks", cursor=first["next_cursor"])


def test_established_principal_drives_exact_owner_without_auth_patches(monkeypatch):
    from fastapi import Request
    from maverick.oidc import VerifiedPrincipal
    request = Request({"type":"http", "method":"GET", "path":"/goals", "headers":[], "query_string":b"", "client":("127.0.0.1",1), "server":("127.0.0.1",80), "scheme":"http"})
    request.state.principal = VerifiedPrincipal(sub="alice", issuer="https://issuer.test", audience="fixture")
    with world_model.WorldModel() as world:
        mine = world.create_goal("My visible record", owner="user:alice")
        world.create_goal("Other owner", owner="user:bob")
        monkeypatch.setattr(_shared, "_world", lambda: world)
        value = history._world(request, "tasks", offset=0, after=None, before=None, oldest=False)
        assert [row["id"] for row in value.rows] == [str(mine)]


def test_history_resolves_the_shared_world_inside_each_tenant_scope(monkeypatch):
    from maverick.paths import current_tenant_id, tenant_scope

    worlds = {"tenant-a": object(), "tenant-b": object()}
    seen = []
    monkeypatch.setattr(_shared, "_world", lambda: worlds[current_tenant_id()])
    monkeypatch.setattr(history, "require_permission", lambda *_args: None)
    monkeypatch.setattr(history, "caller_principal", lambda _request: "user:alice")

    def window(world, **options):
        seen.append((current_tenant_id(), world, options["owner"]))
        return Window([], digest([]), None)

    monkeypatch.setattr(history, "world_window", window)
    for tenant in worlds:
        with tenant_scope(tenant=tenant):
            history._world(object(), "tasks", offset=0, after=None, before=None, oldest=False)
    assert seen == [(tenant, world, "user:alice") for tenant, world in worlds.items()]
