"""Privacy tools as buttons: the impact assessment draft, sampling the
files of a SharePoint site or storage bucket in the data map, preparing
vendor questionnaire links, and a person's uploaded documents (check and
erase) -- ``maverick dpia``, ``maverick data-map scan-*``, ``maverick vendor
questionnaire-index`` and ``maverick knowledge residual / erase-subject``."""
from __future__ import annotations

import html as _html
import re
import sys
import types

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback|residual|subject)\b|/api/v1|HTTP \d{3}|"
    r"maverick |MAVERICK_|\[\w+\]",
    re.IGNORECASE,
)
CONFIG = """
[data_map]
enable = true

[vendor_management]
enable = true

[knowledge]
enable = true
embedder = "deterministic"
store = "sqlite"
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    (tmp_path / "config.toml").write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_GRAPH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _actions(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit import writer

    seen: list[str] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(str(payload.get("action") or kind))
        return real(kind, **payload)
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def _refuse_records(monkeypatch):
    import maverick.audit as audit_pkg
    from maverick.audit import AuditRefused

    def refuse(kind, **payload):
        raise AuditRefused("refused")
    monkeypatch.setattr(audit_pkg, "audit_event", refuse)


# ---- DPIA draft ------------------------------------------------------------------

def test_dpia_draft_downloads_as_a_document(client, monkeypatch):
    text = client.get("/api/v1/privacy-ops/dpia")
    assert text.status_code == 200
    assert text.headers["content-disposition"].startswith('attachment; filename="lightwork-dpia-')
    assert text.headers["content-type"].startswith("text/plain")
    assert "DPIA" in text.text or "impact" in text.text.lower()
    data = client.get("/api/v1/privacy-ops/dpia", params={"format": "json"})
    assert data.status_code == 200 and data.json()
    assert client.get("/api/v1/privacy-ops/dpia", params={"format": "xml"}).status_code == 422
    _as(monkeypatch, "viewer")
    assert client.get("/api/v1/privacy-ops/dpia").status_code == 403


# ---- data map file scans -----------------------------------------------------------

def _fake_boto3(monkeypatch, objects, bodies):
    calls: list[tuple] = []

    class Client:
        def list_objects_v2(self, **kwargs):
            calls.append(("list", kwargs["Bucket"], kwargs["Prefix"]))
            return {"Contents": objects}

        def get_object(self, Bucket, Key):  # noqa: N803 -- the AWS client's own names
            calls.append(("get", Bucket, Key))
            data = bodies[Key]
            return {"Body": types.SimpleNamespace(read=lambda limit: data[:limit])}

    module = types.ModuleType("boto3")
    module.client = lambda name: Client()
    monkeypatch.setitem(sys.modules, "boto3", module)
    return calls


def test_bucket_scan_records_what_was_found_and_is_recorded_first(client, monkeypatch):
    from maverick import data_map as dm

    asset = dm.register_data_asset("corp-exports", system="s3", kind="bucket", owner="it", actor="ops")
    calls = _fake_boto3(monkeypatch, [{"Key": "hr/roster.csv", "Size": 40}],
                        {"hr/roster.csv": b"name,email\nAda,ada@example.com\n"})
    seen = _actions(monkeypatch)
    r = client.post(f"/api/v1/data-map/assets/{asset['id']}/scan-files",
                    json={"revision": asset["revision"], "folder": "hr/"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sampled"] == 1 and "email" in body["categories"]
    assert "Read 1 file" in body["message"] and "ada@example.com" not in r.text
    assert ("list", "corp-exports", "hr/") in calls
    assert "data_map_scan_files" in seen
    # The same page, now stale: the place changed since it was loaded.
    stale = client.post(f"/api/v1/data-map/assets/{asset['id']}/scan-files",
                        json={"revision": asset["revision"], "folder": "hr/"})
    assert stale.status_code == 409


def test_site_scan_looks_the_site_up_from_its_address(client, monkeypatch):
    from maverick import data_map as dm

    monkeypatch.setenv("MAVERICK_GRAPH_TOKEN", "token-value")  # pragma: allowlist secret
    asset = dm.register_data_asset("Legal Hub", system="sharepoint", kind="site", owner="it", actor="ops",
                                   location="https://contoso.sharepoint.com/sites/legal", source="microsoft_graph")
    fetched: list[str] = []

    def fetch(url, token):
        fetched.append(url)
        if "/drive/root/children" in url:
            return {"value": [{"id": "item-1!a", "name": "staff.csv", "size": 60, "file": {}}]}
        return {"value": [{"id": "contoso.sharepoint.com,g1,g2", "displayName": "Legal Hub",
                           "webUrl": "https://contoso.sharepoint.com/sites/legal/"}]}

    monkeypatch.setattr(dm, "_default_graph_fetch", fetch)
    monkeypatch.setattr(dm, "_default_graph_download", lambda url, token: b"call +1 415 555 2671")
    r = client.post(f"/api/v1/data-map/assets/{asset['id']}/scan-files", json={"revision": asset["revision"]})
    assert r.status_code == 200, r.text
    assert any("/sites/contoso.sharepoint.com,g1,g2/drive/root/children" in u for u in fetched)
    assert r.json()["sampled"] == 1

    # A site Graph no longer lists is refused plainly.
    monkeypatch.setattr(dm, "_default_graph_fetch", lambda url, token: {"value": []})
    current = dm.get_data_asset(asset["id"])
    gone = client.post(f"/api/v1/data-map/assets/{asset['id']}/scan-files", json={"revision": current["revision"]})
    assert gone.status_code == 409 and "SharePoint" in gone.json()["detail"]


def test_scan_refusals(client, monkeypatch):
    from maverick import data_map as dm

    table = dm.register_data_asset("orders", system="snowflake", kind="table", owner="it", actor="ops")
    r = client.post(f"/api/v1/data-map/assets/{table['id']}/scan-files", json={"revision": table["revision"]})
    assert r.status_code == 409
    assert client.post("/api/v1/data-map/assets/..%2Fx/scan-files", json={"revision": 1}).status_code == 404
    assert client.post("/api/v1/data-map/assets/nope/scan-files", json={"revision": 0}).status_code == 422
    bucket = dm.register_data_asset("exports", system="s3", kind="bucket", owner="it", actor="ops")
    bad = client.post(f"/api/v1/data-map/assets/{bucket['id']}/scan-files",
                      json={"revision": bucket["revision"], "bucket": "Not A Bucket!"})
    assert bad.status_code == 422
    with monkeypatch.context() as patch:
        _refuse_records(patch)
        refused = client.post(f"/api/v1/data-map/assets/{bucket['id']}/scan-files",
                              json={"revision": bucket["revision"]})
    assert refused.status_code == 503
    _as(monkeypatch, "viewer")
    assert client.post(f"/api/v1/data-map/assets/{bucket['id']}/scan-files",
                       json={"revision": bucket["revision"]}).status_code == 403


# ---- vendor questionnaire links ---------------------------------------------------

def test_questionnaire_links_are_prepared_by_a_workspace_admin(client, monkeypatch):
    from maverick import vendor_management as vm

    vm.register_vendor("Acme Payroll", category="payroll", criticality="high", owner="it", actor="ops")
    seen = _actions(monkeypatch)
    r = client.post("/api/v1/vendors/questionnaire-links/prepare", json={"start_over": True})
    assert r.status_code == 200, r.text
    assert r.json()["ready"] is True and "ready to share" in r.json()["message"]
    assert "vendor_questionnaire_links_prepare" in seen
    assert client.post("/api/v1/vendors/questionnaire-links/prepare", json={"extra": 1}).status_code == 422
    _as(monkeypatch, "operator")
    assert client.post("/api/v1/vendors/questionnaire-links/prepare", json={}).status_code == 403


# ---- a person's uploaded documents ------------------------------------------------

def _person_with_documents():
    from maverick import knowledge_admin
    from maverick_dashboard import app as dash_app

    world = dash_app._world()
    conv = world.get_or_create_conversation(channel="slack", user_id="U123")
    world.append_turn(conv.id, "user", "hello")
    kb = knowledge_admin.open_knowledge_base()
    try:
        kb.ingest_text("contracts", "Ada's employment contract, signed 2026.", subject="slack:U123")
    finally:
        kb.close()


def test_documents_are_checked_then_erased_with_the_typed_name(client, monkeypatch):
    _person_with_documents()
    person = {"channel": "slack", "user": "U123"}
    check = client.post("/api/v1/compliance/people/documents/check", json=person).json()
    assert check["remaining"] >= 1 and not check["clean"]
    assert not BANNED.search(check["message"])
    erase = "/api/v1/compliance/people/documents/erase"
    assert client.post(erase, json=person).status_code == 409
    wrong = client.post(erase, json={**person, "confirm": True, "confirm_name": "Somebody Else"})
    assert wrong.status_code == 409 and "does not match" in wrong.json()["detail"]
    assert client.post("/api/v1/compliance/people/documents/check", json=person).json()["remaining"] >= 1
    seen = _actions(monkeypatch)
    done = client.post(erase, json={**person, "confirm": True, "confirm_name": "  u123 "})
    assert done.status_code == 200, done.text
    assert done.json()["erased"] >= 1 and done.json()["clean"] is True
    assert "person_documents_erase" in seen
    assert client.post("/api/v1/compliance/people/documents/check", json=person).json()["clean"] is True


def test_documents_erase_is_recorded_before_anything_is_deleted(client, monkeypatch):
    _person_with_documents()
    person = {"channel": "slack", "user": "U123"}
    with monkeypatch.context() as patch:
        _refuse_records(patch)
        r = client.post("/api/v1/compliance/people/documents/erase",
                        json={**person, "confirm": True, "confirm_name": "U123"})
    assert r.status_code == 503
    assert client.post("/api/v1/compliance/people/documents/check", json=person).json()["remaining"] >= 1


def test_documents_need_a_workspace_admin_and_a_listed_person(client, monkeypatch):
    person = {"channel": "slack", "user": "U123"}
    assert client.post("/api/v1/compliance/people/documents/check",
                       json={"channel": "../x", "user": "U123"}).status_code == 422
    assert client.post("/api/v1/compliance/people/documents/erase",
                       json={**person, "confirm": True, "confirm_name": "U123"}).status_code == 404
    _as(monkeypatch, "operator")
    assert client.post("/api/v1/compliance/people/documents/check", json=person).status_code == 403
    assert client.post("/api/v1/compliance/people/documents/erase",
                       json={**person, "confirm": True, "confirm_name": "U123"}).status_code == 403


# ---- pages -------------------------------------------------------------------------

def _text(page: str, root_id: str, end: str = "</section>") -> str:
    start = page.index(f'id="{root_id}"')
    section = page[start:page.index(end, start)]
    section = re.sub(r"<(script|style)\b.*?</\1>", " ", section, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", section)))


def test_privacy_and_compliance_pages_show_the_new_buttons_plainly(client):
    from maverick import data_map as dm
    dm.register_data_asset("corp-exports", system="s3", kind="bucket", owner="it", actor="ops")
    page = client.get("/privacy").text
    for control in ("ops-dpia-text", "ops-breach-plan", "ops-qlinks"):
        assert f'id="{control}"' in page
    assert 'class="btn btn--ghost ops-dm-scan"' in page and "Scan the files" in page
    assert not BANNED.search(_text(page, "ops-privacy"))
    compliance = client.get("/compliance").text
    for control in ("ops-docs-check", "ops-docs-erase"):
        assert f'id="{control}"' in compliance
    assert not BANNED.search(_text(compliance, "ops-docs", "<script"))
