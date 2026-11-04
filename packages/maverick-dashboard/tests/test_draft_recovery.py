"""Private durable draft recovery, including failed writes and ownership boundaries."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from maverick import crypto_at_rest, world_model
from maverick_dashboard import draft_api
from maverick_dashboard.app import app
from maverick_dashboard.draft_store import DraftConflict, DraftStore

CONTEXT = hashlib.sha256(b"alice:workspace-a").hexdigest()
SLOT = hashlib.sha256(b"editor:new").hexdigest()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(crypto_at_rest, "per_tenant_at_rest", lambda: False)
    monkeypatch.setattr(crypto_at_rest, "_active_keyring_key", lambda: None)
    monkeypatch.setattr(draft_api.config, "config_source_errors", lambda **kw: [])
    monkeypatch.setattr(draft_api.config, "get_features", lambda: {"draft_recovery": True})
    return tmp_path


def test_recovery_survives_new_store_and_is_always_encrypted(isolated, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    store = DraftStore(CONTEXT, directory=isolated / "drafts")
    saved = store.save(SLOT, {"body": "unfinished private workflow"}, expected_revision=0, operation_id="request-one")
    raw = (store.directory / (SLOT + ".draft")).read_bytes()
    assert crypto_at_rest.is_sealed(raw)
    assert b"unfinished private workflow" not in raw
    assert DraftStore(CONTEXT, directory=store.directory).read(SLOT) == saved


def test_exact_retry_does_not_advance_and_conflict_cannot_overwrite(isolated):
    store = DraftStore(CONTEXT, directory=isolated)
    first = store.save(SLOT, {"body": "first"}, expected_revision=0, operation_id="request-one")
    assert store.save(SLOT, {"body": "first"}, expected_revision=0, operation_id="request-one") == first
    with pytest.raises(DraftConflict):
        store.save(SLOT, {"body": "changed retry"}, expected_revision=0, operation_id="request-one")
    with pytest.raises(DraftConflict):
        store.save(SLOT, {"body": "stale tab"}, expected_revision=0, operation_id="request-two")
    assert store.read(SLOT) == first


def test_long_workspace_path_reopens_saved_copy_and_retains_cas(isolated):
    directory = isolated / ("workspace-" + "x" * 70) / ("principal-" + "y" * 70)
    store = DraftStore(CONTEXT, directory=directory)
    assert len(str(store._path(SLOT))) > 260
    first = store.save(SLOT, {"brief": "recover after browser restart"}, expected_revision=0, operation_id="first-long-path")
    reopened = DraftStore(CONTEXT, directory=directory)
    assert reopened.read(SLOT) == first
    with pytest.raises(DraftConflict):
        reopened.save(SLOT, {"brief": "stale tab"}, expected_revision=0, operation_id="second-long-path")
    assert reopened.read(SLOT) == first


def test_discard_tombstone_does_not_allow_old_tab_to_resurrect(isolated):
    store = DraftStore(CONTEXT, directory=isolated)
    store.save(SLOT, {"brief": "draft"}, expected_revision=0, operation_id="request-one")
    discarded = store.save(SLOT, None, expected_revision=1, operation_id="request-two")
    assert discarded["payload"] is None and discarded["revision"] == 2
    with pytest.raises(DraftConflict):
        store.save(SLOT, {"brief": "stale"}, expected_revision=1, operation_id="request-three")


def test_concurrent_editors_have_one_winner(isolated):
    def attempt(body):
        try:
            return DraftStore(CONTEXT, directory=isolated).save(SLOT, {"brief": body}, expected_revision=0, operation_id=body)
        except DraftConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["first-editor", "other-editor"]))
    assert sum(item is not None for item in results) == 1
    assert DraftStore(CONTEXT, directory=isolated).read(SLOT)["revision"] == 1


@pytest.mark.parametrize("payload", [
    {"nodes": [{"params": {"password": "private-value"}}]},  # pragma: allowlist secret -- rejected synthetic credential
    {"raw": json.dumps({"nested": {"accessToken": "private-value"}})},  # pragma: allowlist secret -- rejected synthetic credential
    {"raw": json.dumps({"nested": {"token": "private-value"}})},  # pragma: allowlist secret -- rejected synthetic credential
    {"brief": "password=private-value"},  # pragma: allowlist secret -- rejected synthetic credential
    {"nested": {"client-secret": "private-value"}},  # pragma: allowlist secret -- rejected synthetic credential
])
def test_credentials_are_refused_before_disk_write(isolated, payload):
    store = DraftStore(CONTEXT, directory=isolated / "drafts")
    with pytest.raises(ValueError, match="credentials|passwords"):
        store.save(SLOT, payload, expected_revision=0, operation_id="request-one")
    assert not list(isolated.rglob("*.draft"))


def test_connection_references_remain_recoverable(isolated):
    payload = {"params": {"token_ref": "connection-one", "password_env": "SAVED_CREDENTIAL"}}  # pragma: allowlist secret -- reference names only
    assert DraftStore(CONTEXT, directory=isolated).save(SLOT, payload, expected_revision=0, operation_id="request-one")["payload"] == payload


def test_wrong_context_and_plaintext_are_refused(isolated):
    store = DraftStore(CONTEXT, directory=isolated)
    store.save(SLOT, {"brief": "private"}, expected_revision=0, operation_id="request-one")
    with pytest.raises(ValueError, match="binding"):
        DraftStore("b" * 64, directory=isolated).read(SLOT)
    (isolated / (SLOT + ".draft")).write_text("{}")
    with pytest.raises(ValueError, match="encryption"):
        store.read(SLOT)


def test_api_requires_rendered_identity_binding_and_preserves_user_isolation(isolated, monkeypatch):
    identity = ["user:alice"]
    monkeypatch.setattr(draft_api, "_authorization_principal", lambda request: identity[0])
    monkeypatch.setattr(draft_api, "current_tenant_id_strict", lambda: "workspace-a")
    monkeypatch.setattr(draft_api, "require_permission", lambda *args: None)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    context = hashlib.sha256(json.dumps(["workspace-a", "principal", "user:alice"], separators=(",", ":")).encode()).hexdigest()
    path = "/api/v1/drafts/" + SLOT
    body = {"expected_revision": 0, "operation_id": "a-request-reference", "payload": {"brief": "private"}}
    assert client.put(path, json=body).status_code == 409
    headers = {"X-Lightwork-Draft-Context": context}
    assert client.put(path, json=body, headers=headers).status_code == 200
    identity[0] = "user:bob"
    assert client.get(path, headers=headers).status_code == 409
    bob = hashlib.sha256(json.dumps(["workspace-a", "principal", "user:bob"], separators=(",", ":")).encode()).hexdigest()
    assert client.get(path, headers={"X-Lightwork-Draft-Context": bob}).json()["payload"] is None
    identity[0] = "user:alice"
    assert client.get(path, headers=headers).json()["payload"] == {"brief": "private"}


def test_feature_control_denies_read_and_write(isolated, monkeypatch):
    monkeypatch.setattr(draft_api.config, "get_features", lambda: {"draft_recovery": False})
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/api/v1/drafts/" + SLOT).status_code == 403
    assert client.put("/api/v1/drafts/" + SLOT, json={"expected_revision": 0, "operation_id": "a-request-reference", "payload": {}}).status_code == 403

def test_retry_cannot_rebind_its_expected_revision(isolated):
    store = DraftStore(CONTEXT, directory=isolated)
    store.save(SLOT, {"brief": "same draft"}, expected_revision=0, operation_id="request-one")
    with pytest.raises(DraftConflict):
        store.save(SLOT, {"brief": "same draft"}, expected_revision=1, operation_id="request-one")


def test_retirement_reclaims_capacity_and_keeps_saved_copy_and_old_tabs_fenced(isolated, monkeypatch):
    from maverick_dashboard import draft_store
    monkeypatch.setattr(draft_store, "MAX_RECORDS", 2)
    store = DraftStore(CONTEXT, directory=isolated)
    discarded = store.save(SLOT, None, expected_revision=0, operation_id="discarded")
    active_slot, new_slot = "a" * 64, "b" * 64
    active = store.save(active_slot, {"brief": "keep this"}, expected_revision=0, operation_id="active")
    with pytest.raises(ValueError, match="Manage recovery storage"):
        store.save(new_slot, {}, expected_revision=0, operation_id="full")
    inventory = store.inventory()
    assert inventory["discarded"] == 1 and inventory["saved"] == 1 and inventory["available"] == 0
    assert "keep this" not in json.dumps(inventory)
    retired = store.retire_discarded(expected_version=inventory["version"])
    assert retired["retired"] == 1 and retired["available"] == 1
    assert store.read(active_slot) == active
    assert crypto_at_rest.is_sealed((isolated / "retention.index").read_bytes())
    reopened = DraftStore(CONTEXT, directory=isolated)
    for revision in (0, discarded["revision"]):
        with pytest.raises(DraftConflict):
            reopened.save(SLOT, {"brief": "stale"}, expected_revision=revision, operation_id="stale")
    fresh = reopened.read(new_slot)
    assert fresh["revision"] > discarded["revision"]
    assert reopened.save(new_slot, {}, expected_revision=fresh["revision"], operation_id="fresh")["payload"] == {}
    # A saved draft predating retirement keeps normal +1 CAS and exact retry
    # when it is later discarded, despite having a lower revision than the floor.
    later = reopened.save(active_slot, None, expected_revision=active["revision"], operation_id="later-discard")
    assert later["revision"] == active["revision"] + 1
    assert reopened.save(active_slot, None, expected_revision=active["revision"], operation_id="later-discard") == later


def test_retirement_refuses_changed_inventory_and_survives_interrupted_cleanup(isolated, monkeypatch):
    from pathlib import Path
    store = DraftStore(CONTEXT, directory=isolated)
    store.save(SLOT, None, expected_revision=0, operation_id="discarded")
    before = store.inventory()
    store.save("b" * 64, {"brief": "new saved copy"}, expected_revision=0, operation_id="new-copy")
    with pytest.raises(DraftConflict, match="storage changed"):
        store.retire_discarded(expected_version=before["version"])
    original_unlink = Path.unlink
    def fail_cleanup(path, *args, **kwargs):
        if path.name == SLOT + ".draft":
            raise OSError("synthetic cleanup interruption")
        return original_unlink(path, *args, **kwargs)
    with monkeypatch.context() as cleanup:
        cleanup.setattr(Path, "unlink", fail_cleanup)
        with pytest.raises(OSError, match="interruption"):
            store.retire_discarded(expected_version=store.inventory()["version"])
    reopened = DraftStore(CONTEXT, directory=isolated)
    with pytest.raises(DraftConflict):
        reopened.save(SLOT, {"brief": "resurrect"}, expected_revision=1, operation_id="old-tab")
    assert reopened.retire_discarded(expected_version=reopened.inventory()["version"])["retired"] == 1
    assert reopened.read("b" * 64)["payload"] == {"brief": "new saved copy"}


def test_retention_index_cannot_be_rebound_or_read_as_plaintext(isolated):
    store = DraftStore(CONTEXT, directory=isolated)
    store.save(SLOT, None, expected_revision=0, operation_id="discarded")
    store.retire_discarded(expected_version=store.inventory()["version"])
    with pytest.raises(ValueError, match="retention history"):
        DraftStore("b" * 64, directory=isolated).read(SLOT)
    (isolated / "retention.index").write_text("{}")
    with pytest.raises(ValueError, match="retention history"):
        store.save(SLOT, {}, expected_revision=0, operation_id="new")


def test_storage_api_requires_context_and_exact_reviewed_inventory(isolated, monkeypatch):
    monkeypatch.setattr(draft_api, "_authorization_principal", lambda request: "user:alice")
    monkeypatch.setattr(draft_api, "current_tenant_id_strict", lambda: "workspace-a")
    monkeypatch.setattr(draft_api, "require_permission", lambda *args: None)
    context = hashlib.sha256(json.dumps(["workspace-a", "principal", "user:alice"], separators=(",", ":")).encode()).hexdigest()
    store = DraftStore(context)
    store.save(SLOT, None, expected_revision=0, operation_id="discarded")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/api/v1/drafts/storage").status_code == 409
    headers = {"X-Lightwork-Draft-Context": context}
    response = client.get("/api/v1/drafts/storage", headers=headers)
    assert response.status_code == 200 and response.headers["cache-control"] == "private, no-store"
    version = response.json()["version"]
    assert client.post("/api/v1/drafts/storage/retire", headers=headers, json={"expected_version": "0" * 64}).status_code == 409
    response = client.post("/api/v1/drafts/storage/retire", headers=headers, json={"expected_version": version})
    assert response.status_code == 200 and response.json()["retired"] == 1
    monkeypatch.setattr(draft_api, "current_tenant_id_strict", lambda: "workspace-b")
    assert client.get("/api/v1/drafts/storage", headers=headers).status_code == 409


def test_api_refuses_a_non_ascii_context_header_like_any_other_wrong_one(isolated, monkeypatch):
    monkeypatch.setattr(draft_api, "_authorization_principal", lambda request: "user:alice")
    monkeypatch.setattr(draft_api, "current_tenant_id_strict", lambda: "workspace-a")
    monkeypatch.setattr(draft_api, "require_permission", lambda *args: None)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    for value in ("0" * 64, b"caf\xe9"):
        refused = client.get("/api/v1/drafts/storage", headers={"X-Lightwork-Draft-Context": value})
        assert refused.status_code == 409, (value, refused.status_code, refused.text)
