"""Owned saved-task views share native validation/CAS with typed Copilot."""
import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import ux_store
from maverick_dashboard import app, auth
from maverick_dashboard import product_operations_task_views as actions
from maverick_dashboard import task_saved_views as native
from starlette.requests import Request


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app._world_cache.clear()
    store = ux_store.UxStore(tmp_path / "ux.json")
    monkeypatch.setattr(ux_store, "shared", lambda: store)
    monkeypatch.setattr(auth, "caller_principal", lambda request: request.headers.get("x-test-account", "user:alice"))
    monkeypatch.setattr(native, "context_for", lambda request: hashlib.sha256(auth.caller_principal(request).encode()).hexdigest())
    request = Request({"type": "http", "method": "POST", "scheme": "http", "path": "/api/v1/views",
                       "headers": [(b"host", b"127.0.0.1"), (b"origin", b"http://127.0.0.1")]})
    client = TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return store, request, client


def body(state, **values):
    return {"expected_revision": state["revision"], "context": state["context"], **values}


def test_existing_endpoints_offer_complete_reviewed_task_view_journey(setup):
    store, _request, client = setup
    state = client.get('/api/v1/views?task_filters=true').json()
    response = client.post('/api/v1/views/Invoices?task_filters=true', json=body(state, q=' invoice ', status='failed'))
    assert response.status_code == 201, response.text
    row = response.json()['views'][0]
    assert row['params'] == {'page': '/goals', 'q': 'invoice', 'status': 'failed'}
    assert row['href'] == '/goals?q=invoice&status=failed'
    assert ux_store.UxStore(store.path).views('user:alice')['Invoices']['params'] == row['params']
    removed = client.request('DELETE', '/api/v1/views/Invoices?task_filters=true', json=body(response.json()))
    assert removed.status_code == 200 and removed.json()['views'] == []


def test_named_accounts_are_isolated_and_anonymous_cannot_use_task_filter_preferences(setup):
    _store, request, client = setup
    state = native.current(request)
    native.change(request, 'Private', native.Change(**body(state, q='confidential')))
    other = client.get('/api/v1/views?task_filters=true', headers={'x-test-account': 'user:bob'})
    assert other.json()['views'] == []
    denied = client.get('/api/v1/views?task_filters=true', headers={'x-test-account': ''})
    assert denied.status_code == 403


def test_stale_context_and_revision_preserve_current_filters(setup):
    store, request, client = setup
    state = native.current(request)
    native.change(request, 'Latest', native.Change(**body(state, q='newer')))
    stale = client.post('/api/v1/views/Latest?task_filters=true', json=body(state, q='old'))
    assert stale.status_code == 409
    wrong = client.post('/api/v1/views/Latest?task_filters=true', json={**body(state), 'context': '0' * 64})
    assert wrong.status_code == 409 and wrong.json()['detail']['code'] == 'context_changed'
    assert store.views('user:alice')['Latest']['params']['q'] == 'newer'


def test_allowlist_preserves_unrelated_legacy_views_without_replaying_urls(setup):
    store, request, client = setup
    store.save_view('user:alice', 'Legacy', {'redirect': 'https://outside.invalid', 'status': 'failed'})
    state = native.current(request)
    assert state['views'] == [] and state['other_views'] == 1
    refused = client.post('/api/v1/views/Bad?task_filters=true', json=body(state, status='anything'))
    assert refused.status_code == 422
    refused = client.post('/api/v1/views/Bad?task_filters=true', json=body(state, q='x' * 257))
    assert refused.status_code == 422
    collision = client.post('/api/v1/views/Legacy?task_filters=true', json=body(state, q='replacement'))
    assert collision.status_code == 409
    deletion = client.request('DELETE', '/api/v1/views/Legacy?task_filters=true', json=body(state))
    assert deletion.status_code == 409
    assert 'Legacy' in store.views('user:alice')


def test_native_and_copilot_share_reviewed_current_state_and_uncertain_readback(setup):
    store, request, _client = setup
    args = {'name': 'Done', 'q': 'review', 'status': 'done'}
    prepared = actions._preview(request, args, delete=False).native
    result = actions.execute(request, {}, args, prepared, 'operation')
    assert result.status == 'confirmed'
    saved = store.view_snapshot('user:alice')
    recovered = actions.recover(request, {}, args, prepared, 'operation')
    assert recovered.status == 'unconfirmed'  # State read is not a historical receipt.
    assert store.view_snapshot('user:alice') == saved
    with pytest.raises(HTTPException) as stale:
        actions.execute(request, {}, args, prepared, 'operation')
    assert stale.value.status_code == 409


def test_two_writers_cannot_both_commit_one_reviewed_view_revision(setup):
    store, _request, _client = setup
    revision = store.view_revision('user:alice')
    def save(name):
        try:
            store.save_view('user:alice', name, {'q': name}, expected_revision=revision)
            return 'saved'
        except ux_store.ViewConflict:
            return 'stale'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(save, ['one', 'two'])) == ['saved', 'stale']
    assert len(store.views('user:alice')) == 1


def test_delete_checks_whole_owned_inventory_before_changing_anything(setup):
    store, _request, _client = setup
    store.save_view('user:alice', 'one', {'q': 'one'})
    revision = store.view_revision('user:alice')
    store.save_view('user:alice', 'two', {'q': 'two'})
    with pytest.raises(ux_store.ViewConflict):
        store.delete_view('user:alice', 'one', expected_revision=revision)
    assert set(store.views('user:alice')) == {'one', 'two'}


def test_feature_gate_and_actual_asset_route(setup, monkeypatch):
    _store, _request, client = setup
    from maverick import experience_preferences
    monkeypatch.setattr(experience_preferences, 'enabled', lambda: False)
    assert client.get('/api/v1/views?task_filters=true').status_code == 403
    assert 'task-views-form' not in client.get('/goals').text
    asset = client.get('/static/lightwork-task-views.js')
    assert asset.status_code == 200 and 'application/javascript' in asset.headers['content-type']
