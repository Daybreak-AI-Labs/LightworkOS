from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import auth
from maverick_dashboard import device_pairing as pairing
from starlette.requests import Request


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pairing, '_path', lambda: tmp_path / 'registry.enc')
    monkeypatch.setattr(pairing, 'seal', lambda value: b'SEALED:' + value)
    monkeypatch.setattr(pairing, 'unseal', lambda value: value[7:])
    monkeypatch.setattr(pairing, 'is_sealed', lambda value: value.startswith(b'SEALED:'))
    monkeypatch.setattr(pairing, 'deployment_key_scope', nullcontext)
    monkeypatch.setattr(pairing, 'authority_effect_fence', nullcontext)
    monkeypatch.setattr(pairing, '_audit', lambda *args: None)
    monkeypatch.setattr(pairing, '_current', lambda *args: None)
    monkeypatch.setattr(pairing, 'current_tenant_id_strict', lambda: 'workspace-a')
    monkeypatch.setattr(pairing, '_policy', lambda **kwargs: {'ttl': 86400, 'actions': False})
    yield


def paired():
    pending = pairing.begin('My phone', 'synthetic-peer')
    device = pairing.confirm('user:alice', pending['code'])
    reply = pairing.poll(pending['pairing_token'])
    return pending, device, reply['token']


def test_pairing_requires_browser_approval_then_only_own_read_route_scope(store):
    pending = pairing.begin('My phone', 'synthetic-peer')
    assert pairing.poll(pending['pairing_token'])['status'] == 'pending'
    pairing.confirm('user:alice', pending['code'])
    token = pairing.poll(pending['pairing_token'])['token']
    assert pairing.authenticate(token, 'GET', '/api/v1/goals').principal == 'user:alice'
    for method, path in [('POST', '/api/v1/goals'), ('GET', '/api/v1/settings'), ('GET', '/api/v1/goals/1/attachments'), ('POST', '/api/v1/devices/confirm')]:
        with pytest.raises(HTTPException) as error:
            pairing.authenticate(token, method, path)
        assert error.value.status_code == 403


def test_pairing_proof_does_not_become_dashboard_credential(store):
    pending = pairing.begin('My watch', 'synthetic-peer')
    with pytest.raises(HTTPException):
        pairing.authenticate(pending['pairing_token'], 'GET', '/api/v1/goals')
    bad = pending['pairing_token'][:-1] + ('A' if pending['pairing_token'][-1] != 'A' else 'B')
    with pytest.raises(HTTPException):
        pairing.poll(bad)


def test_wrong_workspace_or_removed_device_cannot_read(store, monkeypatch):
    _, device, token = paired()
    monkeypatch.setattr(pairing, 'current_tenant_id_strict', lambda: 'workspace-b')
    with pytest.raises(HTTPException):
        pairing.authenticate(token, 'GET', '/api/v1/goals')
    monkeypatch.setattr(pairing, 'current_tenant_id_strict', lambda: 'workspace-a')
    pairing.revoke('user:alice', device['id'])
    with pytest.raises(HTTPException) as error:
        pairing.authenticate(token, 'GET', '/api/v1/goals')
    assert error.value.status_code == 401


def test_renewal_rotates_secret_and_recovers_only_the_same_generation(store):
    _, _, token = paired()
    renewed = pairing.renew(token, 1)
    assert renewed['token'] != token
    assert renewed['device']['generation'] == 2
    assert pairing.renew(token, 1) == renewed
    with pytest.raises(HTTPException):
        pairing.authenticate(token, 'GET', '/api/v1/goals')
    assert pairing.authenticate(renewed['token'], 'GET', '/api/v1/goals').principal == 'user:alice'


def test_a_device_removed_while_it_renews_is_refused_not_a_server_error(store, monkeypatch):
    # renew() authenticates, releases the lock, then reads the row again; a
    # removal in between drops the row from the store.
    _, device, token = paired()
    real_authenticate = pairing.authenticate

    def authenticate_then_remove(*args):
        principal = real_authenticate(*args)
        pairing.revoke('user:alice', device['id'])
        return principal

    monkeypatch.setattr(pairing, 'authenticate', authenticate_then_remove)
    with pytest.raises(HTTPException) as error:
        pairing.renew(token, 1)
    assert error.value.status_code == 401


def test_pairing_expires_and_never_upgrades_actions_silently(store, monkeypatch):
    pending = pairing.begin('Phone', 'synthetic-peer')
    with pytest.raises(HTTPException):
        pairing.confirm('user:alice', pending['code'], actions=True)
    monkeypatch.setattr(pairing.time, 'time', lambda: pending['expires_at'] + 1)
    with pytest.raises(HTTPException):
        pairing.confirm('user:alice', pending['code'])


def test_member_revocation_is_checked_on_each_read(store, monkeypatch):
    _, _, token = paired()
    def deny(*args):
        raise HTTPException(401, 'revoked')
    monkeypatch.setattr(pairing, '_current', deny)
    with pytest.raises(HTTPException):
        pairing.authenticate(token, 'GET', '/api/v1/goals')


def test_paired_administrator_cannot_expand_own_goal_scope(monkeypatch, tmp_path):
    from maverick import world_model
    # Goal access also re-checks copied-conversation sources in an isolated world.
    monkeypatch.setattr(world_model, 'DEFAULT_DB', tmp_path / 'world.db')
    request = Request({'type': 'http', 'method': 'GET', 'path': '/api/v1/goals', 'headers': []})
    request.state.paired_device_id = 'a' * 32
    monkeypatch.setattr(auth, '_authorization_principal', lambda request: 'user:alice')
    monkeypatch.setattr(auth, 'is_dashboard_admin', lambda principal: True)
    assert auth.goal_owner_filter(request) == 'user:alice'
    assert not auth.can_access_goal(request, SimpleNamespace(id='goal-bob', owner='user:bob'))
    assert auth.can_access_goal(request, SimpleNamespace(id='goal-alice', owner='user:alice'))


def test_oidc_issuer_string_cannot_mint_device_binding(monkeypatch):
    request = Request({'type': 'http', 'method': 'GET', 'path': '/', 'headers': []})
    principal = SimpleNamespace(issuer='lightwork:paired-device', claims={'device_id': 'forged'})
    assert pairing.bind(request, principal) is False


def test_read_paths_do_not_admit_prefix_or_encoded_traversal():
    for path in ['/api/v1/goals-other', '/api/v1/goals/../settings', '/api/v1/goals/1/events/stream', '/api/v1/goals/0']:
        assert not pairing.READ_PATHS.fullmatch(path)


def test_explicit_device_credential_cannot_fall_back_to_browser_identity(monkeypatch):
    request = Request({'type': 'http', 'method': 'GET', 'path': '/api/v1/goals',
                       'headers': [(b'authorization', b'Bearer lwdev1_invalid')]})
    monkeypatch.setattr(auth, '_dashboard_token_authenticated', lambda request: False)
    monkeypatch.setattr(auth, '_session_principal', lambda request: pytest.fail('must not borrow a browser session'))
    monkeypatch.setattr(auth, '_proxy_principal', lambda request: pytest.fail('must not borrow proxy identity'))
    with pytest.raises(HTTPException) as caught:
        auth._resolve_principal(request=request)
    assert caught.value.status_code == 401


def test_device_bootstrap_exemption_does_not_exempt_approval_or_management():
    assert auth._self_authenticated_path('/api/v1/devices/pairing/begin')
    assert auth._self_authenticated_path('/api/v1/devices/pairing/poll')
    assert not auth._self_authenticated_path('/api/v1/devices/confirm')
    assert not auth._self_authenticated_path('/api/v1/devices/remove')
    assert not auth._self_authenticated_path('/devices')


def test_pairing_review_refuses_a_non_ascii_context_like_any_other_wrong_one(monkeypatch):
    from maverick_dashboard import app as app_module
    from maverick_dashboard import device_pairing_api as api

    monkeypatch.setattr(app_module, '_require_same_origin', lambda _request: None)
    monkeypatch.setattr(api, 'context_for', lambda _request: 'a' * 64)
    request = Request({'type': 'http', 'method': 'POST', 'path': '/api/v1/devices/confirm', 'headers': []})
    for wrong in ('0' * 64, 'café'):
        with pytest.raises(HTTPException) as refused:
            api._binding(request, wrong)
        assert refused.value.status_code == 409
    api._binding(request, 'a' * 64)
