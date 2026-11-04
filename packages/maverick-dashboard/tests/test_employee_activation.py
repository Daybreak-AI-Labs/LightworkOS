import json
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import employee_activation as activation
from starlette.requests import Request


class Drafts:
    def __init__(self):
        self.rows = {}

    def get(self, identity):
        return self.rows.get(identity)

    def create(self, row, **kwargs):
        if row['id'] in self.rows:
            raise RecordConflict('changed')
        value = {**row, 'revision': 1}
        self.rows[row['id']] = value
        return value

    def update(self, identity, mutate, *, expected_revision, **kwargs):
        value = self.rows[identity]
        if expected_revision != value['revision']:
            raise RecordConflict('changed')
        value = dict(value)
        mutate(value)
        value['revision'] += 1
        self.rows[identity] = value
        return value


@pytest.fixture
def state(monkeypatch):
    from cryptography.fernet import Fernet
    codec = Fernet(Fernet.generate_key())
    value = {'actor': 'user:a', 'receipt': None, 'goal': None, 'suites': {}}
    value['store'] = Drafts()
    world = SimpleNamespace(get_goal=lambda identity: value['goal'])
    value['app'] = SimpleNamespace(_world=lambda: world, _require_same_origin=lambda request: None)
    monkeypatch.setattr(activation, '_app', lambda: value['app'])
    monkeypatch.setattr(activation, 'DRAFTS', value['store'])
    monkeypatch.setattr(activation, 'SubmissionStore', lambda world: SimpleNamespace(lookup=lambda **kwargs: value['receipt']))
    monkeypatch.setattr(activation, 'context_for', lambda request: 'context')
    monkeypatch.setattr(activation.auth, 'require_permission', lambda *args: None)
    monkeypatch.setattr(activation.auth, 'caller_principal', lambda request: value['actor'])
    monkeypatch.setattr(activation.auth, 'suite_allowed', lambda request, suite: suite in {None, 'privacy'})
    monkeypatch.setattr(activation.auth, 'assert_goal_access', lambda *args: None)
    monkeypatch.setattr(activation.config, 'config_source_errors', lambda **kwargs: [])
    monkeypatch.setattr(activation.config, 'get_features', lambda: {'employee_activation': True})
    monkeypatch.setattr(activation.config, 'load_config', lambda: {'suites': value['suites']})
    monkeypatch.setattr(activation.crypto_at_rest, 'seal_to_str', lambda text: 'sealed:' + codec.encrypt(text.encode()).decode())
    monkeypatch.setattr(activation.crypto_at_rest, 'unseal_from_str', lambda text: codec.decrypt(text[7:].encode()).decode())
    monkeypatch.setattr(activation.crypto_at_rest, 'is_sealed_str', lambda text: text.startswith('sealed:'))
    value['request'] = Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': [], 'state': {}})
    return value


def draft(state, **overrides):
    values = dict(context='context', operation_id='a' * 32, job='weekly_update', mode='sample', criteria='Ground every claim in the source.')
    values.update(overrides)
    return activation.save(state['request'], activation.DraftIn(**values))


def test_encrypted_draft_and_exact_creation_receipt(state):
    first = draft(state, mode='real', material='PRIVATE OWN MATERIAL')
    second = draft(state, mode='real', material='PRIVATE OWN MATERIAL')
    assert first['id'] == second['id'] and len(state['store'].rows) == 1
    assert 'PRIVATE OWN MATERIAL' not in json.dumps(state['store'].rows)
    with pytest.raises(HTTPException) as error:
        draft(state, mode='real', material='Different work')
    assert error.value.status_code == 409


def test_no_admin_or_cross_person_content_authority(state):
    saved = draft(state)
    state['actor'] = 'user:admin'
    with pytest.raises(HTTPException) as error:
        activation._read(state['request'], saved['id'])
    assert error.value.status_code == 404


def test_catalog_omits_denied_and_disabled_suites(state):
    assert 'security_review' not in activation.jobs(state['request'])
    assert 'privacy_evidence' in activation.jobs(state['request'])
    state['suites']['privacy'] = False
    assert 'privacy_evidence' not in activation.jobs(state['request'])


def test_workspace_cannot_expand_organization_job_catalog(state, monkeypatch):
    monkeypatch.setattr(activation.config, 'load_global_config', lambda: {'dashboard': {'employee_activation_jobs': ['weekly_update']}})
    monkeypatch.setattr(activation.config, 'load_config', lambda: {'dashboard': {'employee_activation_jobs': ['weekly_update', 'privacy_evidence']}})
    assert set(activation.jobs(state['request'])) == {'weekly_update'}


@pytest.mark.asyncio
async def test_incomplete_connector_draft_survives_setup_but_never_launches(state, monkeypatch):
    saved = draft(state, mode='real', source_kind='connected')
    assert saved['values']['source'] == {} and 'activation_draft=' in saved['repair_href']
    from maverick import doc_discovery
    monkeypatch.setattr(doc_discovery, 'enabled', lambda: True)
    monkeypatch.setattr(doc_discovery, 'fetch', lambda *args, **kwargs: pytest.fail('No source selected'))
    with pytest.raises(HTTPException) as error:
        await activation.launch(state['request'], saved['id'], activation.ActionIn(context='context', expected_revision=1, confirmed=True), BackgroundTasks())
    assert error.value.status_code == 409
    assert state['store'].get(saved['id'])['state'] == 'draft'


def test_acceptance_is_invalidated_by_current_result_change(state):
    saved = draft(state)
    state['goal'] = SimpleNamespace(id=8, owner='user:a', status='done', result='Reviewed answer', updated_at=1)
    state['receipt'] = {'goal_id': 8}
    row = state['store'].get(saved['id'])
    result = activation._result(state['request'], row)
    accepted = activation.accept(state['request'], saved['id'], activation.ActionIn(context='context', expected_revision=1, confirmed=True, result_fingerprint=result['fingerprint']))
    assert accepted['result']['accepted']
    state['goal'].result = 'Changed answer'
    assert not activation.public(state['request'], state['store'].get(saved['id']))['result']['accepted']


def test_non_ascii_context_or_fingerprint_is_refused_like_any_other_wrong_one(state):
    with pytest.raises(HTTPException) as refused:
        draft(state, context='café')
    assert refused.value.status_code == 409
    saved = draft(state)
    state['goal'] = SimpleNamespace(id=8, owner='user:a', status='done', result='Reviewed answer', updated_at=1)
    state['receipt'] = {'goal_id': 8}
    for body in ({'context': 'café'}, {'context': 'context', 'result_fingerprint': 'café'}):
        with pytest.raises(HTTPException) as refused:
            activation.accept(state['request'], saved['id'], activation.ActionIn(expected_revision=1, confirmed=True, **body))
        assert refused.value.status_code == 409


@pytest.mark.asyncio
async def test_recovering_admitted_draft_never_dispatches_again(state, monkeypatch):
    saved = draft(state)
    state['goal'] = SimpleNamespace(id=8, owner='user:a', status='pending', result='', updated_at=1)
    state['receipt'] = {'goal_id': 8}
    async def must_not_send(*args, **kwargs):
        pytest.fail('Recovery repeated a native admission')
    state['app'].chat_send = must_not_send
    result = await activation.launch(state['request'], saved['id'], activation.ActionIn(context='context', expected_revision=1, confirmed=True), BackgroundTasks())
    assert result['result']['id'] == 8


def test_reusable_instructions_exclude_original_sources_and_results(state):
    saved = draft(state, mode='real', material='PRIVATE SOURCE THAT MUST NOT BE COPIED')
    spec = activation._workflow_spec(state['store'].get(saved['id']))
    assert 'PRIVATE SOURCE' not in json.dumps(spec)
    assert '{{ source_material }}' in spec['body']
    assert spec['params'] == ['source_material']
