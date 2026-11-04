"""An employee's decision history is a scoped view, not global audit access."""
import json
from types import SimpleNamespace

import pytest
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.world_model import WorldModel
from maverick_dashboard import api, auth


@pytest.fixture
def history(monkeypatch, tmp_path):
    world = WorldModel(tmp_path / 'world.db')
    allowed, permissions = set(), []
    monkeypatch.setattr(api, '_world', lambda: world)
    monkeypatch.setattr(api, '_supervisor', lambda _: 'user:alice')
    monkeypatch.setattr(api, 'require_permission', lambda _, permission: permissions.append(permission))
    monkeypatch.setattr(auth, 'can_access_goal', lambda _, goal: goal.id in allowed)
    yield world, allowed, permissions
    world.close()


def create(world, requester, goal_id=None, detail='Reviewed request'):
    token = set_goal_context(goal_id=goal_id)
    try:
        return world.create_approval('publish_report', requested_by=requester, detail=detail)
    finally:
        reset_goal_context(token)


def test_operator_sees_only_own_requests_with_current_task_access(history):
    world, allowed, permissions = history
    own = world.create_goal('Own task', owner='user:alice')
    foreign = world.create_goal('Private task', owner='user:bob')
    allowed.add(own)
    expected = create(world, 'user:alice', own)
    create(world, 'user:bob', own, 'Other requester content')
    create(world, 'user:alice', foreign, 'Now inaccessible task content')
    result = api.requested_approval_history(SimpleNamespace())
    assert [item['id'] for item in result['items']] == [expected]
    assert permissions == ['operate'], 'Own history does not require global audit capability'
    assert 'Other requester' not in json.dumps(result) and 'Now inaccessible' not in json.dumps(result)
    assert result['items'][0]['execution'] == 'Current task state: pending'


def test_permission_revocation_removes_historical_content_on_next_read(history):
    world, allowed, _ = history
    goal = world.create_goal('Task', owner='user:alice')
    allowed.add(goal)
    create(world, 'user:alice', goal)
    assert len(api.requested_approval_history(SimpleNamespace())['items']) == 1
    allowed.clear()
    assert api.requested_approval_history(SimpleNamespace())['items'] == []


def test_filtered_page_advances_without_dropping_older_allowed_request(history):
    world, allowed, _ = history
    own = world.create_goal('Own task', owner='user:alice')
    private = world.create_goal('Closed private task', owner='user:bob')
    allowed.add(own)
    oldest = create(world, 'user:alice', own)
    for _ in range(51):
        create(world, 'user:alice', private)
    for _ in range(5):
        create(world, 'user:bob', private)
    first = api.requested_approval_history(SimpleNamespace())
    assert first['items'] == [] and first['has_more'] is True
    second = api.requested_approval_history(SimpleNamespace(), first['before_id'])
    assert [item['id'] for item in second['items']] == [oldest]
    assert second['has_more'] is False


def test_legacy_request_detail_redacts_token_and_does_not_claim_execution(history):
    world, _, _ = history
    secret = 'lw-rest-' + 'A' * 43
    create(world, 'user:alice', detail='Credentials ' + secret)
    row = api.requested_approval_history(SimpleNamespace())['items'][0]
    assert secret not in json.dumps(row)
    assert row['execution'] == 'No task execution outcome is attached to this decision.'


@pytest.mark.parametrize('before_id', [10**20, 2**63, 0, -1])
def test_an_out_of_range_cursor_is_a_plain_refusal_not_a_server_error(history, before_id):
    from fastapi import HTTPException

    world, _allowed, _permissions = history
    create(world, 'user:alice')
    with pytest.raises(HTTPException) as refused:
        api.requested_approval_history(SimpleNamespace(), before_id=before_id)
    assert refused.value.status_code == 422
    assert api.requested_approval_history(SimpleNamespace(), before_id=2**63 - 1)['items']
