"""Source selection stays bound to the native idempotent task admission."""
import pytest
from fastapi.testclient import TestClient
from maverick import knowledge_task_context
from maverick.attachment_submissions import SubmissionStore
from maverick.world_model import WorldModel
from maverick_dashboard import api, draft_api
from maverick_dashboard import app as dashboard


@pytest.fixture
def client(monkeypatch,tmp_path):
    world=WorldModel(tmp_path/'world.db')
    runs=[]
    async def run(*args,**kwargs):
        runs.append(args)
    monkeypatch.setattr(api,'_world',lambda:world)
    monkeypatch.setattr(api,'require_provider_or_400',lambda:None)
    monkeypatch.setattr(dashboard,'check_goal_rate_limit',lambda request:None)
    monkeypatch.setattr(api,'caller_principal',lambda request:'user:alice')
    monkeypatch.setattr(api,'assert_goal_access',lambda *args:None)
    monkeypatch.setattr(draft_api,'context_for',lambda request:'a'*64)
    monkeypatch.setattr('maverick.runner.run_goal_in_background_async',run)
    monkeypatch.setattr(knowledge_task_context,'validate_selection',lambda *args,**kwargs:{})
    bindings=[]
    monkeypatch.setattr(knowledge_task_context,'bind',lambda *args:bindings.append(args))
    with TestClient(dashboard.app, base_url="http://127.0.0.1",headers={'Origin':'http://127.0.0.1'}) as client:
        yield client,world,runs,bindings
    world.close()


def payload():
    return {'title':'Analyze current source','knowledge_context':{'context':'a'*64,'purpose':'business','references':[{'kind':'dataset','asset_id':'policy','version':'v1','manifest_sha256':'b'*64}]}}


def test_context_and_operation_identity_required_before_admission(client):
    http,world,runs,_=client
    assert http.post('/api/v1/goals',json=payload()).status_code==422
    body=payload()
    body['knowledge_context']['context']='c'*64
    assert http.post('/api/v1/goals',json=body,headers={'Idempotency-Key':'source-test'}).status_code==409
    assert not world.list_goals() and not runs


def test_template_cannot_smuggle_selection_into_tool_task(client):
    http,world,runs,_=client
    assert http.post('/api/v1/goals',json={**payload(),'template':'tool-template'},headers={'Idempotency-Key':'source-test'}).status_code==422
    assert not world.list_goals() and not runs


def test_native_receipt_records_source_mode_and_replay_has_one_dispatch(client):
    http,world,runs,bindings=client
    headers={'Idempotency-Key':'source-test'}
    first=http.post('/api/v1/goals',json=payload(),headers=headers)
    assert first.status_code==201,first.text
    second=http.post('/api/v1/goals',json=payload(),headers=headers)
    assert second.status_code==201,second.text
    assert first.json()['id']==second.json()['id']
    assert len(runs)==len(bindings)==1
    assert SubmissionStore(world).for_goal(first.json()['id'])['detail']['kind']=='source_analysis'
    assert 'context' not in bindings[0][-1]
