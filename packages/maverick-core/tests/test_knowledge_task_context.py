"""Temporary native storage and fake-model checks; no provider is called."""
from types import SimpleNamespace

import pytest
from maverick import config
from maverick import knowledge_task_context as context
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv('MAVERICK_HOME', str(tmp_path))
    monkeypatch.setenv('MAVERICK_CONFIG', str(tmp_path / 'config.toml'))
    monkeypatch.setenv('MAVERICK_ENCRYPT_AT_REST', '0')
    config.reset_config_cache()
    monkeypatch.setattr(context, 'enabled', lambda: True)
    allowed = {'value': True, 'calls': 0}
    def materialize(*args, **kwargs):
        allowed['calls'] += 1
        if not allowed['value']:
            raise PermissionError('withdrawn')
        return {'binding_sha256': 'f' * 64, 'items': [], 'references': []}
    monkeypatch.setattr(context, 'service', lambda: SimpleNamespace(materialize_at_job_start=materialize))
    from maverick import audit, knowledge_retrieval, orchestrator
    from maverick import employee_companion_model as model
    monkeypatch.setattr(model, 'prepare_route', lambda: 'route')
    monkeypatch.setattr(model, 'validate_route', lambda value: None)
    monkeypatch.setattr(audit, 'audit_event', lambda *args, **kwargs: None)
    monkeypatch.setattr(knowledge_retrieval, 'render_evidence', lambda value: 'private source excerpt')
    monkeypatch.setattr(orchestrator, '_shield_input_block_reason', lambda *args: None)
    with tenant_scope(tenant='workspace-a'):
        world=WorldModel(tmp_path / 'world.db')
        goal=world.create_goal('Analyze policy', 'Compare selected evidence', owner='user:alice')
        world.set_goal_status(goal, 'draft')
        selection={'purpose':'business', 'references':[{'kind':'dataset','asset_id':'policy','version':'v1','manifest_sha256':'a'*64,'schema':'lightwork.research-registry-ref.v1'}]}
        lifecycle=SimpleNamespace(episodes=[], end_episode=lambda result,state: lifecycle.episodes.append((result,state)))
        yield SimpleNamespace(world=world, goal=goal, selection=selection, allowed=allowed, lifecycle=lifecycle, budget=SimpleNamespace(check=lambda:None,max_output_tokens=3000), model=model)
        world.close()
    config.reset_config_cache()


def test_binding_is_immutable_owner_brief_and_exact_sources(setup):
    state=setup
    context.bind(state.world,state.goal,'user:alice',state.selection)
    assert context.has_binding(state.goal)
    from maverick.pilot_learning import excluded
    assert excluded(state.goal)
    with pytest.raises(context.SourceContextUnavailable):
        context.bind(state.world,state.goal,'user:bob',state.selection)
    changed={**state.selection,'purpose':'training'}
    with pytest.raises(context.SourceContextUnavailable,match='different selected'):
        context.bind(state.world,state.goal,'user:alice',changed)
    assert not context.has_binding(state.goal+1)


@pytest.mark.asyncio
async def test_one_tool_free_attempt_stores_only_private_result(setup, monkeypatch):
    state=setup
    calls=[]
    class Fake:
        def __init__(self,route): pass
        async def complete_async(self,**kwargs):
            kwargs['dispatch_guard']()
            calls.append(kwargs)
            return SimpleNamespace(text='Secret analysis',tool_calls=[])
    monkeypatch.setattr(state.model,'_PinnedDraftLLM',Fake)
    context.bind(state.world,state.goal,'user:alice',state.selection)
    state.world.set_goal_status(state.goal,'active')
    result=await context.run_analysis(state.world,state.goal,state.budget,state.lifecycle)
    assert 'Secret analysis' not in result
    assert state.world.get_goal(state.goal).status=='done'
    assert 'Secret analysis' not in str(state.lifecycle.episodes)
    assert context.read_analysis(state.world,state.goal,'user:alice')['result']=='Secret analysis'
    assert calls[0]['tools'] is None and calls[0]['max_physical_attempts']==1
    state.allowed['value']=False
    with pytest.raises(context.SourceContextUnavailable):
        context.read_analysis(state.world,state.goal,'user:alice')
    with pytest.raises(context.SourceContextUnavailable):
        context.read_analysis(state.world,state.goal,'user:bob')
    state.world.set_goal_status(state.goal,'active')
    await context.run_analysis(state.world,state.goal,state.budget,state.lifecycle)
    assert len(calls)==1


@pytest.mark.asyncio
async def test_revocation_during_reply_never_publishes(setup,monkeypatch):
    state=setup
    class Fake:
        def __init__(self,route): pass
        async def complete_async(self,**kwargs):
            kwargs['dispatch_guard']()
            state.allowed['value']=False
            return SimpleNamespace(text='WITHHELD PRIVATE ANALYSIS',tool_calls=[])
    monkeypatch.setattr(state.model,'_PinnedDraftLLM',Fake)
    context.bind(state.world,state.goal,'user:alice',state.selection)
    state.world.set_goal_status(state.goal,'active')
    await context.run_analysis(state.world,state.goal,state.budget,state.lifecycle)
    assert state.world.get_goal(state.goal).status=='blocked'
    assert 'WITHHELD' not in state.world.get_goal(state.goal).result
    assert 'result' not in context._read(state.goal)


@pytest.mark.asyncio
async def test_unfinished_binding_blocks_before_any_model(setup,monkeypatch):
    state=setup
    from maverick.attachment_submissions import SubmissionStore
    receipt=SubmissionStore(state.world).create(token='interrupted',fingerprint='a'*64,owner='user:alice',title='Analysis',description='',manifest=[],kind='source_analysis')
    assert context.has_binding(receipt['goal_id'],state.world)
    monkeypatch.setattr(state.model,'prepare_route',lambda:pytest.fail('model admission must not happen'))
    state.world.set_goal_status(receipt['goal_id'],'active')
    result=await context.run_analysis(state.world,receipt['goal_id'],state.budget,state.lifecycle)
    assert 'not fully saved' in result
    assert state.world.get_goal(receipt['goal_id']).status=='blocked'


def test_owner_or_brief_change_refuses_read(setup):
    state=setup
    context.bind(state.world,state.goal,'user:alice',state.selection)
    goal=state.world.get_goal(state.goal)
    from dataclasses import replace
    with pytest.raises(context.SourceContextUnavailable):
        context.require_read(replace(goal,description='Different instructions'),'user:alice')
    with pytest.raises(context.SourceContextUnavailable):
        context.require_read(replace(goal,owner='user:bob'),'user:bob')
