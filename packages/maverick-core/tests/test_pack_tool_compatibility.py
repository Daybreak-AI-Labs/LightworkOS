"""Shipped pack/skill contracts and actual read-seat dispatch, entirely offline."""
from __future__ import annotations

import json
import sqlite3

import pytest
from maverick import agent_autonomy, domain, skills, tools
from maverick.assessment import AssessmentSession
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.capability import Capability
from maverick.safety.tool_risk import tool_risk
from maverick.sandbox.local import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools.assessment_tools import assessment_tools
from maverick.tools.spreadsheet import spreadsheet_read
from maverick.tools.sql_query import sql_query_read
from maverick.world_model import WorldModel


@pytest.fixture
def context(tmp_path, monkeypatch):
    for name in ('_apply_python_plugins', '_apply_ts_plugins', '_apply_grpc_plugins'):
        monkeypatch.setattr(tools, name, lambda registry: None)
    world = WorldModel(tmp_path / 'world.db')
    ctx = SwarmContext(llm=None, world=world, budget=Budget(max_dollars=1),
                       blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=world.create_goal('offline pack qualification'), use_skills=False)
    yield ctx
    world.close()


def test_all_shipped_pack_and_skill_tool_contracts(context):
    registry = tools.base_registry(context.world, context.sandbox,
                                   _include_generated_tools=False, _skip_tool_acl=True,
                                   enable_web_search=True, enable_computer_use=True,
                                   enable_browser=True, enable_mobile_tools=True, enable_ros=True)
    names = {tool.name for tool in registry.all()} | {
        'send_to_agent', 'recv_from_agent', 'delegate_to_agent', 'spawn_subagent',
        'spawn_swarm', 'spawn_specialist', 'list_specialists', 'learn_capability',
        'code_exec', 'knowledge_search', 'find_tools',
    }
    profiles = domain.load_domains(domain.builtin_dir())
    assert len(list(domain.builtin_dir().glob('*.toml'))) == 2031
    assert len(profiles) == 2031
    problems = {name: errors for name, profile in profiles.items()
                if (errors := domain.tool_compatibility_errors(profile, risk_overrides={}))}
    assert problems == {}
    # Abstract/operator-provisioned adapter names remain prerequisites, as in
    # the audited catalog. Registry validation must identify each one honestly.
    for profile in profiles.values():
        absent = set(profile.allow_tools) - names
        errors = domain.tool_compatibility_errors(profile, names, risk_overrides={})
        assert len(errors) == len(absent)
        assert all('not available in the installed registry' in error for error in errors)
    # Questionnaire tools exist intentionally only in the assessment registry.
    specialized = {tool.name for tool in assessment_tools(AssessmentSession())}
    loaded = skills.load_builtin_skills()
    assert len(loaded) == 513
    assert {s.name: sorted(set(s.tools_needed) - names - specialized) for s in loaded
            if set(s.tools_needed) - names - specialized} == {}


@pytest.mark.parametrize('name', ['sql_query', 'spreadsheet', 'okta_read', 'crunchbase_read'])
def test_original_risk_floors_are_preserved(name):
    assert tool_risk(name, overrides={}) == 'high'


@pytest.mark.parametrize('op', ['write', 'set_cell', 'recalculate', None])
def test_spreadsheet_read_refuses_every_mutation(tmp_path, op):
    target = tmp_path / 'ledger.csv'
    target.write_text('week,amount\n1,100\n', encoding='utf-8')
    before = target.read_bytes()
    tool = spreadsheet_read(LocalBackend(workdir=tmp_path))
    result = tool.fn({'op': op, 'path': 'ledger.csv', 'rows': [['changed']],
                      'cell': 'A1', 'value': 'changed'})
    assert result.startswith('ERROR:')
    assert target.read_bytes() == before


@pytest.mark.parametrize('args', [
    {'query': 'UPDATE actuals SET amount=0'},
    {'query': 'DELETE FROM actuals', 'read_only': False},
    {'query': 'SELECT * FROM actuals', 'read_only': 0},
    {'query': 'CREATE TABLE unwanted(x)'},
])
def test_sql_read_refuses_mutations_and_preserves_database(tmp_path, args):
    path = tmp_path / 'ledger.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE actuals(amount INTEGER)')
        db.execute('INSERT INTO actuals VALUES (100)')
    before = path.read_bytes()
    tool = sql_query_read(LocalBackend(workdir=tmp_path))
    assert tool.fn({'database': 'ledger.db', **args}).startswith('ERROR:')
    assert path.read_bytes() == before


@pytest.mark.parametrize('levels', [False, True])
@pytest.mark.asyncio
async def test_finance_factory_dispatches_actual_read_tools(context, tmp_path, monkeypatch, levels):
    monkeypatch.setattr(agent_autonomy, 'levels_enabled', lambda: levels)
    path = tmp_path / 'cash.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE actuals(amount INTEGER)')
        db.executemany('INSERT INTO actuals VALUES (?)', [(20,), (30,)])
    (tmp_path / 'cash.csv').write_text('week,amount\n1,50\n', encoding='utf-8')
    profile = domain.load_domain(domain.builtin_dir() / 'finance_cash13w.toml')
    agent = domain.agent_from_profile(profile, context, 'Prepare the cash forecast')
    monkeypatch.setattr(agent, '_audit_tool_event', lambda *args, **kwargs: True)
    assert agent.capability.permits('sql_query_read')
    assert agent.capability.permits('spreadsheet_read')
    assert not agent.capability.permits('sql_query')
    assert not agent.capability.permits('spreadsheet')
    sql = await agent._run_tool('sql_query_read', {'database': 'cash.db',
                                                 'query': 'SELECT SUM(amount) AS total FROM actuals'})
    sheet = await agent._run_tool('spreadsheet_read', {'path': 'cash.csv', 'op': 'read'})
    assert '50' in sql and 'DENIED' not in sql and 'ERROR' not in sql
    assert 'DENIED' not in sheet and 'ERROR' not in sheet
    assert json.loads(sheet.split('\n', 1)[1].rsplit('\n', 1)[0]) == [['week', 'amount'], ['1', '50']]


@pytest.mark.parametrize(('name', 'args'), [
    ('spreadsheet_read', {'path': 'cash.csv', 'op': 'read'}),
    ('sql_query_read', {'database': 'cash.db', 'query': 'SELECT 1'}),
])
@pytest.mark.asyncio
async def test_read_aliases_keep_parent_denial_and_path_scopes(context, monkeypatch, name, args):
    profile = domain.DomainProfile(name='reader', allow_tools=[name], max_risk='low')
    parent = type('Parent', (), {'capability': Capability(principal='parent',
                                                        deny_tools=frozenset({name}))})()
    cap = domain.domain_capability(profile, parent.capability, 'child')
    assert not cap.permits(name)
    profile.allow_paths = ['permitted/*']
    agent = domain.agent_from_profile(profile, context, 'read')
    monkeypatch.setattr(agent, '_audit_tool_event', lambda *a, **k: True)
    result = await agent._run_tool(name, args)
    assert 'DENIED' in result and 'path' in result.lower()


def test_factory_rejects_contradictory_custom_profile_before_agent_creation(context):
    profile = domain.DomainProfile(name='bad-pack', allow_tools=['spreadsheet'], max_risk='low')
    with pytest.raises(ValueError, match='spreadsheet.*exceeds max_risk'):
        domain.agent_from_profile(profile, context, 'prepare')


def test_registry_aware_validation_rejects_missing_and_denied_names():
    profile = domain.DomainProfile(name='bad', allow_tools=['missing', 'read_file'],
                                   deny_tools=['read_*'], max_risk='high')
    errors = domain.tool_compatibility_errors(profile, {'read_file'}, risk_overrides={})
    assert any('not available' in error for error in errors)
    assert any('denied' in error for error in errors)


def _rate_customer_ledger(monkeypatch):
    """The operator's reviewed rating for the sample adapter ([security.tool_risk])."""
    import importlib
    risk_module = importlib.import_module('maverick.safety.tool_risk')
    monkeypatch.setattr(risk_module, '_load_overrides', lambda: {'customer_ledger': 'medium'})


def test_unrated_adapter_keeps_the_high_floor_under_a_medium_pack():
    profile = domain.DomainProfile(name='p', allow_tools=['customer_ledger'], max_risk='medium')
    errors = domain.tool_compatibility_errors(profile, risk_overrides={})
    assert any("'customer_ledger' (high) exceeds max_risk" in error for error in errors)
    rated = domain.tool_compatibility_errors(profile, risk_overrides={'customer_ledger': 'medium'})
    assert rated == []


def test_required_adapter_refuses_deployment_but_custom_registry_can_provision(context, monkeypatch):
    from maverick.agent import Agent
    _rate_customer_ledger(monkeypatch)
    profile = domain.DomainProfile(name='adapter-pack', allow_tools=['customer_ledger'], max_risk='medium',
                                   workflow=[domain.WorkflowStep('Read ledger', tools=['customer_ledger'])])
    with pytest.raises(ValueError, match='cannot deploy.*customer_ledger.*operator-approved workspace export'):
        domain.agent_from_profile(profile, context, 'read')
    build_tools = Agent._build_tools

    def provisioned(agent):
        registry = build_tools(agent)
        registry.register(tools.Tool(name='customer_ledger', description='Offline test adapter',
                                     input_schema={'type': 'object'}, fn=lambda args: 'ledger rows'))
        return registry

    monkeypatch.setattr(Agent, '_build_tools', provisioned)
    agent = domain.agent_from_profile(profile, context, 'read')
    assert agent.tools.get('customer_ledger').fn({}) == 'ledger rows'
    assert agent.deployment_prerequisites == []


def test_optional_allowlist_seat_reports_prerequisite_without_blocking(context, monkeypatch):
    _rate_customer_ledger(monkeypatch)
    profile = domain.DomainProfile(name='optional', allow_tools=['customer_ledger'], max_risk='medium')
    agent = domain.agent_from_profile(profile, context, 'prepare')
    assert agent.deployment_prerequisites == ['customer_ledger']


@pytest.mark.parametrize(('name', 'required', 'absent'), [
    ('extract-from-document', {'read_pdf', 'ocr', 'read_file'}, 'extract_document'),
    ('redact-pii-before-egress', {'read_file', 'redact'}, 'pii_scan'),
    ('redact-secrets-in-output', {'read_file', 'redact'}, 'secret_scan'),
    ('write-to-audit-trail', {'redact'}, 'audit_append'),
])
def test_corrected_skills_recall_supported_contracts(name, required, absent):
    catalog = skills.load_builtin_skills()
    skill = next(item for item in catalog if item.name == name)
    recalled = skills._relevant_skills_lexical(skill.triggers[0], catalog, max_n=3, min_score=4)
    assert name in {item.name for item in recalled}
    assert set(skill.tools_needed) == required
    assert absent not in skill.body
    if name == 'write-to-audit-trail':
        assert 'no durable audit entry was appended' in skill.body


def test_export_fallback_discloses_missing_live_connector():
    profiles = domain.load_domains(domain.builtin_dir())
    examples = [p for p in profiles.values() if 'Live connectors ' in p.persona]
    assert examples
    for profile in examples:
        assert 'operator-approved export' in profile.persona
        assert 'missing prerequisite' in profile.persona
        assert 'read_file' in profile.allow_tools
        assert not domain.tool_compatibility_errors(profile, risk_overrides={})
