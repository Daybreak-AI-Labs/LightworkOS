from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def _run(code: str, tmp_path: Path):
    env = os.environ.copy()
    env.update(
        {
            "MODEL_RISK_OFFICER_STANDALONE": "1",
            "MODEL_RISK_OFFICER_STORE": str(tmp_path / "records.json"),
            "PYTHONPATH": str(HERE),
        }
    )
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=HERE,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_forced_standalone_blocks_every_maverick_import(tmp_path):
    code = r"""
import importlib.abc
import sys

class BlockMaverick(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'maverick' or fullname.startswith('maverick.'):
            raise AssertionError(f'forbidden import attempted: {fullname}')
        return None

sys.meta_path.insert(0, BlockMaverick())
import app, assurance_engine, backend
assert backend.STANDALONE is True
assert backend.FORCED_STANDALONE is True
summary = backend.caps_summary()
assert summary['analysis_backend'] == 'vendored-deterministic-rules'
assert summary['authority'] == 'unsigned-local-advisory-only'
assert summary['legal_applicability_default'] == 'undetermined'
assert summary['certification'] is False
assert summary['dgm_execution'] is False
assert set(backend.CAPABILITY_BINDINGS) == set(backend.CAPS)
assert all(row['active'] is backend.CAPS[row['id']] for row in summary['capabilities'])
assert not any(name == 'maverick' or name.startswith('maverick.') for name in sys.modules)
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_deterministic_inventory_classification_and_gap_analysis(tmp_path):
    code = r"""
import assurance_engine as engine

snapshot = {
  'assets': [
    {
      'id': 'model-1', 'asset_type': 'model', 'name': 'Decision model',
      'owner': '', 'criticality': 'critical', 'lifecycle': 'production',
      'version': 'v2', 'intended_use': '', 'data_classification': 'restricted',
      'eu_use_case': 'employment', 'third_party': True,
      'provider_ref': 'provider-1', 'lineage_refs': [],
    },
    {
      'id': 'provider-1', 'asset_type': 'provider', 'name': 'Model provider',
      'owner': 'vendor-risk', 'criticality': 'high', 'lifecycle': 'production',
      'version': 'service-1', 'intended_use': 'Model hosting',
      'data_classification': 'confidential', 'eu_use_case': 'general',
      'third_party': True,
      'legal_applicability': {
        'status': 'in_scope', 'asserted_by': 'counsel',
        'asserted_at': '2026-07-01T00:00:00Z', 'rationale': 'Recorded review',
        'basis_version': 'Regulation-EU-2024-1689-reviewed-2026-07-01',
      },
    },
  ],
  'evaluations': [{
    'id': 'eval-1', 'asset_ref': 'model-1', 'evaluation_type': 'red_team',
    'conducted_at': '2026-01-01T00:00:00Z', 'outcome': 'fail',
    'evaluator': 'assurance', 'evidence_ref': 'evidence://eval-1',
    'scope_version': 'v1',
  }],
  'changes': [{
    'id': 'change-1', 'asset_ref': 'model-1',
    'changed_at': '2026-07-15T00:00:00Z', 'change_type': 'model',
    'approved': False, 'version_after': 'v2',
    'evidence_ref': 'change://change-1',
  }],
  'drift_signals': [{
    'id': 'drift-1', 'asset_ref': 'model-1',
    'observed_at': '2026-07-20T00:00:00Z', 'status': 'breach',
    'metric': 'quality-band', 'evidence_ref': 'metric://drift-1',
  }],
  'incidents': [{
    'id': 'incident-1', 'asset_ref': 'model-1',
    'occurred_at': '2026-07-19T00:00:00Z', 'severity': 'high',
    'status': 'open', 'title': 'Unsafe outcome',
    'evidence_ref': 'incident://incident-1',
  }],
  'third_party_assessments': [{
    'id': 'third-party-1', 'asset_ref': 'provider-1',
    'assessed_at': '2026-01-01T00:00:00Z', 'status': 'incomplete',
    'assessor': 'vendor-risk', 'contract_controls': False, 'exit_plan': False,
    'evidence_ref': 'vendor://assessment-1',
  }],
}
first = engine.analyze_snapshot(snapshot, now='2026-07-21T00:00:00Z', freshness_days=90)
second = engine.analyze_snapshot(snapshot, now='2026-07-21T00:00:00Z', freshness_days=90)
assert first == second
assert first['id'] == second['id']
assert first['certification'] is False and first['advisory_only'] is True
assert first['legal_applicability_automation'] is False
classification = next(row for row in first['classifications'] if row['asset_ref'] == 'model-1')
assert classification['level'] == 'critical'
assert classification['classification_type'] == 'operational-triage-not-legal'
assert classification['legal_applicability']['status'] == 'undetermined'
kinds = {row['finding_type'] for row in first['findings']}
assert {
  'unowned-asset', 'missing-intended-use', 'legal-applicability-undetermined',
  'missing-lineage', 'failed-evaluation', 'stale-or-invalidated-evidence',
  'missing-current-red-team', 'unapproved-change', 'drift-breach',
  'open-incident', 'third-party-assurance-gap', 'third-party-resilience-gap',
} <= kinds
for finding in first['findings']:
    assert finding['framework_refs'] and finding['evidence_ids']
    assert all(ref['advisory'] is True for ref in finding['framework_refs'])
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_human_review_and_clean_dgm_readiness_report_never_execute(tmp_path):
    code = r"""
import backend

legal = {
  'status': 'in_scope', 'asserted_by': 'qualified-reviewer',
  'asserted_at': '2026-07-20T00:00:00Z',
  'rationale': 'Current human review recorded for this use.',
  'basis_version': 'legal-review-2026-07-20',
}
snapshot = {
  'assets': [
    {
      'id': 'provider-1', 'asset_type': 'provider', 'name': 'Provider',
      'owner': 'vendor-risk', 'criticality': 'moderate', 'lifecycle': 'testing',
      'version': '1', 'intended_use': 'Upstream service',
      'data_classification': 'internal', 'eu_use_case': 'general',
      'third_party': True,
    },
    {
      'id': 'dataset-1', 'asset_type': 'dataset', 'name': 'Evaluation data',
      'owner': 'data-owner', 'criticality': 'moderate', 'lifecycle': 'testing',
      'version': '1', 'intended_use': 'Evaluation only',
      'data_classification': 'internal', 'eu_use_case': 'general',
      'third_party': False, 'lineage_refs': ['provider-1'],
    },
    {
      'id': 'model-1', 'asset_type': 'model', 'name': 'Candidate model',
      'owner': 'model-owner', 'criticality': 'high', 'lifecycle': 'production',
      'version': 'candidate-7', 'intended_use': 'Bounded assistance',
      'data_classification': 'internal', 'eu_use_case': 'general',
      'third_party': False, 'lineage_refs': ['dataset-1'],
      'dataset_refs': ['dataset-1'], 'legal_applicability': legal,
    },
  ],
  'evaluations': [
    {'id': f'eval-{kind}', 'asset_ref': 'model-1', 'evaluation_type': kind,
     'conducted_at': '2026-07-20T12:00:00Z', 'outcome': 'pass',
     'evaluator': 'independent-assurance', 'evidence_ref': f'evidence://{kind}',
     'scope_version': 'candidate-7'}
    for kind in ('performance', 'safety', 'security', 'red_team')
  ],
  'changes': [{
    'id': 'change-1', 'asset_ref': 'model-1',
    'changed_at': '2026-07-19T00:00:00Z', 'change_type': 'model',
    'approved': True, 'approver': 'change-board', 'version_after': 'candidate-7',
    'evidence_ref': 'change://candidate-7',
  }],
  'drift_signals': [{
    'id': 'drift-1', 'asset_ref': 'model-1',
    'observed_at': '2026-07-20T13:00:00Z', 'status': 'within_threshold',
    'metric': 'holdout-band', 'evidence_ref': 'metric://holdout-band',
  }],
  'incidents': [],
  'third_party_assessments': [{
    'id': 'provider-review', 'asset_ref': 'provider-1',
    'assessed_at': '2026-07-20T00:00:00Z', 'status': 'satisfactory',
    'assessor': 'vendor-risk', 'contract_controls': True, 'exit_plan': True,
    'evidence_ref': 'vendor://provider-review',
  }],
}
assessment = backend.create_assessment(snapshot, 0, now='2026-07-21T00:00:00Z')
assert not [row for row in assessment['findings'] if row['asset_ref'] == 'model-1']
reviewed = backend.review_assessment(
  assessment['id'], 'approved', 'assurance-board', 'Evidence reviewed.',
  '2026-07-21T01:00:00Z', 1,
)
assert reviewed['review']['status'] == 'approved'
report = backend.create_dgm_readiness_report(
  assessment['id'], 'model-1', 'candidate-7', '7.0.0', 'release-reviewer',
  '2026-07-21T02:00:00Z', 2,
)
assert report['ready_for_human_promotion_decision'] is True
assert report['blockers'] == []
for key in ('promotion_executed', 'deployment_executed', 'rollback_executed', 'external_effects', 'certification'):
    assert report[key] is False
assert backend.current_revision() == 3
assert [row['type'] for row in backend.list_records()] == [
  'assurance_assessment', 'dgm_readiness_report'
]
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_risk_acceptance_is_bounded_does_not_close_and_cannot_override_safety_blockers(tmp_path):
    code = r"""
import backend

snapshot = {
  'assets': [{
    'id': 'model-1', 'asset_type': 'model', 'name': 'Candidate',
    'owner': 'owner', 'criticality': 'high', 'lifecycle': 'production',
    'version': '1', 'intended_use': 'Assistance', 'data_classification': 'internal',
    'eu_use_case': 'general', 'third_party': False, 'lineage_refs': [],
    'legal_applicability': {'status': 'in_scope', 'asserted_by': 'reviewer',
      'asserted_at': '2026-07-20T00:00:00Z', 'rationale': 'Human review',
      'basis_version': 'review-v1'},
  }],
  'evaluations': [{
    'id': 'eval-1', 'asset_ref': 'model-1', 'evaluation_type': 'security',
    'conducted_at': '2026-07-20T00:00:00Z', 'outcome': 'fail',
    'evaluator': 'assurance', 'evidence_ref': 'evidence://security',
    'scope_version': '1',
  }],
  'changes': [], 'drift_signals': [{'id':'d1','asset_ref':'model-1',
    'observed_at':'2026-07-20T00:00:00Z','status':'within_threshold',
    'metric':'band','evidence_ref':'metric://band'}],
  'incidents': [], 'third_party_assessments': [],
}
assessment = backend.create_assessment(snapshot, 0, now='2026-07-21T00:00:00Z')
failure = next(row for row in assessment['findings'] if row['finding_type'] == 'failed-evaluation')
reviewed = backend.review_assessment(assessment['id'], 'approved', 'board', 'Reviewed.', '2026-07-21T01:00:00Z', 1)
acceptance = backend.create_risk_acceptance(
  reviewed['id'], failure['id'], 'accepted', 'risk-owner', 'Temporary exception.',
  '2026-07-30T00:00:00Z', '2026-07-21T01:30:00Z', 2,
)
assert acceptance['closes_finding'] is False
assert next(row for row in backend.list_records() if row['type'] == 'assurance_assessment')['findings']
report = backend.create_dgm_readiness_report(
  reviewed['id'], 'model-1', 'candidate-1', '1', 'reviewer',
  '2026-07-21T02:00:00Z', 3,
)
assert report['ready_for_human_promotion_decision'] is False
blocker = next(row for row in report['blockers'] if row.get('finding_type') == 'failed-evaluation')
assert blocker['risk_acceptance_considered'] is True
assert blocker['acceptance_can_override'] is False
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_api_rejects_sensitive_content_and_future_evidence(tmp_path):
    code = r"""
from fastapi.testclient import TestClient
from app import app

client = TestClient(app, base_url='http://127.0.0.1')
base = {
  'snapshot': {'assets': [{
    'id':'m1','asset_type':'model','name':'Model','owner':'owner',
    'criticality':'moderate','lifecycle':'testing','version':'1',
    'intended_use':'test','data_classification':'internal','eu_use_case':'general',
    'third_party':False,'lineage_refs':[],
  }], 'evaluations':[], 'changes':[], 'drift_signals':[], 'incidents':[],
  'third_party_assessments':[]},
  'expected_revision': 0, 'now':'2026-07-21T00:00:00Z',
}
accepted = client.post('/api/assessments', json=base)
assert accepted.status_code == 200, accepted.text
assert accepted.json()['certification'] is False
for key in ('credentials','access_token','prompt','messages','tool_arguments',
            'tool_results','raw_telemetry','request_body','api_key','private_key'):
    hostile = dict(base)
    hostile['expected_revision'] = 1
    hostile['snapshot'] = dict(base['snapshot'])
    hostile['snapshot']['assets'] = [dict(base['snapshot']['assets'][0])]
    hostile['snapshot']['assets'][0][key] = 'not-stored'
    response = client.post('/api/assessments', json=hostile)
    assert response.status_code == 422, (key, response.text)
    assert 'not accepted' in response.text, (key, response.text)
future = dict(base)
future['expected_revision'] = 1
future['snapshot'] = dict(base['snapshot'])
future['snapshot']['evaluations'] = [{
  'id':'e1','asset_ref':'m1','evaluation_type':'safety',
  'conducted_at':'2026-07-22T00:00:00Z','outcome':'pass','evaluator':'a',
  'evidence_ref':'evidence://e1','scope_version':'1'}]
response = client.post('/api/assessments', json=future)
assert response.status_code == 422 and 'future' in response.text
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_http_boundaries_revision_conflict_and_no_effect_routes(tmp_path):
    code = r"""
import json
from fastapi.testclient import TestClient
from app import app

client = TestClient(app, base_url='http://127.0.0.1')
valid = {'snapshot': {'assets': [{
  'id':'m1','asset_type':'model','name':'M','owner':'o','criticality':'low',
  'lifecycle':'development','version':'1','intended_use':'test',
  'data_classification':'public','eu_use_case':'general','third_party':False,
  'lineage_refs':[]}], 'evaluations':[], 'changes':[], 'drift_signals':[],
  'incidents':[], 'third_party_assessments':[]}, 'expected_revision':0,
  'now':'2026-07-21T00:00:00Z'}
assert client.post('/api/assessments', json={k:v for k,v in valid.items() if k != 'expected_revision'}).status_code == 422
assert client.post('/api/assessments', json={**valid, 'expected_revision':False}).status_code == 422
assert client.post('/api/assessments', content=json.dumps(valid), headers={'Content-Type':'text/plain'}).status_code == 415
assert client.post('/api/assessments', json=valid, headers={'Origin':'https://evil.example'}).status_code == 403
assert client.get('/', headers={'Host':'evil.example'}).status_code == 400
accepted = client.post('/api/assessments', json=valid, headers={'Origin':'http://127.0.0.1'})
assert accepted.status_code == 200, accepted.text
assert client.post('/api/assessments', json=valid).status_code == 409
huge = b'{"snapshot":{},"expected_revision":1,"padding":"' + b'x' * (769 * 1024) + b'"}'
assert client.post('/api/assessments', content=huge, headers={'content-type':'application/json'}).status_code == 413
for path in ('/api/discover','/api/certify','/api/dgm/promote','/api/dgm/deploy',
             '/api/dgm/rollback','/api/connectors','/api/policy/mutate'):
    assert client.post(path, json={}).status_code == 404, path
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_about_framework_metadata_and_browser_surface_are_explicit(tmp_path):
    code = r"""
from fastapi.testclient import TestClient
from app import app

client = TestClient(app, base_url='http://127.0.0.1')
response = client.get('/about')
assert response.status_code == 200
text = response.text
for marker in (
  'Capability and authority matrix', 'vendored-deterministic-rules',
  'unsigned-local-advisory-only', 'No certification, legal verdict, or DGM execution',
  'default to', 'undetermined', 'NIST AI Risk Management Framework',
  'ISO/IEC 42001', 'Regulation (EU) 2024/1689', 'hardcodes no compliance deadline',
  'report-only-no-promotion-authority', 'Integrated Lightwork only / prohibited',
):
    assert marker in text, marker
assert response.headers['x-frame-options'] == 'DENY'
assert response.headers['x-content-type-options'] == 'nosniff'
assert response.headers['referrer-policy'] == 'no-referrer'
assert response.headers['cache-control'] == 'no-store'
csp = response.headers['content-security-policy']
assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
assert client.get('/docs').status_code == 404
assert client.get('/redoc').status_code == 404
assert client.get('/openapi.json').status_code == 404
frameworks = client.get('/api/frameworks').json()
assert frameworks['certification'] is False and frameworks['legal_verdict'] is False
assert {row['id'] for row in frameworks['frameworks']} == {
  'nist-ai-rmf-1.0','iso-iec-42001-2023','eu-ai-act-2024-1689'}
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_legal_applicability_is_human_asserted_or_undetermined(tmp_path):
    code = r"""
import assurance_engine as engine

base = {'assets':[{'id':'m','asset_type':'model','name':'M','owner':'o',
  'criticality':'moderate','lifecycle':'production','version':'1',
  'intended_use':'test','data_classification':'internal','eu_use_case':'biometric',
  'third_party':False,'lineage_refs':[]}], 'evaluations':[], 'changes':[],
  'drift_signals':[], 'incidents':[], 'third_party_assessments':[]}
report = engine.analyze_snapshot(base, now='2026-07-21T00:00:00Z')
classification = report['classifications'][0]
assert classification['legal_applicability']['status'] == 'undetermined'
assert classification['automatic_legal_verdict'] is False
assert any(row['finding_type'] == 'legal-applicability-undetermined' for row in report['findings'])
hostile = {**base, 'assets':[dict(base['assets'][0])]}
hostile['assets'][0]['legal_applicability'] = {'status':'in_scope'}
try:
    engine.analyze_snapshot(hostile, now='2026-07-21T00:00:00Z')
except ValueError as exc:
    assert 'asserted_by' in str(exc)
else:
    raise AssertionError('unattributed legal assertion accepted')
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_store_cas_is_cross_instance_safe(tmp_path):
    code = r"""
import json
import os
import threading
from pathlib import Path
from assurance_engine import LocalStore

path = Path(os.environ['MODEL_RISK_OFFICER_STORE'])
stores = (LocalStore(path), LocalStore(path))
record = {'type':'test_record','value':'bounded'}
barrier = threading.Barrier(2)
results = []

def save(store):
    barrier.wait()
    try:
        store.save(record, 0)
        results.append('saved')
    except ValueError as exc:
        assert 'revision changed' in str(exc)
        results.append('conflict')

threads = [threading.Thread(target=save, args=(store,)) for store in stores]
for thread in threads: thread.start()
for thread in threads: thread.join()
state = json.loads(path.read_text(encoding='utf-8'))
assert sorted(results) == ['conflict','saved']
assert state['revision'] == 1 and len(state['records']) == 1
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_headerless_stream_stops_before_buffering_oversized_body(tmp_path):
    code = r"""
import asyncio
from starlette.requests import Request
from request_limits import PayloadError, read_bounded_json

chunks = [b'{' + b'x' * 500000, b'y' * 500000, b'never-read']
calls = 0
async def receive():
    global calls
    chunk = chunks[calls]; calls += 1
    return {'type':'http.request','body':chunk,'more_body':calls < len(chunks)}
scope = {'type':'http','method':'POST','scheme':'http','path':'/api/assessments',
  'query_string':b'', 'headers':[(b'host',b'127.0.0.1'),
  (b'content-type',b'application/json')], 'server':('127.0.0.1',80),
  'client':('127.0.0.1',1234)}
try:
    asyncio.run(read_bounded_json(Request(scope, receive)))
except PayloadError as exc:
    assert exc.status_code == 413
else:
    raise AssertionError('oversized streamed request was accepted')
assert calls == 2
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_app_and_engine_preserve_standalone_boundary():
    app_source = (HERE / "app.py").read_text(encoding="utf-8")
    engine_source = (HERE / "assurance_engine.py").read_text(encoding="utf-8")
    backend_source = (HERE / "backend.py").read_text(encoding="utf-8")
    for source in (app_source, engine_source, backend_source):
        assert "import maverick" not in source
        assert "from maverick" not in source
    assert "/api/dgm/promote" not in app_source
    assert "/api/dgm/deploy" not in app_source
