from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent


def _standalone(code: str, tmp_path: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"GRC_STANDALONE": "1", "GRC_STORE": str(tmp_path / "records.json"), "PYTHONPATH": str(HERE)})
    return subprocess.run([sys.executable, "-c", code], cwd=HERE, env=env, text=True, capture_output=True, check=False)


def _auto(code: str, tmp_path: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.pop("GRC_STANDALONE", None)
    core = HERE.parents[1] / "packages" / "maverick-core"
    env.update(
        {
            "GRC_STORE": str(tmp_path / "records.json"),
            "MAVERICK_HOME": str(tmp_path / "maverick-home"),
            "PYTHONPATH": os.pathsep.join((str(HERE), str(core))),
        }
    )
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=HERE,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_forced_standalone_never_imports_maverick(tmp_path):
    code = """
import app, backend, sys
assert backend.STANDALONE is True
assert backend.FORCED_STANDALONE is True
summary = backend.caps_summary()
assert summary['standalone'] is True
assert summary['forced_standalone'] is True
assert summary['vendored_analysis'] is True
assert summary['core_analysis'] is False
assert summary['analysis_backend'] == 'vendored'
assert summary['integrated_governance'] is False
assert summary['authority'] == 'unsigned-local'
assert set(backend.CAPABILITY_BINDINGS) == set(backend.CAPS)
assert all(row['active'] is backend.CAPS[row['id']] for row in summary['capabilities'])
assert not any(x == 'maverick' or x.startswith('maverick.') for x in sys.modules)
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_auto_detection_falls_back_when_core_analysis_is_absent(tmp_path):
    code = """
import importlib.util, os
os.environ.pop('GRC_STANDALONE', None)
real_find_spec = importlib.util.find_spec
importlib.util.find_spec = lambda name: None if name == 'maverick.assessment' else real_find_spec(name)
import capabilities
assert capabilities.FORCED_STANDALONE is False
assert capabilities.CORE_ANALYSIS is False
assert capabilities.STANDALONE is True
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_auto_mode_reuses_core_scoring_without_platform_audit_or_store(tmp_path):
    code = """
import maverick.audit
audit_calls = []
maverick.audit.record = lambda *args, **kwargs: audit_calls.append((args, kwargs))
import backend, sys
assert backend.STANDALONE is False and backend.PLATFORM_ENGINE is True
summary = backend.caps_summary()
assert summary['standalone'] is True
assert summary['forced_standalone'] is False
assert summary['vendored_analysis'] is False
assert summary['core_analysis'] is True
assert summary['analysis_backend'] == 'lightwork-core'
assert summary['integrated_governance'] is False
assert summary['authority'] == 'unsigned-local'
assert set(backend.CAPABILITY_BINDINGS) == set(backend.CAPS)
assert all(row['active'] is backend.CAPS[row['id']] for row in summary['capabilities'])
frameworks = {row['id'] for row in backend.list_frameworks()}
assert {'soc2','iso27001','nist-csf','fedramp_moderate'} <= frameworks
framework = backend.get_framework('soc2')
answers = {control['id']:'unknown' for control in framework['controls']}
result = backend.score_questionnaire('soc2', answers, 'Customer API')
assert result['engine'] == 'lightwork_assessment'
assert result['authority'] == 'unsigned_local_demo'
assert result['posture'].endswith(' risk') and result['findings']
saved = backend.save_record(result, 0)
assert saved['revision'] == 1
from fastapi.testclient import TestClient
page = TestClient(__import__('app').app, base_url='http://127.0.0.1').get('/')
assert page.status_code == 200
assert 'Standalone GRC Concierge (Lightwork core analysis)' in page.text
about = TestClient(__import__('app').app, base_url='http://127.0.0.1').get('/about')
assert 'lightwork-core' in about.text
assert 'unsigned local only' in about.text
assert 'Integrated Lightwork only' in about.text
assert 'FedRAMP' in page.text
assert 'maverick.security_ops' not in sys.modules
assert audit_calls == []
"""
    result = _auto(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_scoring_evidence_and_revision_cas(tmp_path):
    code = """
import json, backend
r = backend.score_questionnaire('soc2', {'CC1':'yes','CC2':'yes','CC6':'no','CC7':'no','CC8':'yes'}, 'Acme')
saved = backend.save_record(r, 0)
quotes = backend.evaluate_evidence('soc2', 'Our access review enforces least privilege every quarter.', 'policy.txt')
try:
    backend.save_record({'type':'risk'}, 0)
except ValueError as exc:
    conflict = 'revision changed' in str(exc)
else:
    conflict = False
print(json.dumps({'posture':r['posture'],'quote':quotes[2]['quote'],'conflict':conflict,'revision':saved['revision']}))
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data == {"posture": "moderate risk", "quote": "Our access review enforces least privilege every quarter.", "conflict": True, "revision": 1}


def test_about_page_discloses_platform_gates(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    code = """
from fastapi.testclient import TestClient
from app import app
r = TestClient(app, base_url='http://127.0.0.1').get('/about')
assert r.status_code == 200
for marker in (
    'tamper-evident', 'Standalone GRC', 'Analysis backend', 'vendored',
    'unsigned local only', 'Capability and authority matrix',
    'Every advertised capability', 'Integrated Lightwork only',
    'grc_engine.create_risk and LocalStore',
):
    assert marker in r.text, marker
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_app_routes_do_not_branch_on_runtime_mode():
    source = (HERE / "app.py").read_text(encoding="utf-8")
    assert "STANDALONE" not in source
    assert "PLATFORM_ENGINE" not in source
    assert "import maverick" not in source


def test_backend_stays_explicitly_local_and_poam_contract_is_stable(tmp_path):
    code = """
import backend, sys
assert backend.STANDALONE is True
assert not any(x == 'maverick.security_ops' for x in sys.modules)
poam = backend.create_poam('Rotate inherited credentials', 'alice', '2027-01-31', 'Inventory accounts')
saved = backend.save_record(poam, 0)
assert saved['type'] == 'poam' and saved['due_date'] == '2027-01-31'
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_http_request_size_depth_and_key_limits(tmp_path):
    code = """
from fastapi.testclient import TestClient
from app import app
client = TestClient(app, base_url='http://127.0.0.1')
huge = b'{"text":"' + (b'x' * (513 * 1024)) + b'"}'
assert client.post('/api/evidence', content=huge, headers={'content-type':'application/json'}).status_code == 413
deep = value = {}
for _ in range(10):
    value['next'] = {}
    value = value['next']
assert client.post('/api/risks', json=deep).status_code == 422
wide = {f'k{i}': i for i in range(65)}
assert client.post('/api/risks', json=wide).status_code == 422
valid = {'finding':'Gap','owner':'alice','due_date':'2027-01-31','milestone':'Fix it','expected_revision':0}
response = client.post('/api/poam', json=valid)
assert response.status_code == 200, response.text
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_workspace_exposes_accessible_guided_intake_without_api_dead_end(tmp_path):
    code = """
from fastapi.testclient import TestClient
from app import app
response = TestClient(app, base_url='http://127.0.0.1').get('/')
assert response.status_code == 200
text = response.text
for marker in (
    'id="assessment-form"', 'id="evidence-form"', 'id="risk-form"',
    'id="poam-form"', 'id="handoff-form"', 'aria-live="polite"',
    'GRC platform A', 'GRC platform B', 'GRC platform C', 'external/manual',
        'No delivery occurs', 'no chat model, voice service',
        'id="vendor-form"', 'id="review-queue"', 'Measured local workflow timing',
        'local mock tenant', 'field records whether it was new',
):
    assert marker.lower() in text.lower(), marker
assert 'Use the JSON API' not in text
assert 'CC1' in text and 'A.5.1' in text and 'GV.OC' in text
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_guided_api_workflow_and_mock_handoff_never_deliver(tmp_path):
    code = """
import socket
from fastapi.testclient import TestClient
from app import app

client = TestClient(app, base_url='http://127.0.0.1')
client.__enter__()
assessment = client.post('/api/assessments', json={
    'framework':'soc2', 'subject':'Customer API',
    'answers':{'CC1':'yes','CC2':'yes','CC6':'no','CC7':'yes','CC8':'yes'},
    'expected_revision':0,
})
assert assessment.status_code == 200, assessment.text
evidence = client.post('/api/evidence', json={
    'framework':'soc2', 'source':'access-policy.txt',
    'text':'Quarterly access review enforces least privilege.',
})
assert evidence.status_code == 200 and evidence.json()['verdicts'][2]['quote']
risk = client.post('/api/risks', json={
    'title':'Inherited credentials', 'owner':'alice', 'likelihood':3,
    'impact':5, 'treatment':'mitigate', 'expected_revision':1,
})
assert risk.status_code == 200, risk.text
poam = client.post('/api/poam', json={
    'finding':'Rotate inherited credentials', 'owner':'alice',
    'due_date':'2027-01-31', 'milestone':'Inventory accounts',
    'expected_revision':2,
})
assert poam.status_code == 200, poam.text

def no_network(*args, **kwargs):
    raise AssertionError('mock handoff attempted a network connection')
original_connect = socket.socket.connect
socket.socket.connect = no_network
handoff = client.post('/api/handoffs/mock', json={
    'record_id':risk.json()['id'], 'destination':'grc_platform_a',
    'prepared_by':'reviewer', 'note':'Import manually after approval',
    'expected_revision':3,
})
socket.socket.connect = original_connect
assert handoff.status_code == 200, handoff.text
data = handoff.json()
receipt = data['receipt']
assert receipt['type'] == 'mock_handoff_receipt'
assert receipt['destination_label'] == 'GRC platform A'
assert receipt['network_call_made'] is False
assert receipt['delivery_status'] == 'not_sent_mock_only'
assert receipt['approval_authority'] == 'local_mock_reviewer_only'
assert receipt['manual_approval_required'] is True
assert receipt['status'] == 'pending_human_review'
assert len(receipt['source_record_sha256']) == 64
assert 'no network delivery or approval occurred' in data['warning']

decision = client.post(f"/api/handoffs/mock/{receipt['id']}/decision", json={
    'decision':'approve', 'reviewer':'tenant reviewer',
    'rationale':'Ready for a separate manual import', 'expected_revision':4,
})
assert decision.status_code == 200, decision.text
decided = decision.json()['receipt']
assert decided['status'] == 'mock_approved'
assert decided['decision'] == 'approve'
assert decided['reviewer'] == 'tenant reviewer'
assert decided['network_call_made'] is False
assert decided['delivery_status'] == 'not_sent_mock_only'
assert decision.json()['speed_story']['receipts_reviewed'] == 1
assert 'Local mock decision only' in decision.json()['warning']

invalid = client.post('/api/handoffs/mock', json={
    'record_id':assessment.json()['id'], 'destination':'unknown',
    'prepared_by':'reviewer', 'expected_revision':5,
})
assert invalid.status_code == 422
missing = client.post('/api/handoffs/mock', json={
    'record_id':'missing', 'destination':'grc_platform_b',
    'prepared_by':'reviewer', 'expected_revision':5,
})
assert missing.status_code == 404
receipt_source = client.post('/api/handoffs/mock', json={
    'record_id':receipt['id'], 'destination':'grc_platform_c',
    'prepared_by':'reviewer', 'expected_revision':5,
})
assert receipt_source.status_code == 422
client.__exit__(None, None, None)
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_vendor_carry_forward_mock_review_and_measured_speed_story(tmp_path):
    code = """
import socket
from fastapi.testclient import TestClient
from app import app

client = TestClient(app, base_url='http://127.0.0.1')
client.__enter__()
first = client.post('/api/vendors', json={
    'vendor':'Acme Cloud', 'owner':'alice', 'expected_revision':0,
    'answers':{
        'data_encryption':'yes', 'mfa':'yes', 'incident_response':'yes',
        'vulnerability_management':'unknown', 'business_continuity':'yes',
    },
})
assert first.status_code == 200, first.text
second = client.post('/api/vendors', json={
    'vendor':'Acme Cloud', 'owner':'bob', 'expected_revision':1,
    'carry_forward_from':first.json()['id'], 'answers':{'mfa':'no'},
})
assert second.status_code == 200, second.text
vendor = second.json()
assert vendor['answers']['mfa'] == 'no'
assert vendor['answers']['data_encryption'] == 'yes'
assert vendor['answer_provenance']['mfa'] == 'new'
assert vendor['answer_provenance']['data_encryption'] == 'carried_forward'
assert vendor['carried_field_count'] == 4

cross_vendor = client.post('/api/vendors', json={
    'vendor':'Different Vendor', 'owner':'bob', 'expected_revision':2,
    'carry_forward_from':first.json()['id'], 'answers':{},
})
assert cross_vendor.status_code == 422
unknown_source = client.post('/api/vendors', json={
    'vendor':'Acme Cloud', 'owner':'bob', 'expected_revision':2,
    'carry_forward_from':'missing', 'answers':{},
})
assert unknown_source.status_code == 404

def no_network(*args, **kwargs):
    raise AssertionError('local mock workflow attempted a network connection')
original_connect = socket.socket.connect
socket.socket.connect = no_network
handoff = client.post('/api/handoffs/mock', json={
    'record_id':vendor['id'], 'destination':'grc_platform_c',
    'prepared_by':'bob', 'expected_revision':2,
})
assert handoff.status_code == 200, handoff.text
receipt = handoff.json()['receipt']
missing_cas = client.post(f"/api/handoffs/mock/{receipt['id']}/decision", json={
    'decision':'reject', 'reviewer':'carol',
})
assert missing_cas.status_code == 422
decision = client.post(f"/api/handoffs/mock/{receipt['id']}/decision", json={
    'decision':'reject', 'reviewer':'carol', 'rationale':'Needs current evidence',
    'expected_revision':3,
})
socket.socket.connect = original_connect
assert decision.status_code == 200, decision.text
decided = decision.json()['receipt']
assert decided['status'] == 'mock_rejected'
assert decided['review_seconds'] >= 0
assert decided['network_call_made'] is False
assert decided['delivery_status'] == 'not_sent_mock_only'
story = decision.json()['speed_story']
assert story['receipts_prepared'] == 1
assert story['receipts_reviewed'] == 1
assert story['pending_reviews'] == 0
assert story['average_prepare_seconds'] is not None
assert story['average_review_seconds'] is not None
queue = client.get('/api/handoffs/mock/queue')
assert queue.status_code == 200
assert queue.json()['pending'] == [] and len(queue.json()['reviewed']) == 1
repeat = client.post(f"/api/handoffs/mock/{receipt['id']}/decision", json={
    'decision':'approve', 'reviewer':'dave', 'expected_revision':4,
})
assert repeat.status_code == 422
client.__exit__(None, None, None)
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_mutations_require_strict_cas_and_reject_browser_cross_origin(tmp_path):
    code = """
from fastapi.testclient import TestClient
from app import app

client = TestClient(app, base_url='http://127.0.0.1')
body = {'title':'Forged risk','owner':'mallory','likelihood':1,'impact':1,'treatment':'accept'}
assert client.post('/api/risks', json=body).status_code == 422
assert client.post('/api/risks', json={**body,'expected_revision':False}).status_code == 422
assert client.post('/api/risks', json={**body,'likelihood':True,'expected_revision':0}).status_code == 422
assert client.post('/api/risks', json={**body,'raw_payload':{'secret':'x'},'expected_revision':0}).status_code == 422
assert client.post('/api/assessments', json={
    'framework':'soc2', 'subject':'Scope', 'answers':{'untrusted_nested':{'x':1}},
    'expected_revision':0,
}).status_code == 422
plain = client.post('/api/risks', content=__import__('json').dumps({**body,'expected_revision':0}), headers={'Content-Type':'text/plain'})
assert plain.status_code == 415
hostile = client.post('/api/risks', json={**body,'expected_revision':0}, headers={'Origin':'https://evil.example'})
assert hostile.status_code == 403
assert client.get('/', headers={'Host':'evil.example'}).status_code == 400
valid = client.post('/api/risks', json={**body,'expected_revision':0}, headers={'Origin':'http://127.0.0.1'})
assert valid.status_code == 200, valid.text
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_store_cas_is_cross_instance_safe(tmp_path):
    code = """
import json, os, threading
from pathlib import Path
from grc_engine import LocalStore

path = Path(os.environ['GRC_STORE'])
stores = (LocalStore(path), LocalStore(path))
barrier = threading.Barrier(2)
results = []

def save(store, record_id):
    barrier.wait()
    try:
        store.save({'id':record_id,'type':'risk'}, 0)
        results.append('saved')
    except ValueError as exc:
        assert 'revision changed' in str(exc)
        results.append('conflict')

threads = [threading.Thread(target=save,args=(store,record_id)) for store,record_id in zip(stores,('one','two'))]
for thread in threads: thread.start()
for thread in threads: thread.join()
state = json.loads(path.read_text(encoding='utf-8'))
assert sorted(results) == ['conflict','saved']
assert state['revision'] == 1 and len(state['records']) == 1

record = state['records'][0]
barrier = threading.Barrier(2)
replacements = []
def replace(store, reviewer):
    barrier.wait()
    try:
        store.replace(record['id'], {**record,'reviewer':reviewer}, 1)
        replacements.append('replaced')
    except ValueError as exc:
        assert 'revision changed' in str(exc)
        replacements.append('conflict')

threads = [threading.Thread(target=replace,args=(store,reviewer)) for store,reviewer in zip(stores,('alice','bob'))]
for thread in threads: thread.start()
for thread in threads: thread.join()
state = json.loads(path.read_text(encoding='utf-8'))
assert sorted(replacements) == ['conflict','replaced']
assert state['revision'] == 2 and len(state['records']) == 1
assert state['records'][0]['reviewer'] in {'alice','bob'}
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_headerless_stream_stops_before_buffering_oversized_body(tmp_path):
    code = """
import asyncio
from starlette.requests import Request
from request_limits import MAX_REQUEST_BYTES, PayloadError, read_bounded_json

chunks = [b'{' + b'x' * 300000, b'y' * 300000, b'never-read']
calls = 0
async def receive():
    global calls
    chunk = chunks[calls]
    calls += 1
    return {'type':'http.request','body':chunk,'more_body':calls < len(chunks)}

scope = {'type':'http','method':'POST','scheme':'http','path':'/api/risks','query_string':b'',
         'headers':[(b'host',b'127.0.0.1'),(b'content-type',b'application/json')],
         'server':('127.0.0.1',80),'client':('127.0.0.1',1234)}
try:
    asyncio.run(read_bounded_json(Request(scope, receive)))
except PayloadError as exc:
    assert exc.status_code == 413
else:
    raise AssertionError('oversized streamed request was accepted')
assert calls == 2
assert MAX_REQUEST_BYTES < 600000
"""
    result = _standalone(code, tmp_path)
    assert result.returncode == 0, result.stderr
