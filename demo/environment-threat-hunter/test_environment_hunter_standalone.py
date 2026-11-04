from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def _run(code: str, tmp_path: Path, **extra):
    env = os.environ.copy()
    env.update({"ENV_HUNTER_STANDALONE": "1", "ENV_HUNTER_STORE": str(tmp_path / "derived.json"), "PYTHONPATH": str(HERE), **extra})
    return subprocess.run([sys.executable, "-c", code], cwd=HERE, env=env, capture_output=True, text=True, check=False)


def _auto(code: str, tmp_path: Path):
    env = os.environ.copy()
    env.pop("ENV_HUNTER_STANDALONE", None)
    core = HERE.parents[1] / "packages" / "maverick-core"
    env.update(
        {
            "ENV_HUNTER_STORE": str(tmp_path / "derived.json"),
            "MAVERICK_HOME": str(tmp_path / "maverick-home"),
            "PYTHONPATH": os.pathsep.join((str(HERE), str(core))),
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
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_auto_detection_falls_back_when_core_analysis_is_absent(tmp_path):
    code = """
import importlib.util, os
os.environ.pop('ENV_HUNTER_STANDALONE', None)
real_find_spec = importlib.util.find_spec
importlib.util.find_spec = lambda name: None if name == 'maverick.env_hunt' else real_find_spec(name)
import capabilities
assert capabilities.FORCED_STANDALONE is False
assert capabilities.CORE_ANALYSIS is False
assert capabilities.STANDALONE is True
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_generic_ingestion_sigma_and_raw_event_boundary(tmp_path):
    code = """
import json, backend
events=backend.ingest('syslog','Jan 1 host sshd: Failed password for root')
sigma=[{'id':'custom-1','title':'Root login marker','level':'high','tags':['attack.t1078'],'detection':{'selection':{'message|contains':'root'}}}]
findings=backend.detect(events,sigma)
saved=backend.save_derived(findings,0)
try:
    backend.save_derived([{'type':'raw_event','message':'secret'}], len(saved))
except ValueError:
    blocked=True
else:
    blocked=False
print(json.dumps({'rules':sorted(x['rule_id'] for x in findings),'blocked':blocked,'raw':any('raw_event' in x for x in saved)}))
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["rules"] == ["linux-auth-failure", "sigma:custom-1"]
    assert data["blocked"] is True
    assert data["raw"] is False


def test_response_is_proposal_only_and_disclosed(tmp_path):
    code = """
from fastapi.testclient import TestClient
from app import app
import backend
client=TestClient(app, base_url='http://127.0.0.1')
ingested=client.post('/api/ingest',json={'source_type':'syslog','payload':'host sshd: Failed password for root','expected_revision':0})
assert ingested.status_code==200, ingested.text
finding=ingested.json()['findings'][0]
opened=client.post('/api/investigations',json={'finding_id':finding['id'],'expected_revision':1})
assert opened.status_code==200, opened.text
proposal=client.post('/api/responses/propose',json={'investigation_id':opened.json()['id'],'action':'isolate_host','target':'host-1','expected_revision':2})
assert proposal.status_code==200, proposal.text
assert len(proposal.json()['digest'])==64
assert client.post('/api/responses/deliver',json={'proposal':proposal.json(),'approved_by':'alice'}).status_code==404
assert not hasattr(backend,'deliver_response')
text=client.get('/about').text
assert 'proposal-only' in text and 'no delivery endpoint' in text
for marker in (
    'Analysis backend', 'vendored', 'unsigned local only',
    'Capability and authority matrix', 'Every advertised capability',
    'Integrated Lightwork only', 'env_engine.detect vendored detector',
):
    assert marker in text, marker
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_app_routes_do_not_branch_on_runtime_mode():
    source = (HERE / "app.py").read_text(encoding="utf-8")
    assert "STANDALONE" not in source
    assert "PLATFORM_ENGINE" not in source
    assert "import maverick" not in source


def test_investigation_uses_stored_ids_and_rejects_nested_raw_fields(tmp_path):
    code = """
from fastapi.testclient import TestClient
from app import app
import backend
client=TestClient(app, base_url='http://127.0.0.1')
ingested=client.post('/api/ingest',json={'source_type':'syslog','payload':'host sshd: Failed password for root','expected_revision':0})
finding=ingested.json()['findings'][0]
assert client.post('/api/investigations',json={'finding':finding,'expected_revision':1}).status_code==422
for key in ('raw','raw_event','raw_events','raw_payload','raw_telemetry'):
    body={'finding_id':finding['id'],'context':{'nested':{key:{'secret':'value'}}},'expected_revision':1}
    response=client.post('/api/investigations',json=body)
    assert response.status_code==422, (key,response.text)
try:
    backend.save_derived([{**finding,'evidence':{**finding['evidence'],'nested':{'raw_telemetry':'secret'}}}], 1)
except ValueError:
    pass
else:
    raise AssertionError('nested raw field reached the derived store')
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_http_request_depth_and_per_event_limits(tmp_path):
    code = """
from fastapi.testclient import TestClient
from app import app
client=TestClient(app, base_url='http://127.0.0.1')
huge=b'{"source_type":"json","payload":[],"padding":"'+(b'x'*(513*1024))+b'"}'
assert client.post('/api/ingest',content=huge,headers={'content-type':'application/json'}).status_code==413
deep=value={}
for _ in range(10):
    value['next']={}
    value=value['next']
assert client.post('/api/ingest',json={'source_type':'json','payload':[deep]}).status_code==422
wide={'id':'wide',**{f'k{i}':i for i in range(64)}}
assert client.post('/api/ingest',json={'source_type':'json','payload':[wide]}).status_code==422
large={'id':'large','message':'x'*(33*1024)}
assert client.post('/api/ingest',json={'source_type':'json','payload':[large]}).status_code==422
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_platform_adapter_uses_governed_detection_and_proposal_contract(tmp_path):
    code = """
import os
os.environ.pop('ENV_HUNTER_STANDALONE', None)
import maverick.audit
audit_calls=[]
maverick.audit.record=lambda *args, **kwargs: audit_calls.append((args,kwargs)) or True
import backend
assert backend.STANDALONE is False
assert backend.PLATFORM_ENGINE is True
summary = backend.caps_summary()
assert summary['standalone'] is True
assert summary['forced_standalone'] is False
assert summary['core_analysis'] is True
assert summary['analysis_backend'] == 'lightwork-core'
assert summary['integrated_governance'] is False
assert summary['authority'] == 'unsigned-local'
assert set(backend.CAPABILITY_BINDINGS) == set(backend.CAPS)
assert all(row['active'] is backend.CAPS[row['id']] for row in summary['capabilities'])
event={'id':'e1','source':'aws.cloudtrail','timestamp':1,'category':'cloudtrail','action':'ConsoleLogin','attributes':{'mfa':'No'}}
findings=backend.detect([event])
assert findings and findings[0]['rule_id']=='LW-SIGMA-001'
investigation=backend.investigate(findings[0])
proposal=backend.propose_response(investigation,'disable_identity','user-1')
assert proposal['type']=='response_proposal' and len(proposal['digest'])==64
cloudtrail=backend.ingest('cloudtrail',{'Records':[{'eventID':'c1','eventTime':1,'eventName':'ConsoleLogin','responseElements':{'ConsoleLogin':'Failure'},'additionalEventData':{'MFAUsed':'No'},'userIdentity':{'arn':'alice'}}]})
syslog=backend.ingest('syslog','Jan1 host sshd: Failed password for root')
kubernetes=backend.ingest('kubernetes',{'items':[{'auditID':'k1','verb':'create','objectRef':{'subresource':'exec'},'user':{'username':'alice'}}]})
native_rules={item['rule_id'] for item in backend.detect([*cloudtrail,*syslog,*kubernetes])}
assert {'LW-SIGMA-001','aws-console-failure','linux-auth-failure','k8s-interactive-access'} <= native_rules
assert audit_calls == []
try:
    getattr(backend,'deliver_response')
except AttributeError:
    pass
else:
    raise AssertionError('standalone delivery seam still exists')
from fastapi.testclient import TestClient
about = TestClient(__import__('app').app, base_url='http://127.0.0.1').get('/about')
assert 'lightwork-core' in about.text
assert 'unsigned local only' in about.text
assert 'Integrated Lightwork only' in about.text
"""
    result = _auto(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_mutations_reject_malformed_inputs_and_browser_cross_origin(tmp_path):
    code = """
import json
from fastapi.testclient import TestClient
from app import app

client=TestClient(app, base_url='http://127.0.0.1')
valid={'source_type':'syslog','payload':'host sshd: Failed password for root'}
assert client.post('/api/ingest',json=valid).status_code==422
assert client.post('/api/ingest',json={**valid,'expected_revision':False}).status_code==422
invalid=(
    {'source_type':7,'payload':[]},
    {'source_type':'syslog','payload':[7]},
    {'source_type':'json','payload':[{'id':'x','objectRef':'pod'}]},
    {'source_type':'json','payload':[{'id':'x'}],'sigma_rules':{'bad':'shape'}},
    {'source_type':'json','payload':[{'id':'x'}],'sigma_rules':[{'id':'x','title':'x','detection':{'selection':{'message|re':'(a+)+$'}}}]},
)
for body in invalid:
    response=client.post('/api/ingest',json={**body,'expected_revision':0})
    assert response.status_code==422, (body,response.text)
plain=client.post('/api/ingest',content=json.dumps({**valid,'expected_revision':0}),headers={'Content-Type':'text/plain'})
assert plain.status_code==415
hostile=client.post('/api/ingest',json={**valid,'expected_revision':0},headers={'Origin':'https://evil.example'})
assert hostile.status_code==403
assert client.get('/',headers={'Host':'evil.example'}).status_code==400
accepted=client.post('/api/ingest',json={**valid,'expected_revision':0},headers={'Origin':'http://127.0.0.1'})
assert accepted.status_code==200, accepted.text
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_store_cas_is_cross_instance_safe(tmp_path):
    code = """
import json, os, threading
from pathlib import Path
from env_engine import DerivedStore

path=Path(os.environ['ENV_HUNTER_STORE'])
stores=(DerivedStore(path),DerivedStore(path))
barrier=threading.Barrier(2)
results=[]
def save(store,record_id):
    barrier.wait()
    try:
        store.save([{'id':record_id,'type':'finding','evidence':{}}],0)
        results.append('saved')
    except ValueError as exc:
        assert 'revision changed' in str(exc)
        results.append('conflict')
threads=[threading.Thread(target=save,args=(store,record_id)) for store,record_id in zip(stores,('one','two'))]
for thread in threads: thread.start()
for thread in threads: thread.join()
state=json.loads(path.read_text(encoding='utf-8'))
assert sorted(results)==['conflict','saved']
assert state['revision']==1 and len(state['records'])==1
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr


def test_headerless_stream_stops_before_buffering_oversized_body(tmp_path):
    code = """
import asyncio
from starlette.requests import Request
from request_limits import PayloadError, read_bounded_json

chunks=[b'{' + b'x'*300000,b'y'*300000,b'never-read']
calls=0
async def receive():
    global calls
    chunk=chunks[calls]
    calls+=1
    return {'type':'http.request','body':chunk,'more_body':calls < len(chunks)}
scope={'type':'http','method':'POST','scheme':'http','path':'/api/ingest','query_string':b'',
       'headers':[(b'host',b'127.0.0.1'),(b'content-type',b'application/json')],
       'server':('127.0.0.1',80),'client':('127.0.0.1',1234)}
try:
    asyncio.run(read_bounded_json(Request(scope,receive)))
except PayloadError as exc:
    assert exc.status_code==413
else:
    raise AssertionError('oversized streamed request was accepted')
assert calls==2
"""
    result = _run(code, tmp_path)
    assert result.returncode == 0, result.stderr
