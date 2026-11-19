"""Static concurrency audit: async FastAPI route handlers with no await that
block the dashboard event loop on synchronous DB/file/config work."""
from __future__ import annotations

import json

from maverick import async_route_audit as ara


def _write(root, rel, body):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def _give_reasons(lock_file):
    entries = json.loads(lock_file.read_text())
    for entry in entries:
        entry["reason"] = "tracked for conversion"
    lock_file.write_text(json.dumps(entries), encoding="utf-8")


def test_flags_zero_await_route_with_blocking_call(tmp_path):
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    findings = ara.scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].name == "get_x"
    assert "_world" in findings[0].blocking_calls[0]


def test_does_not_flag_a_route_that_awaits(tmp_path):
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return await _world_async().get_goal(1)
""")
    assert ara.scan(tmp_path) == []


def test_does_not_flag_zero_await_route_with_no_blocking_call(tmp_path):
    """A zero-await handler that does no I/O at all isn't this bug."""
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return {"ok": True}
""")
    assert ara.scan(tmp_path) == []


def test_does_not_flag_a_non_route_async_function(tmp_path):
    _write(tmp_path, "maverick_dashboard/api.py", """
async def helper():
    return _world().get_goal(1)
""")
    assert ara.scan(tmp_path) == []


def test_skips_test_files_and_test_directories(tmp_path):
    _write(tmp_path, "maverick_dashboard/test_api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    _write(tmp_path, "maverick_dashboard/tests/more.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/y")
async def get_y():
    return _world().get_goal(2)
""")
    assert ara.scan(tmp_path) == []


def test_finding_key_is_stable_across_line_shifts():
    f1 = ara.Finding(path="a.py", name="get_x", lineno=5, blocking_calls=("_world",))
    f2 = ara.Finding(path="a.py", name="get_x", lineno=9, blocking_calls=("_world",))
    assert f1.key == f2.key


def test_lock_round_trips(tmp_path, monkeypatch):
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    lock_file = tmp_path / "lock.json"
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    written = ara.write_lock(tmp_path)
    assert written == lock_file
    _give_reasons(lock_file)
    locked = ara.load_lock()
    assert len(locked) == 1
    finding = next(iter(locked.values()))
    assert finding.name == "get_x"
    assert ara.problems(tmp_path) == []


def test_problems_flags_a_new_unlocked_finding(tmp_path, monkeypatch):
    lock_file = tmp_path / "lock.json"
    lock_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    probs = ara.problems(tmp_path)
    assert len(probs) == 1
    assert "get_x" in probs[0] and "blocks the dashboard event loop" in probs[0]


def test_problems_flags_a_stale_lock_entry_that_no_longer_reproduces(tmp_path, monkeypatch):
    lock_file = tmp_path / "lock.json"
    lock_file.write_text(json.dumps([
        {"path": "maverick_dashboard/api.py", "name": "get_x", "lineno": 5,
         "blocking_calls": ["_world"]},
    ]), encoding="utf-8")
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return await _world_async().get_goal(1)
""")
    probs = ara.problems(tmp_path)
    assert len(probs) == 1
    assert "no longer reproduces" in probs[0]


def test_main_regen_writes_the_lock(tmp_path, monkeypatch):
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    lock_file = tmp_path / "lock.json"
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    rc = ara.main(["--regen", "--dir", str(tmp_path)])
    assert rc == 0
    assert json.loads(lock_file.read_text())


def test_main_ci_fails_on_a_new_violation(tmp_path, monkeypatch):
    lock_file = tmp_path / "lock.json"
    lock_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    rc = ara.main(["--ci", "--dir", str(tmp_path)])
    assert rc == 1


def test_main_ci_passes_when_everything_is_grandfathered(tmp_path, monkeypatch):
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

@router.get("/x")
async def get_x():
    return _world().get_goal(1)
""")
    lock_file = tmp_path / "lock.json"
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    assert ara.main(["--regen", "--dir", str(tmp_path)]) == 0
    assert ara.main(["--ci", "--dir", str(tmp_path)]) == 1  # no reason yet
    _give_reasons(lock_file)
    assert ara.main(["--ci", "--dir", str(tmp_path)]) == 0


def test_main_fails_loudly_on_an_empty_or_missing_directory(tmp_path):
    empty = tmp_path / "nothing_here"
    rc = ara.main(["--ci", "--dir", str(empty)])
    assert rc == 2


def test_the_committed_lock_matches_the_real_dashboard():
    """The checked-in grandfather list must describe the CURRENT dashboard,
    not a stale snapshot -- this is exactly what CI enforces."""
    assert ara.problems() == []


def test_flags_zero_await_route_with_synchronous_network_fetch(tmp_path):
    """A catalog index fetch or urllib/httpx call on the loop stalls every
    request for the duration of the network round trip (measured: /store
    took every concurrent /livez from 15 ms to 158 ms)."""
    _write(tmp_path, "maverick_dashboard/app.py", """
from fastapi import FastAPI
app = FastAPI()

@app.get("/store")
async def store_page():
    return [e.to_dict() for e in load_catalog("skills")]

@app.get("/probe")
async def probe():
    with guarded_urlopen("https://example.invalid") as resp:
        return resp.read()

@app.get("/probe2")
async def probe2():
    return urllib.request.urlopen("https://example.invalid").read()

@app.get("/probe3")
async def probe3():
    return httpx.Client().get("https://example.invalid").text
""")
    names = {f.name for f in ara.scan(tmp_path)}
    assert names == {"store_page", "probe", "probe2", "probe3"}


_STORE_MODULE = """
from functools import partial
from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool
router = APIRouter()

def _ops():
    return object()

def authority(request):
    ops = _ops()
    return ops, ThirdPartyIntelligenceStore(request.app.state.path)

def open_authority(request):
    factory = request.app.state.store_factory
    return factory(tenant_id="t")

off_loop = partial(run_in_threadpool, open_authority)

@router.get("/sources")
async def sources(request):
    ops, store = authority(request)
    return await run_in_threadpool(store.list_sources)

@router.get("/vendors")
async def vendors(request):
    store = await off_loop(request)
    other = await run_in_threadpool(open_authority, request)
    return await run_in_threadpool(store.list_vendors, other)

@router.get("/nested")
async def nested(request):
    return await run_in_threadpool(lambda: authority(request))

@router.get("/argument")
async def argument(request):
    return await run_in_threadpool(len, open_authority(request))
"""


def test_flags_a_store_opened_on_the_loop_before_the_first_await(tmp_path):
    """The hosted-demo freeze: each list awaited its query in the worker pool
    but first opened the tenant store (SQLite, 30 s busy timeout) on the
    event loop, so the old zero-await rule never saw it."""
    _write(tmp_path, "maverick_dashboard/api.py", _STORE_MODULE)
    found = {f.name: f for f in ara.scan(tmp_path)}
    assert set(found) == {"sources", "argument"}
    assert found["sources"].rule == ara.OPENS_STORE
    assert found["sources"].blocking_calls == ("authority",)
    assert found["argument"].blocking_calls == ("open_authority",)
    assert found["sources"].key != ara.Finding(
        path=found["sources"].path, name="sources", lineno=1, blocking_calls=()).key


def test_flags_list_handlers_registered_through_add_api_route(tmp_path):
    _write(tmp_path, "maverick_dashboard/api.py", """
from fastapi import APIRouter
router = APIRouter()

def build(deps):
    def authority(request):
        return deps.store_for("tenant")

    def _lister(name):
        async def listing(request):
            store = authority(request)
            return {"items": await call(store, name)}
        return listing

    for path, name in (("/a", "a"), ("/b", "b")):
        router.add_api_route(path, _lister(name), methods=["GET"])
""")
    found = ara.scan(tmp_path)
    assert [(f.name, f.rule, f.blocking_calls) for f in found] == [
        ("listing", ara.OPENS_STORE, ("authority",))]


def test_flags_a_zero_await_page_that_renders_on_the_loop(tmp_path):
    """Rendering a page reads its settings, permissions and navigation from
    disk: about 290 file reads, all on the loop in an ``async def``."""
    _write(tmp_path, "maverick_dashboard/app.py", """
from fastapi import FastAPI
app = FastAPI()

@app.get("/third-party/intelligence")
async def page(request):
    return templates.TemplateResponse(request, "page.html", {})

@app.get("/fine")
def fine(request):
    return templates.TemplateResponse(request, "page.html", {})
""")
    found = ara.scan(tmp_path)
    assert [(f.name, f.rule) for f in found] == [("page", ara.NO_AWAIT)]


def test_a_grandfathered_entry_needs_a_reason(tmp_path, monkeypatch):
    _write(tmp_path, "maverick_dashboard/api.py", _STORE_MODULE)
    lock_file = tmp_path / "lock.json"
    monkeypatch.setattr(ara, "lock_path", lambda: lock_file)
    ara.write_lock(tmp_path)
    probs = ara.problems(tmp_path)
    assert len(probs) == 2 and all("reason" in prob for prob in probs)

    entries = json.loads(lock_file.read_text())
    for entry in entries:
        entry["reason"] = "tracked: converted with the next change to this module"
    lock_file.write_text(json.dumps(entries), encoding="utf-8")
    assert ara.problems(tmp_path) == []
    ara.write_lock(tmp_path)  # regenerating keeps the reasons already given
    assert ara.problems(tmp_path) == []


def test_the_pages_that_froze_the_demo_are_not_grandfathered():
    """The third-party intelligence and continuous-evidence pages (and the
    pages reported stuck on Loading) must stay off the event loop."""
    fixed = {
        "third_party_intelligence_api.py", "trc_continuous_evidence_api.py", "trc_setup_api.py",
        "privacy_data_discovery_api.py", "privacy_regulatory_intelligence_api.py",
        "consent_profile_data_api.py", "ai_evidence_analysis_api.py",
        "ai_evidence_analysis_authority_api.py", "privacy_rights_consumer_delivery_api.py",
        "assessment_evidence_autopopulation_api.py", "privacy_rights_orchestration_api.py",
        "third_party_lifecycle_api.py", "third_party_collaboration_api.py",
        "ai_evidence_analysis_page.py", "assessment_evidence_autopopulation_page.py",
        "consent_custom_index_page.py",
    }
    pages = {
        "consent_profile_data_page", "privacy_data_discovery_page",
        "privacy_regulatory_intelligence_page", "privacy_rights_consumer_delivery_page",
        "third_party_intelligence_page", "trc_continuous_evidence_page",
    }
    locked = ara.load_lock().values()
    assert not [f.key for f in locked if f.path.rsplit("/", 1)[-1] in fixed]
    assert not [f.key for f in locked if f.path.endswith("/app.py") and f.name in pages]
