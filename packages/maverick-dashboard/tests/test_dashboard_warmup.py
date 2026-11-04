"""Start-up warm-up of the dashboard's first-hit caches (templates, OpenAPI,
packs, shield) and the Jinja environment's production settings."""
from __future__ import annotations

import os

import pytest
from maverick_dashboard import app as dashboard


def test_warm_dashboard_caches_compiles_templates_and_routes_but_not_the_schema(monkeypatch):
    """Routing needs every included route's context (FastAPI builds them on
    the first request otherwise, about 2.5 s); the OpenAPI schema (about
    4.3 s) is only for /openapi.json and is built when the server is idle."""
    from maverick_dashboard import route_identity

    env = dashboard.templates.env
    env.cache.clear()
    dashboard.app.openapi_schema = None
    walked = []
    real = route_identity.iter_compatible_route_contexts
    monkeypatch.setattr(route_identity, "iter_compatible_route_contexts",
                        lambda routes: walked.append(1) or real(routes))

    timings = dashboard._warm_dashboard_caches()

    assert set(timings) == {"templates", "routes", "domains", "agents", "shield"}
    assert list(timings)[:3] == ["domains", "agents", "routes"], "the pack catalogue and routes warm first"
    assert walked, "every route context is materialised"
    cached = {getattr(t, "name", None) for t in env.cache.values()}
    partials = [name for name in env.list_templates() if name.startswith("_") and name.endswith(".html")]
    assert "_sidebar_nav.html" in partials and "settings.html" in dashboard._WARM_TEMPLATES
    for name in (*dashboard._WARM_TEMPLATES, *partials):
        assert name in cached, name
    assert dashboard.app.openapi_schema is None, "the schema is not built with the request-path caches"


def test_warm_dashboard_caches_is_fail_open(monkeypatch):
    from maverick_dashboard import route_identity

    def _boom(_routes):
        raise RuntimeError("no routes today")

    monkeypatch.setattr(route_identity, "iter_compatible_route_contexts", _boom)
    timings = dashboard._warm_dashboard_caches()
    assert "routes" in timings  # the failed step is timed and skipped, not raised


def test_the_schema_waits_for_a_quiet_moment(monkeypatch):
    """The OpenAPI build holds the CPU for seconds, so it starts only when no
    request is in flight and none has started for a moment."""
    from maverick_dashboard import request_activity

    built = []
    monkeypatch.setattr(dashboard.app, "openapi", lambda: built.append(1))
    request_activity.started()
    waits = []

    def fake_sleep(seconds):
        waits.append(seconds)
        if len(waits) == 2:
            request_activity.finished()

    assert dashboard._build_openapi_when_idle(quiet=0.0, sleep=fake_sleep) is True
    assert built == [1] and len(waits) >= 2, "it waited while a request was in flight"


@pytest.mark.parametrize("fails", [False, True])
def test_the_schema_build_hands_the_gil_back_quickly_then_restores_it(monkeypatch, fails):
    """About six seconds of pure-Python CPU: at the default 5 ms switch
    interval each I/O call of a request arriving meanwhile waited for the GIL,
    and the clicks after someone's first pause took about a second each."""
    import sys

    before = sys.getswitchinterval()
    during = []

    def build():
        during.append(sys.getswitchinterval())
        if fails:
            raise RuntimeError("schema failed")

    monkeypatch.setattr(dashboard.app, "openapi", build)
    assert dashboard._build_openapi_when_idle(quiet=0.0, sleep=lambda _s: None) is (not fails)
    assert during and during[0] < before and during[0] <= 0.0001
    assert sys.getswitchinterval() == before


def test_request_activity_counts_requests_in_flight():
    import asyncio

    from maverick_dashboard import request_activity

    seen = []

    async def inner(scope, receive, send):
        seen.append(request_activity.in_flight())

    middleware = request_activity.RequestActivityMiddleware(inner)
    before = request_activity.in_flight()
    asyncio.run(middleware({"type": "http"}, None, None))
    assert seen == [before + 1] and request_activity.in_flight() == before


def test_templates_do_not_auto_reload_outside_development(monkeypatch):
    monkeypatch.delenv("MAVERICK_DEBUG", raising=False)
    monkeypatch.delenv("MAVERICK_TEMPLATE_AUTO_RELOAD", raising=False)
    assert dashboard._templates_auto_reload() is False
    monkeypatch.setenv("MAVERICK_TEMPLATE_AUTO_RELOAD", "true")
    assert dashboard._templates_auto_reload() is True
    monkeypatch.delenv("MAVERICK_TEMPLATE_AUTO_RELOAD")
    monkeypatch.setenv("MAVERICK_DEBUG", "1")
    assert dashboard._templates_auto_reload() is True


def test_template_bytecode_cache_lives_under_maverick_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    cache = dashboard._template_bytecode_cache()
    assert cache is not None
    assert os.path.isdir(tmp_path / "cache" / "templates")
    assert dashboard.templates.env.bytecode_cache is not None


def test_the_pack_catalogue_warms_before_the_slower_steps(monkeypatch):
    """Ctrl+K's first agent lookup needs the parsed pack catalogue and the
    tool inventory; both are person-independent and warm before hooks and
    the OpenAPI build, so the first search after start answers in time."""
    from maverick_dashboard import route_identity

    order = []
    monkeypatch.setattr("maverick.domain_edit.list_agents", lambda: order.append("agents") or [])
    monkeypatch.setattr(route_identity, "iter_compatible_route_contexts", lambda _routes: order.append("routes") or [])
    dashboard._warm_dashboard_caches()
    assert order.index("agents") < order.index("routes")


def test_a_stopped_dashboard_does_not_build_the_schema(monkeypatch):
    """Shutdown ends the background warm-up: a stopped server (or a test's
    TestClient) must not keep spending seconds of CPU on its schema."""
    import threading

    from maverick_dashboard import request_activity

    built = []
    monkeypatch.setattr(dashboard.app, "openapi", lambda: built.append(1))
    stop = threading.Event()
    stop.set()
    assert dashboard._build_openapi_when_idle(quiet=0.0, sleep=lambda _s: None, stop=stop) is False
    assert built == []

    stop = threading.Event()
    request_activity.started()
    try:
        assert dashboard._build_openapi_when_idle(quiet=0.0, sleep=lambda _s: stop.set(), stop=stop) is False
    finally:
        request_activity.finished()
    assert built == [], "a stop that arrives while waiting for quiet also ends it"


def test_leaving_the_lifespan_stops_its_warm_up_thread(monkeypatch, tmp_path):
    """Every startup used to leave a warm-up thread behind that later built the
    OpenAPI schema in whatever process it was in (dozens per test worker)."""
    import threading
    import time

    from fastapi.testclient import TestClient
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    built = []
    monkeypatch.setattr(dashboard.app, "openapi", lambda: built.append(1))

    def mine():
        return {t for t in threading.enumerate() if t.name == "lightwork-warm-hooks"}

    before = mine()
    with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}):
        started = mine() - before
    assert started, "startup runs the warm-up in the background"
    deadline = time.monotonic() + 120
    for thread in started:
        thread.join(max(0.0, deadline - time.monotonic()))
        assert not thread.is_alive(), "the warm-up thread outlived its dashboard"
    assert built == [], "a stopped dashboard never builds its schema"
    dashboard._world_cache.clear()


def test_a_garbage_round_unfreezes_collects_then_freezes(monkeypatch):
    """A full collection walked every warmed object (about 700,000), pausing
    whichever request triggered it for 350-450 ms. Each round reclaims what
    was frozen and has become garbage since, then freezes the survivors."""
    order = []
    monkeypatch.setattr(dashboard.gc, "unfreeze", lambda: order.append("unfreeze"))
    monkeypatch.setattr(dashboard.gc, "collect", lambda: order.append("collect") or 0)
    monkeypatch.setattr(dashboard.gc, "freeze", lambda: order.append("freeze"))
    dashboard._freeze_long_lived_objects()
    assert order == ["unfreeze", "collect", "freeze"]


def test_garbage_rounds_wait_for_a_quiet_moment_and_stop_with_the_dashboard(monkeypatch):
    import threading

    from maverick_dashboard import request_activity

    rounds, waits, sleeps = [], [], []
    monkeypatch.setattr(request_activity, "_in_flight", 1)  # restored after the test
    monkeypatch.setattr(request_activity, "_last_start", 0.0)
    monkeypatch.setattr(dashboard, "_freeze_long_lived_objects", lambda: rounds.append("round"))
    monkeypatch.setattr(dashboard.gc, "unfreeze", lambda: rounds.append("unfreeze"))

    def sleep(_seconds):
        sleeps.append(1)
        if len(sleeps) == 3:
            monkeypatch.setattr(request_activity, "_in_flight", 0)  # the request ends

    def wait(seconds):
        waits.append(seconds)
        return len(waits) == 2  # the dashboard stops during the second pause

    dashboard._collect_when_idle(threading.Event(), quiet=0.0, sleep=sleep, wait=wait, every=60.0)
    assert len(sleeps) == 3, "no round while a request is in flight"
    assert rounds == ["round", "round"] and waits == [60.0, 60.0]


def test_traffic_that_never_quietens_unfreezes_instead_of_keeping_garbage(monkeypatch):
    """A round that finds no quiet moment returns the frozen objects to
    ordinary collection, so nothing frozen is kept indefinitely."""
    import threading

    from maverick_dashboard import request_activity

    calls = []
    monkeypatch.setattr(request_activity, "_in_flight", 1)
    monkeypatch.setattr(dashboard, "_freeze_long_lived_objects", lambda: calls.append("round"))
    monkeypatch.setattr(dashboard.gc, "unfreeze", lambda: calls.append("unfreeze"))
    dashboard._collect_when_idle(threading.Event(), quiet=0.0, sleep=lambda _s: None,
                                 wait=lambda _s: True, limit=2.0)
    assert calls == ["unfreeze"]
    stop = threading.Event()
    stop.set()
    dashboard._collect_when_idle(stop, quiet=0.0, sleep=lambda _s: None, wait=lambda _s: False)
    assert calls == ["unfreeze"], "a stopped dashboard does nothing"


def test_the_warm_up_freezes_before_serving_and_collects_after_the_schema(monkeypatch):
    """Until the first quiet garbage round (ten quiet seconds), every full
    collection walked the warmed objects, 0.4-0.6 s on whichever request
    triggered it; someone clicking from the start never got that quiet."""
    import threading

    steps, targets = [], []

    class _Thread:
        def __init__(self, target, **_kwargs):
            targets.append(target)

        def start(self):
            pass

    async def _hooks():
        steps.append("hooks")

    ready = threading.Event()
    monkeypatch.setattr("maverick.hooks.ensure_loaded", _hooks)
    monkeypatch.setattr(dashboard, "_warm_dashboard_caches",
                        lambda stop=None: steps.append(("caches", ready.is_set())) or {})
    monkeypatch.setattr(dashboard, "_build_openapi_when_idle", lambda stop=None: steps.append("schema") or True)
    monkeypatch.setattr(dashboard, "_collect_when_idle", lambda stop: steps.append(("gc", stop.is_set())))
    monkeypatch.setattr(dashboard, "_freeze_long_lived_objects", lambda: steps.append(("freeze", ready.is_set())))
    stop = dashboard._warm_goal_runtime(thread_factory=_Thread, ready=ready)
    assert isinstance(stop, threading.Event) and len(targets) == 1
    targets[0]()
    # The request-path caches, then their freeze, both before ready; hooks,
    # the schema and the garbage rounds follow in the background.
    assert steps == [("caches", False), ("freeze", False), "hooks", "schema", ("gc", False)] and ready.is_set()


def test_a_dashboard_stopped_during_warm_up_does_not_freeze(monkeypatch):
    import threading

    targets, frozen = [], []

    class _Thread:
        def __init__(self, target, **_kwargs):
            targets.append(target)

        def start(self):
            pass

    ready = threading.Event()
    monkeypatch.setattr(dashboard, "_freeze_long_lived_objects", lambda: frozen.append(1))
    stop = dashboard._warm_goal_runtime(thread_factory=_Thread, ready=ready)
    monkeypatch.setattr(dashboard, "_warm_dashboard_caches", lambda stop=None: stop.set() or {})
    targets[0]()
    assert frozen == [] and ready.is_set() and stop.is_set()


def test_the_dashboard_serves_only_after_its_request_path_caches_are_warm(monkeypatch, tmp_path):
    """A first page opened while the route table, templates and pack catalogue
    were still cold took 4 to 9 seconds (and longer while the background
    warm-up competed with it). Startup now waits for them before serving."""
    import asyncio
    import threading

    from fastapi.testclient import TestClient
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    monkeypatch.setattr(dashboard.app, "openapi", lambda: None)
    warmed, release = [], threading.Event()

    async def slow_hooks():  # hook discovery is not needed for the first page
        await asyncio.to_thread(release.wait, 30)

    monkeypatch.setattr("maverick.hooks.ensure_loaded", slow_hooks)
    monkeypatch.setattr(dashboard, "_warm_dashboard_caches", lambda stop=None: warmed.append(1) or {})
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}):
            assert warmed == [1], "the caches were warm before the first request"
    finally:
        release.set()
        dashboard._world_cache.clear()


def test_overdue_automation_starts_after_the_warm_up(monkeypatch, tmp_path):
    """A dream cycle missed while the dashboard was stopped is claimed as soon
    as the automation worker starts; beside the warm-up it delayed serving by
    about 2.8 s. The worker now starts once the caches are warm."""
    from fastapi.testclient import TestClient
    from maverick import world_model
    from maverick_dashboard import automation_queue

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    monkeypatch.setattr(dashboard.app, "openapi", lambda: None)
    order = []
    monkeypatch.setattr(dashboard, "_warm_dashboard_caches", lambda stop=None: order.append("warm") or {})
    monkeypatch.setattr(automation_queue, "start", lambda: order.append("automation") or False)
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}):
            assert order == ["warm", "automation"]
    finally:
        dashboard._world_cache.clear()


def test_a_slow_warm_up_delays_serving_only_up_to_its_limit(monkeypatch, tmp_path):
    import threading
    import time

    from fastapi.testclient import TestClient
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    monkeypatch.setattr(dashboard.app, "openapi", lambda: None)
    monkeypatch.setattr(dashboard, "_WARM_BEFORE_SERVING_SECONDS", 0.2)
    release = threading.Event()
    monkeypatch.setattr(dashboard, "_warm_dashboard_caches", lambda stop=None: release.wait(30) and {})
    try:
        started = time.monotonic()
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            assert time.monotonic() - started < 10, "startup waited past its limit (15 s by default)"
            assert client.get("/livez").status_code == 200
    finally:
        release.set()
        dashboard._world_cache.clear()


def test_a_dashboard_that_just_started_is_not_yet_quiet(monkeypatch):
    """Before its first request the dashboard counted as quiet, so the
    schema build (about 4 s of CPU) started at once and slowed the first
    pages to 4 seconds; a garbage round did the same."""
    from maverick_dashboard import request_activity

    monkeypatch.setattr(request_activity, "_in_flight", 0)
    monkeypatch.setattr(request_activity, "_last_start", 0.0)  # nothing served yet
    sleeps = []
    assert dashboard._wait_for_quiet(2.0, sleeps.append, 60.0, None) is True
    assert len(sleeps) == 4, "it waited the quiet period itself"
