"""A request for a path served before goes straight to its route."""
from __future__ import annotations

import threading

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from maverick_dashboard import app as dash_app
from maverick_dashboard import route_dispatch
from starlette.routing import Host, Route


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    # A served dashboard checks its routes during start-up, before it serves.
    assert route_dispatch.validate(dash_app.app.router) is True
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    dash_app._world_cache.clear()


def _restore(routes):
    dash_app.app.router.routes[:] = routes
    dash_app.app.router._mark_routes_changed()


def test_the_dashboard_router_remembers_its_matches():
    assert isinstance(dash_app.app.router.middleware_stack, route_dispatch.RememberedRouteDispatch)


def test_a_page_served_before_skips_the_routes_ahead_of_it(client, monkeypatch):
    # /workforce sits about 250 entries in; every request tried each of them
    # first (6.5-7.4 ms).
    assert client.get("/workforce").status_code == 200
    tried = []
    for route in dash_app.app.router.routes[:50]:
        monkeypatch.setattr(route, "matches", lambda scope, real=route.matches: tried.append(1) or real(scope))
    assert client.get("/workforce").status_code == 200
    assert tried == []


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/workforce"),
    ("GET", "/approvals"),
    ("GET", "/static/board.js"),
    ("GET", "/api/v1/halt"),
    ("GET", "/static/no-such-file.css"),
    ("GET", "/no-such-page"),
    ("GET", "/workforce/"),
    ("DELETE", "/workforce"),
])
def test_remembered_and_ordinary_dispatch_answer_alike(client, monkeypatch, method, path):
    remembered = [client.request(method, path, follow_redirects=False) for _ in range(2)]
    dispatcher = dash_app.app.router.middleware_stack
    monkeypatch.setattr(dash_app.app.router, "middleware_stack", dispatcher.dispatch)
    ordinary = client.request(method, path, follow_redirects=False)
    for response in remembered:
        assert response.status_code == ordinary.status_code
        assert response.headers.get("content-type") == ordinary.headers.get("content-type")
        assert response.headers.get("location") == ordinary.headers.get("location")
    if path.startswith("/static/") and ordinary.status_code == 200:
        assert remembered[1].content == ordinary.content


def test_a_route_added_ahead_of_a_remembered_one_takes_over(client):
    router = dash_app.app.router
    original = list(router.routes)
    assert client.get("/workforce").status_code == 200
    try:
        router.routes.insert(0, APIRoute("/workforce", lambda: PlainTextResponse("first now")))
        router._mark_routes_changed()
        assert client.get("/workforce").text == "first now"
        router.routes.insert(0, APIRoute("/workforce", lambda: PlainTextResponse("first again")))
        assert client.get("/workforce").text == "first again", "an unannounced insert is seen too"
    finally:
        _restore(original)
    page = client.get("/workforce").text
    assert "first now" not in page and "first again" not in page and "<!doctype" in page.lower()


def test_a_long_path_is_never_remembered(client):
    # Each remembered path is kept in memory; a flood of long unique paths
    # must not grow it.
    dispatcher = dash_app.app.router.middleware_stack
    long_path = "/share/" + "x" * 400
    for _ in range(2):
        assert client.get(long_path).status_code in {401, 403, 404}
    assert not any(len(key[2]) > 256 for key in dispatcher.remembered)


def test_a_route_that_matches_on_the_host_turns_the_memory_off():
    app = FastAPI()

    @app.get("/page")
    def page():
        return PlainTextResponse("any host")

    app.router.routes.insert(0, Host("special.example", app=Route("/page", lambda request: PlainTextResponse("special"))))
    assert route_dispatch.install(app.router)
    client = TestClient(app, base_url="http://127.0.0.1")
    for _ in range(2):
        assert client.get("/page", headers={"host": "special.example"}).text == "special"
        assert client.get("/page").text == "any host"
    _wait_for_a_background_check(app.router.middleware_stack)
    assert app.router.middleware_stack.verdict[0] is not None, "the routes were checked"
    assert app.router.middleware_stack.usable is False


def _app_with_a_late_page():
    """A small app whose page sits past the entries cheaper to scan than to
    remember, so a remembered match is actually used."""
    app = FastAPI()
    for number in range(route_dispatch._SCAN_IS_CHEAPER_BELOW + 4):
        app.add_api_route(f"/filler/{number}", lambda: PlainTextResponse("filler"))
    served_on = []

    @app.get("/page")
    async def page():
        served_on.append(threading.current_thread())
        return PlainTextResponse("page")

    assert route_dispatch.install(app.router)
    return app, served_on


def _remembered_routes(monkeypatch):
    used = []
    real = route_dispatch._OneRoute
    monkeypatch.setattr(route_dispatch, "_OneRoute", lambda router, route: used.append(route) or real(router, route))
    return used


def _wait_for_a_background_check(dispatcher):
    checking = getattr(dispatcher, "checking", None)
    if checking is not None:
        checking.join(60)
        assert not checking.is_alive()


def test_start_up_checks_the_routes_so_the_first_request_does_not(monkeypatch, tmp_path):
    """The first request after start-up ran the route-memory check itself: a
    walk of every route on the event loop, 8 ms once warm and 3.8-4.7 s while
    FastAPI still had to build them. Start-up's warm-up thread runs it now."""
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    monkeypatch.setattr(dash_app.app, "openapi", lambda: None)
    monkeypatch.setattr(dash_app, "_WARM_BEFORE_SERVING_SECONDS", 120.0)
    dispatcher = dash_app.app.router.middleware_stack
    dash_app.app.router._mark_routes_changed()  # whatever this process checked before is stale
    checks = []
    real = route_dispatch._leaves

    def leaves(routes):
        checks.append(threading.current_thread().name)
        yield from real(routes)

    monkeypatch.setattr(route_dispatch, "_leaves", leaves)
    try:
        with TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            at_start = list(checks)
            assert client.get("/livez").status_code == 200
            _wait_for_a_background_check(dispatcher)
            on_first_request = checks[len(at_start):]
    finally:
        dash_app._world_cache.clear()
    assert at_start == ["lightwork-warm-hooks"], "start-up checks the routes in its warm-up thread"
    assert on_first_request == [], "the first request checked the routes again"
    assert dispatcher.usable is True


def test_unchecked_routes_are_checked_off_the_request_path(monkeypatch):
    """Before its routes are checked (a start-up whose warm-up has not
    finished, or routes that changed), a request is served the ordinary way
    at once, as when a check turns the memory off, and the check runs in the
    background instead of on the event loop that serves /livez."""
    app, served_on = _app_with_a_late_page()
    dispatcher = app.router.middleware_stack
    remembered = _remembered_routes(monkeypatch)
    release, checked_on = threading.Event(), []
    real = route_dispatch._leaves

    def slow_leaves(routes):
        checked_on.append(threading.current_thread())
        assert release.wait(5), "the check was not released"
        yield from real(routes)

    monkeypatch.setattr(route_dispatch, "_leaves", slow_leaves)
    client = TestClient(app, base_url="http://127.0.0.1")
    try:
        for _ in range(2):
            assert client.get("/page").text == "page", "served while the check is still running"
        assert remembered == [], "nothing is remembered before the check passes"
    finally:
        release.set()
    _wait_for_a_background_check(dispatcher)
    assert len(checked_on) == 1 and checked_on[0] not in served_on, "the check ran on the request's thread"
    assert dispatcher.usable is True
    for _ in range(2):
        assert client.get("/page").text == "page"
    assert remembered, "once checked, the page is served from memory"


def test_a_check_that_fails_keeps_the_memory_off(monkeypatch):
    """A check that cannot read the routes (an unknown router shape) turns
    the memory off for that route table, as before: every request takes the
    ordinary dispatch, and the check is not repeated per request."""
    app, _served_on = _app_with_a_late_page()
    dispatcher = app.router.middleware_stack
    remembered = _remembered_routes(monkeypatch)
    attempts = []

    def unreadable(_routes):
        attempts.append(1)
        raise RuntimeError("unknown router shape")
        yield  # pragma: no cover - makes this a generator, like _leaves

    monkeypatch.setattr(route_dispatch, "_leaves", unreadable)
    client = TestClient(app, base_url="http://127.0.0.1")
    for _ in range(3):
        assert client.get("/page").text == "page"
    _wait_for_a_background_check(dispatcher)
    for _ in range(3):
        assert client.get("/page").text == "page"
    _wait_for_a_background_check(dispatcher)
    assert attempts == [1] and dispatcher.usable is False and remembered == []
