"""A request for a path served before goes straight to its route."""
from __future__ import annotations

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
    assert app.router.middleware_stack.usable is False
