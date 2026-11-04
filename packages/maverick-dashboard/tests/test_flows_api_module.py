"""The flow routes live in flows_api; the api module stays the facade.

These pin what keeps the move invisible to callers and tests: every name is
still reachable as ``maverick_dashboard.api.<name>``, the router is included
at the same point in the api module (same precedence), the routes keep the parent
router's prefix and tag, and workflow dependencies are explicitly bound by
the application composition root.
"""
from __future__ import annotations

import ast
import dataclasses
import pathlib

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from maverick_dashboard import api, flow_dependencies, flows_api
from starlette.requests import Request


def _request(path: str = "/api/v1/flows/gallery") -> Request:
    return Request({"type": "http", "method": "GET", "scheme": "http", "path": path, "headers": []})


def _defined_names(module) -> set[str]:
    tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names - {"router", "log"}


def test_every_flows_api_name_is_reachable_through_the_api_facade():
    names = _defined_names(flows_api)
    assert len(names) >= 50
    for name in names:
        assert getattr(api, name) is getattr(flows_api, name), name
    # Sibling modules import these from .api at call time; they must resolve.
    for name in ("_assert_flow_access", "_require_flows", "_can_access_flow", "_load_owned_run",
                 "_require_learned_flow_evidence", "_save_flow_definition", "_legacy_local_flow_run"):
        assert getattr(api, name) is getattr(flows_api, name)


def test_flow_routes_moved_with_their_precedence():
    own = [r for r in flows_api.router.routes if isinstance(r, APIRoute)]
    assert len(own) == 31
    assert all(r.path.startswith("/flows") for r in own)
    assert flows_api.router.prefix == "" and not flows_api.router.tags
    # No flow handler is left inline in api.py ...
    inline = [r for r in api.router.routes if isinstance(r, APIRoute)]
    assert not any(r.path.startswith("/api/v1/flows") for r in inline)
    # ... and the included router sits where the handlers were: between inline
    # routes, ahead of every router the module includes at its tail.
    included = [i for i, r in enumerate(api.router.routes) if getattr(r, "original_router", None) is not None]
    flows_at = next(i for i in included if api.router.routes[i].original_router is flows_api.router)
    assert flows_at == included[0]
    assert any(isinstance(r, APIRoute) for r in api.router.routes[flows_at + 1:])
    assert any(isinstance(r, APIRoute) for r in api.router.routes[:flows_at])


def test_flow_routes_keep_the_api_prefix_and_tag_on_the_app():
    from maverick_dashboard.app import app

    served = []
    for route in app.routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if contexts is None:
            continue
        for ctx in contexts():
            if getattr(ctx.endpoint, "__module__", "") == flows_api.__name__:
                served.append((ctx.path, list(ctx.tags or []), ctx.include_in_schema))
    assert len(served) == 31
    assert all(path.startswith("/api/v1/flows") for path, _, _ in served)
    assert all(tags == ["v1"] and in_schema for _, tags, in_schema in served)


def test_flows_api_receives_services_without_importing_the_api_facade():
    tree = ast.parse(pathlib.Path(flows_api.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "api":
            raise AssertionError(f"flows_api imports api directly at line {node.lineno}")
    module_level = {n.module: {a.name for a in n.names} for n in tree.body if isinstance(n, ast.ImportFrom)}
    assert {"require_permission", "caller_principal", "goal_owner_filter", "run_in_threadpool"} <= module_level["flow_dependencies"]
    assert "auth" not in module_level and "_shared" not in module_level
    for name in module_level["flow_dependencies"]:
        assert callable(getattr(flow_dependencies, name))


def test_workflow_services_can_be_injected_without_changing_the_api(monkeypatch):
    calls: list[object] = []
    services = dataclasses.replace(flow_dependencies._services(),
        caller_suites=lambda request: calls.append(request) or ["finance"])
    monkeypatch.setattr(flow_dependencies, "_dependencies", services)
    assert flow_dependencies.caller_suites("req") == ["finance"]
    assert calls == ["req"]


def test_request_dependencies_are_isolated_per_application():
    defaults = flow_dependencies._services()
    first = FastAPI()
    second = FastAPI()
    first.state.flow_dependencies = dataclasses.replace(defaults, caller_principal=lambda _: "user:first")
    second.state.flow_dependencies = dataclasses.replace(defaults, caller_principal=lambda _: "user:second")

    def install(app):
        @app.get("/who", dependencies=[Depends(flow_dependencies.bind_request_services)])
        def who(request: Request):
            return {"principal": flow_dependencies.caller_principal(request)}

    install(first)
    install(second)
    assert TestClient(first, base_url="http://127.0.0.1").get("/who").json() == {"principal": "user:first"}
    assert TestClient(second, base_url="http://127.0.0.1").get("/who").json() == {"principal": "user:second"}


@pytest.mark.asyncio
async def test_a_patch_on_the_api_module_reaches_a_flows_handler(monkeypatch):
    seen: list[str] = []

    def deny(request, permission):
        seen.append(permission)
        raise HTTPException(status_code=418, detail="patched on api")

    monkeypatch.setattr(api, "require_permission", deny)
    with pytest.raises(HTTPException) as exc:
        await flows_api.flow_gallery_endpoint(_request())
    assert exc.value.status_code == 418
    assert seen == ["operate"]


def test_api_module_keeps_shrinking():
    size = len(pathlib.Path(api.__file__).read_text(encoding="utf-8").splitlines())
    # api.py was 18,016 lines before the flow routes moved out. Move the next
    # domain out instead of raising this bound.
    assert size <= 16_200, size
    assert "noqa: C901" not in pathlib.Path(flows_api.__file__).read_text(encoding="utf-8")
