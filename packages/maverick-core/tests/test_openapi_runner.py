"""Tests for the openapi_runner tool (maverick.tools.openapi_runner)."""
from __future__ import annotations

import json
import types
from unittest.mock import MagicMock

# ---------- OpenAPI runner ----------

_TINY_OAS = {
    "openapi": "3.0.0",
    "info": {"title": "Petstore", "version": "1.0"},
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/pets/{petId}": {
            "get": {
                "operationId": "getPet",
                "summary": "Get a pet by id",
                "parameters": [
                    {"name": "petId", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
            },
            "delete": {
                "operationId": "deletePet",
                "summary": "Delete a pet",
                "parameters": [
                    {"name": "petId", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ],
            },
        },
        "/pets": {
            "post": {
                "operationId": "createPet",
                "summary": "Create a pet",
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {"type": "object",
                                   "properties": {"name": {"type": "string"}}},
                    }},
                },
            },
        },
    },
}


def _write_spec(tmp_path, name="spec.json"):
    import maverick.tools.openapi_runner as oas
    oas._spec_cache.clear()  # noqa: SLF001 - test reset
    p = tmp_path / name
    p.write_text(json.dumps(_TINY_OAS))
    return str(p)


def _sb(tmp_path):
    """A stand-in sandbox whose workdir is the test's tmp_path, so the
    spec-path confinement allows the in-workspace spec file."""
    return types.SimpleNamespace(workdir=str(tmp_path))


def _patch_safe_client(monkeypatch, response, captured):
    """Stand in for maverick.tools._ssrf.safe_client (which pins the
    connection to a validated public IP). Captures the request and returns
    ``response`` so the offline unit tests don't do real DNS / sockets.

    The runner streams responses under a byte ceiling (``client.stream(...)`` +
    ``iter_bytes()``), so the mock exposes that interface; ``request``/``get``
    are kept for any caller still on the buffered path."""
    class _StreamResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def raise_for_status(self):
            return None

        status_code = response.status_code
        encoding = "utf-8"

        def iter_bytes(self):
            text = response.text if isinstance(response.text, str) else ""
            yield text.encode("utf-8")

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def stream(self, method, url, **kw):
            captured["method"] = method
            captured["url"] = url
            captured["kw"] = kw
            captured["body"] = kw.get("json")
            return _StreamResp()

        def request(self, method, url, **kw):
            captured["method"] = method
            captured["url"] = url
            captured["kw"] = kw
            captured["body"] = kw.get("json")
            return response

        def get(self, url, **kw):
            captured["url"] = url
            captured["kw"] = kw
            return response

    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "safe_client", lambda url, **kw: _Client())


def test_openapi_list_ops(tmp_path):
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({"op": "list_ops", "spec": _write_spec(tmp_path)})
    assert "getPet" in out and "createPet" in out and "deletePet" in out
    assert "GET" in out and "POST" in out


def test_openapi_describe(tmp_path):
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "describe", "spec": _write_spec(tmp_path), "op_id": "getPet",
    })
    assert "GET /pets/{petId}" in out
    assert "param (path): petId*" in out


def test_openapi_describe_unknown(tmp_path):
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "describe", "spec": _write_spec(tmp_path), "op_id": "bogus",
    })
    assert "not found" in out


def test_openapi_call_substitutes_path_param(tmp_path, monkeypatch):
    captured = {"url": None}
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '{"id": 7, "name": "Fido"}'
    _patch_safe_client(monkeypatch, resp, captured)
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "call", "spec": _write_spec(tmp_path),
        "op_id": "getPet", "params": {"petId": 7},
    })
    assert "HTTP 200" in out and "Fido" in out
    assert captured["url"] == "https://api.example.com/pets/7"
    assert captured["method"] == "GET"


def test_openapi_call_missing_required_path_param(tmp_path, monkeypatch):
    # Missing path param is rejected before any fetch, so no client needed.
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "call", "spec": _write_spec(tmp_path),
        "op_id": "getPet", "params": {},
    })
    assert "required path param" in out


def test_openapi_call_sends_body(tmp_path, monkeypatch):
    captured = {"body": None}
    resp = MagicMock()
    resp.status_code = 201
    resp.text = "{}"
    _patch_safe_client(monkeypatch, resp, captured)
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "call", "spec": _write_spec(tmp_path),
        "op_id": "createPet", "body": {"name": "Rex"},
    })
    assert "HTTP 201" in out
    assert captured["body"] == {"name": "Rex"}


def test_openapi_http_failure_is_error_and_secret_scrubbed(tmp_path, monkeypatch):
    captured = {"body": None}
    resp = MagicMock()
    resp.status_code = 500
    resp.text = "Authorization: Bearer tok123"
    _patch_safe_client(monkeypatch, resp, captured)
    from maverick.tools.openapi_runner import openapi_runner

    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "call", "spec": _write_spec(tmp_path),
        "op_id": "createPet", "body": {"name": "Rex"},
    })

    assert out.startswith("ERROR: HTTP 500")
    assert "tok123" not in out


def test_openapi_call_blocks_private_base_url(tmp_path, monkeypatch):
    # No client patch: safe_client must resolve 127.0.0.1, see it's
    # non-public, and refuse before any connection (works offline).
    from maverick.tools.openapi_runner import openapi_runner
    out = openapi_runner(_sb(tmp_path)).fn({
        "op": "call", "spec": _write_spec(tmp_path),
        "op_id": "getPet", "params": {"petId": 7},
        "base_url": "http://127.0.0.1:8080",
    })
    assert "refusing to fetch" in out and "127.0.0.1" in out


def test_openapi_blocks_spec_path_escape(tmp_path):
    # A local spec path outside the sandbox workdir is refused, so the
    # agent can't read /etc/passwd or ~/.ssh/id_rsa via the spec arg.
    import maverick.tools.openapi_runner as oas
    from maverick.tools.openapi_runner import openapi_runner
    oas._spec_cache.clear()  # noqa: SLF001 - test reset
    # Write a real spec OUTSIDE the workdir; confinement must still refuse it.
    outside = tmp_path.parent / "outside_spec.json"
    outside.write_text(json.dumps(_TINY_OAS))
    out = openapi_runner(_sb(tmp_path / "work")).fn(
        {"op": "list_ops", "spec": str(outside)}
    )
    assert "outside the workspace" in out


def test_openapi_cache_is_scoped_to_resolved_local_path(tmp_path):
    # Local specs are process-cached, but relative names must not collide
    # across sandbox workdirs.
    import maverick.tools.openapi_runner as oas
    from maverick.tools.openapi_runner import openapi_runner

    oas._spec_cache.clear()  # noqa: SLF001 - test reset
    work_a = tmp_path / "a"
    work_b = tmp_path / "b"
    work_a.mkdir()
    work_b.mkdir()

    spec_a = dict(_TINY_OAS)
    spec_a["paths"] = {"/attacker_A": {"get": {"operationId": "attacker_A"}}}
    spec_b = dict(_TINY_OAS)
    spec_b["paths"] = {"/victim_B": {"get": {"operationId": "victim_B"}}}
    (work_a / "spec.json").write_text(json.dumps(spec_a))
    (work_b / "spec.json").write_text(json.dumps(spec_b))

    out_a = openapi_runner(_sb(work_a)).fn({"op": "list_ops", "spec": "spec.json"})
    out_b = openapi_runner(_sb(work_b)).fn({"op": "list_ops", "spec": "spec.json"})

    assert "attacker_A" in out_a
    assert "victim_B" in out_b
    assert "attacker_A" not in out_b


def test_openapi_blocks_absolute_etc_passwd(tmp_path):
    # An absolute system path is refused regardless of contents.
    from maverick.tools.openapi_runner import openapi_runner
    (tmp_path / "work").mkdir()
    out = openapi_runner(_sb(tmp_path / "work")).fn(
        {"op": "list_ops", "spec": "/etc/passwd"}
    )
    assert "outside the workspace" in out
