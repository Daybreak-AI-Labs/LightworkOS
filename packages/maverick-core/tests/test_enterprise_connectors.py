"""Generic REST connector factory + the enterprise-connector spec batch.

Network-free: ``httpx`` is faked. Covers auth modes, the confirm gate, request
routing, and that every spec'd connector registers.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from unittest.mock import MagicMock

import httpx


def _fake_httpx(monkeypatch, **methods):
    # The REST/GraphQL connectors now fetch through ``_ssrf.safe_client`` (host
    # resolve-once + IP-pin), not a bare ``httpx.request``/``httpx.post``. Patch
    # at that boundary instead: ``safe_client(url)`` yields a client whose
    # ``.request``/``.post`` are the supplied mocks, so the call shape the tests
    # assert on (method/url args, headers kwargs) is unchanged.
    client = MagicMock()
    for name, value in methods.items():
        setattr(client, name, value)

    @contextmanager
    def stream(method, url, **kwargs):
        if "request" in methods:
            response = methods["request"](method, url, **kwargs)
        else:
            kwargs.pop("params", None)
            response = methods[method.lower()](url, **kwargs)
        # Real streaming HTTPX response; retain the buffered fixture for repeat
        # calls while each connector invocation owns/closes a fresh byte stream.
        with closing(httpx.Response(response.status_code, headers=response.headers,
                                    stream=httpx.ByteStream(response.content))) as streamed:
            yield streamed
    client.stream = stream

    @contextmanager
    def _fake_safe_client(url, **kwargs):
        yield client

    from maverick.tools import _ssrf
    monkeypatch.setattr(_ssrf, "safe_client", _fake_safe_client)
    return client


def _resp(status, body):
    return httpx.Response(status, json=body)


def _tool(**kw):
    from maverick.tools._rest_connector import make_rest_tool
    spec = dict(name="acme", base_url_env="ACME_BASE_URL", token_env="ACME_TOKEN",
                description="Acme test connector")
    spec.update(kw)
    return make_rest_tool(**spec)


def _set(monkeypatch):
    monkeypatch.setenv("ACME_BASE_URL", "https://acme.example.com")
    monkeypatch.setenv("ACME_TOKEN", "tok123")


def test_requires_config(monkeypatch):
    monkeypatch.delenv("ACME_BASE_URL", raising=False)
    monkeypatch.delenv("ACME_TOKEN", raising=False)
    _fake_httpx(monkeypatch, request=MagicMock())
    out = _tool().fn({"op": "get", "path": "/things"})
    assert out == "ERROR: connector requires ACME_BASE_URL + ACME_TOKEN"


def test_config_error_names_only_missing_identifiers_not_values(monkeypatch):
    _fake_httpx(monkeypatch, request=MagicMock())
    base = "https://private-operator-host.example"
    monkeypatch.setenv("ACME_BASE_URL", base)
    monkeypatch.delenv("ACME_TOKEN", raising=False)

    out = _tool().fn({"op": "get", "path": "/things"})

    assert out == "ERROR: connector requires ACME_TOKEN"
    assert base not in out

    token = "low-entropy-active-value"  # pragma: allowlist secret
    monkeypatch.delenv("ACME_BASE_URL", raising=False)
    monkeypatch.setenv("ACME_TOKEN", token)
    out = _tool().fn({"op": "get", "path": "/things"})

    assert out == "ERROR: connector requires ACME_BASE_URL"
    assert token not in out


def test_invalid_config_identifiers_are_not_reflected(monkeypatch):
    _fake_httpx(monkeypatch, request=MagicMock())
    bad_base = "BAD-NAME"
    bad_token = "BAD.TOKEN"

    out = _tool(base_url_env=bad_base, token_env=bad_token).fn(
        {"op": "get", "path": "/things"}
    )

    assert out == "ERROR: connector configuration is incomplete"
    assert bad_base not in out and bad_token not in out


def test_get_routes_and_returns_json(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {"items": [{"id": 1}]}))
    _fake_httpx(monkeypatch, request=req)
    out = _tool().fn({"op": "get", "path": "/things", "params": {"q": "x"}})
    assert "items" in out
    assert req.call_args.args[0] == "GET"
    assert req.call_args.args[1] == "https://acme.example.com/things"


def test_rest_exception_never_returns_secret_detail(monkeypatch):
    _set(monkeypatch)
    secret = "postgres://admin:super-secret@db.internal/customer"  # pragma: allowlist secret
    req = MagicMock(side_effect=RuntimeError(secret))
    _fake_httpx(monkeypatch, request=req)

    out = _tool().fn({"op": "get", "path": "/things"})

    assert out == "ERROR: connector configuration or request failed (RuntimeError)"
    assert "super-secret" not in out and "postgres://" not in out


def test_rest_error_body_is_secret_scrubbed_and_bounded(monkeypatch):
    _set(monkeypatch)
    secret = "tok123"  # pragma: allowlist secret
    req = MagicMock(return_value=_resp(500, {"detail": secret + ("x" * 2000)}))
    _fake_httpx(monkeypatch, request=req)

    out = _tool().fn({"op": "get", "path": "/things"})

    assert out.startswith("ERROR: get (500)")
    assert secret not in out
    assert len(out) < 600


def test_write_needs_confirm(monkeypatch):
    _set(monkeypatch)
    req = MagicMock()
    _fake_httpx(monkeypatch, request=req)
    out = _tool().fn({"op": "post", "path": "/things", "body": {"a": 1}})
    assert "DRY RUN" in out
    req.assert_not_called()


def test_write_with_confirm_executes(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(201, {"ok": True}))
    _fake_httpx(monkeypatch, request=req)
    out = _tool().fn({"op": "post", "path": "/things", "body": {"a": 1}, "confirm": True})
    assert "ok" in out
    assert req.call_args.args[0] == "POST"


def test_existing_record_update_requires_and_sends_if_match(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {"ok": True}))
    _fake_httpx(monkeypatch, request=req)
    tool = _tool()

    missing = tool.fn({
        "op": "patch", "path": "/things/7", "body": {"name": "new"},
        "confirm": True,
    })
    assert "requires the current remote ETag/revision" in missing
    req.assert_not_called()

    out = tool.fn({
        "op": "patch", "path": "/things/7", "body": {"name": "new"},
        "if_match": '"revision-7"', "confirm": True,
    })
    assert "ok" in out
    assert req.call_args.kwargs["headers"]["If-Match"] == '"revision-7"'
    assert tool.input_schema["x-lightwork-conditional-revision"] == {
        "field": "if_match",
        "header": "If-Match",
        "operations": ["put", "patch", "delete"],
    }


def test_existing_record_update_rejects_wildcard_if_match(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {"ok": True}))
    _fake_httpx(monkeypatch, request=req)

    out = _tool().fn({
        "op": "patch", "path": "/things/7", "body": {"name": "new"},
        "if_match": "*", "confirm": True,
    })

    assert "single ETag/revision value" in out
    req.assert_not_called()


def test_bearer_auth_header(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {}))
    _fake_httpx(monkeypatch, request=req)
    _tool().fn({"op": "get", "path": "/x"})
    assert req.call_args.kwargs["headers"]["Authorization"] == "Bearer tok123"


def test_basic_auth_header(monkeypatch):
    import base64
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {}))
    _fake_httpx(monkeypatch, request=req)
    _tool(basic=True).fn({"op": "get", "path": "/x"})
    expected = "Basic " + base64.b64encode(b"tok123:x").decode()
    assert req.call_args.kwargs["headers"]["Authorization"] == expected


def test_scheme_override(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {}))
    _fake_httpx(monkeypatch, request=req)
    _tool(scheme="SSWS").fn({"op": "get", "path": "/x"})
    assert req.call_args.kwargs["headers"]["Authorization"] == "SSWS tok123"


def test_custom_header_raw_token(monkeypatch):
    _set(monkeypatch)
    req = MagicMock(return_value=_resp(200, {}))
    _fake_httpx(monkeypatch, request=req)
    _tool(token_header="X-Tableau-Auth", scheme="").fn({"op": "get", "path": "/x"})
    assert req.call_args.kwargs["headers"]["X-Tableau-Auth"] == "tok123"


def test_all_enterprise_connectors_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry
    from maverick.tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES

    class _W:
        def open_questions(self, gid):
            return []

    names = {t.name for t in base_registry(_W(), LocalBackend(workdir=tmp_path)).all()}
    for n in ENTERPRISE_CONNECTOR_NAMES:
        assert n in names, n
    # sanity: the batch is non-trivial and unique
    assert len(ENTERPRISE_CONNECTOR_NAMES) == len(set(ENTERPRISE_CONNECTOR_NAMES))
    assert len(ENTERPRISE_CONNECTOR_NAMES) >= 15


def _gql(**kw):
    from maverick.tools._rest_connector import make_graphql_tool
    spec = dict(name="acmegql", base_url_env="ACMEGQL_URL", token_env="ACMEGQL_TOKEN",
                description="Acme GraphQL")
    spec.update(kw)
    return make_graphql_tool(**spec)


def test_graphql_query_runs(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock(return_value=_resp(200, {"data": {"me": {"id": 1}}}))
    _fake_httpx(monkeypatch, post=post)
    out = _gql().fn({"op": "query", "query": "query { me { id } }"})
    assert "me" in out
    assert post.call_args.args[0] == "https://gql.example.com"


def test_graphql_mutation_needs_confirm(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    out = _gql().fn({"op": "query", "query": "mutation { delete_item(id: 1) { id } }"})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_graphql_mutation_with_leading_comment_needs_confirm(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    out = _gql().fn({
        "op": "query",
        "query": "# leading comment\nmutation { delete_item(id: 1) { id } }",
    })
    assert "DRY RUN" in out
    post.assert_not_called()


def test_graphql_mutation_with_leading_bom_needs_confirm(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    out = _gql().fn({
        "op": "query",
        "query": "\ufeffmutation { delete_item(id: 1) { id } }",
    })
    assert "DRY RUN" in out
    post.assert_not_called()


def test_graphql_mutation_after_escaped_block_string_needs_confirm(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    document = (
        'query Q { echo(text: """ignored \\""" {""") }\n'
        "mutation M { delete_item(id: 1) { id } }"
    )
    out = _gql().fn({"op": "query", "query": document})
    assert "DRY RUN" in out
    post.assert_not_called()


def test_graphql_mutation_after_fragment_needs_confirm(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock()
    _fake_httpx(monkeypatch, post=post)
    out = _gql().fn({
        "op": "query",
        "query": (
            "fragment ItemFields on Item { id }\n"
            "mutation { delete_item(id: 1) { ...ItemFields } }"
        ),
    })
    assert "DRY RUN" in out
    post.assert_not_called()


def test_graphql_requires_config(monkeypatch):
    monkeypatch.delenv("ACMEGQL_URL", raising=False)
    monkeypatch.delenv("ACMEGQL_TOKEN", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    out = _gql().fn({"op": "query", "query": "query { x }"})
    assert out == "ERROR: connector requires ACMEGQL_URL + ACMEGQL_TOKEN"


def test_graphql_runtime_error_never_returns_secret_detail(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    secret = "opaque-low-entropy-value"  # pragma: allowlist secret
    post = MagicMock(side_effect=RuntimeError(secret))
    _fake_httpx(monkeypatch, post=post)

    out = _gql().fn({"op": "query", "query": "query { x }"})

    assert out.startswith("INDETERMINATE: connector request may have executed")
    assert out.attempt.outcome_unknown
    post.assert_called_once()
    assert secret not in out


def test_no_collision_with_opt_in_ambient_cred_tools():
    """Names reserved for the ambient-credential tools (registered only when
    MAVERICK_ENABLE_CRED_TOOLS=true) must never appear in the always-on
    enterprise_connectors catalog, or the opt-in gate is silently bypassed."""
    from maverick.tools import AMBIENT_CRED_TOOL_NAMES
    from maverick.tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES

    assert AMBIENT_CRED_TOOL_NAMES.isdisjoint(ENTERPRISE_CONNECTOR_NAMES)


def test_every_bespoke_deferred_connector_is_ambient_blocked_or_scoped(tmp_path):
    """A new hand-written connector cannot silently borrow operator env auth."""
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import (
        AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES,
        base_registry,
    )
    from maverick.world_model import open_world

    reg = base_registry(
        open_world(None), LocalBackend(workdir=tmp_path),
        _include_generated_tools=False,
    )
    unscoped = {
        tool.name
        for tool in reg.all()
        if tool.name in reg.deferrable_names
        and getattr(tool.fn, "__module__", "") != "maverick.tools._rest_connector"
        and tool.name not in AUTHENTICATED_AMBIENT_CRED_TOOL_NAMES
    }
    assert unscoped == set()


def test_automation_platform_connectors_present():
    from maverick.tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES, connector_catalog

    for name in ("zapier", "n8n", "power_automate", "make", "workato"):
        assert name in ENTERPRISE_CONNECTOR_NAMES

    catalog = {e["name"]: e for e in connector_catalog()}
    assert catalog["n8n"]["env"] == [("N8N_BASE_URL", False), ("N8N_TOKEN", True)]
    assert catalog["power_automate"]["env"] == [
        ("POWER_AUTOMATE_BASE_URL", False), ("POWER_AUTOMATE_TOKEN", True),
    ]


def test_slack_and_google_calendar_connectors_present():
    from maverick.tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES, connector_catalog

    for name in ("slack_api", "google_calendar"):
        assert name in ENTERPRISE_CONNECTOR_NAMES

    catalog = {e["name"]: e for e in connector_catalog()}
    assert catalog["slack_api"]["env"] == [
        ("SLACK_API_BASE_URL", False), ("SLACK_API_TOKEN", True),
    ]
    assert catalog["google_calendar"]["env"] == [
        ("GOOGLE_CALENDAR_BASE_URL", False), ("GOOGLE_CALENDAR_TOKEN", True),
    ]


def test_graphql_errors_field_is_error(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok")
    post = MagicMock(return_value=_resp(200, {"errors": [{"message": "bad field"}]}))
    _fake_httpx(monkeypatch, post=post)
    out = _gql().fn({"op": "query", "query": "query { nope }"})
    assert out == "ERROR: graphql (200): upstream request failed"


def test_graphql_failure_never_echoes_low_entropy_active_token(monkeypatch):
    monkeypatch.setenv("ACMEGQL_URL", "https://gql.example.com")
    monkeypatch.setenv("ACMEGQL_TOKEN", "tok123")
    post = MagicMock(return_value=_resp(401, {
        "errors": [{"message": "Authorization: Bearer tok123"}],
    }))
    _fake_httpx(monkeypatch, post=post)

    out = _gql().fn({"op": "query", "query": "query { nope }"})

    assert out == "ERROR: graphql (401): upstream request failed"
    assert "tok123" not in out
