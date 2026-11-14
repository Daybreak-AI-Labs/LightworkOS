"""Fresh-human and conditional-revision governance for connector writes."""
from __future__ import annotations

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from maverick.governed_tools import (
    _is_governed_write,
    apply_governed_connectors,
    governance_enabled,
    wrap_connector_tool,
)
from maverick.tools import Tool, ToolRegistry

_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["get", "post", "put", "patch", "delete"]},
        "path": {"type": "string"},
        "if_match": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op", "path"],
    "x-lightwork-conditional-revision": {
        "field": "if_match",
        "header": "If-Match",
        "operations": ["put", "patch", "delete"],
    },
}


def _fake_tool(calls):
    def _fn(args):
        calls.append(dict(args))
        return f"DID {args.get('op')} {args.get('path')} confirm={args.get('confirm')}"
    return Tool(name="acme", description="Acme connector", input_schema=_SCHEMA, fn=_fn)


def _grant_human(monkeypatch):
    import maverick.safety.consent as consent

    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: SimpleNamespace(
            granted=True, source="dashboard", actor="user:reviewer",
        ),
    )



def _graphql_tool(calls):
    schema = {
        "type": "object",
        "properties": {
            "op": {"type": "string", "enum": ["query"]},
            "query": {"type": "string", "description": "GraphQL query or mutation."},
            "variables": {"type": "object"},
            "confirm": {"type": "boolean"},
        },
        "required": ["op", "query"],
    }

    def _fn(args):
        calls.append(dict(args))
        return f"GQL {args.get('op')} confirm={args.get('confirm')}"

    return Tool(name="monday", description="monday GraphQL", input_schema=schema, fn=_fn)


def _salesforce_tool(calls):
    schema = {
        "type": "object",
        "properties": {
            "op": {
                "type": "string",
                "enum": ["soql", "record_create", "record_update", "record_delete"],
            },
            "sobject": {"type": "string"},
            "id": {"type": "string"},
            "fields": {"type": "object"},
            "confirm": {"type": "boolean"},
        },
        "required": ["op"],
    }

    def _fn(args):
        calls.append(dict(args))
        return f"SF {args.get('op')} {args.get('sobject')} confirm={args.get('confirm')}"

    return Tool(name="salesforce", description="Salesforce", input_schema=schema, fn=_fn)


def _teams_style_tool(calls):
    """A bespoke external writer with no legacy ``confirm`` field."""
    schema = {
        "type": "object",
        "properties": {
            "op": {"type": "string", "enum": ["send", "history"]},
            "text": {"type": "string"},
        },
        "required": ["op"],
    }

    def _fn(args):
        calls.append(dict(args))
        return f"TEAMS {args.get('op')}"

    return Tool(name="teams", description="Teams", input_schema=schema, fn=_fn)


def _op_tool(name, operations, calls, *, confirm=True):
    properties = {
        "op": {"type": "string", "enum": list(operations)},
        "path": {"type": "string"},
    }
    if confirm:
        properties["confirm"] = {"type": "boolean"}

    def _fn(args):
        calls.append(dict(args))
        return f"{name}:{args.get('op')}"

    return Tool(
        name=name,
        description=f"{name} connector",
        input_schema={
            "type": "object", "properties": properties, "required": ["op"],
        },
        fn=_fn,
    )


class TestWrap:
    def test_real_registry_refuses_unapproved_default_teams(self, monkeypatch):
        import maverick.config as cfg
        import maverick.safety.consent as consent
        from maverick.tools import teams_tool

        monkeypatch.setattr(cfg, "get_governed_connectors", lambda: {"connectors": [], "approver": ""})
        monkeypatch.setattr("maverick.governed_tools._enterprise_mode", lambda: False)
        def deny(*_args, **_kwargs):
            raise consent.ConsentDenied("not approved")
        monkeypatch.setattr(consent, "require_operation_consent", deny)
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://teams.example.test/channel-secret")
        reg = ToolRegistry()
        reg.register(teams_tool.teams_tool())
        assert apply_governed_connectors(reg) == ["teams"]
        result = asyncio.run(reg.run("teams", {"text": "hello"}))
        assert "REFUSED (governed)" in result

    def test_default_teams_send_requires_human_decision(self, monkeypatch):
        from maverick.safety import consent
        calls = []
        tool = _teams_style_tool(calls)
        def deny(*_args, **_kwargs):
            raise consent.ConsentDenied("not approved")
        monkeypatch.setattr(consent, "require_operation_consent", deny)
        result = wrap_connector_tool(tool).fn({"text": "hello"})
        assert "REFUSED (governed)" in result
        assert not calls

    def test_read_passes_through(self):
        calls = []
        wrapped = wrap_connector_tool(_fake_tool(calls))
        out = wrapped.fn({"op": "get", "path": "/x"})
        assert "DID get /x" in out
        assert calls == [{"op": "get", "path": "/x"}]

    def test_write_without_approver_is_refused(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["acme"], "approver": ""})
        calls = []
        wrapped = wrap_connector_tool(_fake_tool(calls))
        out = wrapped.fn({"op": "post", "path": "/accounts", "body": {"n": 1}})
        assert "REFUSED (governed)" in out
        assert "approval was denied" in out
        assert calls == []  # the underlying write never ran

    def test_write_with_fresh_human_decision_commits(self, monkeypatch):
        _grant_human(monkeypatch)
        calls = []
        wrapped = wrap_connector_tool(_fake_tool(calls))
        out = wrapped.fn({"op": "post", "path": "/accounts"})
        # The original write ran, with confirm forced true (approval cleared it).
        assert calls and calls[0]["confirm"] is True
        assert "DID post /accounts" in out

    def test_success_result_redacts_lightwork_capability_token(self, monkeypatch):
        import maverick.governed_actions as actions

        _grant_human(monkeypatch)
        monkeypatch.setattr(actions, "record_tool_lineage", lambda *a, **k: True)
        token = "lw-rest-" + "R" * 43
        tool = Tool(
            name="acme",
            description="Acme connector",
            input_schema=_SCHEMA,
            fn=lambda _args: f"created with credential {token}",
        )

        out = wrap_connector_tool(tool).fn({"op": "post", "path": "/accounts"})

        assert token not in out
        assert "REDACTED:lightwork_agent_token" in out

    def test_existing_record_write_without_revision_still_requires_human(
        self, monkeypatch,
    ):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        calls = []

        out = wrap_connector_tool(_fake_tool(calls)).fn({
            "op": "patch", "path": "/accounts/7", "body": {"role": "admin"},
        })

        assert out.startswith("REFUSED (governed)")
        assert "approval was denied" in out
        assert calls == []

    def test_approved_existing_record_write_explains_missing_revision(self, monkeypatch):
        import maverick.safety.consent as consent

        seen = []
        monkeypatch.setattr(
            consent, "require_consent",
            lambda *_args, **kwargs: (
                seen.append(kwargs) or SimpleNamespace(
                    granted=True, source="dashboard", actor="user:reviewer",
                )
            ),
        )
        calls = []
        out = wrap_connector_tool(_fake_tool(calls)).fn({
            "op": "patch", "path": "/accounts/7", "body": {"role": "admin"},
        })
        assert "DID patch /accounts/7" in out
        assert len(calls) == 1 and calls[0]["confirm"] is True
        assert "no remote revision check" in str(seen).lower()

    def test_wildcard_precondition_cannot_authorize_existing_record_write(
        self, monkeypatch,
    ):
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent,
            "require_consent",
            lambda *_args, **_kwargs: pytest.fail(
                "approval must not start with an unconditional wildcard"
            ),
        )
        calls = []

        out = wrap_connector_tool(_fake_tool(calls)).fn({
            "op": "delete", "path": "/accounts/7", "if_match": "*",
        })

        assert out.startswith("REFUSED (governed)")
        assert "ETag/revision is required" in out
        assert "/accounts/7" in out
        assert calls == []

    def test_description_marks_governed(self):
        wrapped = wrap_connector_tool(_fake_tool([]))
        assert "governed" in wrapped.description

    def test_graphql_query_passes_through(self):
        calls = []
        wrapped = wrap_connector_tool(_graphql_tool(calls))
        out = wrapped.fn({"op": "query", "query": "query { boards { id } }"})
        assert "GQL query" in out
        assert calls == [{"op": "query", "query": "query { boards { id } }"}]

    def test_graphql_mutation_without_approver_is_refused(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["monday"], "approver": ""})
        calls = []
        wrapped = wrap_connector_tool(_graphql_tool(calls))
        out = wrapped.fn({"op": "query", "query": "mutation { create_item { id } }", "confirm": True})
        assert "REFUSED (governed)" in out
        assert calls == []

    def test_graphql_bom_prefixed_mutation_is_governed(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(
            cfg, "get_governed_connectors",
            lambda: {"enable": True, "connectors": ["monday"], "approver": ""},
        )
        calls = []
        wrapped = wrap_connector_tool(_graphql_tool(calls))
        out = wrapped.fn({
            "op": "query", "query": "\ufeffmutation { create_item { id } }",
        })
        assert "REFUSED (governed)" in out
        assert calls == []

    def test_graphql_mutation_after_escaped_block_string_is_governed(
        self, monkeypatch,
    ):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(
            cfg, "get_governed_connectors",
            lambda: {"enable": True, "connectors": ["monday"], "approver": ""},
        )
        calls = []
        document = (
            'query Q { echo(text: """ignored \\""" {""") }\n'
            "mutation M { create_item { id } }"
        )
        out = wrap_connector_tool(_graphql_tool(calls)).fn({
            "op": "query", "query": document,
        })
        assert "REFUSED (governed)" in out
        assert calls == []

    def test_graphql_mutation_without_conditional_contract_needs_human(self, monkeypatch):
        _grant_human(monkeypatch)
        calls = []
        wrapped = wrap_connector_tool(_graphql_tool(calls))
        out = wrapped.fn({"op": "query", "query": "mutation { create_item { id } }"})
        assert "GQL query confirm=True" in out
        assert len(calls) == 1 and calls[0]["confirm"] is True


class TestApply:
    def test_disable_configuration_cannot_remove_boundary(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_CONNECTORS", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": False, "connectors": ["acme"], "approver": ""})
        reg = ToolRegistry()
        reg.register(_fake_tool([]))
        assert apply_governed_connectors(reg) == ["acme"]
        assert "governed" in reg.get("acme").description

    def test_enabled_wraps_configured(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "1")
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["acme"], "approver": "ops"})
        reg = ToolRegistry()
        reg.register(_fake_tool([]))
        assert apply_governed_connectors(reg) == ["acme"]
        assert "governed" in reg.get("acme").description

    def test_enabled_wraps_bespoke_salesforce_schema(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "1")
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["salesforce"], "approver": ""})
        calls = []
        reg = ToolRegistry()
        reg.register(_salesforce_tool(calls))
        assert apply_governed_connectors(reg) == ["salesforce"]
        assert "governed" in reg.get("salesforce").description
        out = reg.get("salesforce").fn({
            "op": "record_create",
            "sobject": "Account",
            "fields": {"Name": "poc"},
            "confirm": True,
        })
        assert "REFUSED (governed)" in out
        assert calls == []

    def test_skips_non_op_tool(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "1")
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["plain"], "approver": "ops"})
        reg = ToolRegistry()
        reg.register(Tool(name="plain", description="no op schema",
                          input_schema={"type": "object", "properties": {}}, fn=lambda a: "x"))
        assert apply_governed_connectors(reg) == []  # left ungoverned, not crashed

    def test_unknown_connector_skipped(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "1")
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["absent"], "approver": "ops"})
        assert apply_governed_connectors(ToolRegistry()) == []


class TestThroughRegistryRun:
    def test_governed_write_runs_via_registry(self, monkeypatch):
        # End-to-end through ToolRegistry.run (async), proving the wrapper's sync
        # fn executes correctly in the agent's tool-execution path.
        _grant_human(monkeypatch)
        calls = []
        reg = ToolRegistry()
        reg.register(wrap_connector_tool(_fake_tool(calls)))
        out = asyncio.run(reg.run(
            "acme", {"op": "put", "path": "/x", "if_match": '"rev-7"'},
        ))
        assert "DID put /x" in out and calls[0]["confirm"] is True

    def test_governance_cannot_be_disabled_by_legacy_flag(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "1")
        assert governance_enabled() is True
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "0")
        assert governance_enabled() is True


class TestEnterpriseBoundary:
    def test_enterprise_is_mandatory_even_with_disable_override(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "0")
        monkeypatch.setattr("maverick.governed_tools._enterprise_mode", lambda: True)
        assert governance_enabled() is True

    def test_enterprise_discovers_every_compatible_connector(self, monkeypatch):
        import maverick.config as cfg

        monkeypatch.setattr("maverick.governed_tools._enterprise_mode", lambda: True)
        monkeypatch.setattr(
            cfg,
            "get_governed_connectors",
            lambda: {"enable": False, "connectors": [], "approver": ""},
        )
        reg = ToolRegistry()
        reg.register(_fake_tool([]))
        reg.register(Tool(
            name="plain", description="read-only", parallel_safe=True,
            input_schema={"type": "object", "properties": {}}, fn=lambda _a: "ok",
        ))
        assert apply_governed_connectors(reg) == ["acme"]
        assert "transaction-receipted" in reg.get("acme").description
        assert "governed" not in reg.get("plain").description

    def test_enterprise_governs_bespoke_writer_without_confirm_field(
        self, monkeypatch,
    ):
        import maverick.config as cfg
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr("maverick.governed_tools._enterprise_mode", lambda: True)
        monkeypatch.setattr(
            cfg,
            "get_governed_connectors",
            lambda: {"enable": False, "connectors": [], "approver": ""},
        )
        monkeypatch.setattr(
            consent,
            "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )
        receipts = []
        monkeypatch.setattr(
            actions,
            "record_tool_lineage",
            lambda *a, **k: receipts.append(k) or True,
        )
        calls = []
        reg = ToolRegistry(principal="user:alice")
        reg.register(_teams_style_tool(calls))

        assert apply_governed_connectors(reg, goal_id=31) == ["teams"]
        out = reg.get("teams").fn({"op": "send", "text": "production notice"})

        assert out == "TEAMS send"
        assert calls == [{
            "op": "send", "text": "production notice", "confirm": True,
        }]
        assert [receipt["phase"] for receipt in receipts] == ["PREPARE", "COMMIT"]
        assert all(receipt["actor"] == "user:alice" for receipt in receipts)

    def test_bespoke_read_operation_passes_through_without_approval(self, monkeypatch):
        import maverick.config as cfg
        import maverick.safety.consent as consent

        monkeypatch.setattr("maverick.governed_tools._enterprise_mode", lambda: True)
        monkeypatch.setattr(
            cfg,
            "get_governed_connectors",
            lambda: {"enable": False, "connectors": [], "approver": ""},
        )
        monkeypatch.setattr(
            consent,
            "require_consent",
            lambda *a, **k: pytest.fail("read operation requested approval"),
        )
        calls = []
        reg = ToolRegistry()
        reg.register(_teams_style_tool(calls))
        assert apply_governed_connectors(reg) == ["teams"]

        assert reg.get("teams").fn({"op": "history"}) == "TEAMS history"
        assert calls == [{"op": "history"}]

    @pytest.mark.parametrize(
        ("name", "operation"),
        [
            ("asana", "task_create"),
            ("s3", "put"),
            ("ses", "send"),
            ("redis", "set"),
            ("clickup", "task_create"),
            ("replicate", "run"),
        ],
    )
    def test_custom_connector_writes_cannot_fall_through(
        self, monkeypatch, name, operation,
    ):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg

        monkeypatch.setattr(
            cfg, "get_governed_connectors",
            lambda: {"enable": True, "connectors": [name], "approver": ""},
        )
        calls = []
        wrapped = wrap_connector_tool(
            _op_tool(name, [operation], calls, confirm=name != "replicate"),
        )

        out = wrapped.fn({"op": operation, "path": "/production"})

        assert out.startswith("REFUSED (governed)")
        assert calls == []

    @pytest.mark.parametrize(
        ("name", "operation"),
        [
            ("asana", "task_create"), ("asana", "task_complete"),
            ("calendly", "cancel"), ("clickup", "task_create"),
            ("cloudflare", "dns_create"), ("cloudflare", "dns_update"),
            ("cloudflare", "dns_delete"), ("cloudflare", "purge"),
            ("confluence", "page_create"), ("confluence", "page_update"),
            ("databricks", "job_run"), ("datadog", "submit_event"),
            ("datadog", "submit_metric"), ("dropbox", "upload"),
            ("dropbox", "share"), ("elasticsearch", "index"),
            ("github_actions", "dispatch"), ("github_actions", "cancel"),
            ("gmail", "send"), ("home_assistant", "call_service"),
            ("hubspot", "contact_create"), ("hubspot", "contact_update"),
            ("lambda", "invoke"), ("mongodb", "insert"),
            ("msgraph", "send_mail"), ("pagerduty", "acknowledge"),
            ("pagerduty", "resolve"), ("pagerduty", "trigger"),
            ("redis", "set"), ("redis", "lpush"), ("redis", "publish"),
            ("replicate", "run"), ("replicate", "cancel"),
            ("sentry", "resolve"), ("ses", "send"),
            ("shopify", "refund_create"), ("sns", "publish"),
            ("sns", "sms"), ("sns", "subscribe"), ("sns", "unsubscribe"),
            ("spotify", "play"), ("spotify", "pause"),
            ("stripe", "refund_create"), ("trello", "card_create"),
            ("trello", "card_move"), ("trello", "comment"),
            ("twilio", "sms_send"), ("twilio", "call_create"),
            ("vercel", "cancel"), ("zoom", "meeting_create"),
            ("zoom", "meeting_delete"), ("s3", "put"),
        ],
    )
    def test_reviewed_mutating_inventory_is_governed(self, name, operation):
        tool = _op_tool(name, [operation], [], confirm=name != "replicate")
        assert _is_governed_write(tool, {"op": operation}) is True

    def test_confirm_schema_unknown_operation_fails_closed(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg

        monkeypatch.setattr(
            cfg, "get_governed_connectors",
            lambda: {"enable": True, "connectors": ["future"], "approver": ""},
        )
        calls = []
        wrapped = wrap_connector_tool(
            _op_tool("future", ["future_mutation"], calls),
        )

        assert wrapped.fn({"op": "future_mutation"}).startswith("REFUSED (governed)")
        assert calls == []

    def test_custom_connector_read_still_passes_without_approval(self, monkeypatch):
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent,
            "require_consent",
            lambda *a, **k: pytest.fail("safe read requested approval"),
        )
        calls = []
        wrapped = wrap_connector_tool(
            _op_tool("asana", ["task_get", "task_create"], calls),
            enterprise=True,
        )

        assert wrapped.fn({"op": "task_get"}) == "asana:task_get"
        assert calls == [{"op": "task_get"}]

    @pytest.mark.parametrize(("name", "operation", "field"), [
        ("database", "query", "sql"),
        ("bigquery", "query", "sql"),
        ("snowflake", "query", "statement"),
        ("oracle", "sql", "statement"),
        ("databricks", "sql", "statement"),
    ])
    def test_only_exact_constant_sql_probe_passes_without_governed_write(
        self, monkeypatch, name, operation, field,
    ):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg

        monkeypatch.setattr(
            cfg, "get_governed_connectors",
            lambda: {"enable": True, "connectors": [name], "approver": ""},
        )
        calls = []
        tool = _op_tool(name, [operation], calls)
        wrapped = wrap_connector_tool(tool)
        assert "constant SELECT 1 connection check" in wrapped.description
        assert "require a fresh human review" in wrapped.description
        assert "read runs" not in wrapped.description
        assert "simple reads run" not in wrapped.description

        for statement in ("SELECT 1", " select\t1; \n"):
            args = {"op": operation, field: statement}
            assert wrapped.fn(args) == f"{name}:{operation}"
            assert calls[-1] == args

        calls.clear()
        for statement in (
            "SELECT 1 FROM customers",
            "SELECT 1 INTO result",
            "SELECT 'owned' INTO OUTFILE '/tmp/pwn'",
            "DELETE FROM customers",
            "SELECT 1; DELETE FROM customers",
            "SELECT 1 -- comment",
            "SELECT 1 + nextval('sequence')",
            "PRAGMA user_version = 7",
            "/*M! DELETE FROM customers */ SELECT 1",
        ):
            assert wrapped.fn({
                "op": operation, field: statement,
            }).startswith("REFUSED (governed)"), statement
        assert calls == []

    def test_database_probe_reaches_real_read_path_through_registry(self, monkeypatch):
        from maverick.tools.database_tool import database_tool

        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
        reg = ToolRegistry()
        reg.register(wrap_connector_tool(database_tool()))

        out = asyncio.run(reg.run("database", {
            "op": "query", "sql": "SELECT 1", "response_format": "json",
        }))
        result = json.loads(out)
        assert result["rows"] == [[1]]
        assert result["transaction_status"] == "read_only"

    def test_customer_sql_query_reaches_connector_after_human_review(
        self, monkeypatch, tmp_path,
    ):
        import sqlite3

        from maverick.tools.database_tool import database_tool

        _grant_human(monkeypatch)
        database = tmp_path / "customers.db"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE customers (name TEXT)")
            connection.execute("INSERT INTO customers VALUES ('Acme')")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database.as_posix()}")
        reg = ToolRegistry()
        reg.register(wrap_connector_tool(database_tool()))
        out = asyncio.run(reg.run("database", {
            "op": "query", "sql": "SELECT name FROM customers",
            "response_format": "json",
        }))
        assert json.loads(out)["rows"] == [["Acme"]]

    def test_no_revision_rest_write_requires_bound_human_decision(self, monkeypatch):
        from maverick.tools._rest_connector import _rest_validate

        def rest_call(args):
            validated = _rest_validate(
                args, name="acme", read_only=False, read_prefixes=(),
                read_path_allowed=lambda _path: True, norm=lambda path: path,
            )
            return "accepted" if validated == ("patch", "/accounts/7") else str(validated)

        tool = Tool(
            name="acme", description="Acme REST", input_schema=_SCHEMA, fn=rest_call,
        )
        args = {"op": "patch", "path": "/accounts/7", "body": {"role": "admin"}}
        assert "requires the current remote ETag" in rest_call({**args, "confirm": True})
        _grant_human(monkeypatch)
        assert wrap_connector_tool(tool).fn(args) == "accepted"
        assert "requires the current remote ETag" in rest_call({**args, "confirm": True})

    def test_lambda_dryrun_is_non_effecting_but_live_invoke_is_governed(
        self, monkeypatch,
    ):
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        import maverick.config as cfg

        monkeypatch.setattr(
            cfg, "get_governed_connectors",
            lambda: {"enable": True, "connectors": ["lambda"], "approver": ""},
        )
        calls = []
        wrapped = wrap_connector_tool(_op_tool("lambda", ["invoke"], calls))

        assert wrapped.fn({
            "op": "invoke", "invocation_type": "DryRun",
        }) == "lambda:invoke"
        assert wrapped.fn({
            "op": "invoke", "invocation_type": "Event",
        }).startswith("REFUSED (governed)")
        assert calls == [{
            "op": "invoke", "invocation_type": "DryRun",
        }]

    def test_enterprise_rejects_invalid_explicit_policy(self, monkeypatch):
        import maverick.config as cfg

        monkeypatch.setattr("maverick.governed_tools._enterprise_mode", lambda: True)
        monkeypatch.setattr(
            cfg,
            "get_governed_connectors",
            lambda: {"enable": True, "connectors": ["missing"], "approver": ""},
        )
        with pytest.raises(RuntimeError, match="missing or incompatible"):
            apply_governed_connectors(ToolRegistry())

    def test_unreadable_enterprise_policy_cannot_remove_wrappers(self, monkeypatch):
        import maverick.config as cfg
        import maverick.enterprise as enterprise

        monkeypatch.setattr(
            cfg,
            "config_source_errors",
            lambda **_kwargs: {"config.toml": "unreadable"},
        )
        monkeypatch.setattr(enterprise, "enterprise_enabled", lambda: False)
        monkeypatch.setattr(
            cfg,
            "get_governed_connectors",
            lambda: {"enable": False, "connectors": [], "approver": ""},
        )
        registry = ToolRegistry()
        registry.register(_fake_tool([]))

        assert governance_enabled() is True
        assert apply_governed_connectors(registry) == ["acme"]
        assert "[governed:" in registry.get("acme").description

    def test_enterprise_policy_exception_cannot_remove_wrappers(self, monkeypatch):
        import maverick.config as cfg
        import maverick.enterprise as enterprise

        monkeypatch.setattr(cfg, "config_source_errors", lambda **_kwargs: {})
        monkeypatch.setattr(
            enterprise,
            "enterprise_enabled",
            lambda: (_ for _ in ()).throw(OSError("policy unavailable")),
        )

        assert governance_enabled() is True

    def test_fresh_human_consent_and_prepare_commit_receipts(self, monkeypatch):
        import maverick.config as cfg
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        monkeypatch.setattr(
            cfg,
            "get_governed_connectors",
            lambda: {"enable": True, "connectors": ["acme"], "approver": ""},
        )
        consent_calls = []

        def _consent(*args, **kwargs):
            consent_calls.append((args, kwargs))
            return SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            )

        receipts = []

        def _record(*args, **kwargs):
            receipts.append((args, kwargs))
            return True

        monkeypatch.setattr(consent, "require_consent", _consent)
        monkeypatch.setattr(actions, "record_tool_lineage", _record)
        calls = []
        wrapped = wrap_connector_tool(
            _fake_tool(calls), goal_id=17, actor="user:alice", enterprise=True,
        )
        out = wrapped.fn({"op": "post", "path": "/accounts", "body": {"n": 1}})

        assert "DID post /accounts" in out
        assert calls[0]["confirm"] is True
        assert consent_calls[0][1]["allow_auto_approve"] is False
        assert consent_calls[0][1]["consult_ledger"] is False
        assert consent_calls[0][1]["scope"].startswith("/accounts#sha256=")
        assert "request_sha256=" in consent_calls[0][1]["detail"]
        assert '"body":{"n":1}' in " ".join(
            consent_calls[0][1]["approval_card"]["parameters"]["summary"]
        )
        assert [entry[1]["phase"] for entry in receipts] == ["PREPARE", "COMMIT"]
        assert receipts[0][1]["strict"] is True
        assert receipts[0][1]["transaction_id"] == receipts[1][1]["transaction_id"]
        assert receipts[0][1]["actor"] == "user:alice"
        assert receipts[0][1]["approver"] == "user:reviewer"
        assert receipts[0][0][0] == 17

    def test_async_connector_write_is_awaited_before_commit(self, monkeypatch):
        import maverick.governed_actions as actions

        _grant_human(monkeypatch)
        receipts = []
        monkeypatch.setattr(actions, "record_tool_lineage",
                            lambda *a, **k: receipts.append(k["phase"]) or True)
        calls = []

        async def _afn(args):
            await asyncio.sleep(0)
            calls.append(dict(args))
            return "created"

        tool = Tool(name="acme", description="Acme", input_schema=_SCHEMA, fn=_afn)
        wrapped = wrap_connector_tool(tool, enterprise=True)

        out = asyncio.run(wrapped.fn({"op": "post", "path": "/accounts"}))

        assert out == "created"
        assert calls and calls[0]["confirm"] is True
        assert receipts == ["PREPARE", "COMMIT"]

    def test_unreadable_config_refuses_instead_of_dropping_approver_pin(self, monkeypatch):
        import maverick.config as cfg

        _grant_human(monkeypatch)
        monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
        monkeypatch.setattr(cfg, "get_governed_connectors", lambda: {"approver": ""})
        monkeypatch.setattr(cfg, "config_source_errors",
                            lambda **_k: {"config.toml": "parse error"})
        calls = []

        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn(
            {"op": "post", "path": "/accounts"})

        assert out.startswith("ERROR (governed)")
        assert calls == []

    def test_approval_card_redacts_nested_sensitive_values(self, monkeypatch):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        cards = []

        def _consent(*_args, **kwargs):
            cards.append(kwargs["approval_card"])
            return SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            )

        monkeypatch.setattr(consent, "require_consent", _consent)
        monkeypatch.setattr(actions, "record_tool_lineage", lambda *a, **k: True)
        calls = []
        request = {
            "op": "post", "path": "/accounts",
            "body": {
                "role": "viewer",
                "credentials": {
                    "username": "hidden-user",
                    "nested": [{"apiKey": "hidden-api-key", "token": "hidden-token"}],  # pragma: allowlist secret
                },
                "access_key": "hidden-access-key",
                "private_key": "hidden-private-key",  # pragma: allowlist secret
                "client_secret": "hidden-client-secret",  # pragma: allowlist secret
                "client_key": "hidden-client-key",  # pragma: allowlist secret
                "connectionString": "hidden-connection-string",
                "dsn": "hidden-dsn",
                "password": "hidden-password",  # pragma: allowlist secret
                "certificate": "hidden-certificate",
            },
            "headers": {
                "Authorization": "hidden-authorization",
                "Cookie": "hidden-cookie",
                "auth": "hidden-auth",
            },
        }

        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn(request)

        assert out.startswith("DID post")
        assert cards and calls
        card = cards[0]
        summary = card["parameters"]["summary"]
        assert all(len(part) <= 500 for part in summary)
        displayed = "".join(
            part.split(": ", 1)[1]
            for part in summary if part.startswith("Request part ")
        )
        shown = json.loads(displayed)
        marker = "[REDACTED:sensitive field]"
        assert shown["body"]["role"] == "viewer"
        assert shown["body"]["credentials"] == {
            "username": marker,
            "nested": [{"apiKey": marker, "token": marker}],
        }
        for key in (
            "access_key", "private_key", "client_secret", "client_key",
            "connectionString", "dsn", "password", "certificate",
        ):
            assert shown["body"][key] == marker
        assert shown["headers"] == {
            "Authorization": marker, "Cookie": marker, "auth": marker,
        }
        persisted = json.dumps(card)
        assert "hidden-" not in persisted
        frozen = {**request, "confirm": True}
        request_sha256 = hashlib.sha256(
            json.dumps(frozen, sort_keys=True, separators=(",", ":"), default=str).encode(),
        ).hexdigest()
        assert f"#sha256={request_sha256}" in card["target"]["label"]

    def test_overlong_approval_request_refuses_before_consent(self, monkeypatch):
        import maverick.safety.consent as consent

        consent_calls = []
        monkeypatch.setattr(
            consent, "require_consent", lambda *a, **k: consent_calls.append((a, k)),
        )
        calls = []

        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn({
            "op": "post", "path": "/accounts", "body": {"note": "x" * 8000},
        })

        assert out.startswith("REFUSED (governed)")
        assert "full connector request is too long to review" in out
        assert consent_calls == []
        assert calls == []

    def test_enterprise_refuses_an_unattributed_dashboard_approval(
        self, monkeypatch,
    ):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent,
            "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="",
            ),
        )
        receipts = []
        monkeypatch.setattr(
            actions, "record_tool_lineage",
            lambda *a, **k: receipts.append(k) or True,
        )
        calls = []

        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn({
            "op": "post", "path": "/accounts", "body": {"n": 1},
        })

        assert out.startswith("REFUSED (governed)")
        assert "authenticated approver identity" in out
        assert receipts == []
        assert calls == []

    def test_approval_binds_a_frozen_request_and_actual_approver(
        self, monkeypatch,
    ):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setenv("MAVERICK_GOVERNED_APPROVER", "user:reviewer")
        request = {
            "op": "post", "path": "/accounts", "body": {"role": "viewer"},
        }

        def _consent(*_args, **_kwargs):
            # Simulate a caller retaining and mutating the submitted object
            # while the approval round trip is in progress.
            request["body"]["role"] = "admin"
            return SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            )

        receipts = []
        monkeypatch.setattr(consent, "require_consent", _consent)
        monkeypatch.setattr(
            actions, "record_tool_lineage",
            lambda *a, **k: receipts.append((a, k)) or True,
        )
        calls = []

        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn(request)

        assert out.startswith("DID post")
        assert calls[0]["body"] == {"role": "viewer"}
        assert receipts[0][1]["approver"] == "user:reviewer"
        assert receipts[0][0][2]["body"] == {"role": "viewer"}

    def test_configured_approver_rejects_a_different_person_before_prepare(self, monkeypatch):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setenv("MAVERICK_GOVERNED_APPROVER", "user:owner")
        monkeypatch.setattr(
            consent, "require_consent",
            lambda *_args, **_kwargs: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )
        receipts, calls = [], []
        monkeypatch.setattr(actions, "record_tool_lineage",
                            lambda *_args, **kwargs: receipts.append(kwargs) or True)

        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn({
            "op": "post", "path": "/accounts", "body": {"n": 1},
        })

        assert "configured approver did not approve" in out
        assert receipts == [] and calls == []

    def test_credential_rotation_after_approval_blocks_external_write(
        self, monkeypatch,
    ):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setenv("MAVERICK_GOVERNED_APPROVER", "user:reviewer")
        monkeypatch.setenv("ACME_TOKEN", "generation-one")

        def approve(*_args, **_kwargs):
            monkeypatch.setenv("ACME_TOKEN", "generation-two")
            return SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            )

        monkeypatch.setattr(consent, "require_consent", approve)
        monkeypatch.setattr(actions, "record_tool_lineage", lambda *a, **k: True)
        calls = []

        out = wrap_connector_tool(
            _fake_tool(calls), enterprise=True,
        ).fn({"op": "post", "path": "/accounts", "body": {"n": 1}})

        assert out.startswith("REFUSED (governed)")
        assert "operation or its authority changed" in out
        assert calls == []

    def test_prepare_failure_refuses_before_external_effect(self, monkeypatch):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent, "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )
        monkeypatch.setattr(actions, "record_tool_lineage", lambda *a, **k: False)
        calls = []
        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn({
            "op": "delete", "path": "/accounts/1", "if_match": '"rev-7"',
        })
        assert out.startswith("REFUSED (governed)")
        assert "PREPARE" in out
        assert calls == []

    def test_missing_commit_receipt_is_indeterminate_not_retryable(self, monkeypatch):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent, "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )

        def _record(*args, **kwargs):
            return kwargs["phase"] == "PREPARE"

        monkeypatch.setattr(actions, "record_tool_lineage", _record)
        calls = []
        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn({
            "op": "put", "path": "/accounts/1", "if_match": '"rev-7"',
        })
        assert calls and calls[-1]["confirm"] is True
        assert out.startswith("INDETERMINATE (governed)")
        assert "do not retry automatically" in out

    def test_strict_commit_receipt_exception_is_indeterminate(self, monkeypatch):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent, "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )

        def _record(*args, **kwargs):
            if kwargs["phase"] == "COMMIT":
                raise OSError("ledger disk unavailable")
            return True

        monkeypatch.setattr(actions, "record_tool_lineage", _record)
        calls = []
        out = wrap_connector_tool(_fake_tool(calls), enterprise=True).fn({
            "op": "post", "path": "/accounts",
        })
        assert calls and calls[0]["confirm"] is True
        assert out.startswith("INDETERMINATE (governed)")
        assert "do not retry automatically" in out

    @pytest.mark.parametrize("failure_kind", ["raise", "error-result", "typed-unknown", "typed-refusal"])
    def test_connector_failure_after_prepare_is_indeterminate(
        self, monkeypatch, failure_kind,
    ):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent, "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )
        receipts = []

        def _record(*args, **kwargs):
            receipts.append(kwargs["phase"])
            return True

        monkeypatch.setattr(actions, "record_tool_lineage", _record)

        def _fail(_args):
            if failure_kind == "raise":
                raise TimeoutError("response lost")
            if failure_kind == "typed-unknown":
                from maverick.tool_results import ToolOutcome, ToolResultState

                return ToolOutcome(ToolResultState.INDETERMINATE, "acknowledgment lost")
            if failure_kind == "typed-refusal":
                from maverick.tool_results import ToolOutcome, ToolResultState

                return ToolOutcome(ToolResultState.REFUSED, "denied")
            return "ERROR: upstream connection reset"

        tool = Tool(
            name="acme", description="Acme", input_schema=_SCHEMA, fn=_fail,
        )
        out = wrap_connector_tool(tool, enterprise=True).fn({
            "op": "delete", "path": "/accounts/1", "if_match": '"rev-7"',
        })
        assert out.startswith("INDETERMINATE (governed)")
        assert "reconcile" in out
        assert receipts == ["PREPARE", "INDETERMINATE"]

    def test_typed_success_commits_and_returns_content(self, monkeypatch):
        import maverick.governed_actions as actions
        from maverick.tool_results import ToolOutcome, ToolResultState

        _grant_human(monkeypatch)
        receipts = []
        monkeypatch.setattr(
            actions, "record_tool_lineage",
            lambda *args, **kwargs: receipts.append(kwargs["phase"]) or True,
        )
        tool = Tool(
            name="acme", description="Acme", input_schema=_SCHEMA,
            fn=lambda _args: ToolOutcome(ToolResultState.SUCCEEDED, "created"),
        )
        out = wrap_connector_tool(tool, enterprise=True).fn({
            "op": "post", "path": "/accounts",
        })
        assert out == "created"
        assert receipts == ["PREPARE", "COMMIT"]

    @pytest.mark.parametrize("stop_name", ["BudgetExceeded", "UsageAccountingError", "Halted", "CancelledError"])
    @pytest.mark.parametrize("receipt_fails", [None, "OSError", "UsageAccountingError", "CancelledError"])
    def test_connector_stop_keeps_indeterminate_receipt_and_original_exception(
        self, monkeypatch, stop_name, receipt_fails,
    ):
        import maverick.budget as budget
        import maverick.governed_actions as actions
        import maverick.killswitch as killswitch

        _grant_human(monkeypatch)
        error_type = {"Halted": killswitch.Halted, "CancelledError": asyncio.CancelledError}.get(
            stop_name, getattr(budget, stop_name, None))
        original = (error_type("original stop", "test") if stop_name == "Halted"
                    else error_type("original stop"))
        receipts = []

        def record(*_args, **kwargs):
            receipts.append(kwargs["phase"])
            if receipt_fails and kwargs["phase"] == "INDETERMINATE":
                reporting_type = {"OSError": OSError, "UsageAccountingError": budget.UsageAccountingError,
                                  "CancelledError": asyncio.CancelledError}[receipt_fails]
                raise reporting_type("receipt unavailable")
            return True

        def fail(_args):
            raise original

        monkeypatch.setattr(actions, "record_tool_lineage", record)
        wrapped = wrap_connector_tool(Tool("acme", "fixture", _SCHEMA, fail), enterprise=True)
        with pytest.raises(error_type) as raised:
            wrapped.fn({"op": "post", "path": "/accounts"})
        assert raised.value is original
        assert receipts == ["PREPARE", "INDETERMINATE"]

    @pytest.mark.parametrize("failure_kind", ["raise", "error-result"])
    def test_connector_failure_never_returns_secret_detail_to_model(
        self, monkeypatch, failure_kind,
    ):
        import maverick.governed_actions as actions
        import maverick.safety.consent as consent

        monkeypatch.setattr(
            consent, "require_consent",
            lambda *a, **k: SimpleNamespace(
                granted=True, source="dashboard", actor="user:reviewer",
            ),
        )
        monkeypatch.setattr(actions, "record_tool_lineage", lambda *a, **k: True)
        secret = "postgres://admin:super-secret@db.internal/customer"  # pragma: allowlist secret

        def _fail(_args):
            if failure_kind == "raise":
                raise RuntimeError(secret)
            return f"ERROR: upstream rejected DSN {secret}"

        out = wrap_connector_tool(Tool(
            name="acme", description="Acme", input_schema=_SCHEMA, fn=_fail,
        ), enterprise=True).fn({
            "op": "delete", "path": "/accounts/1", "if_match": '"rev-7"',
        })

        assert out.startswith("INDETERMINATE (governed)")
        assert "super-secret" not in out
        assert "postgres://" not in out
