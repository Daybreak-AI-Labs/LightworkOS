"""Focused regressions for federation and connector boundary reporting."""
from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest


def test_unauthenticated_delegation_is_limited_before_audit(monkeypatch):
    from maverick import federation as fed

    records, rates = [], []
    service = fed.FederationService(peers=[], record=lambda *a, **k: records.append(k))
    monkeypatch.setattr(fed, "_fed_rate_ok", lambda key: rates.append(key) or len(rates) == 1)
    for _ in range(2):
        assert not service.delegate_goal({"auth_token": "invalid"})["accepted"]
    assert len(records) == 1
    assert len(rates) == 2


def test_record_run_holds_fleet_lock_alongside_runs_lock(monkeypatch, tmp_path):
    from maverick import file_lock, fleet

    held = []
    monkeypatch.setattr(fleet, "fleets_dir", lambda **kwargs: tmp_path)

    @contextmanager
    def locked(path):
        held.append(path.name)
        try:
            yield
        finally:
            held.remove(path.name)

    def write(path, text):
        assert "team.json" in held
        assert "team.runs.json" in held

    monkeypatch.setattr(file_lock, "cross_process_lock", locked)
    monkeypatch.setattr(file_lock, "atomic_write_text", write)
    fleet.record_run("team", "agent", 1)


@pytest.mark.parametrize("field,value", [
    ("repository", []), ("label", "maverick"), ("label", {"name": []}),
    ("issue", []), ("sender", "person"), ("comment", {"body": 123}),
])
def test_malformed_webhook_fields_are_refused(field, value):
    from maverick.github_app import parse_webhook

    payload = {"action": "labeled", "repository": {"full_name": "org/repo"},
               "issue": {"number": 1}, "label": {"name": "maverick"}}
    event = "issues"
    if field == "comment":
        payload["action"] = "created"
        event = "issue_comment"
    payload[field] = value
    assert parse_webhook(event, payload) is None


@pytest.mark.parametrize("credentials", [
    {"auth_token": "sample"}, {"headers": {"aUtHoRiZaTiOn": "Bearer sample"}},
])
def test_static_mcp_credentials_require_secure_remote_transport(credentials):
    from maverick.mcp_client import MCPServerSpec

    with pytest.raises(ValueError, match="https"):
        MCPServerSpec(name="remote", url="http://remote.example/mcp", **credentials)
    assert MCPServerSpec(name="remote", url="https://remote.example/mcp", **credentials)
    for host in ("127.0.0.1", "[::1]", "localhost"):
        assert MCPServerSpec(name="local", url=f"http://{host}/mcp", **credentials)


def test_department_validates_name_before_lock(monkeypatch):
    from maverick import departments, file_lock
    from maverick.fleet import Fleet

    monkeypatch.setattr(departments, "get_department", lambda *a: SimpleNamespace(members=[]))
    monkeypatch.setattr(departments, "department_entitled", lambda *a, **k: True)
    monkeypatch.setattr("maverick.suite_grants.ensure_suite_allowed", lambda *a: None)
    monkeypatch.setattr(departments, "fleet_from_department", lambda *a, **k: Fleet("../escape", ""))

    def forbidden_lock(path):
        pytest.fail("invalid fleet name reached filesystem lock")

    monkeypatch.setattr(file_lock, "cross_process_lock", forbidden_lock)
    with pytest.raises(ValueError, match="invalid fleet name"):
        departments.deploy_department("finance", "")


def _approved_connector(monkeypatch, result):
    from maverick import governed_actions, governed_tools
    from maverick.tools import Tool

    receipts = []
    monkeypatch.setattr("maverick.safety.consent.require_consent", lambda *a, **k: SimpleNamespace(
        granted=True, source="dashboard", actor="user:reviewer"))
    monkeypatch.setattr(governed_actions, "record_tool_lineage",
                        lambda *a, **k: receipts.append(k) or True)
    schema = {"type": "object", "properties": {"op": {"type": "string"}, "path": {"type": "string"}}}
    return governed_tools.wrap_connector_tool(Tool("acme", "fixture", schema, lambda args: result),
                                             enterprise=True), receipts


@pytest.mark.parametrize("failure_at", ["context_exit", "outcome", "redaction"])
def test_post_effect_failures_record_indeterminate(monkeypatch, failure_at):
    from maverick import governed_tools
    from maverick.safety import consent
    from maverick.tool_results import ToolOutcome

    wrapped, receipts = _approved_connector(monkeypatch, "created")

    def fail(*a, **k):
        raise RuntimeError("secret failure detail")

    if failure_at == "context_exit":
        consume = consent.consume_operation_consent

        @contextmanager
        def failing_exit(permit):
            with consume(permit):
                yield
            fail()

        monkeypatch.setattr(consent, "consume_operation_consent", failing_exit)
    elif failure_at == "outcome":
        monkeypatch.setattr(ToolOutcome, "from_legacy", fail)
    else:
        monkeypatch.setattr(governed_tools, "_safe_connector_result", fail)
    result = wrapped.fn({"op": "post", "path": "/accounts"})
    assert result.startswith("INDETERMINATE (governed)")
    assert "secret failure detail" not in result
    assert [r["phase"] for r in receipts] == ["PREPARE", "INDETERMINATE"]
    assert "transaction_id=" in result


def test_indeterminate_connector_result_preserves_redacted_reconciliation(monkeypatch):
    from maverick.tool_results import ToolOutcome, ToolResultState

    wrapped, receipts = _approved_connector(monkeypatch, ToolOutcome(
        ToolResultState.INDETERMINATE,
        "Job job-123 in US is running; postgres://admin:secret@db.internal/data",  # pragma: allowlist secret -- synthetic redaction fixture
    ))
    result = wrapped.fn({"op": "post", "path": "/jobs"})
    assert "job-123" in result and "US" in result
    assert "postgres://" not in result and "admin:secret" not in result
    assert [r["phase"] for r in receipts] == ["PREPARE", "INDETERMINATE"]


def test_s3_presign_requires_governed_write_approval():
    from maverick.governed_tools import _is_governed_write
    from maverick.tools.s3_tool import s3_tool

    assert _is_governed_write(s3_tool(), {"op": "presign", "bucket": "b", "key": "k"})


def test_redirect_preserves_caller_transport_and_strips_cross_origin_secrets(monkeypatch):
    from maverick.governed_http import guarded_redirect_get

    requests = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)

    def transport(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(302, headers={"Location": "https://other.example/done"})
        return httpx.Response(200, text="done")

    client = httpx.Client(transport=httpx.MockTransport(transport),
                          headers={"X-Api-Key": "secret", "Authorization": "Bearer secret"})
    client.cookies.set("destination", "session", domain="other.example", path="/")
    with client:
        def no_replacement(**kwargs):
            pytest.fail("redirect discarded caller-owned transport")

        monkeypatch.setattr(httpx, "Client", no_replacement)
        result = guarded_redirect_get(client.get)("https://first.example/start")
        assert result.text == "done"
    assert requests[0].headers["X-Api-Key"] == "secret"
    assert "X-Api-Key" not in requests[1].headers
    assert "Authorization" not in requests[1].headers
    assert requests[1].headers["Cookie"] == "destination=session"


def test_dispatch_authorization_must_precede_in_the_same_function(tmp_path):
    from maverick.dispatch_contract import scan_file

    source = tmp_path / "dispatch.py"
    source.write_text(
        "def late(registry):\n registry.run(name, args)\n authorize(name, args)\n"
        "def nested(registry):\n def unused():\n  authorize(name, args)\n registry.run(name, args)\n"
        "def outer(registry):\n authorize(name, args)\n def inner():\n  registry.run(name, args)\n"
        "def good(registry):\n authorize(name, args)\n registry.run(name, args)\n",
        encoding="utf-8",
    )
    assert [hit["gated"] for hit in scan_file(source)] == [False, False, True, False]


@pytest.mark.parametrize("cap", [None, 0.0, 2.5])
def test_grpc_preserves_dollar_cap_presence_to_both_service_methods(monkeypatch, cap):
    from maverick.agent_trust import TrustedAgent
    from maverick.grpc_api import server
    from maverick.grpc_dispatcher import GrpcDispatcher

    requests, received = [], []
    pb2 = SimpleNamespace(RunGoalRequest=lambda **kwargs: SimpleNamespace(**kwargs),
                          GoalStatus=lambda **kwargs: SimpleNamespace(**kwargs),
                          StartGoalResponse=lambda **kwargs: SimpleNamespace(**kwargs))
    stub = SimpleNamespace(RunGoal=lambda request, **kwargs: requests.append(request) or
                           SimpleNamespace(found=True, status="done"))
    dispatcher = GrpcDispatcher("worker:50051", stub_factory=lambda: (stub, pb2))
    assert dispatcher.submit(7, max_dollars=cap) == "done"
    request = requests[0]
    assert request.has_max_dollars is (cap is not None)
    request.title, request.description = "title", ""
    agent = TrustedAgent(id="caller", max_dollars=10, max_wall_seconds=100)
    monkeypatch.setattr(server, "_authorize_caller", lambda *a: agent)
    monkeypatch.setattr(server, "_trust_capability", lambda *a: None)
    monkeypatch.setattr(server, "_rpc_capability", lambda *a, **k: None)
    service = SimpleNamespace(
        run_goal=lambda *a, **kwargs: received.append(kwargs) or
        SimpleNamespace(goal_id=7, status="done", result="ok"),
        start_goal=lambda *a, **kwargs: received.append(kwargs) or 7,
    )
    servicer = server._servicer(service, pb2, SimpleNamespace(MaverickServicer=object),
                               bearer_token="test-token")
    servicer.RunGoal(request, object())
    servicer.StartGoal(request, object())
    assert [call["max_dollars"] for call in received] == [10 if cap is None else cap] * 2


def test_network_redirect_is_pinned_and_private_destination_is_refused(monkeypatch):
    import socket

    from maverick.governed_http import guarded_redirect_get
    from maverick.tools import _ssrf

    seen = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    monkeypatch.setattr(_ssrf.socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host if host == "127.0.0.1" else "93.184.216.34", 0))])

    def network_handle_request(self, request):
        seen.append((str(request.url), request.headers["Host"], request.extensions.get("sni_hostname")))
        if len(seen) == 1:
            return httpx.Response(302, headers={"Location": "https://next.example/step"})
        if len(seen) == 2:
            return httpx.Response(302, headers={"Location": "/relative"})
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/internal"})

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", network_handle_request)
    with httpx.Client(transport=httpx.HTTPTransport()) as client:
        with pytest.raises(_ssrf.BlockedHost):
            guarded_redirect_get(client.get)("https://first.example/start")
        assert not client.is_closed
    assert [item[0] for item in seen] == ["https://first.example/start",
                                        "https://93.184.216.34/step",
                                        "https://93.184.216.34/relative"]
    assert seen[1][1:] == ("next.example", "next.example")
    assert seen[2][1:] == ("next.example", "next.example")
