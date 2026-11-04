"""Controlled contracts for maintained examples, using synthetic external boundaries."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "docs" / "clients" / "examples" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loop = load("external_agent_loop")
rest = load("rest_lifecycle")


class Gateway:
    def __init__(self, mode="approved"):
        self.mode, self.finishes = mode, []

    def start(self, *_args, **_kwargs):
        return {"goal_id": 4}

    def heartbeat(self, _goal):
        return self.mode != "halt"

    def screen(self, *_args, **_kwargs):
        return {"allowed": False, "requires_approval": self.mode != "denied",
                "approval_id": 12, "approval_binding_sha256": "a" * 64}

    def approval(self, _approval_id, binding):
        if self.mode == "stale":
            raise requests.HTTPError("stale binding")
        return {"approval_id": 12, "approval_binding_sha256": binding,
                "status": "pending" if self.mode == "pending" else "approved",
                "expires_at": 1 if self.mode == "expired" else 2000}

    def finish(self, goal, outcome, **fields):
        self.finishes.append((goal, outcome, fields))
        return {"recorded": True}


def completion():
    call = SimpleNamespace(id="call-1", function=SimpleNamespace(name="send_email", arguments='{"to":"finance@example.test","body":"reviewed"}'))
    messages = iter((SimpleNamespace(content="", tool_calls=[call]), SimpleNamespace(content="Complete", tool_calls=[])))
    return lambda _messages: next(messages)


def immediate_clock_authorize(lw, tool, args, **kwargs):
    clock = [0.0]
    def sleep(seconds):
        clock[0] += seconds
    return loop.authorize(lw, tool, args, **kwargs, wait_seconds=3, clock=lambda: clock[0], now=lambda: 1000, sleep=sleep)


@pytest.mark.parametrize("mode", ["pending", "denied", "expired", "stale", "halt"])
def test_unapproved_or_halted_work_never_sends_or_reports_success(mode):
    gateway, emails = Gateway(mode), []
    result = loop.run_tool_loop(gateway, completion(), lambda **args: emails.append(args), [], authorize_action=immediate_clock_authorize)
    assert emails == []
    assert result["outcome"] == "failure"
    assert len(gateway.finishes) == 1 and gateway.finishes[0][1] == "failure"


def test_normal_completion_and_exception_finalize_once():
    gateway, emails = Gateway(), []
    result = loop.run_tool_loop(gateway, completion(), lambda **args: emails.append(args) or "sent", [], authorize_action=immediate_clock_authorize)
    assert result["outcome"] == "success" and len(emails) == len(gateway.finishes) == 1
    failed = Gateway()
    loop.run_tool_loop(failed, lambda _messages: (_ for _ in ()).throw(RuntimeError("provider token secret")), lambda **_args: None, [])
    assert len(failed.finishes) == 1 and failed.finishes[0][1] == "failure"
    assert "secret" not in str(failed.finishes)


class Response:
    def __init__(self, body, status=200):
        self.body, self.status_code = body, status
    def json(self):
        return self.body
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


@pytest.mark.parametrize("status", ["done", "blocked", "completed", "failed", "cancelled", "error"])
def test_three_page_terminal_backlog_is_delivered_once(status):
    pages = iter([
        Response({"events": [{"id": 2}, {"id": 9}], "next_id": 9, "has_more": True, "terminal": False, "status": status}),
        Response({"events": [{"id": 9}, {"id": 21}], "next_id": 21, "has_more": True, "terminal": False, "status": status}),
        Response({"events": [{"id": 40}], "next_id": 40, "has_more": False, "terminal": True, "status": status}),
    ])
    seen = []
    result = rest.poll_events(SimpleNamespace(get=lambda *_args, **_kwargs: next(pages)), "https://example.test", {}, 1, seen.append)
    assert [row["id"] for row in seen] == [2, 9, 21, 40]
    assert result == {"terminal": True, "since": 40, "status": status}


def test_shared_dashboard_fixture_replays_in_the_standalone_rest_client():
    path = ROOT / "apps/client-contract-tests/contracts/goal-events-v1.json"
    fixture = json.loads(path.read_text(encoding="utf-8"))
    pages = iter(Response(page) for page in fixture["pages"])
    seen = []
    result = rest.poll_events(SimpleNamespace(get=lambda *_args, **_kwargs: next(pages)),
                              "https://example.test", {}, 1, seen.append)
    assert [event["id"] for event in seen] == [1, 2, 3]
    assert result["terminal"] is True and result["since"] == 3


def test_poll_401_stops_with_repair_message():
    with pytest.raises(PermissionError, match="Restore sign-in"):
        rest.poll_events(SimpleNamespace(get=lambda *_args, **_kwargs: Response({}, 401)), "https://example.test", {}, 1, lambda _event: None)


def test_accepted_timeout_performs_one_post_then_original_key_receipt_get():
    fixture = json.loads((ROOT / "apps/client-contract-tests/contracts/goal-submission-recovery-v1.json").read_text())
    writes, reads = [], []
    def post(*args, **kwargs):
        writes.append(kwargs)
        raise requests.Timeout("reply lost")
    def get(*args, **kwargs):
        reads.append(kwargs)
        return Response(fixture["receipt"])
    receipt = rest.start_or_reconcile(SimpleNamespace(post=post, get=get), "https://example.test", {}, {"title": fixture["title"]}, fixture["idempotency_key"])
    assert receipt["execution_confirmed"] is False and len(writes) == len(reads) == 1
    assert writes[0]["headers"]["Idempotency-Key"] == reads[0]["headers"]["Idempotency-Key"] == fixture["idempotency_key"]


class Unreadable(Response):
    def json(self):
        raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)


@pytest.mark.parametrize("outcome", [
    requests.exceptions.ChunkedEncodingError("connection broken mid-response"),
    requests.exceptions.ConnectionError("reset after the request was sent"),
    Unreadable(None),
], ids=["cut-off-body", "connection-reset", "unparsable-2xx"])
def test_any_failure_after_the_post_was_sent_reconciles_with_one_get(outcome):
    writes, reads = [], []
    def post(*args, **kwargs):
        writes.append(kwargs)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    def get(*args, **kwargs):
        reads.append(kwargs)
        return Response({"state": "accepted", "goal": {"id": 9}, "execution_confirmed": False})
    receipt = rest.start_or_reconcile(SimpleNamespace(post=post, get=get), "https://example.test", {}, {"title": "work"}, "persisted-key")
    assert receipt["execution_confirmed"] is False and len(writes) == len(reads) == 1
    assert writes[0]["headers"]["Idempotency-Key"] == reads[0]["headers"]["Idempotency-Key"] == "persisted-key"


def test_a_definite_rejection_is_not_reconciled():
    reads = []
    session = SimpleNamespace(post=lambda *a, **k: Response({}, 422), get=lambda *a, **k: reads.append(k))
    with pytest.raises(requests.HTTPError):
        rest.start_or_reconcile(session, "https://example.test", {}, {"title": "work"}, "persisted-key")
    assert reads == []
